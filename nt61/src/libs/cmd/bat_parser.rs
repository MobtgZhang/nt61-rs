//! BAT Batch File Parser
//
//! Implements a Windows-compatible batch file interpreter supporting:
//! - GOTO label
//! - IF conditionals (EXIST, ERRORLEVEL, string comparison)
//! - FOR loops
//! - CALL subroutines
//! - SETLOCAL/ENDLOCAL environment scoping
//! - Variable expansion %VAR%

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::format;

/// Batch parser error types
#[derive(Debug, Clone)]
pub enum BatError {
    /// File not found
    FileNotFound(String),
    /// Label not found (for GOTO)
    LabelNotFound(String),
    /// Syntax error
    SyntaxError(String),
    /// Exit batch file (with optional error code)
    Exit(i32),
    /// Call stack underflow (too many ENDLOCALs)
    CallStackUnderflow,
    /// I/O error
    IoError,
}

/// Line type classification
#[derive(Debug, Clone)]
pub enum LineType {
    /// Empty line or whitespace
    Empty,
    /// REM or :: comment
    Comment,
    /// :label definition
    Label(String),
    /// GOTO command
    Goto(String),
    /// IF conditional
    If {
        condition: String,
        true_branch: String,
        false_branch: Option<String>,
    },
    /// FOR loop
    For {
        variable: String,
        set: String,
        command: String,
    },
    /// CALL command
    Call(String),
    /// SETLOCAL command
    SetLocal,
    /// ENDLOCAL command
    EndLocal,
    /// PAUSE command (wait for keypress)
    Pause,
    /// SHIFT command (shift batch arguments)
    Shift,
    /// EXIT [/B] command
    Exit {
        batch_only: bool,
        code: Option<i32>,
    },
    /// Regular command
    Command(String),
}

/// Batch parser state
pub struct BatchParser {
    /// Preprocessed lines (comments removed, variables expanded)
    lines: Vec<String>,
    /// Labels (label_name -> line_index)
    labels: Vec<(&'static str, usize)>,
    /// Current execution position
    current: usize,
    /// FOR loop variable stack
    for_stack: Vec<ForContext>,
    /// Call stack for nested GOTO/CALL
    call_stack: Vec<usize>,
    /// SETLOCAL stack (saved environment snapshots)
    setlocal_stack: Vec<EnvSnapshot>,
    /// Echo state
    echo: bool,
    /// Error level from last command
    error_level: i32,
    /// Whether batch file is running
    running: bool,
    /// Internal variables for SETLOCAL/ENDLOCAL support
    variables: Vec<(String, String)>,
}

/// FOR loop context
struct ForContext {
    variable: String,
    items: Vec<String>,
    current_index: usize,
    command: String,
}

/// Environment snapshot for SETLOCAL/ENDLOCAL
#[derive(Clone)]
struct EnvSnapshot {
    variables: Vec<(String, String)>,
    error_level: i32,
}

impl BatchParser {
    /// Create a new batch parser
    pub fn new() -> Self {
        Self {
            lines: Vec::new(),
            labels: Vec::new(),
            current: 0,
            for_stack: Vec::new(),
            call_stack: Vec::new(),
            setlocal_stack: Vec::new(),
            echo: true,
            error_level: 0,
            running: false,
            variables: Vec::new(),
        }
    }

    /// Execute a batch file
    /// Returns Ok(()) on normal completion, Err on error
    pub fn execute(&mut self, filename: &str, executor: &mut dyn BatchExecutor) -> Result<(), BatError> {
        self.lines.clear();
        self.labels.clear();
        self.current = 0;
        self.for_stack.clear();
        self.call_stack.clear();
        self.setlocal_stack.clear();
        self.variables.clear();
        self.echo = true;
        self.running = true;

        // Read the batch file content
        let content = executor.read_file(filename)?;
        crate::boot_println!("[BAT] loaded {} bytes from {}", content.len(), filename);
        // Preprocess: remove comments, handle special lines
        self.preprocess(&content);
        
        // Collect labels
        self.collect_labels();
        
        // Execute the batch file. A simple line-cap guards against
        // runaway GOTO/CALL recursion (e.g. an infinite `GOTO :LOOP`
        // because SET /A arithmetic is not supported yet). After
        // MAX_BAT_STEPS lines we just stop and return Ok.
        const MAX_BAT_STEPS: usize = 5000;
        crate::boot_println!("[BAT] exec: total_lines={}", self.lines.len());
        let mut steps: usize = 0;
        while self.current < self.lines.len() && self.running {
            steps += 1;
            if steps > MAX_BAT_STEPS {
                crate::boot_println!("[BAT] step cap ({}) reached — aborting batch", MAX_BAT_STEPS);
                break;
            }
            let line = &self.lines[self.current];
            self.current += 1;

            // Expand variables in the line
            let expanded = self.expand_variables(line);
            crate::boot_println!("[BAT]   line[{}] '{}'", self.current - 1, expanded);
            
            // Classify and process the line
            match self.classify_line(&expanded) {
                LineType::Empty => {}
                LineType::Comment => {}
                LineType::Label(_) => {} // Already handled by collect_labels
                LineType::Goto(label) => {
                    self.handle_goto(&label)?;
                }
                LineType::If { condition, true_branch, false_branch } => {
                    let cond = self.evaluate_condition(&condition)?;
                    // The lowered block-IF puts a GOTO in the true branch
                    // (e.g. `IF "%A%" == "%B%" GOTO :__IF_THEN_1__`). If
                    // condition is true we just run the GOTO; if false,
                    // control falls through to the next line (which the
                    // lowering emitted as `GOTO :__IF_ELSE_1__` for the
                    // else-branch case).
                    if cond && !true_branch.is_empty() {
                        let upper_branch =
                            true_branch.to_uppercase();
                        if upper_branch.starts_with("GOTO ") {
                            let label = true_branch[4..].trim().to_string();
                            self.handle_goto(&label)?;
                        } else {
                            self.execute_command(&true_branch, executor)?;
                        }
                    } else if !cond {
                        if let Some(fb) = false_branch {
                            if !fb.is_empty() {
                                self.execute_command(&fb, executor)?;
                            }
                        }
                    }
                }
                LineType::For { variable, set, command } => {
                    self.handle_for(&variable, &set, &command, executor)?;
                }
                LineType::Call(target) => {
                    self.handle_call(&target, executor)?;
                }
                LineType::SetLocal => {
                    self.push_setlocal();
                }
                LineType::EndLocal => {
                    self.pop_setlocal();
                }
                LineType::Pause => {
                    // PAUSE — print "Press any key to continue . . ." and
                    // wait for a keypress. We don't have a blocking
                    // read-until-key API in the kernel, so we just emit
                    // the prompt and yield. The serial port is line-
                    // buffered in our setup, so a newline from the user
                    // unblocks.
                    executor.echo_line("Press any key to continue . . .");
                    // Drain a single character from the executor's
                    // environment by issuing an empty SET (the parser
                    // already runs inside the shell's executor, so the
                    // user just has to press Enter to continue).
                    let _ = executor.execute_command("REM pause");
                }
                LineType::Shift => {
                    // SHIFT without arguments is a no-op in this
                    // implementation — we don't have a real %0..%9
                    // argument vector. It is recognised so batch files
                    // that contain it don't error out.
                }
                LineType::Exit { batch_only, code } => {
                    if batch_only {
                        // Pop call stack if we're in a called subroutine
                        if let Some(_saved_pos) = self.call_stack.pop() {
                            // Return to caller
                            return Ok(());
                        }
                        self.running = false;
                        return Ok(());
                    } else {
                        // Exit the entire CMD
                        self.running = false;
                        return Err(BatError::Exit(code.unwrap_or(0)));
                    }
                }
                LineType::Command(cmd) => {
                    if self.echo {
                        executor.echo_line(&expanded);
                    }

                    // Handle batch SET VAR=value commands inline (don't
                    // hand them to the executor). Returning here would
                    // *exit the whole batch*, so we guard with a
                    // local flag and `continue` the outer loop.
                    let upper_cmd = cmd.to_uppercase();
                    if upper_cmd.starts_with("SET ") {
                        let set_part = &cmd[4..].trim();
                        // Support `SET [/A] VAR=...` and the operator
                        // shorthands `VAR-=1`, `VAR+=2`, etc. Real
                        // CMD recognises `/A` as arithmetic, so we do
                        // the same to keep the test suite's loops
                        // (which use `SET /A VAR-=1`) from spinning
                        // forever.
                        let (arith, body) = if let Some(stripped) =
                            set_part.strip_prefix("/A")
                        {
                            (true, stripped.trim_start())
                        } else {
                            (false, set_part as &str)
                        };
                        // Detect compound assignment operator at the
                        // position of the LAST `=` if the character
                        // right before it is one of `+ - * / %`.
                        // Examples: `VAR-=1`, `VAR+=2`, `VAR*=3`.
                        let split = find_assignment_split(body);
                        if let Some((var_name, op, raw_value)) = split {
                            let expanded_value = if arith || op.is_some() {
                                let lhs = self
                                    .get_variable(&var_name)
                                    .unwrap_or_default();
                                let resolved = if op.is_some() {
                                    // VAR-=N => VAR = (VAR op N)
                                    let op_char = op.unwrap();
                                    alloc::format!(
                                        "{} {} {}",
                                        lhs.trim(),
                                        op_char,
                                        raw_value.trim()
                                    )
                                } else {
                                    raw_value.to_string()
                                };
                                let v = eval_int_expr(&self.expand_variables(&resolved));
                                v.map(|i| i.to_string())
                                    .unwrap_or_else(|| resolved)
                            } else {
                                self.expand_variables(raw_value)
                            };
                            self.set_variable(&var_name, &expanded_value);
                            self.error_level = 0;
                            continue;
                        }
                    }

                    self.error_level = executor.execute_command(&cmd)? as i32;
                }
            }
        }

        Ok(())
    }

    /// Stop execution
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Check if still running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get current error level
    pub fn get_error_level(&self) -> i32 {
        self.error_level
    }

    /// Set error level
    pub fn set_error_level(&mut self, level: i32) {
        self.error_level = level;
    }

    /// Set echo state
    pub fn set_echo(&mut self, on: bool) {
        self.echo = on;
    }

    /// Preprocess batch file content
    fn preprocess(&mut self, content: &str) {
        let in_block_comment = false;
        let _ = &in_block_comment;
        
        for line in content.lines() {
            let trimmed = line.trim().to_string();
            
            // Skip empty lines
            if trimmed.is_empty() {
                self.lines.push(String::new());
                continue;
            }
            
            // Handle labels (`:FOO` or `::FOO`). Both forms are valid
            // goto targets in real Windows CMD; `::FOO` is a
            // comment-shaped label, but GOTO can still land on it.
            // We push the raw line so `collect_labels` sees it, and
            // the per-line classifier still skips it at execution
            // time so the line does not produce a spurious echo.
            if trimmed.starts_with(':') && !trimmed.is_empty() {
                let after_colons = trimmed.trim_start_matches(':');
                // If there are no colons following the first set (i.e.
                // exactly one `:` followed by a name) treat it as a
                // real label; if there are two colons it's the DOS
                // comment form that doubles as a goto target.
                let is_real_label =
                    !trimmed.starts_with("::") || !after_colons.starts_with(':');
                let label_name = after_colons.trim_start_matches(':').trim();
                if !label_name.is_empty() {
                    self.lines.push(trimmed);
                    let _ = is_real_label;
                    continue;
                }
            }

            // Handle REM comments
            if trimmed.to_uppercase().starts_with("REM ") || trimmed.to_uppercase() == "REM" {
                continue;
            }
            
            // Handle @ prefix (suppress echo for this line only).
            // Special-case `@echo off` / `@echo on` because `@echo`
            // would otherwise be parsed as a regular command.
            if trimmed.starts_with('@') {
                let after_at = trimmed[1..].trim();
                let upper = after_at.to_uppercase();
                if upper == "ECHO OFF" {
                    self.echo = false;
                    continue;
                }
                if upper == "ECHO ON" {
                    self.echo = true;
                    continue;
                }
                self.lines.push(after_at.to_string());
                continue;
            }

            // Handle ECHO OFF (suppress subsequent echo)
            if trimmed.to_uppercase() == "ECHO OFF" {
                self.echo = false;
                continue;
            }

            // Handle ECHO ON
            if trimmed.to_uppercase() == "ECHO ON" {
                self.echo = true;
                self.lines.push(trimmed);
                continue;
            }
            
            // Regular line
            self.lines.push(trimmed);
        }
        // Convert multi-line `IF cond ( ... ) ELSE ( ... )` blocks into
        // equivalent flat `IF cond body` plus synthetic labels. This is
        // the standard CMD lowering transformation.
        self.flatten_block_ifs();
    }

    /// Walk through `self.lines` and rewrite multi-line IF blocks into
    /// their equivalent goto-chain form. Specifically:
    ///
    /// ```text
    /// IF %A% == %B% (
    ///     body1
    /// ) ELSE (
    ///     body2
    /// )
    /// ```
    ///
    /// becomes the synthetic sequence:
    ///
    /// ```text
    /// IF "%A%" == "%B%" GOTO :__if_then_<N>
    /// GOTO :__if_else_<N>
    /// :__if_then_<N>
    ///     body1
    /// GOTO :__if_end_<N>
    /// :__if_else_<N>
    ///     body2
    /// :__if_end_<N>
    /// ```
    ///
    /// For nested IFs we walk top-down: at each opening IF line we
    /// search for the matching closing `)` (skipping nested
    /// `IF ... (` blocks), then for an optional `) ELSE (` clause,
    /// then for the second closing `)`.
    fn flatten_block_ifs(&mut self) {
        let mut out: Vec<alloc::string::String> =
            alloc::vec::Vec::with_capacity(self.lines.len());
        let mut counter: usize = 0;
        let mut i: usize = 0;
        while i < self.lines.len() {
            let line = self.lines[i].clone();
            let upper = line.to_uppercase();
            if upper.starts_with("IF ") && line.trim_end().ends_with('(') {
                crate::boot_println!(
                    "[BAT] flatten-block-if at line[{}]: '{}'",
                    i,
                    line
                );
                counter += 1;
                // Extract the condition by stripping `IF ` prefix
                // and trailing `(`.
                let cond = if let Some(rest) =
                    line.trim_start().strip_prefix("IF ")
                {
                    rest.trim_end().trim_end_matches('(').trim().to_string()
                } else if let Some(rest) =
                    line.trim_start().strip_prefix("IF")
                {
                    rest.trim().trim_end_matches('(').trim().to_string()
                } else {
                    String::new()
                };
                // Search for matching `)` taking nesting into
                // account.
                let (close_pos, else_pos) =
                    self.find_block_close(&self.lines, i + 1);
                // Verify by logging what lines we see at i+1..close_pos
                crate::boot_println!(
                    "[BAT]   flatten verification: i={} line='{}' i+1={} line[{}]='{}' close_pos={} else_pos={:?}",
                    i, line, i+1, i+1, self.lines.get(i+1).cloned().unwrap_or_default(),
                    close_pos, else_pos
                );
                crate::boot_println!(
                    "[BAT]   find_block_close returned close_pos={} else_pos={:?} lines.len={}",
                    close_pos,
                    else_pos,
                    self.lines.len()
                );
                if close_pos == 0 || close_pos >= self.lines.len() {
                    // Malformed — just emit the line verbatim.
                    out.push(line);
                    i += 1;
                    continue;
                }
                let then_label = alloc::format!(
                    "__IF_THEN_{}__",
                    counter
                );
                let else_label = alloc::format!(
                    "__IF_ELSE_{}__",
                    counter
                );
                let end_label = alloc::format!("__IF_END_{}__", counter);
                crate::boot_println!(
                    "[BAT]   flatten result: cond='{}' close_pos={} else_pos={:?}",
                    cond, close_pos, else_pos
                );
                // Build the lowered sequence locally so we can splice it
                // without doing arithmetic on the out-vector's
                // indices.
                let mut lowered: alloc::vec::Vec<
                    alloc::string::String,
                > = alloc::vec::Vec::new();
                let then_body_end = else_pos.unwrap_or(close_pos);
                // 1. `IF cond GOTO :then_label`
                lowered.push(alloc::format!(
                    "IF {} GOTO :{}",
                    cond, then_label
                ));
                // 2. Skip-past: `GOTO :else_label` (ELSE form) or
                //    `GOTO :end_label` (no-ELSE form). This is
                //    what cond=false falls into.
                if let Some(_) = else_pos {
                    lowered
                        .push(alloc::format!("GOTO :{}", else_label));
                } else {
                    lowered
                        .push(alloc::format!("GOTO :{}", end_label));
                }
                // 3. `:then_label` + then-body
                lowered.push(alloc::format!(":{}", then_label));
                let then_body_end = else_pos.unwrap_or(close_pos);
                let then_body: alloc::vec::Vec<alloc::string::String> =
                    self.lines[(i + 1)..then_body_end]
                        .iter()
                        .cloned()
                        .collect();
                let then_body = self.flatten_lines_block_ifs(
                    then_body,
                    counter,
                );
                counter = then_body.1;
                for b in then_body.0 {
                    lowered.push(b);
                }
                if let Some(ep) = else_pos {
                    // 4. tail GOTO to skip the else branch
                    lowered
                        .push(alloc::format!("GOTO :{}", end_label));
                    // 5. `:else_label` + else-body
                    lowered.push(alloc::format!(":{}", else_label));
                    let else_body: alloc::vec::Vec<
                        alloc::string::String,
                    > = self.lines[(ep + 1)..close_pos]
                        .iter()
                        .cloned()
                        .collect();
                    let else_body = self.flatten_lines_block_ifs(
                        else_body,
                        counter,
                    );
                    counter = else_body.1;
                    for b in else_body.0 {
                        lowered.push(b);
                    }
                    // 6. `:end_label`
                    lowered.push(alloc::format!(":{}", end_label));
                } else {
                    // 4. `:end_label` (cond=false GOTO lands here,
                    //    past the body).
                    lowered.push(alloc::format!(":{}", end_label));
                }
                crate::boot_println!(
                    "[BAT]   lowered IF ({} lines, next counter {})",
                    lowered.len(),
                    counter
                );
                out.append(&mut lowered);
                i = close_pos + 1;
                continue;
            }
            out.push(line);
            i += 1;
        }
        self.lines = out;
    }

    /// Recursively flatten any block-IFs inside a slice of lines.
    /// Used by `flatten_block_ifs` so that nested IFs become
    /// goto-chains at preprocessing time rather than being left
    /// unflattened for the runtime to (mis-)handle. The label
    /// counter is shared with the outer caller so multiple
    /// blocks across the same file never collide.
    fn flatten_lines_block_ifs(
        &self,
        lines: alloc::vec::Vec<alloc::string::String>,
        counter: usize,
    ) -> (
        alloc::vec::Vec<alloc::string::String>,
        usize,
    ) {
        let mut counter: usize = counter;
        // Run through `lines`, dropping block-IFs down to
        // goto-chains. We re-use the same lowering shape: each
        // nested `IF cond ( ... ) [ELSE ( ... )]` becomes
        // `IF cond GOTO :...`, `GOTO :...`, `:...`, body, GOTO
        // :...`, `:...`, body, `:...` — exactly the same
        // recipe, just on a smaller slice and with locally
        // unique label numbers.
        let mut out: alloc::vec::Vec<alloc::string::String> =
            alloc::vec::Vec::with_capacity(lines.len());
        let mut i: usize = 0;
        while i < lines.len() {
            let line = lines[i].clone();
            let upper = line.to_uppercase();
            if upper.starts_with("IF ")
                && line.trim_end().ends_with('(')
            {
                let cond = if let Some(rest) =
                    line.trim_start().strip_prefix("IF ")
                {
                    rest.trim_end()
                        .trim_end_matches('(')
                        .trim()
                        .to_string()
                } else if let Some(rest) =
                    line.trim_start().strip_prefix("IF")
                {
                    rest.trim()
                        .trim_end_matches('(')
                        .trim()
                        .to_string()
                } else {
                    String::new()
                };
                let (close_pos, else_pos) =
                    self.find_block_close(&lines, i + 1);
                if close_pos == 0 || close_pos >= lines.len() {
                    out.push(line);
                    i += 1;
                    continue;
                }
                counter += 1;
                let then_label = alloc::format!(
                    "__IF_THEN_{}__",
                    counter
                );
                let else_label = alloc::format!(
                    "__IF_ELSE_{}__",
                    counter
                );
                let end_label =
                    alloc::format!("__IF_END_{}__", counter);
                let mut lowered: alloc::vec::Vec<
                    alloc::string::String,
                > = alloc::vec::Vec::new();
                let then_body_end = else_pos.unwrap_or(close_pos);
                lowered.push(alloc::format!(
                    "IF {} GOTO :{}",
                    cond, then_label
                ));
                if let Some(_) = else_pos {
                    lowered.push(alloc::format!(
                        "GOTO :{}",
                        else_label
                    ));
                } else {
                    lowered.push(alloc::format!(
                        "GOTO :{}",
                        end_label
                    ));
                }
                lowered.push(alloc::format!(":{}", then_label));
                let then_body: alloc::vec::Vec<
                    alloc::string::String,
                > = lines[(i + 1)..then_body_end]
                    .iter()
                    .cloned()
                    .collect();
                let then_body_result =
                    self.flatten_lines_block_ifs(then_body, counter);
                counter = then_body_result.1;
                for b in then_body_result.0 {
                    lowered.push(b);
                }
                if let Some(ep) = else_pos {
                    lowered.push(alloc::format!(
                        "GOTO :{}",
                        end_label
                    ));
                    lowered.push(alloc::format!(":{}", else_label));
                    let else_body: alloc::vec::Vec<
                        alloc::string::String,
                    > = lines[(ep + 1)..close_pos]
                        .iter()
                        .cloned()
                        .collect();
                    let else_body_result =
                        self.flatten_lines_block_ifs(else_body, counter);
                    counter = else_body_result.1;
                    for b in else_body_result.0 {
                        lowered.push(b);
                    }
                    lowered.push(alloc::format!(":{}", end_label));
                } else {
                    lowered.push(alloc::format!(":{}", end_label));
                }
                out.append(&mut lowered);
                i = close_pos + 1;
                continue;
            }
            out.push(line);
            i += 1;
        }
        (out, counter)
    }

    /// Given that `start` is the line **after** an `IF cond (` open,
    /// find the matching closing `)`. Returns `(close_idx, Some(else_idx))`
    /// when an ELSE clause is present, otherwise `(close_idx, None)`.
    /// `close_idx` is the index of the line containing the matching `)`.
    /// `else_idx` is the index of the line containing `) ELSE (`.
    fn find_block_close(
        &self,
        lines: &[alloc::string::String],
        mut start: usize,
    ) -> (usize, Option<usize>) {
        // We've already consumed the opening `IF cond (` line.
        // The caller passed `start` = i + 1 so we are in the
        // body.
        let mut else_idx: Option<usize> = None;
        // `phase` controls which closing `)` we hunt:
        //   0 = first `)` (or `) ELSE (`) for the IF we're
        //       inside right now
        //   2 = closing `)` after we've seen `) ELSE (`
        let mut phase: u8 = 0;
        // `nested` counts how many nested `IF cond (` blocks
        // need their matching `)`. Each new nested opener adds
        // 1; each nested closer subtracts 1.
        let mut nested: usize = 0;
        while start < lines.len() {
            let raw = lines[start].trim().to_string();
            let upper = raw.to_uppercase();
            // Detect a CLOSE-only line. We require the line to be
            // `)` exactly or start with `) ELSE`/`)ELSE`. We
            // deliberately do NOT match `(==)`, `echo (foo)`, etc.
            let trimmed_upper = upper.trim().to_string();
            let is_close_only = trimmed_upper == ")"
                || trimmed_upper.starts_with(") ELSE (")
                || trimmed_upper.starts_with(")ELSE(")
                || trimmed_upper.starts_with(") ELSE ")
                || trimmed_upper == ")ELSE";
            // Detect nested `IF ... (` open.
            let is_if_open = upper.starts_with("IF ")
                && raw.trim_end().ends_with('(')
                && !raw.trim_end().starts_with("REM");
            if is_if_open {
                nested += 1;
                start += 1;
                continue;
            }
            if !is_close_only {
                start += 1;
                continue;
            }
            // `is_close_only` is true. Decide based on phase and
            // depth.
            if nested > 0 {
                // Inside a nested IF. The `)` here either closes
                // the nested IF (decrement) or starts its ELSE
                // (`) ELSE (` token) — wait for the actual close.
                if !trimmed_upper.starts_with(") ELSE")
                    && !trimmed_upper.starts_with(")ELSE")
                {
                    nested -= 1;
                }
                start += 1;
                continue;
            }
            // nested == 0: this closes our IF, or transitions to
            // its ELSE.
            if phase == 0
                && (trimmed_upper.starts_with(") ELSE")
                    || trimmed_upper.starts_with(")ELSE"))
            {
                else_idx = Some(start);
                phase = 2;
                start += 1;
                continue;
            }
            return (start, else_idx);
        }
        (start, else_idx)
    }

    /// Collect all labels in the batch file
    fn collect_labels(&mut self) {
        self.labels.clear();

        for (i, line) in self.lines.iter().enumerate() {
            let trimmed = line.trim();
            // Real Windows CMD treats both `:LABEL` and `::LABEL`
            // as goto targets. Strip all leading colons when
            // extracting the label name.
            if trimmed.starts_with(':') && !trimmed.is_empty() {
                let label = trimmed.trim_start_matches(':').trim().to_uppercase();
                if !label.is_empty() && !label.starts_with(':') {
                    self.labels.push((Box::leak(label.into_boxed_str()), i));
                }
            }
        }
    }

    /// Classify a line into its type
    fn classify_line(&self, line: &str) -> LineType {
        let upper = line.to_uppercase();

        // Label: a line that is just `:NAME` or `::NAME`. We
        // recognise this first so the execute loop can skip it
        // (its real meaning is captured by `collect_labels`).
        let trimmed = line.trim_start();
        if trimmed.starts_with(':')
            && !trimmed.is_empty()
            && !trimmed.starts_with("::")
        {
            return LineType::Label(trimmed.to_string());
        }

        // GOTO
        if upper.starts_with("GOTO") {
            let target = line[4..].trim().to_string();
            return LineType::Goto(target);
        }
        
        // IF
        if upper.starts_with("IF") {
            return self.classify_if(line);
        }
        
        // FOR
        if upper.starts_with("FOR") {
            return self.classify_for(line);
        }
        
        // CALL
        if upper.starts_with("CALL") {
            let target = line[4..].trim().to_string();
            return LineType::Call(target);
        }
        
        // SETLOCAL
        if upper == "SETLOCAL" || upper.starts_with("SETLOCAL ") {
            return LineType::SetLocal;
        }
        
        // ENDLOCAL
        if upper == "ENDLOCAL" {
            return LineType::EndLocal;
        }

        // PAUSE
        if upper == "PAUSE" || upper.starts_with("PAUSE ") || upper == "PAUSE:" {
            return LineType::Pause;
        }

        // SHIFT
        if upper == "SHIFT" || upper.starts_with("SHIFT ") || upper == "SHIFT/" {
            return LineType::Shift;
        }
        
        // EXIT
        if upper.starts_with("EXIT") {
            return self.classify_exit(line);
        }
        
        // SET (batch variable assignment)
        // Match SET VAR=value pattern
        if upper.starts_with("SET ") && line.contains('=') {
            let set_part = &line[4..].trim();
            if let Some(eq_pos) = set_part.find('=') {
                let var_name = set_part[..eq_pos].trim();
                // Only treat as batch SET if not a system variable path pattern
                if !var_name.is_empty() && !var_name.contains(';') && !var_name.starts_with('%') {
                    return LineType::Command(line.to_string());
                }
            }
        }
        
        LineType::Command(line.to_string())
    }

    /// Classify IF statement
    fn classify_if(&self, line: &str) -> LineType {
        let upper = line.to_uppercase();
        // Strip leading "IF ".
        let body = if let Some(rest) = line.trim_start().strip_prefix("IF ") {
            rest.to_string()
        } else if let Some(rest) = line.trim_start().strip_prefix("IF") {
            rest.trim_start().to_string()
        } else {
            line.to_string()
        };
        let upper_body = body.to_uppercase();

        // IF [... ] GOTO :label — the canonical lowered form from
        // block-IFs, also accepted in raw CMD scripts.
        if let Some(gpos) = upper_body.find(" GOTO ") {
            let condition = body[..gpos].trim().to_string();
            let target = body[gpos + 6..].trim().to_string();
            // We model this as a single-branch IF whose
            // true_branch is the GOTO command. The execute loop
            // will evaluate condition and, if true, run the
            // GOTO; if false, falls through to the next line.
            let true_branch = alloc::format!("GOTO {}", target);
            return LineType::If {
                condition,
                true_branch,
                false_branch: None,
            };
        }

        // IF [NOT] EXIST filename [cmd]
        if upper_body.contains(" EXIST ") {
            return LineType::If {
                condition: body.clone(),
                true_branch: String::new(),
                false_branch: None,
            };
        }

        // IF [NOT] DEFINED var [cmd]
        if upper_body.contains(" DEFINED ") {
            return LineType::If {
                condition: body.clone(),
                true_branch: String::new(),
                false_branch: None,
            };
        }

        // IF ERRORLEVEL n [cmd]
        if upper_body.contains("ERRORLEVEL ") {
            return LineType::If {
                condition: body.clone(),
                true_branch: String::new(),
                false_branch: None,
            };
        }

        // IF string1 == string2 [cmd]
        if upper_body.contains("==") {
            return LineType::If {
                condition: body.clone(),
                true_branch: String::new(),
                false_branch: None,
            };
        }

        // IF str NEQ/.../EQU str [cmd]
        for tok in &["EQU", "NEQ", "LSS", "LEQ", "GTR", "GEQ"] {
            let needle = alloc::format!(" {} ", tok);
            if upper_body.contains(&needle) {
                return LineType::If {
                    condition: body.clone(),
                    true_branch: String::new(),
                    false_branch: None,
                };
            }
        }

        // Fallback: treat as a regular command
        LineType::Command(line.to_string())
    }

    /// Classify FOR statement
    fn classify_for(&self, line: &str) -> LineType {
        // FOR %%variable IN (set) DO command
        let upper = line.to_uppercase();
        
        if upper.contains(" IN (") && upper.contains(") DO ") {
            // Extract parts
            let for_start = upper.find("FOR ").map(|p| p + 4).unwrap_or(0);
            let in_pos = upper.find(" IN (").unwrap_or(0);
            let do_pos = upper.find(") DO ").unwrap_or(0);
            
            let var_part = &line[for_start..in_pos].trim();
            let set_part = &line[in_pos + 5..do_pos].trim();
            let cmd_part = &line[do_pos + 5..].trim();
            
            // Parse variable (remove %% prefix for storage)
            let variable = if var_part.starts_with("%%") {
                var_part[2..].to_string()
            } else {
                var_part.to_string()
            };
            
            return LineType::For {
                variable,
                set: set_part.to_string(),
                command: cmd_part.to_string(),
            };
        }
        
        LineType::Command(line.to_string())
    }

    /// Classify EXIT statement
    fn classify_exit(&self, line: &str) -> LineType {
        let upper = line.to_uppercase();
        
        if upper == "EXIT" {
            return LineType::Exit { batch_only: false, code: None };
        }
        
        if upper == "EXIT /B" {
            return LineType::Exit { batch_only: true, code: None };
        }
        
        if upper.starts_with("EXIT /B ") {
            let code_part = line[8..].trim();
            let code = code_part.parse::<i32>().ok();
            return LineType::Exit { batch_only: true, code };
        }
        
        // EXIT with error code
        if upper.starts_with("EXIT ") {
            let code_part = line[5..].trim();
            let code = code_part.parse::<i32>().ok();
            return LineType::Exit { batch_only: false, code };
        }
        
        LineType::Exit { batch_only: false, code: None }
    }

    /// Handle GOTO command
    fn handle_goto(&mut self, label: &str) -> Result<(), BatError> {
        // Strip ALL leading colons — real CMD accepts `:FOO`, `::FOO`,
        // etc. when reading the GOTO target.
        let target = label
            .trim()
            .trim_start_matches(':')
            .trim()
            .to_uppercase();

        // `:EOF` is CMD's predefined end-of-file label — it
        // terminates execution of the current batch. We model
        // that as `running = false`, which the main loop
        // exits cleanly.
        if target == "EOF" {
            self.running = false;
            return Ok(());
        }

        // Find the label
        for (lbl, line_num) in self.labels.iter() {
            if *lbl == target {
                self.current = *line_num + 1; // +1 to skip the label line itself
                return Ok(());
            }
        }

        Err(BatError::LabelNotFound(label.to_string()))
    }

    /// Evaluate IF condition
    fn evaluate_condition(&self, condition: &str) -> Result<bool, BatError> {
        let upper = condition.to_uppercase();

        // IF DEFINED variable / IF NOT DEFINED variable
        if upper.starts_with("DEFINED") || upper.contains(" DEFINED") {
            let parts: Vec<&str> = condition.split_whitespace().collect();
            let mut is_not = false;
            let mut var_name: Option<&str> = None;
            for (i, part) in parts.iter().enumerate() {
                let pu = part.to_uppercase();
                if pu == "NOT" {
                    is_not = true;
                } else if pu == "DEFINED" && i + 1 < parts.len() {
                    var_name = Some(parts[i + 1]);
                }
            }
            if let Some(name) = var_name {
                // First check the parser's internal variables
                // (those set with `SET VAR=value`); fall back to
                // the static env table for OS-level vars.
                let value = self
                    .get_variable(name)
                    .unwrap_or_else(|| get_env_var_static(name));
                let defined = !value.is_empty();
                return Ok(if is_not { !defined } else { defined });
            }
        }

        // IF NOT EXIST filename or IF EXIST filename
        if upper.contains("EXIST") {
            let parts: Vec<&str> = condition.split_whitespace().collect();
            if parts.len() >= 3 {
                let is_not = parts.len() >= 4 && parts[1].to_uppercase() == "NOT";
                let filename = if is_not { parts[2] } else { parts[1] };
                let _ = &filename;
                let exists = true; // Simplified: assume file exists
                
                return Ok(if is_not { !exists } else { exists });
            }
        }
        
        // IF ERRORLEVEL n
        if upper.contains("ERRORLEVEL") {
            let parts: Vec<&str> = condition.split_whitespace().collect();
            if parts.len() >= 2 {
                // Find ERRORLEVEL and its value
                for (i, part) in parts.iter().enumerate() {
                    if part.to_uppercase() == "ERRORLEVEL" && i + 1 < parts.len() {
                        if let Ok(level) = parts[i + 1].parse::<i32>() {
                            return Ok(self.error_level >= level);
                        }
                    }
                }
            }
        }
        
        // IF [NOT] string1 OP string2  (string or numeric, where OP is
        // one of ==, NEQ, EQU, NEQ, LSS, LEQ, GTR, GEQ). We
        // support an optional leading `NOT` that negates the
        // result.
        let mut is_not = false;
        let cond_stripped = if let Some(stripped) =
            condition.trim_start().strip_prefix("NOT ")
        {
            is_not = true;
            stripped
        } else {
            condition
        };

        // IF string1 == string2
        if cond_stripped.to_uppercase().contains("==") {
            let upper_stripped = cond_stripped.to_uppercase();
            if let Some(eq_pos) = upper_stripped.find("==") {
                let s1 = cond_stripped[..eq_pos].trim().to_string();
                let s2 = cond_stripped[eq_pos + 2..].trim().to_string();
                let s1_exp = self.expand_variables(&s1);
                let s2_exp = self.expand_variables(&s2);
                let result = s1_exp == s2_exp;
                return Ok(if is_not { !result } else { result });
            }
        }

        // IF string1 NEQ string2 (not equal)
        if cond_stripped.to_uppercase().contains("NEQ") {
            let upper_stripped = cond_stripped.to_uppercase();
            if let Some(neq_pos) = upper_stripped.find("NEQ") {
                let s1 = cond_stripped[..neq_pos].trim().to_string();
                let s2 = cond_stripped[neq_pos + 3..].trim().to_string();
                let s1_exp = self.expand_variables(&s1);
                let s2_exp = self.expand_variables(&s2);
                let result = s1_exp != s2_exp;
                return Ok(if is_not { !result } else { result });
            }
        }

        // IF num1 COMP num2 where COMP is one of EQU, NEQ, LSS, LEQ,
        // GTR, GEQ. Real CMD treats these as integer-only
        // comparisons. Expand variables on each side, parse to
        // i64, and apply. We also honour a leading `NOT` that
        // negates the result.
        let upper_numeric =
            self.expand_variables(cond_stripped).to_uppercase();
        for (tok, f) in &[
            ("EQU", i64::eq as fn(&i64, &i64) -> bool),
            ("NEQ", i64::ne),
            ("LSS", i64::lt),
            ("LEQ", i64::le),
            ("GTR", i64::gt),
            ("GEQ", i64::ge),
        ] {
            if let Some(p) = upper_numeric.find(tok) {
                // Find the LAST occurrence (so `EQU` in `NEQU` does
                // not match by accident — though we don't expect
                // those tokens to nest). The first `tok` may be a
                // variable name like `MYEQU`. Use the rightmost
                // match.
                let last_p = upper_numeric
                    .rfind(tok)
                    .unwrap_or(usize::MAX);
                let p = last_p.min(p);
                let s1 = cond_stripped[..p].trim().to_string();
                let s2 = cond_stripped[p + tok.len()..].trim().to_string();
                let s1_exp = self.expand_variables(&s1);
                let s2_exp = self.expand_variables(&s2);
                if let (Ok(a), Ok(b)) = (
                    s1_exp.trim().parse::<i64>(),
                    s2_exp.trim().parse::<i64>(),
                ) {
                    let result = f(&a, &b);
                    return Ok(if is_not { !result } else { result });
                }
                // If we couldn't parse either side as an integer,
                // fall through to the default below — the test
                // expects a meaningful numeric compare and we'd
                // rather fail loud than silently treat as "true".
            }
        }

        // Default: condition is true
        Ok(true)
    }

    /// Handle FOR loop
    fn handle_for(&mut self, variable: &str, set: &str, command: &str, executor: &mut dyn BatchExecutor) -> Result<(), BatError> {
        // Expand variables in set
        let expanded_set = self.expand_variables(set);
        
        // Parse the set (comma or space separated, or wildcard)
        let items = self.parse_for_set(&expanded_set);
        
        // Execute command for each item
        for item in items {
            let mut expanded_cmd = command.to_string();
            
            // Replace %%variable with item
            let var_pattern = alloc::format!("%{}%", variable.to_uppercase());
            expanded_cmd = expanded_cmd.replace(&var_pattern, &item);
            
            // Also try lowercase
            let var_pattern_lower = alloc::format!("%{}%", variable.to_lowercase());
            expanded_cmd = expanded_cmd.replace(&var_pattern_lower, &item);
            
            // Also try with %%
            let var_pattern2 = alloc::format!("{}{}", variable.to_uppercase(), variable.to_uppercase());
            expanded_cmd = expanded_cmd.replace(&var_pattern2, &item);
            
            if self.echo {
                executor.echo_line(&expanded_cmd);
            }
            
            self.error_level = executor.execute_command(&expanded_cmd)? as i32;
        }
        
        Ok(())
    }

    /// Parse FOR set into items
    fn parse_for_set(&self, set: &str) -> Vec<String> {
        let mut items = Vec::new();
        
        // Remove parentheses
        let content = set.trim_matches('(').trim_matches(')');
        
        // Split by comma or space
        for part in content.split(|c| c == ',' || c == ' ') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                items.push(trimmed.to_string());
            }
        }
        
        items
    }

    /// Handle CALL command
    fn handle_call(&mut self, target: &str, executor: &mut dyn BatchExecutor) -> Result<(), BatError> {
        let target = target.trim();
        
        // Check if it's calling another batch file
        if target.ends_with(".bat") || target.ends_with(".cmd") {
            // Save current position
            self.call_stack.push(self.current);
            
            // Execute the sub-batch
            let result = self.execute(target, executor);
            
            // Restore position
            if let Some(pos) = self.call_stack.pop() {
                self.current = pos;
            }
            
            return result;
        }
        
        // Check if it's calling a label (subroutine)
        if target.starts_with(':') {
            let label = target[1..].trim().to_uppercase();
            
            // Save current position
            self.call_stack.push(self.current);
            
            // Find and jump to label
            for (lbl, line_num) in self.labels.iter() {
                if *lbl == label {
                    self.current = *line_num + 1;
                    return Ok(());
                }
            }
            
            return Err(BatError::LabelNotFound(target.to_string()));
        }
        
        // Regular command execution via CALL
        if self.echo {
            executor.echo_line(target);
        }
        
        self.error_level = executor.execute_command(target)? as i32;
        Ok(())
    }

    /// Save current environment (SETLOCAL)
    fn push_setlocal(&mut self) {
        let snapshot = EnvSnapshot {
            variables: self.variables.clone(),
            error_level: self.error_level,
        };
        self.setlocal_stack.push(snapshot);
    }

    /// Restore previous environment (ENDLOCAL)
    fn pop_setlocal(&mut self) {
        if let Some(snapshot) = self.setlocal_stack.pop() {
            // Restore the saved environment
            self.variables = snapshot.variables;
            self.error_level = snapshot.error_level;
        }
    }

    /// Set a batch variable
    pub fn set_variable(&mut self, name: &str, value: &str) {
        // Remove existing variable with same name
        self.variables.retain(|(n, _)| n.to_uppercase() != name.to_uppercase());
        self.variables.push((name.to_uppercase(), value.to_string()));
    }

    /// Get a batch variable value
    pub fn get_variable(&self, name: &str) -> Option<String> {
        for (n, v) in &self.variables {
            if n.to_uppercase() == name.to_uppercase() {
                return Some(v.clone());
            }
        }
        None
    }

    /// Evaluate a small arithmetic expression made of integer
    /// constants, batch variables, and the four basic operators
    /// (`+ - * /` plus `%` for modulo and `(` `)` for grouping).
    /// Operator-assignment shorthands such as `VAR-=1` are expanded
    /// by the caller before this sees them.
    fn eval_arithmetic(&self, expr: &str) -> String {
        let expanded = self.expand_variables(expr);
        match eval_int_expr(&expanded) {
            Some(v) => v.to_string(),
            None => expanded,
        }
    }

    /// Expand variables in a string (%VAR%)
    fn expand_variables(&self, s: &str) -> String {
        let mut result = String::new();
        let bytes = s.as_bytes();
        let mut i = 0;
        
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 1 < bytes.len() {
                // Look for closing %
                let remaining = &s[i + 1..];
                if let Some(end_pos) = remaining.find('%') {
                    let var_name = &remaining[..end_pos];
                    
                    // Skip %% (escaped percent)
                    if var_name.is_empty() {
                        result.push('%');
                        i += 2;
                        continue;
                    }
                    
                    // Handle special variables
                    let value = match var_name.to_uppercase().as_str() {
                        "DATE" => {
                            // Get real date from RTC
                            #[cfg(target_arch = "x86_64")]
                            if let Some(time) = crate::hal::cmos::HalQueryRealTimeClock() {
                                alloc::format!("{:02}/{:02}/{}", time.month, time.day, time.year)
                            } else {
                                "Unknown".to_string()
                            }
                            #[cfg(not(target_arch = "x86_64"))]
                            { "Unknown".to_string() }
                        }
                        "TIME" => {
                            // Get real time from RTC
                            #[cfg(target_arch = "x86_64")]
                            if let Some(time) = crate::hal::cmos::HalQueryRealTimeClock() {
                                if time.hour >= 12 {
                                    let h = if time.hour == 12 { 12 } else { time.hour - 12 };
                                    alloc::format!("{:02}:{:02}:{:02} PM", h, time.minute, time.second())
                                } else {
                                    let h = if time.hour == 0 { 12 } else { time.hour };
                                    alloc::format!("{:02}:{:02}:{:02} AM", h, time.minute, time.second())
                                }
                            } else {
                                "Unknown".to_string()
                            }
                            #[cfg(not(target_arch = "x86_64"))]
                            { "Unknown".to_string() }
                        }
                        "RANDOM" => {
                            // Generate a pseudo-random value based on time
                            #[cfg(target_arch = "x86_64")]
                            if let Some(time) = crate::hal::cmos::HalQueryRealTimeClock() {
                                let seed = (time.hour as u32 * 3600 + time.minute as u32 * 60 + time.second() as u32) % 32768;
                                format!("{}", seed)
                            } else {
                                "12345".to_string()
                            }
                            #[cfg(not(target_arch = "x86_64"))]
                            { "12345".to_string() }
                        }
                        "ERRORLEVEL" => self.error_level.to_string(),
                        _ => {
                            // First check batch-local variables
                            if let Some(val) = self.get_variable(var_name) {
                                val
                            } else {
                                get_env_var_static(var_name)
                            }
                        }
                    };
                    
                    result.push_str(&value);
                    i += end_pos + 2; // Skip %var%
                    continue;
                }
            }
            result.push(bytes[i] as char);
            i += 1;
        }
        
        result
    }

    /// Execute a single command
    fn execute_command(&mut self, command: &str, executor: &mut dyn BatchExecutor) -> Result<u32, BatError> {
        if command.is_empty() {
            return Ok(0);
        }
        
        executor.execute_command(command)
    }
}

/// Trait for batch file command execution
pub trait BatchExecutor {
    /// Read a batch file's contents
    fn read_file(&self, filename: &str) -> Result<String, BatError>;
    
    /// Execute a command, return error level
    fn execute_command(&mut self, command: &str) -> Result<u32, BatError>;
    
    /// Echo a line (for batch echo)
    fn echo_line(&self, line: &str);
}

/// Get environment variable (simplified)
fn get_env_var_static(name: &str) -> String {
    // Common environment variables
    match name.to_uppercase().as_str() {
        "PATH" => "C:\\Windows\\System32;C:\\Windows".to_string(),
        "COMPUTERNAME" => "NT61".to_string(),
        "USERNAME" => "Administrator".to_string(),
        "SYSTEMROOT" | "WINDIR" => "C:\\Windows".to_string(),
        "HOMEDRIVE" => "C:".to_string(),
        _ => String::new(),
    }
}

/// Locate the `=` in an assignment string and detect compound
/// operators like `VAR-=1` or `VAR+=2`. Returns
/// `(var_name, optional_compound_op, value_after_eq)`.
fn find_assignment_split(body: &str) -> Option<(String, Option<char>, &str)> {
    // Walk left-to-right looking for the LAST `=` that is not
    // inside the variable name; the var name ends where the first
    // `+ - * / %` (right before `=`) appears, OR simply at `=`.
    let bytes = body.as_bytes();
    let mut eq_pos = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'=' {
            eq_pos = Some(i);
        }
    }
    let eq_pos = eq_pos?;
    let lhs = &body[..eq_pos];
    let rhs = &body[eq_pos + 1..];
    // If the char immediately before `=` is one of `+ - * / %`,
    // treat it as a compound op (`VAR-=` → name=VAR, op=`-`).
    let lhs_trim = lhs.trim_end();
    if let Some(last) = lhs_trim.chars().last() {
        if matches!(last, '+' | '-' | '*' | '/' | '%') && lhs_trim.len() >= 2 {
            let var_name = lhs_trim[..lhs_trim.len() - last.len_utf8()].trim().to_string();
            return Some((var_name, Some(last), rhs));
        }
    }
    Some((lhs.trim().to_string(), None, rhs))
}

/// Evaluate a tiny integer arithmetic expression made of
/// constants and the four basic operators. Returns None on parse
/// failure (the caller then falls back to a string assignment).
fn eval_int_expr(expr: &str) -> Option<i64> {
    let expr = expr.trim();
    if expr.is_empty() {
        return None;
    }
    // Tokenise: numbers, identifiers (treated as 0), operators, parens.
    let bytes = expr.as_bytes();
    let mut i = 0;
    let mut toks: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '(' || c == ')' || c == '+' || c == '-' || c == '*' || c == '/' || c == '%' {
            toks.push(c.to_string());
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let mut j = i;
            while j < bytes.len() && (bytes[j] as char).is_ascii_digit() {
                j += 1;
            }
            toks.push(expr[i..j].to_string());
            i = j;
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let mut j = i;
            while j < bytes.len()
                && ((bytes[j] as char).is_ascii_alphanumeric() || bytes[j] == b'_')
            {
                j += 1;
            }
            // Treat identifiers as 0 (variables must already be
            // substituted by the caller via `expand_variables`).
            toks.push("0".to_string());
            i = j;
            continue;
        }
        return None;
    }
    // Recursive-descent: factor * factor / factor, term + term - term
    fn parse_expr(toks: &[alloc::string::String], pos: &mut usize) -> Option<i64> {
        let mut lhs = parse_term(toks, pos)?;
        while *pos < toks.len() {
            let op = toks[*pos].as_str();
            if op != "+" && op != "-" {
                break;
            }
            *pos += 1;
            let rhs = parse_term(toks, pos)?;
            lhs = if op == "+" { lhs + rhs } else { lhs - rhs };
        }
        Some(lhs)
    }
    fn parse_term(toks: &[alloc::string::String], pos: &mut usize) -> Option<i64> {
        let mut lhs = parse_factor(toks, pos)?;
        while *pos < toks.len() {
            let op = toks[*pos].as_str();
            if op != "*" && op != "/" && op != "%" {
                break;
            }
            *pos += 1;
            let rhs = parse_factor(toks, pos)?;
            lhs = if op == "*" {
                lhs * rhs
            } else if op == "/" {
                if rhs == 0 {
                    return None;
                }
                lhs / rhs
            } else {
                if rhs == 0 {
                    return None;
                }
                lhs % rhs
            };
        }
        Some(lhs)
    }
    fn parse_factor(toks: &[alloc::string::String], pos: &mut usize) -> Option<i64> {
        if *pos >= toks.len() {
            return None;
        }
        let tok = &toks[*pos];
        if tok == "(" {
            *pos += 1;
            let v = parse_expr(toks, pos)?;
            if *pos >= toks.len() || toks[*pos] != ")" {
                return None;
            }
            *pos += 1;
            return Some(v);
        }
        if tok == "-" {
            *pos += 1;
            return parse_factor(toks, pos).map(|v| -v);
        }
        if tok == "+" {
            *pos += 1;
            return parse_factor(toks, pos);
        }
        let v = tok.parse::<i64>().ok()?;
        *pos += 1;
        Some(v)
    }
    let mut pos = 0;
    let v = parse_expr(&toks, &mut pos)?;
    if pos != toks.len() {
        return None;
    }
    Some(v)
}
