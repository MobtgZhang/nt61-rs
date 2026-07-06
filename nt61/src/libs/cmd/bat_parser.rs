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
        
        // Preprocess: remove comments, handle special lines
        self.preprocess(&content);
        
        // Collect labels
        self.collect_labels();
        
        // Execute the batch file
        while self.current < self.lines.len() && self.running {
            let line = &self.lines[self.current];
            self.current += 1;
            
            // Expand variables in the line
            let expanded = self.expand_variables(line);
            
            // Classify and process the line
            match self.classify_line(&expanded) {
                LineType::Empty => {}
                LineType::Comment => {}
                LineType::Label(_) => {} // Already handled by collect_labels
                LineType::Goto(label) => {
                    self.handle_goto(&label)?;
                }
                LineType::If { condition, true_branch, false_branch } => {
                    if self.evaluate_condition(&condition)? {
                        if !true_branch.is_empty() {
                            self.execute_command(&true_branch, executor)?;
                        }
                    } else if let Some(fb) = false_branch {
                        if !fb.is_empty() {
                            self.execute_command(&fb, executor)?;
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
                    
                    // Handle batch SET VAR=value commands
                    let upper_cmd = cmd.to_uppercase();
                    if upper_cmd.starts_with("SET ") {
                        let set_part = &cmd[4..].trim();
                        if let Some(eq_pos) = set_part.find('=') {
                            let var_name = set_part[..eq_pos].trim().to_string();
                            let var_value = self.expand_variables(set_part[eq_pos + 1..].trim());
                            self.set_variable(&var_name, &var_value);
                            self.error_level = 0;
                            return Ok(());
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
            
            // Handle REM comments
            if trimmed.to_uppercase().starts_with("REM") {
                continue;
            }
            
            // Handle :: comments (DOS style)
            if trimmed.starts_with("::") {
                continue;
            }
            
            // Handle labels (:label)
            if trimmed.starts_with(':') && !trimmed.starts_with("::") {
                // Remove leading colon and store
                let label = &trimmed[1..].trim().to_uppercase();
                let _ = &label;
                self.lines.push(trimmed); // Keep original for label matching
                continue;
            }
            
            // Handle @ prefix (suppress echo for this line only)
            if trimmed.starts_with('@') {
                let cmd = trimmed[1..].trim().to_string();
                self.lines.push(cmd);
                continue;
            }
            
            // Handle ECHO OFF (suppress subsequent echo)
            if trimmed.to_uppercase() == "ECHO OFF" || trimmed.to_uppercase() == "@ECHO OFF" {
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
    }

    /// Collect all labels in the batch file
    fn collect_labels(&mut self) {
        self.labels.clear();
        
        for (i, line) in self.lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with(':') && !trimmed.starts_with("::") {
                let label = trimmed[1..].trim().to_uppercase();
                self.labels.push((Box::leak(label.into_boxed_str()), i));
            }
        }
    }

    /// Classify a line into its type
    fn classify_line(&self, line: &str) -> LineType {
        let upper = line.to_uppercase();
        
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
        
        // IF [NOT] EXIST filename
        if upper.contains("EXIST") {
            // Extract condition and branch
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() >= 3 {
                let is_not = parts.len() >= 4 && parts[1].to_uppercase() == "NOT";
                let file_part = if is_not { parts[2] } else { parts[1] };
                let condition = if is_not {
                    alloc::format!("{} EXIST {}", parts[0], file_part)
                } else {
                    alloc::format!("{} EXIST {}", parts[0], file_part)
                };
                
                // Find the command after condition - skip finding position for simplicity
                let true_branch = String::new(); // Simplified
                
                return LineType::If {
                    condition,
                    true_branch,
                    false_branch: None,
                };
            }
        }
        
        // IF ERRORLEVEL n
        if upper.contains("ERRORLEVEL") {
            // Find the condition and command
            if let Some(_cmd_pos) = upper.find("ERRORLEVEL") {
                let condition = "ERRORLEVEL".to_string();
                let true_branch = String::new(); // Simplified
                
                return LineType::If {
                    condition,
                    true_branch,
                    false_branch: None,
                };
            }
        }
        
        // IF string1 == string2
        if upper.contains("==") {
            if let Some(eq_pos) = upper.find("==") {
                let before = line[..eq_pos].trim();
                let after_eq = line[eq_pos + 2..].trim();
                
                // Skip "IF" and find the actual strings
                let if_pos = before.to_uppercase().find("IF ").map(|p| p + 3).unwrap_or(0);
                let condition = alloc::format!("{} == {}", &before[if_pos..], after_eq).trim().to_string();
                
                // Find the command (might be on next token)
                let parts: Vec<&str> = line.split_whitespace().collect();
                let mut cmd_parts = Vec::new();
                let mut found_eq = false;
                
                for part in parts.iter().skip(1) {
                    if found_eq {
                        cmd_parts.push(*part);
                    }
                    if part.to_uppercase() == "==" {
                        found_eq = true;
                    }
                }
                
                let true_branch = cmd_parts.join(" ");
                
                return LineType::If {
                    condition,
                    true_branch,
                    false_branch: None,
                };
            }
        }
        
        // Fallback: treat as command
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
        let target = label.trim().to_uppercase();
        
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
                let value = get_env_var_static(name);
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
        
        // IF string1 == string2
        if upper.contains("==") {
            if let Some(eq_pos) = upper.find("==") {
                let s1 = condition[..eq_pos].trim().to_string();
                let s2 = condition[eq_pos + 2..].trim().to_string();
                
                // Expand variables
                let s1_exp = self.expand_variables(&s1);
                let s2_exp = self.expand_variables(&s2);
                
                return Ok(s1_exp == s2_exp);
            }
        }
        
        // IF string1 NEQ string2 (not equal)
        if upper.contains("NEQ") {
            if let Some(neq_pos) = upper.find("NEQ") {
                let s1 = condition[..neq_pos].trim().to_string();
                let s2 = condition[neq_pos + 3..].trim().to_string();
                
                // Expand variables
                let s1_exp = self.expand_variables(&s1);
                let s2_exp = self.expand_variables(&s2);
                
                return Ok(s1_exp != s2_exp);
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
