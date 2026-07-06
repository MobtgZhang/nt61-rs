//! Registry path parser.
//
//! Parses a path like
//!   `\Registry\Machine\System\CurrentControlSet\Services\foo`
//! into a `(Hive, &[&str])` pair. The leading `\Registry\` is
//! optional; bare names like `System\Select\Current` are treated
//! as relative paths (no hive, just subkeys of an unspecified
//! hive — callers must pass a hive).
//
//! The five standard hives are:
//!   * `\Registry\Machine\System`     -> `System`
//!   * `\Registry\Machine\Software`   -> `Software`
//!   * `\Registry\Machine\Security`   -> `Security`
//!   * `\Registry\Machine\SAM`        -> `SAM`
//!   * `\Registry\User\.DEFAULT`      -> `Default`
//!   * `\Registry\Machine\BCD`        -> `BCD` (not on the OS volume; lives on ESP)

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use super::hive::HiveError;


/// The five standard hives we recognise in CM paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    System,
    Software,
    Security,
    SAM,
    Default,
    BCD,
}

impl Hive {
    pub fn name(&self) -> &'static str {
        match self {
            Hive::System => "System",
            Hive::Software => "Software",
            Hive::Security => "Security",
            Hive::SAM => "SAM",
            Hive::Default => "Default",
            Hive::BCD => "BCD",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "System"   => Some(Hive::System),
            "Software" => Some(Hive::Software),
            "Security" => Some(Hive::Security),
            "SAM"      => Some(Hive::SAM),
            "Default"  => Some(Hive::Default),
            ".DEFAULT" => Some(Hive::Default),
            "BCD"      => Some(Hive::BCD),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    Empty,
    BadPrefix,
    UnknownHive(String),
    BadUtf16,
}

impl core::fmt::Display for PathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PathError::Empty => write!(f, "empty path"),
            PathError::BadPrefix => write!(f, "path does not start with \\Registry\\"),
            PathError::UnknownHive(s) => write!(f, "unknown hive '{}'", s),
            PathError::BadUtf16 => write!(f, "bad utf-16 in path"),
        }
    }
}

/// A parsed registry path: a hive + a sequence of subkey names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPath {
    pub hive: Hive,
    pub subkeys: Vec<String>,
}

impl ParsedPath {
    /// Parse a registry path. The path is an NT-style path:
    ///
    ///   `\Registry\Machine\System\CurrentControlSet\Services\foo`
    ///
    /// The first component after `\Registry\Machine\` (or
    /// `\Registry\User\`) names the hive.
    pub fn parse(path: &str) -> Result<Self, PathError> {
        // Step 1: 验证路径非空
        if path.is_empty() {
            return Err(PathError::Empty);
        }

        // Step 2: 去除前导反斜杠并收集剩余部分
        let trimmed = path.trim_start_matches('\\');

        // Step 3: 解析路径，确定 hive 和子键
        // 支持以下格式:
        //   \Registry\Machine\System\CurrentControlSet\Services\foo
        //   \Registry\Machine\SOFTWARE\Microsoft\Windows
        //   \Registry\User\.DEFAULT\Volatile Environment
        //   System\CurrentControlSet\Services (bare path, defaults to System hive)
        //   SOFTWARE\Microsoft (bare path, defaults to Software hive)

        let (hive_name, subkey_str) = if trimmed.to_ascii_uppercase().starts_with("REGISTRY") {
            // Full path: \Registry\Machine\System\...
            let remainder = &trimmed[8..]; // skip "Registry"
            if remainder.starts_with('\\') {
                let after_backslash = &remainder[1..]; // skip the backslash

                // Check for Machine or User prefix and skip it
                let after_prefix = if after_backslash.to_ascii_uppercase().starts_with("MACHINE\\") {
                    &after_backslash[8..] // skip "Machine\"
                } else if after_backslash.to_ascii_uppercase().starts_with("USER\\") {
                    &after_backslash[5..] // skip "User\"
                } else {
                    after_backslash
                };

                // Find the next backslash to separate hive name from subkeys
                if let Some(pos) = after_prefix.find('\\') {
                    (Some(&after_prefix[..pos]), &after_prefix[pos + 1..])
                } else {
                    (Some(after_prefix), "")
                }
            } else {
                (None, "")
            }
        } else {
            // Bare path without \Registry\ prefix
            if let Some(pos) = trimmed.find('\\') {
                (Some(&trimmed[..pos]), &trimmed[pos + 1..])
            } else {
                (Some(trimmed), "")
            }
        };

        // Step 4: 确定 Hive 枚举值
        let hive = match hive_name {
            Some(name) => {
                // Remove trailing backslash if present
                let name = name.trim_end_matches('\\');
                Hive::from_name(name)
                    .ok_or_else(|| PathError::UnknownHive(String::from(name)))?
            }
            None => Hive::System, // Default to System hive if not specified
        };

        // Step 5: 解析子键数组
        let subkeys: Vec<String> = subkey_str
            .split('\\')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        Ok(ParsedPath { hive, subkeys })
    }
}

/// Convert a `ParsedPath` back to its NT-style string form.
impl core::fmt::Display for ParsedPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "\\Registry\\Machine\\{}", self.hive.name())?;
        for s in &self.subkeys {
            write!(f, "\\{}", s)?;
        }
        Ok(())
    }
}

/// Convert a `HiveError` to a `PathError` (they are not the same
/// type, but the only error case the parser can produce is `BadUtf16`).
pub fn utf16_err_from_hive(_e: &HiveError) -> PathError {
    PathError::BadUtf16
}
