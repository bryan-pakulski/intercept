use std::fmt::Display;

#[derive(Debug)]
pub enum BackendErrorKind {
    General,
    Deserialize,
    Regex,
}

#[derive(Debug)]
pub struct BackendError {
    pub kind: BackendErrorKind,
    pub message: String,
}

impl BackendError {
    pub fn new(kind: BackendErrorKind, message: String) -> Self {
        Self { kind, message }
    }
}

impl Default for BackendError {
    fn default() -> Self {
        Self {
            kind: BackendErrorKind::General,
            message: "An error occurred".to_string(),
        }
    }
}

impl Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BackendErrorKind: {:?}, BackendError:{}",
            self.kind, self.message
        )
    }
}

impl From<serde_json::Error> for BackendError {
    fn from(err: serde_json::Error) -> Self {
        Self {
            kind: BackendErrorKind::Deserialize,
            message: err.to_string(),
        }
    }
}

impl From<regex::Error> for BackendError {
    fn from(err: regex::Error) -> Self {
        Self {
            kind: BackendErrorKind::Regex,
            message: err.to_string(),
        }
    }
}

impl From<std::num::ParseIntError> for BackendError {
    fn from(err: std::num::ParseIntError) -> Self {
        Self {
            kind: BackendErrorKind::General,
            message: err.to_string(),
        }
    }
}

impl From<std::io::Error> for BackendError {
    fn from(err: std::io::Error) -> Self {
        Self {
            kind: BackendErrorKind::General,
            message: err.to_string(),
        }
    }
}

impl From<std::str::Utf8Error> for BackendError {
    fn from(err: std::str::Utf8Error) -> Self {
        Self {
            kind: BackendErrorKind::General,
            message: err.to_string(),
        }
    }
}
