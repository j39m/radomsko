#[derive(Debug, PartialEq)]
pub enum RadomskoError {
    NotFound,
    BadPermissions,
    IoError(String),
    SubprocessError(String),
}

impl From<std::io::Error> for RadomskoError {
    fn from(err: std::io::Error) -> RadomskoError {
        RadomskoError::IoError(err.to_string())
    }
}

impl From<std::env::VarError> for RadomskoError {
    fn from(_err: std::env::VarError) -> RadomskoError {
        RadomskoError::NotFound
    }
}

impl From<subprocess::PopenError> for RadomskoError {
    fn from(err: subprocess::PopenError) -> RadomskoError {
        RadomskoError::SubprocessError(err.to_string())
    }
}
