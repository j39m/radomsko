#[derive(Debug, PartialEq)]
pub enum RadomskoError {
    NotFound,
    BadPermissions,
    PasswordLacksGpgExtension,
}

impl From<std::io::Error> for RadomskoError {
    fn from(_err: std::io::Error) -> RadomskoError {
        RadomskoError::NotFound
    }
}

impl From<std::env::VarError> for RadomskoError {
    fn from(_err: std::env::VarError) -> RadomskoError {
        RadomskoError::NotFound
    }
}
