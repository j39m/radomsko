use std::path::{Path, PathBuf};

const GPG_EXTENSION: &'static str = "gpg";

fn default_password_store_root() -> PathBuf {
    let mut path = home::home_dir().unwrap();
    path.push(".password-store");
    path
}

#[derive(Debug, PartialEq)]
pub enum FilesystemError {
    NotFound,
    PasswordNotResident,
    PasswordLacksGpgExtension,
}

// Interacts with the configured root of the password store.
// `root` must be readable at time of instantiation.
#[derive(Debug)]
pub struct PasswordStoreInterface {
    root: PathBuf,
}

impl From<std::io::Error> for FilesystemError {
    fn from(_err: std::io::Error) -> FilesystemError {
        FilesystemError::NotFound
    }
}

impl PasswordStoreInterface {
    pub fn new(
        configured_root: &str,
    ) -> Result<PasswordStoreInterface, FilesystemError> {
        let mut root = PathBuf::from(configured_root);
        if configured_root.is_empty() {
            root = default_password_store_root();
        }

        let metadata = std::fs::metadata(root.as_path())?;
        if !metadata.is_dir() {
            return Err(FilesystemError::NotFound);
        }

        Ok(PasswordStoreInterface { root: root })
    }

    // Borrows a named `password` and returns the underlying path in the
    // password store.
    pub fn path_for(&self, password: &str) -> PathBuf {
        let mut path = self.root.clone();
        path.push(password);
        path.set_extension(GPG_EXTENSION);
        path
    }

    // Borrows a `password_path` and returns its symbolic "name."
    pub fn symbolic_name_for(
        &self,
        password_path: &Path,
    ) -> Result<PathBuf, FilesystemError> {
        match password_path.extension() {
            Some(extension) => match extension.to_str().unwrap() {
                GPG_EXTENSION => (),
                _ => return Err(FilesystemError::PasswordLacksGpgExtension),
            },
            None => return Err(FilesystemError::PasswordLacksGpgExtension),
        }

        let mut name = match password_path.strip_prefix(&self.root) {
            Ok(rootless) => rootless.to_path_buf(),
            Err(_) => return Err(FilesystemError::PasswordNotResident),
        };

        name.set_extension("");
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_data_path(path: &str) -> PathBuf {
        let mut result = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        result.push("filesystem-test-data");
        if !path.is_empty() {
            result.push(path);
        }
        result
    }

    #[test]
    fn password_store_interface_requires_existing_root() {
        let err = PasswordStoreInterface::new(test_data_path("some/random/dir").to_str().unwrap())
            .unwrap_err();
        assert_eq!(err, FilesystemError::NotFound);
    }

    #[test]
    fn path_for_basic() {
        let interface = PasswordStoreInterface::new(test_data_path("").to_str().unwrap()).unwrap();
        let path = interface.path_for("hello/there/general/kenobi");
        assert_eq!(
            path,
            test_data_path("hello/there/general/kenobi.gpg").as_path()
        )
    }

    #[test]
    fn symbolic_name_for_basic() {
        let interface = PasswordStoreInterface::new(test_data_path("").to_str().unwrap()).unwrap();
        let symbolic_name = interface
            .symbolic_name_for(test_data_path("hello/there.gpg").as_path())
            .unwrap();
        assert_eq!(symbolic_name, Path::new("hello/there"));
    }

    #[test]
    fn symbolic_name_for_rejects_nonresident_passwords() {
        let interface = PasswordStoreInterface::new(test_data_path("").to_str().unwrap()).unwrap();
        let result = interface
            .symbolic_name_for(Path::new("/some/random/dir/hello/there.gpg"))
            .unwrap_err();
        assert_eq!(result, FilesystemError::PasswordNotResident);
    }

    #[test]
    fn symbolic_name_for_requires_gpg_extension() {
        let interface = PasswordStoreInterface::new(test_data_path("").to_str().unwrap()).unwrap();
        let result = interface
            .symbolic_name_for(test_data_path("blah.txt").as_path())
            .unwrap_err();
        assert_eq!(
            result,
            FilesystemError::PasswordLacksGpgExtension
        );
    }

    #[test]
    fn symbolic_name_for_rejects_files_without_extension() {
        let interface = PasswordStoreInterface::new(test_data_path("").to_str().unwrap()).unwrap();
        let result = interface
            .symbolic_name_for(test_data_path("blah").as_path())
            .unwrap_err();
        assert_eq!(
            result,
            FilesystemError::PasswordLacksGpgExtension
        );
    }
}
