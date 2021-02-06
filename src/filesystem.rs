use std::path::{Path, PathBuf};

const GPG_EXTENSION: &'static str = "gpg";

fn default_password_store_root() -> PathBuf {
    let mut path = home::home_dir().unwrap();
    path.push(".password-store");
    path
}

#[derive(Debug, PartialEq)]
pub enum FilesystemInterfaceError {
    NotResident,
    LacksGpgExtension,
}

// Interacts with the configured root of the password store.
#[derive(Debug)]
pub struct FilesystemInterface {
    root: PathBuf,
}

impl FilesystemInterface {
    pub fn new(configured_root: &str) -> FilesystemInterface {
        if configured_root.is_empty() {
            return FilesystemInterface {
                root: default_password_store_root(),
            };
        }

        FilesystemInterface {
            root: PathBuf::from(configured_root),
        }
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
    ) -> Result<PathBuf, FilesystemInterfaceError> {
        match password_path.extension() {
            Some(extension) => match extension.to_str().unwrap() {
                GPG_EXTENSION => (),
                _ => return Err(FilesystemInterfaceError::LacksGpgExtension),
            },
            None => return Err(FilesystemInterfaceError::LacksGpgExtension),
        }

        let mut name = match password_path.strip_prefix(&self.root) {
            Ok(rootless) => rootless.to_path_buf(),
            Err(_) => return Err(FilesystemInterfaceError::NotResident),
        };

        name.set_extension("");
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_for_basic() {
        let interface = FilesystemInterface::new("/home/kalvin/.password-store");
        let path = interface.path_for("hello/there/general/kenobi");
        assert_eq!(
            path,
            Path::new("/home/kalvin/.password-store/hello/there/general/kenobi.gpg")
        )
    }

    #[test]
    fn symbolic_name_for_basic() {
        let interface = FilesystemInterface::new("/home/kalvin/.password-store");
        let symbolic_name = interface
            .symbolic_name_for(Path::new("/home/kalvin/.password-store/hello/there.gpg"))
            .unwrap();
        assert_eq!(symbolic_name, Path::new("hello/there"));
    }

    #[test]
    fn symbolic_name_for_rejects_nonresident_passwords() {
        let interface = FilesystemInterface::new("/home/kalvin/.password-store");
        let result = interface
            .symbolic_name_for(Path::new("/some/random/dir/hello/there.gpg"))
            .unwrap_err();
        assert_eq!(result, FilesystemInterfaceError::NotResident);
    }

    #[test]
    fn symbolic_name_for_requires_gpg_extension() {
        let interface = FilesystemInterface::new("/home/kalvin/.password-store");
        let result = interface
            .symbolic_name_for(Path::new("/home/kalvin/.password-store/blah.txt"))
            .unwrap_err();
        assert_eq!(result, FilesystemInterfaceError::LacksGpgExtension);
    }

    #[test]
    fn symbolic_name_for_rejects_files_without_extension() {
        let interface = FilesystemInterface::new("/home/kalvin/.password-store");
        let result = interface
            .symbolic_name_for(Path::new("/home/kalvin/.password-store/blah"))
            .unwrap_err();
        assert_eq!(result, FilesystemInterfaceError::LacksGpgExtension);
    }
}
