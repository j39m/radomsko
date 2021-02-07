use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const GPG_EXTENSION: &'static str = "gpg";
const CLEARTEXT_DIRECTORY_REQUIRED_PERMISSIONS: u32 = 0o700;

fn default_password_store_root() -> PathBuf {
    let mut path = home::home_dir().unwrap();
    path.push(".password-store");
    path
}

fn default_cleartext_holder_dir() -> Result<PathBuf, FilesystemError> {
    let xdg_runtime_dir = std::env::var("XDG_RUNTIME_DIR")?;
    Ok(PathBuf::from(xdg_runtime_dir.as_str()))
}

#[derive(Debug, PartialEq)]
pub enum FilesystemError {
    NotFound,       // generic
    BadPermissions, // specific to `CleartextHolderInterface`
    PasswordNotResident,
    PasswordLacksGpgExtension,
}

// Interacts with the configured root of the password store.
// `root` must be readable at time of instantiation.
#[derive(Debug)]
pub struct PasswordStoreInterface {
    root: PathBuf,
}

// Interacts with the quasi-private space that holds cleartext
// passwords.
// *    Defaults to using ${XDG_RUNTIME_DIR} if no directory is
//      specified.
// *    Requires that backing directory is only accessible to the
//      calling user.
#[derive(Debug)]
pub struct CleartextHolderInterface {
    root: PathBuf,
}

impl From<std::io::Error> for FilesystemError {
    fn from(_err: std::io::Error) -> FilesystemError {
        FilesystemError::NotFound
    }
}

impl From<std::env::VarError> for FilesystemError {
    fn from(_err: std::env::VarError) -> FilesystemError {
        FilesystemError::NotFound
    }
}

impl PasswordStoreInterface {
    pub fn new(configured_root: &str) -> Result<PasswordStoreInterface, FilesystemError> {
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
    pub fn symbolic_name_for(&self, password_path: &Path) -> Result<PathBuf, FilesystemError> {
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

impl CleartextHolderInterface {
    pub fn new(configured_root: &str) -> Result<CleartextHolderInterface, FilesystemError> {
        let mut root = PathBuf::from(configured_root);
        if configured_root.is_empty() {
            root = default_cleartext_holder_dir()?;
        }

        let metadata = std::fs::metadata(root.as_path())?;
        if !metadata.is_dir() {
            return Err(FilesystemError::NotFound);
        } else if metadata.permissions().mode() & 0o777 != CLEARTEXT_DIRECTORY_REQUIRED_PERMISSIONS
        {
            return Err(FilesystemError::BadPermissions);
        }

        Ok(CleartextHolderInterface { root: root })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEARTEXT_DIRECTORY_BAD_PERMISSIONS: u32 = 0o740;
    const CLEARTEXT_DIRECTORY_PREFIX: &'static str = "cleartext-holder-fixture-";

    struct CleartextHolderFixture {
        interface: CleartextHolderInterface,
        backing_dir: tempfile::TempDir,
    }

    impl CleartextHolderFixture {
        pub fn new(
            interface: CleartextHolderInterface,
            backing_dir: tempfile::TempDir,
        ) -> CleartextHolderFixture {
            CleartextHolderFixture {
                interface: interface,
                backing_dir: backing_dir,
            }
        }
    }

    fn test_data_path(path: &str) -> PathBuf {
        let mut result = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        result.push("filesystem-test-data");
        if !path.is_empty() {
            result.push(path);
        }
        result
    }

    fn password_store_interface() -> PasswordStoreInterface {
        PasswordStoreInterface::new(test_data_path("").to_str().unwrap()).unwrap()
    }

    fn cleartext_holder_fixture() -> CleartextHolderFixture {
        let tmp_dir = tempfile::Builder::new()
            .prefix(CLEARTEXT_DIRECTORY_PREFIX)
            .tempdir_in(test_data_path("").to_str().unwrap())
            .unwrap();
        std::fs::set_permissions(tmp_dir.as_ref(), std::fs::Permissions::from_mode(0o700)).unwrap();

        let klaus = PathBuf::from(tmp_dir.as_ref());
        CleartextHolderFixture::new(
            CleartextHolderInterface::new(tmp_dir.as_ref().to_str().unwrap()).unwrap(),
            tmp_dir,
        )
    }

    #[test]
    fn password_store_interface_requires_existing_root() {
        let err = PasswordStoreInterface::new(test_data_path("some/random/dir").to_str().unwrap())
            .unwrap_err();
        assert_eq!(err, FilesystemError::NotFound);
    }

    #[test]
    fn path_for_basic() {
        let path = password_store_interface().path_for("hello/there/general/kenobi");
        assert_eq!(
            path,
            test_data_path("hello/there/general/kenobi.gpg").as_path()
        )
    }

    #[test]
    fn symbolic_name_for_basic() {
        let symbolic_name = password_store_interface()
            .symbolic_name_for(test_data_path("hello/there.gpg").as_path())
            .unwrap();
        assert_eq!(symbolic_name, Path::new("hello/there"));
    }

    #[test]
    fn symbolic_name_for_rejects_nonresident_passwords() {
        let result = password_store_interface()
            .symbolic_name_for(Path::new("/some/random/dir/hello/there.gpg"))
            .unwrap_err();
        assert_eq!(result, FilesystemError::PasswordNotResident);
    }

    #[test]
    fn symbolic_name_for_requires_gpg_extension() {
        let result = password_store_interface()
            .symbolic_name_for(test_data_path("blah.txt").as_path())
            .unwrap_err();
        assert_eq!(result, FilesystemError::PasswordLacksGpgExtension);
    }

    #[test]
    fn symbolic_name_for_rejects_files_without_extension() {
        let result = password_store_interface()
            .symbolic_name_for(test_data_path("blah").as_path())
            .unwrap_err();
        assert_eq!(result, FilesystemError::PasswordLacksGpgExtension);
    }

    #[test]
    fn cleartext_holder_requires_directory() {
        let err = CleartextHolderInterface::new(test_data_path("nonexistent").to_str().unwrap())
            .unwrap_err();
        assert_eq!(err, FilesystemError::NotFound);
    }

    #[test]
    fn cleartext_holder_wants_directory_permissions() {
        let tmp_dir = tempfile::Builder::new()
            .prefix(CLEARTEXT_DIRECTORY_PREFIX)
            .tempdir_in(test_data_path("").to_str().unwrap())
            .unwrap();
        let mut permissions = std::fs::metadata(tmp_dir.as_ref()).unwrap().permissions();
        permissions.set_mode(CLEARTEXT_DIRECTORY_BAD_PERMISSIONS);

        let err = CleartextHolderInterface::new(tmp_dir.as_ref().to_str().unwrap()).unwrap_err();
        assert_eq!(err, FilesystemError::BadPermissions);
    }

    #[test]
    fn cleartext_holder_basic() {
        let fixture = cleartext_holder_fixture();
        let permissions = std::fs::metadata(fixture.backing_dir.as_ref())
            .unwrap()
            .permissions();
        assert_eq!(
            permissions.mode() & 0o777,
            CLEARTEXT_DIRECTORY_REQUIRED_PERMISSIONS
        );
    }
}
