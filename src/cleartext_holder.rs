use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::errors::RadomskoError;

const CLEARTEXT_DIRECTORY_REQUIRED_PERMISSIONS: u32 = 0o700;
const CLEARTEXT_TEMPFILE_PREFIX: &'static str = "radomsko-cleartext-";

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

fn default_cleartext_holder_dir() -> Result<PathBuf, RadomskoError> {
    let xdg_runtime_dir = std::env::var("XDG_RUNTIME_DIR")?;
    Ok(PathBuf::from(xdg_runtime_dir.as_str()))
}

impl CleartextHolderInterface {
    pub fn new(configured_root: &str) -> Result<CleartextHolderInterface, RadomskoError> {
        let root = match configured_root.is_empty() {
            true => default_cleartext_holder_dir()?,
            false => PathBuf::from(configured_root),
        };

        let metadata = std::fs::metadata(root.as_path())?;
        if !metadata.is_dir() {
            return Err(RadomskoError::NotFound);
        } else if metadata.permissions().mode() & 0o777 != CLEARTEXT_DIRECTORY_REQUIRED_PERMISSIONS
        {
            return Err(RadomskoError::BadPermissions);
        }

        Ok(CleartextHolderInterface { root: root })
    }

    pub fn new_entry(&self) -> Result<tempfile::NamedTempFile, RadomskoError> {
        Ok(tempfile::Builder::new()
            .prefix(CLEARTEXT_TEMPFILE_PREFIX)
            .tempfile_in(&self.root)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEARTEXT_DIRECTORY_BAD_PERMISSIONS: u32 = 0o740;
    const CLEARTEXT_DIRECTORY_PREFIX: &'static str = "cleartext-holder-fixture-";

    fn test_data_path(path: &str) -> PathBuf {
        let mut result = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        result.push("cleartext-holder-test-data");
        if !path.is_empty() {
            result.push(path);
        }
        result
    }

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

    fn cleartext_holder_fixture() -> CleartextHolderFixture {
        let tmp_dir = tempfile::Builder::new()
            .prefix(CLEARTEXT_DIRECTORY_PREFIX)
            .tempdir_in(test_data_path("").to_str().unwrap())
            .unwrap();
        std::fs::set_permissions(
            tmp_dir.as_ref(),
            std::fs::Permissions::from_mode(CLEARTEXT_DIRECTORY_REQUIRED_PERMISSIONS),
        )
        .unwrap();

        CleartextHolderFixture::new(
            CleartextHolderInterface::new(tmp_dir.as_ref().to_str().unwrap()).unwrap(),
            tmp_dir,
        )
    }

    #[test]
    fn cleartext_holder_requires_directory() {
        let err = CleartextHolderInterface::new(test_data_path("nonexistent").to_str().unwrap())
            .unwrap_err();
        assert_eq!(err, RadomskoError::NotFound);
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
        assert_eq!(err, RadomskoError::BadPermissions);
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

    #[test]
    fn cleartext_holder_new_entry() {
        let fixture = cleartext_holder_fixture();
        let temporary = fixture.interface.new_entry().unwrap();
        let temporary_path = temporary.path().to_path_buf();

        // We expect that `new_entry()` spawns a tempfile.
        assert!(temporary_path.is_file());

        // We expect that the tempfile is in the expected location.
        assert!(temporary_path.starts_with(&fixture.interface.root));

        // We demand two other properties of the tempfile's name.
        assert!(temporary_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(CLEARTEXT_TEMPFILE_PREFIX));
        assert!(temporary_path.extension().is_none());

        // We expect that the tempfile disappears when dropped.
        assert!(temporary.close().is_ok());
        assert!(!temporary_path.exists());
    }
}
