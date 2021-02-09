use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const GPG_EXTENSION: &'static str = "gpg";
const CLEARTEXT_DIRECTORY_REQUIRED_PERMISSIONS: u32 = 0o700;

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

fn default_password_store_root() -> PathBuf {
    let mut path = home::home_dir().unwrap();
    path.push(".password-store");
    path
}

fn default_cleartext_holder_dir() -> Result<PathBuf, FilesystemError> {
    let xdg_runtime_dir = std::env::var("XDG_RUNTIME_DIR")?;
    Ok(PathBuf::from(xdg_runtime_dir.as_str()))
}

// Helper filter for `PasswordStoreInterface::draw_tree()`.
fn is_gpg_file(path: &PathBuf) -> bool {
    let metadata = match path.metadata() {
        Ok(m) => m,
        Err(_) => return false,
    };
    metadata.file_type().is_file() && path.to_str().unwrap().ends_with(GPG_EXTENSION)
}

// Helper filter for `PasswordStoreInterface::draw_tree()`.
fn dirent_matches_search_term(path: &PathBuf, search_term: &str) -> bool {
    path.to_str().unwrap().contains(search_term)
}

// Helper filter-map for `PasswordStoreInterface::draw_tree()`.
fn ok_dirent_as_pathbuf(entry: Result<walkdir::DirEntry, walkdir::Error>) -> Option<PathBuf> {
    match entry {
        Ok(dir_entry) => Some(dir_entry.into_path()),
        Err(_) => None,
    }
}

impl PasswordStoreInterface {
    pub fn new(configured_root: &str) -> Result<PasswordStoreInterface, FilesystemError> {
        let root = match configured_root.is_empty() {
            true => default_password_store_root(),
            false => PathBuf::from(configured_root),
        };

        if !std::fs::metadata(root.as_path())?.is_dir() {
            return Err(FilesystemError::NotFound);
        }

        Ok(PasswordStoreInterface { root: root })
    }

    // Borrows a named `password` and returns the underlying path in the
    // password store.
    pub fn path_for(&self, password: &str) -> PathBuf {
        self.path_for_impl(password, true)
    }

    // Borrows a relative `path` and returns the underlying path in the
    // password store.
    fn path_for_impl(&self, path: &str, add_gpg_extension: bool) -> PathBuf {
        let mut result = self.root.clone();
        result.push(path);

        if add_gpg_extension {
            result.set_extension(GPG_EXTENSION);
        }
        result
    }

    // Borrows a `password_path` and returns its symbolic "name."
    fn symbolic_name_for(&self, password_path: &Path) -> PathBuf {
        assert!(password_path.is_absolute());
        assert!(password_path.starts_with(&self.root));

        let mut name = password_path
            .strip_prefix(&self.root)
            .unwrap()
            .to_path_buf();
        name.set_extension("");
        name
    }

    // Aids `draw_tree()` when a `subdirectory` is specified.
    //
    // Returns a sorted Vec of passwords in the `subdirectory`.
    fn walk_tree_for_subdirectory(
        &self,
        subdirectory: &str,
    ) -> Result<Vec<PathBuf>, FilesystemError> {
        let path = self.path_for_impl(subdirectory, false);
        if !std::fs::metadata(&path)?.is_dir() {
            return Err(FilesystemError::NotFound);
        }

        let mut result: Vec<PathBuf> = walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| ok_dirent_as_pathbuf(e))
            .filter(|e| is_gpg_file(e))
            .collect();
        result.sort();
        Ok(result)
    }

    // Aids `draw_tree()` when a `search_term` is specified.
    //
    // Returns a sorted Vec of passwords matching `search_term`.
    fn walk_tree_for_search_term(&self, search_term: &str) -> Vec<PathBuf> {
        let mut result: Vec<PathBuf> = walkdir::WalkDir::new(&self.root)
            .into_iter()
            .filter_map(|e| ok_dirent_as_pathbuf(e))
            .filter(|e| {
                is_gpg_file(e)
                    && dirent_matches_search_term(&self.symbolic_name_for(e), search_term)
            })
            .collect();
        result.sort();
        result
    }

    // Aids `draw_tree()`.
    //
    // Returns a sorted Vec of all passwords in the password store.
    fn walk_tree(&self) -> Vec<PathBuf> {
        let mut result: Vec<PathBuf> = walkdir::WalkDir::new(&self.root)
            .into_iter()
            .filter_map(|e| ok_dirent_as_pathbuf(e))
            .filter(|e| is_gpg_file(e))
            .collect();
        result.sort();
        result
    }

    // Aids `draw_tree()` by laying out one branch of the tree.
    //
    // Accepts the `previous` password drawn in the tree and the
    // `current` password to draw.
    fn draw_tree_branch(&self, previous: &Path, current: &Path) -> Vec<String> {
        let symbolic_previous = self.symbolic_name_for(previous);
        let symbolic_current = self.symbolic_name_for(current);

        let mut previous_components = symbolic_previous.iter();
        let mut current_components = symbolic_current.iter();
        let mut indent: usize = 0;

        let mut result: Vec<String> = Vec::new();
        let mut previous_match: Option<&std::ffi::OsStr> = previous_components.next();
        let mut current_match: Option<&std::ffi::OsStr> = current_components.next();

        while previous_match.is_some()
            && current_match.is_some()
            && previous_match.unwrap() == current_match.unwrap()
        {
            previous_match = previous_components.next();
            current_match = current_components.next();
            indent += 1;
        }

        result.push(format!(
            "{}*   {}",
            "    ".repeat(indent),
            current_match.unwrap().to_str().unwrap()
        ));
        for remainder in current_components {
            indent += 1;
            result.push(format!(
                "{}*   {}",
                "    ".repeat(indent),
                remainder.to_str().unwrap()
            ));
        }
        result
    }

    // Aids `draw_tree()` by laying out the actual tree.
    fn draw_tree_impl(&self, tree: Vec<PathBuf>) -> String {
        if tree.len() == 0 {
            return "".to_owned();
        }
        let mut result: Vec<String> = Vec::new();
        let mut prev = self.root.as_path();

        for password in tree.iter() {
            result.extend(self.draw_tree_branch(prev, password));
            prev = password;
        }
        result.push("".to_owned());

        result.join("\n")
    }

    // Returns the human-readable string representation of the password
    // store, drawn as a tree.
    //
    // Arguments:
    // *    `subdirectory` - if nonempty, restricts return value to
    //          branches under relative path `subdirectory`.
    // *    `search_term` - if nonempty, restricts return value to
    //          branches that match `search_term`.
    //
    // `subdirectory` is used with the "show" command while
    // `search_term` is used with the "find" command. Therefore, these
    // arguments are mutually exclusive.
    pub fn draw_tree(
        &self,
        subdirectory: &str,
        search_term: &str,
    ) -> Result<String, FilesystemError> {
        assert!(!(!subdirectory.is_empty() && !search_term.is_empty()));

        let tree: Vec<PathBuf>;
        if !subdirectory.is_empty() {
            tree = self.walk_tree_for_subdirectory(subdirectory)?;
        } else if !search_term.is_empty() {
            tree = self.walk_tree_for_search_term(search_term);
        } else {
            tree = self.walk_tree();
        }

        Ok(self.draw_tree_impl(tree))
    }
}

impl CleartextHolderInterface {
    pub fn new(configured_root: &str) -> Result<CleartextHolderInterface, FilesystemError> {
        let root = match configured_root.is_empty() {
            true => default_cleartext_holder_dir()?,
            false => PathBuf::from(configured_root),
        };

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
    use indoc::indoc;

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

    // `PasswordStoreInterface::path_for()` doesn't need a functional
    // backing directory to be tested, so `subdir` can be blank in
    // such test cases.
    fn password_store_interface(subdir: &str) -> PasswordStoreInterface {
        PasswordStoreInterface::new(test_data_path(subdir).to_str().unwrap()).unwrap()
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
    fn password_store_interface_requires_existing_root() {
        let err = PasswordStoreInterface::new(test_data_path("some/random/dir").to_str().unwrap())
            .unwrap_err();
        assert_eq!(err, FilesystemError::NotFound);
    }

    #[test]
    fn path_for_basic() {
        let path = password_store_interface("").path_for("hello/there/general/kenobi");
        assert_eq!(
            path,
            test_data_path("hello/there/general/kenobi.gpg").as_path()
        )
    }

    #[test]
    fn draw_tree_with_embedded_folders() {
        let interface = password_store_interface("draw-tree-with-embedded-folders");
        assert_eq!(
            interface.draw_tree("", "").unwrap(),
            indoc! {r#"
            *   a
                *   b
                    *   c
                *   d
            *   e
            "#}
        );
    }

    #[test]
    fn draw_tree_with_files() {
        let interface = password_store_interface("draw-tree-with-files");
        assert_eq!(
            interface.draw_tree("", "").unwrap(),
            indoc! {r#"
            *   a
            *   b
            "#}
        );
    }

    #[test]
    fn draw_tree_with_folders() {
        let interface = password_store_interface("draw-tree-with-folders");
        assert_eq!(
            interface.draw_tree("", "").unwrap(),
            indoc! {r#"
            *   a
            *   b
                *   a
                *   b
            *   c
            *   d
                *   a
                *   b
            *   e
            "#}
        );
    }

    #[test]
    fn draw_tree_specifying_subdirectory() {
        let interface = password_store_interface("draw-tree-with-folders");
        assert_eq!(
            interface.draw_tree("b", "").unwrap(),
            indoc! {r#"
            *   b
                *   a
                *   b
            "#}
        );
    }

    #[test]
    fn draw_tree_specifying_subsubdirectory() {
        let interface = password_store_interface("draw-tree-with-embedded-folders");
        assert_eq!(
            interface.draw_tree("a/b", "").unwrap(),
            indoc! {r#"
            *   a
                *   b
                    *   c
            "#}
        );
    }

    #[test]
    fn draw_tree_specifying_subdirectory_with_deeper_subdirectory() {
        let interface = password_store_interface("draw-tree-with-embedded-folders");
        assert_eq!(
            interface.draw_tree("a", "").unwrap(),
            indoc! {r#"
            *   a
                *   b
                    *   c
                *   d
            "#}
        );
    }

    #[test]
    fn draw_tree_specifying_search_term() {
        let interface = password_store_interface("draw-tree-with-folders");
        assert_eq!(
            interface.draw_tree("", "a").unwrap(),
            indoc! {r#"
            *   a
            *   b
                *   a
            *   d
                *   a
            "#}
        );
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
