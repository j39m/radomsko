use std::path::{Path, PathBuf};

use colorful::Colorful;

use crate::errors::RadomskoError;

const GPG_EXTENSION: &'static str = "gpg";

// Interacts with the configured root of the password store.
// `root` must be readable at time of instantiation.
#[derive(Debug)]
pub struct PasswordStoreInterface {
    root: PathBuf,
    colorize_display: bool,
}

fn default_password_store_root() -> PathBuf {
    let mut path = home::home_dir().unwrap();
    path.push(".password-store");
    path
}

// Helper filter for `PasswordStoreInterface::draw_tree()`.
fn is_gpg_file(path: &PathBuf) -> bool {
    path.is_file() && path.to_str().unwrap().ends_with(GPG_EXTENSION)
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

// Helper formatter for `PasswordStoreInterface::draw_tree_branch()`.
fn tree_branch_with_indent(component: &std::ffi::OsStr, indent: usize, colorize: bool) -> String {
    if colorize {
        let pink = colorful::RGB::new(195, 91, 156);
        return format!(
            "{}*   {}",
            "    ".repeat(indent),
            component.to_str().unwrap()
        )
        .color(pink)
        .bold()
        .to_string();
    }
    format!(
        "{}*   {}",
        "    ".repeat(indent),
        component.to_str().unwrap()
    )
}

impl PasswordStoreInterface {
    pub fn new(
        configured_root: &str,
        colorize_display: bool,
    ) -> Result<PasswordStoreInterface, RadomskoError> {
        let root = match configured_root.is_empty() {
            true => default_password_store_root(),
            false => PathBuf::from(configured_root),
        };

        if !std::fs::metadata(root.as_path())?.is_dir() {
            return Err(RadomskoError::NotFound);
        }

        Ok(PasswordStoreInterface {
            root: root,
            colorize_display: colorize_display,
        })
    }

    // Borrows a named `password` and returns the underlying path in the
    // password store.
    pub fn path_for(&self, password: &str) -> Result<PathBuf, RadomskoError> {
        Ok(self.path_for_impl(password, true)?)
    }

    // Borrows a relative `path` and returns the underlying path in the
    // password store.
    fn path_for_impl(&self, path: &str, add_gpg_extension: bool) -> Result<PathBuf, RadomskoError> {
        let mut result = self.root.clone();
        result.push(path);

        if add_gpg_extension {
            // If the symbolic password name has a dot in its name, `set_extension()`
            // will think that it has an extension (and wrongly eat it).
            if result.extension().is_some() {
                result.set_file_name(format!(
                    "{}.{}",
                    result.file_name().unwrap().to_str().unwrap(),
                    GPG_EXTENSION
                ));
            } else {
                result.set_extension(GPG_EXTENSION);
            }
        }

        let canonical = result.canonicalize()?;
        if !canonical.starts_with(&self.root) {
            return Err(RadomskoError::IoError(format!(
                "bad path: {}",
                canonical.display()
            )));
        }
        Ok(canonical)
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
    ) -> Result<Vec<PathBuf>, RadomskoError> {
        let path = self.path_for_impl(subdirectory, false)?;
        if !path.is_dir() {
            return Err(RadomskoError::NotFound);
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

        // Seeks forward along `current` to ignore common ancestry with
        // `previous`, since we only want to draw novel parts of the
        // branch.
        while previous_match.is_some()
            && current_match.is_some()
            && previous_match.unwrap() == current_match.unwrap()
        {
            previous_match = previous_components.next();
            current_match = current_components.next();
            indent += 1;
        }

        // Push the first unique component of the `current` branch.
        result.push(tree_branch_with_indent(
            current_match.unwrap(),
            indent,
            self.colorize_display,
        ));

        // Push the remaining unique components of the `current` branch.
        for remainder in current_components {
            indent += 1;
            result.push(tree_branch_with_indent(
                remainder,
                indent,
                self.colorize_display,
            ));
        }

        // If colorization is enabled, `result` consists solely of
        // colorified entries; however, we want the leaf values to be
        // monochrome.
        if self.colorize_display {
            result.pop();
            result.push(tree_branch_with_indent(
                symbolic_current.iter().last().unwrap(),
                indent,
                false,
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
    ) -> Result<String, RadomskoError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    fn test_data_path(path: &str) -> PathBuf {
        let mut result = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        result.push("filesystem-test-data");
        if !path.is_empty() {
            result.push(path);
        }
        result
    }

    fn password_store_interface(subdir: &str) -> PasswordStoreInterface {
        PasswordStoreInterface::new(test_data_path(subdir).to_str().unwrap(), false).unwrap()
    }

    #[test]
    fn password_store_interface_requires_existing_root() {
        let err =
            PasswordStoreInterface::new(test_data_path("some/random/dir").to_str().unwrap(), false)
                .unwrap_err();
        assert!(matches!(err, RadomskoError::IoError{..}));
    }

    #[test]
    fn path_for_basic() {
        let path = password_store_interface("path-for-basic")
            .path_for("hello-there")
            .unwrap();
        assert_eq!(
            path,
            test_data_path("path-for-basic/hello-there.gpg").as_path()
        )
    }

    #[test]
    fn path_for_rejects_nonexistent_name() {
        let err = password_store_interface("path-for-basic")
            .path_for("general-kenobi")
            .unwrap_err();
        assert!(matches!(err, RadomskoError::IoError{..}));
    }

    #[test]
    fn path_for_allows_sneaky_paths() {
        let path = password_store_interface("path-for-basic")
            .path_for("general/kenobi/../../hello-there")
            .unwrap();
        assert_eq!(
            path,
            test_data_path("path-for-basic/hello-there.gpg").as_path()
        );
    }

    #[test]
    fn path_for_disallows_sneaky_escaping_paths() {
        // For the purpose of this test, verify that the external
        // ("escaped") path exists.
        let _ = password_store_interface("path-for-basic-escape-path")
            .path_for("klaus")
            .unwrap();

        // Now assert that a `PasswordStoreInterface` constructed
        // against a different root cannot "escape" up and over into
        // this other directory.
        let err = password_store_interface("path-for-basic")
            .path_for("general/kenobi/../../../path-for-basic-escape-path/klaus")
            .unwrap_err();
        assert!(matches!(err, RadomskoError::IoError{..}));
    }

    #[test]
    fn path_for_allows_dots_in_basename() {
        let interface = password_store_interface("path-for-allows-dots-in-basename");
        assert_eq!(
            interface.path_for("klaus.txt").unwrap(),
            test_data_path("path-for-allows-dots-in-basename/klaus.txt.gpg")
        );
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
            *   e"#}
        );
    }

    #[test]
    fn draw_tree_with_files() {
        let interface = password_store_interface("draw-tree-with-files");
        assert_eq!(
            interface.draw_tree("", "").unwrap(),
            indoc! {r#"
            *   a
            *   b"#}
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
            *   e"#}
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
                *   b"#}
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
                    *   c"#}
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
                *   d"#}
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
                *   a"#}
        );
    }
}
