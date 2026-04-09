//! # Project detection
//!
//! Walks upward from a process working directory looking for project
//! marker files to determine the project root and name.
//!
//! The upward walk stops at the user's home directory to avoid matching
//! stray marker files (e.g. an accidental `package.json` in `~`), and
//! is capped at [`MAX_WALK_DEPTH`] levels as a safety net.

use std::path::{Path, PathBuf};

/// Files whose presence indicates a project root directory.
const PROJECT_MARKERS: &[&str] = &[
    "package.json",
    "Cargo.toml",
    "go.mod",
    "pyproject.toml",
    "requirements.txt",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
    "mix.exs",
    "deno.json",
    "bun.lockb",
];

/// File extensions whose presence indicates a project root directory.
const PROJECT_MARKER_EXTENSIONS: &[&str] = &["csproj", "fsproj"];

/// Maximum number of parent directories to traverse before giving up.
///
/// Prevents excessive I/O for processes with deeply nested or unusual
/// working directories (e.g. `/var/run/service/nested/deep/path`).
const MAX_WALK_DEPTH: usize = 16;

/// Detect the project root path for a process.
///
/// Tries the working directory first, then falls back to parsing
/// command-line arguments for absolute file paths.
///
/// Returns the project root directory path, or `None` if no project
/// root can be determined.
pub fn detect_project_root(cwd: Option<&Path>, cmd: &[impl AsRef<str>]) -> Option<PathBuf> {
    if let Some(cwd) = cwd
        && let Some(root) = find_from_dir(cwd)
    {
        return Some(root);
    }

    // Fallback: look for absolute paths in command-line arguments
    for arg in cmd {
        let path = Path::new(arg.as_ref());
        if path.is_absolute()
            && let Some(parent) = path.parent()
            && let Some(root) = find_from_dir(parent)
        {
            return Some(root);
        }
    }

    None
}

/// Walk upward from `start` looking for project marker files.
///
/// Returns the path of the directory containing the first marker found,
/// or `None` if no marker is found before reaching any of the following
/// ceilings:
///
/// - The user's home directory (not checked; prevents stray markers in
///   `~` from polluting every unrelated process).
/// - [`MAX_WALK_DEPTH`] levels above `start`.
/// - The filesystem root.
///
/// This is the cwd-only variant exposed for caching in the collector.
/// Use [`detect_project_root`] for the full detection pipeline that also
/// checks command-line arguments.
#[must_use]
pub fn find_from_dir(start: &Path) -> Option<PathBuf> {
    let home = home_dir();
    let mut current = start.to_path_buf();

    for _ in 0..MAX_WALK_DEPTH {
        // Stop at the user's home directory to avoid matching stray
        // marker files that were accidentally placed in ~ or above.
        if let Some(ref h) = home
            && current == *h
        {
            return None;
        }

        if has_marker(&current) {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }

    None
}

/// Return the current user's home directory, if it can be determined.
///
/// Uses `HOME` on Unix and `USERPROFILE` on Windows. Returns `None`
/// when the environment variable is unset, in which case only the
/// [`MAX_WALK_DEPTH`] limit guards against over-traversal.
fn home_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
}

/// Check whether a directory contains any project marker file.
///
/// Uses a single readdir call and in-memory checks instead of individual
/// stat calls per marker, reducing I/O for directories without markers.
fn has_marker(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };

    for entry in entries.filter_map(Result::ok) {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };

        if PROJECT_MARKERS.contains(&name) {
            return true;
        }

        if let Some(ext) = std::path::Path::new(name).extension()
            && PROJECT_MARKER_EXTENSIONS.iter().any(|m| *m == ext)
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_project(marker: &str) -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(marker), "").unwrap();
        dir
    }

    #[test]
    fn detect_node_project() {
        let dir = setup_project("package.json");
        let result = detect_project_root(Some(dir.path()), &Vec::<String>::new());
        assert_eq!(result.as_deref(), Some(dir.path()));
    }

    #[test]
    fn detect_rust_project() {
        let dir = setup_project("Cargo.toml");
        let result = detect_project_root(Some(dir.path()), &Vec::<String>::new());
        assert_eq!(result.as_deref(), Some(dir.path()));
    }

    #[test]
    fn detect_go_project() {
        let dir = setup_project("go.mod");
        let result = detect_project_root(Some(dir.path()), &Vec::<String>::new());
        assert_eq!(result.as_deref(), Some(dir.path()));
    }

    #[test]
    fn detect_python_project() {
        let dir = setup_project("pyproject.toml");
        let result = detect_project_root(Some(dir.path()), &Vec::<String>::new());
        assert_eq!(result.as_deref(), Some(dir.path()));
    }

    #[test]
    fn detect_walks_upward() {
        let dir = setup_project("package.json");
        let sub = dir.path().join("src").join("deep");
        fs::create_dir_all(&sub).unwrap();
        let result = detect_project_root(Some(&sub), &Vec::<String>::new());
        assert_eq!(result.as_deref(), Some(dir.path()));
    }

    #[test]
    fn detect_no_marker_returns_none() {
        let dir = TempDir::new().unwrap();
        let result = detect_project_root(Some(dir.path()), &Vec::<String>::new());
        assert!(result.is_none());
    }

    #[test]
    fn detect_none_cwd_returns_none() {
        let result = detect_project_root(None, &Vec::<String>::new());
        assert!(result.is_none());
    }

    #[test]
    fn detect_csproj_extension_marker() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("MyApp.csproj"), "").unwrap();
        let result = detect_project_root(Some(dir.path()), &Vec::<String>::new());
        assert_eq!(result.as_deref(), Some(dir.path()));
    }

    #[test]
    fn detect_fallback_to_cmd_args() {
        let dir = setup_project("Cargo.toml");
        let fake_path = dir.path().join("src").join("main.rs");
        fs::create_dir_all(fake_path.parent().unwrap()).unwrap();
        fs::write(&fake_path, "").unwrap();
        let cmd = vec![fake_path.to_string_lossy().into_owned()];
        let result = detect_project_root(None, &cmd);
        assert_eq!(result.as_deref(), Some(dir.path()));
    }

    #[test]
    fn walk_stops_at_home_ceiling() {
        // Simulate a stray marker in a directory treated as "home".
        // Override HOME/USERPROFILE so find_from_dir sees a ceiling.
        let fake_home = TempDir::new().unwrap();
        fs::write(fake_home.path().join("package.json"), "").unwrap();
        let sub = fake_home.path().join("unrelated");
        fs::create_dir_all(&sub).unwrap();

        let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let original = std::env::var_os(var);
        // Safety: test is single-threaded; no concurrent readers of this var.
        unsafe { std::env::set_var(var, fake_home.path()) };

        let result = find_from_dir(&sub);

        // Restore original value to avoid polluting other tests.
        if let Some(orig) = original {
            // Safety: same single-threaded test context.
            unsafe { std::env::set_var(var, orig) };
        }

        assert!(
            result.is_none(),
            "should NOT match stray marker in the home directory"
        );
    }

    #[test]
    fn walk_respects_max_depth() {
        let dir = TempDir::new().unwrap();
        // Create a marker at the temp root
        fs::write(dir.path().join("package.json"), "").unwrap();
        // Create a subdirectory deeper than MAX_WALK_DEPTH
        let mut deep = dir.path().to_path_buf();
        for i in 0..=MAX_WALK_DEPTH {
            deep = deep.join(format!("d{i}"));
        }
        fs::create_dir_all(&deep).unwrap();

        let result = find_from_dir(&deep);
        assert!(
            result.is_none(),
            "walk should stop after MAX_WALK_DEPTH levels"
        );
    }
}
