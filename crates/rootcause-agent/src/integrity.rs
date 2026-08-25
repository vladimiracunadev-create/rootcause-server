//! Fingerprints of the files that decide who gets into this server.
//!
//! The agent hashes; it never sends content. A digest is enough to prove that
//! something changed and useless for reading what the file says — which is the
//! only combination acceptable for `/etc/shadow`.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use rootcause_core::security::{CollectionGap, WatchedFile};
use sha2::{Digest, Sha256};

/// Files above this size are skipped: a configuration file is never this big,
/// and hashing a multi-gigabyte log every cycle would be the incident.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Files whose modification changes the security of a Linux server.
const LINUX_DEFAULTS: &[&str] = &[
    "/etc/ssh/sshd_config",
    "/etc/passwd",
    "/etc/group",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/pam.d/common-auth",
    "/etc/nginx/nginx.conf",
    "/etc/fstab",
    "/root/.ssh/authorized_keys",
];

const WINDOWS_DEFAULTS: &[&str] =
    &[r"C:\Windows\System32\drivers\etc\hosts", r"C:\ProgramData\ssh\sshd_config"];

const MACOS_DEFAULTS: &[&str] =
    &["/etc/ssh/sshd_config", "/etc/sudoers", "/etc/hosts", "/etc/pam.d/sudo"];

/// Default watch list for the platform the agent runs on.
pub fn default_paths() -> Vec<PathBuf> {
    let defaults = if cfg!(target_os = "windows") {
        WINDOWS_DEFAULTS
    } else if cfg!(target_os = "macos") {
        MACOS_DEFAULTS
    } else {
        LINUX_DEFAULTS
    };
    defaults.iter().map(PathBuf::from).collect()
}

/// Result of one integrity collection cycle.
#[derive(Debug, Default)]
pub struct IntegritySurface {
    pub files: Vec<WatchedFile>,
    pub gaps: Vec<CollectionGap>,
}

/// Hexadecimal SHA-256 digest of a byte slice.
pub fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Unix permission bits, when the platform exposes them.
#[cfg(unix)]
fn mode_of(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn mode_of(_metadata: &std::fs::Metadata) -> Option<u32> {
    None
}

fn modified_at(metadata: &std::fs::Metadata) -> Option<DateTime<Utc>> {
    metadata.modified().ok().map(DateTime::<Utc>::from)
}

/// Fingerprint every readable path in the watch list.
///
/// A path that does not exist is silently skipped — most servers do not run
/// nginx — while a path that exists and cannot be read is reported as a gap,
/// because that is the case where an operator would otherwise assume coverage
/// they do not have.
pub async fn collect(paths: &[PathBuf]) -> IntegritySurface {
    let mut surface = IntegritySurface::default();
    for path in paths {
        match fingerprint(path).await {
            Ok(Some(file)) => surface.files.push(file),
            Ok(None) => {}
            Err(reason) => surface
                .gaps
                .push(CollectionGap::new("watched-files", format!("{}: {reason}", path.display()))),
        }
    }
    surface
}

async fn fingerprint(path: &Path) -> Result<Option<WatchedFile>, String> {
    let metadata = match tokio::fs::metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("no se pudo consultar el archivo ({error})")),
    };
    if !metadata.is_file() {
        return Ok(None);
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(format!(
            "supera el tamaño máximo vigilado de {} MiB",
            MAX_FILE_BYTES / (1024 * 1024)
        ));
    }
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|error| format!("no se pudo leer el archivo ({error})"))?;

    Ok(Some(WatchedFile {
        path: path.display().to_string(),
        digest: digest(&bytes),
        size_bytes: metadata.len(),
        modified_at: modified_at(&metadata),
        mode: mode_of(&metadata),
    }))
}

/// Parse a comma or semicolon separated watch list supplied by an operator.
pub fn parse_watch_list(value: &str) -> Vec<PathBuf> {
    value
        .split([',', ';'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(PathBuf::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_is_the_published_sha256() {
        // Same value as `printf '' | sha256sum` and `echo -n abc | sha256sum`.
        assert_eq!(digest(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_different_byte_produces_a_different_digest() {
        assert_ne!(digest(b"root:x:0:0"), digest(b"root:x:0:1"));
    }

    #[test]
    fn the_default_watch_list_is_not_empty_and_has_no_duplicates() {
        let paths = default_paths();
        assert!(!paths.is_empty());
        let unique: std::collections::BTreeSet<_> = paths.iter().collect();
        assert_eq!(unique.len(), paths.len());
    }

    #[test]
    fn an_operator_watch_list_accepts_both_separators() {
        let paths = parse_watch_list("/etc/hosts, /etc/ssh/sshd_config ;; /srv/app/.env");
        assert_eq!(paths.len(), 3);
        assert_eq!(paths[2], PathBuf::from("/srv/app/.env"));
        assert!(parse_watch_list("   ").is_empty());
    }

    #[tokio::test]
    async fn a_missing_file_is_skipped_without_a_gap() {
        let surface = collect(&[PathBuf::from("/definitely/not/here/rootcause")]).await;
        assert!(surface.files.is_empty());
        assert!(surface.gaps.is_empty());
    }

    #[tokio::test]
    async fn a_real_file_is_fingerprinted_with_its_size() {
        let directory = std::env::temp_dir().join("rootcause-integrity-test");
        tokio::fs::create_dir_all(&directory).await.unwrap();
        let path = directory.join("watched.conf");
        tokio::fs::write(&path, b"PermitRootLogin no\n").await.unwrap();

        let surface = collect(std::slice::from_ref(&path)).await;
        assert_eq!(surface.files.len(), 1);
        assert_eq!(surface.files[0].size_bytes, 19);
        assert_eq!(surface.files[0].digest, digest(b"PermitRootLogin no\n"));
        assert!(surface.gaps.is_empty());

        tokio::fs::remove_file(&path).await.unwrap();
    }

    #[tokio::test]
    async fn a_directory_is_not_fingerprinted() {
        let surface = collect(&[std::env::temp_dir()]).await;
        assert!(surface.files.is_empty());
        assert!(surface.gaps.is_empty());
    }
}
