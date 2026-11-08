//! Exact-worktree trust for explicitly authorized interactive auto tasks.
//! The lock serializes Ahu writers only. Native applications do not participate;
//! rereading before replacement detects some races, not an atomic transaction.
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::util::{Error, Result};

const LIMIT: u64 = 4 * 1024 * 1024;
const RECEIPT: &str = "native-trust.json";

fn refused() -> Error {
    Error::new(
        "native task trust refused: unsafe, changed, unsupported, or malformed state; native configuration contents are withheld",
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u8,
    harness: String,
    worktree: PathBuf,
    home: PathBuf,
    // Claude's prior false / Codex's prior untrusted value is restored.
    // Only this bounded prior trust state is stored, never native config.
    prior_false: bool,
    project_added: bool,
}

fn checked(path: &Path, directory: bool) -> Result<Option<fs::Metadata>> {
    // SAFETY: geteuid takes no pointers and cannot invalidate filesystem handles.
    let owner = unsafe { libc::geteuid() };
    match fs::symlink_metadata(path) {
        Ok(m)
            if !m.file_type().is_symlink()
                && m.uid() == owner
                && m.mode() & 0o022 == 0
                && (if directory {
                    m.is_dir()
                } else {
                    m.is_file() && m.nlink() == 1
                }) =>
        {
            Ok(Some(m))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        _ => Err(refused()),
    }
}

fn read(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
    let Some(m) = checked(path, false)? else {
        return Ok(None);
    };
    if m.len() > limit {
        return Err(refused());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| refused())?;
    let opened = file.metadata()?;
    if opened.ino() != m.ino() || opened.dev() != m.dev() {
        return Err(refused());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refused())?;
    if bytes.len() as u64 > limit {
        return Err(refused());
    }
    Ok(Some(bytes))
}

fn replace(path: &Path, previous: Option<&[u8]>, bytes: &[u8], limit: u64) -> Result<()> {
    if bytes.len() as u64 > limit {
        return Err(refused());
    }
    let mut tmp = tempfile::NamedTempFile::new_in(path.parent().ok_or_else(refused)?)
        .map_err(|_| refused())?;
    tmp.write_all(bytes).map_err(|_| refused())?;
    tmp.as_file().sync_all().map_err(|_| refused())?;
    if read(path, limit)?.as_deref() != previous {
        return Err(refused());
    }
    tmp.persist(path).map_err(|_| refused())?;
    fs::File::open(path.parent().ok_or_else(refused)?)?.sync_all()?;
    Ok(())
}

// Lock the existing native-home directory so all repositories serialize Ahu
// writers without creating an ahu-owned file in the user's home directory.
// Native applications do not participate in this advisory lock.
fn lock_native(path: &Path) -> Result<fs::File> {
    use std::os::fd::AsRawFd;
    checked(path, true)?.ok_or_else(refused)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| refused())?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        // SAFETY: file owns this live descriptor; flock changes only its advisory lock.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let error = std::io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EWOULDBLOCK))
            || std::time::Instant::now() >= deadline
        {
            return Err(refused());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

pub(crate) fn update(
    home: &Path,
    dir: &Path,
    harness: &str,
    worktree: &Path,
    remove: bool,
) -> Result<()> {
    // Validate every component before creating or reading state. No native
    // document is copied into task state, diagnostics, or a backup file.
    checked(home, true)?.ok_or_else(refused)?;
    crate::files::check_components(dir)?;
    checked(dir, true)?.ok_or_else(refused)?;
    let _lock = lock_native(home)?;
    let path = match harness {
        "claude-code" => home.join(".claude.json"),

        _ => return Err(refused()),
    };
    let receipt_path = dir.join(RECEIPT);
    let receipt_bytes = read(&receipt_path, 8192)?;
    let receipt: Option<Receipt> = receipt_bytes
        .as_ref()
        .map(|b| serde_json::from_slice(b).map_err(|_| refused()))
        .transpose()?;
    if let Some(r) = &receipt
        && (r.schema != 1 || r.harness != harness || r.home != home || r.worktree != worktree)
    {
        return Err(refused());
    }
    if remove && receipt.is_none() {
        return Ok(());
    }
    let before = read(&path, LIMIT)?;
    let key = worktree.to_str().ok_or_else(refused)?;
    let (after, already, prior_false, project_added, project_entry_removed) = {
        let mut doc: Value = match &before {
            Some(bytes) => serde_json::from_slice(bytes).map_err(|_| refused())?,
            None => json!({}),
        };
        let root = doc.as_object_mut().ok_or_else(refused)?;
        let (already, prior_false, project_added, project_entry_removed) = {
            let projects = root
                .entry("projects")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .ok_or_else(refused)?;
            let project_added = !projects.contains_key(key);
            let project = projects
                .entry(key)
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .ok_or_else(refused)?;
            let old = project.get("hasTrustDialogAccepted");
            if old.is_some_and(|v| !v.is_boolean()) {
                return Err(refused());
            }
            let already = old == Some(&Value::Bool(true));
            let prior_false = old == Some(&Value::Bool(false));
            if remove {
                if already {
                    if receipt.as_ref().is_some_and(|r| r.prior_false) {
                        project.insert("hasTrustDialogAccepted".into(), Value::Bool(false));
                    } else {
                        project.remove("hasTrustDialogAccepted");
                    }
                }
            } else {
                project.insert("hasTrustDialogAccepted".into(), Value::Bool(true));
            }
            let project_entry_removed = remove
                && !project_added
                && project.is_empty()
                && receipt.as_ref().is_some_and(|r| r.project_added);
            if project_entry_removed {
                projects.remove(key);
            }
            (already, prior_false, project_added, project_entry_removed)
        };
        let after = serde_json::to_vec_pretty(&doc).map_err(|_| refused())?;
        (
            after,
            already,
            prior_false,
            project_added,
            project_entry_removed,
        )
    };
    if !remove && already {
        return Ok(());
    }
    if after.len() as u64 > LIMIT {
        return Err(refused());
    }
    if !remove && receipt.is_none() {
        // Write-ahead receipt makes a crash on either side of the native write
        // recoverable by retry or task removal. It contains no native history.
        let receipt = Receipt {
            schema: 1,
            harness: harness.into(),
            worktree: worktree.into(),
            home: home.into(),
            prior_false,
            project_added,
        };
        replace(
            &receipt_path,
            None,
            &serde_json::to_vec(&receipt).map_err(|_| refused())?,
            8192,
        )?;
    }
    if !remove || already || project_entry_removed {
        replace(&path, before.as_deref(), &after, LIMIT)?;
    }
    if remove {
        fs::remove_file(receipt_path).map_err(|_| refused())?;
        fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

// Codex 0.163.0's TUI config/read lookup prefers a saved exact cwd entry,
// even for linked worktrees whose fallback trust target is the main checkout.
// Edit the native TOML in place without serializing unrelated settings anew.
