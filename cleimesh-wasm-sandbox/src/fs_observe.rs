//! Which directories a tool actually touched, per directory it was granted
//! (C5). The WASI preview1 functions that take a path
//! are shadowed in the linker: each wrapper reads the path from the guest,
//! runs wasmtime-wasi's own ABI-level function, and notes the access.
//!
//! wasmtime-wasi keeps its generated glue to itself, and calling the
//! original as a `Func` fails (the glue looks for the memory in its caller,
//! and the host has none), so the wrappers repeat that glue. Paths are
//! lexical: a symlink inside a grant is noted where the guest named it.

use std::collections::{BTreeSet, HashMap};

use wasmtime::{Caller, Extern, Linker};
use wasmtime_wasi::p1;

use crate::SandboxData;

/// What a call touched under one granted directory. Directories are
/// relative to `grant`, as path components (the grant itself is `[]`).
/// File names are never kept, only counted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantUse {
    pub grant: String,
    pub read: BTreeSet<Vec<String>>,
    pub write: BTreeSet<Vec<String>>,
    pub files_read: u64,
    pub files_written: u64,
    /// Accesses WASI refused (a path escaping the grant, a missing right).
    pub refused: u64,
}

/// Every granted directory of a call, used or not, in grant order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsObserved {
    pub grants: Vec<GrantUse>,
}

/// wasmtime-wasi numbers preopens from 3, in the order they were added.
const FIRST_PREOPEN_FD: i32 = 3;

// WASI preview1 errno values.
const ERRNO_SUCCESS: i32 = 0;
const ERRNO_ACCES: i32 = 2;
const ERRNO_PERM: i32 = 63;
const ERRNO_NOTCAPABLE: i32 = 76;

// WASI preview1 flags.
const OFLAGS_CREAT: i32 = 1;
const OFLAGS_DIRECTORY: i32 = 2;
const OFLAGS_TRUNC: i32 = 8;
const RIGHTS_FD_WRITE: i64 = 1 << 6;

enum Access {
    /// A file opened for reading: counts, notes its directory.
    ReadFile,
    /// A file opened for writing, created or truncated.
    WriteFile,
    /// The path itself is a directory being read.
    ReadDir,
    /// Metadata or a link's target: notes the directory holding it.
    Inspect,
    /// Created, removed, renamed or linked: a write to the directory holding it.
    Change,
}

/// Collects a call's accesses; open directory descriptors map to where
/// they point, so paths relative to them resolve.
#[derive(Debug, Default)]
pub struct FsTracker {
    observed: FsObserved,
    fds: HashMap<i32, (usize, Vec<String>)>,
}

impl FsTracker {
    /// `grants` as preopened, in order: they become fds 3, 4, ...
    pub fn new(grants: Vec<String>) -> Self {
        let fds = (0..grants.len()).map(|i| (FIRST_PREOPEN_FD + i as i32, (i, Vec::new()))).collect();
        let grants = grants.into_iter().map(|grant| GrantUse { grant, ..Default::default() }).collect();
        FsTracker { observed: FsObserved { grants }, fds }
    }

    pub fn observed(&self) -> &FsObserved {
        &self.observed
    }

    /// `path` under `fd`: the grant and the components below it, `Err` with
    /// the grant if it climbs out. `None` if `fd` is not a known directory.
    fn resolve(&self, fd: i32, path: &str) -> Option<Result<(usize, Vec<String>), usize>> {
        let (grant, base) = self.fds.get(&fd)?;
        let mut components = base.clone();
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    if components.pop().is_none() {
                        return Some(Err(*grant));
                    }
                }
                name => components.push(name.to_string()),
            }
        }
        Some(Ok((*grant, components)))
    }

    fn note(&mut self, fd: i32, path: Option<&str>, errno: i32, access: Access) {
        let Some(path) = path else { return };
        let Some(resolved) = self.resolve(fd, path) else { return };
        let (grant, components) = match resolved {
            Ok(found) if !matches!(errno, ERRNO_ACCES | ERRNO_PERM | ERRNO_NOTCAPABLE) => found,
            Ok((grant, _)) | Err(grant) => {
                self.observed.grants[grant].refused += 1;
                return;
            }
        };
        let parent = || components[..components.len().saturating_sub(1)].to_vec();
        let usage = &mut self.observed.grants[grant];
        match access {
            Access::ReadFile => {
                usage.files_read += u64::from(errno == ERRNO_SUCCESS);
                usage.read.insert(parent());
            }
            Access::WriteFile => {
                usage.files_written += u64::from(errno == ERRNO_SUCCESS);
                usage.write.insert(parent());
            }
            Access::ReadDir => {
                usage.read.insert(components);
            }
            Access::Inspect => {
                usage.read.insert(parent());
            }
            Access::Change => {
                usage.write.insert(parent());
            }
        }
    }

    fn opened(&mut self, dirfd: i32, path: Option<&str>, oflags: i32, rights: i64, errno: i32, fd: Option<i32>) {
        let access = if oflags & OFLAGS_DIRECTORY != 0 {
            Access::ReadDir
        } else if rights & RIGHTS_FD_WRITE != 0 || oflags & (OFLAGS_CREAT | OFLAGS_TRUNC) != 0 {
            Access::WriteFile
        } else {
            Access::ReadFile
        };
        self.note(dirfd, path, errno, access);
        // Kept for files too: a directory opened without O_DIRECTORY still
        // resolves the paths opened under it.
        if let (ERRNO_SUCCESS, Some(fd), Some(path)) = (errno, fd, path) {
            if let Some(Ok(target)) = self.resolve(dirfd, path) {
                self.fds.insert(fd, target);
            }
        }
    }
}

fn guest_str(bytes: &[u8], ptr: i32, len: i32) -> Option<String> {
    let start = ptr as u32 as usize;
    let end = start.checked_add(len as u32 as usize)?;
    bytes.get(start..end).map(|b| String::from_utf8_lossy(b).into_owned())
}

fn guest_u32(bytes: &[u8], ptr: i32) -> Option<i32> {
    let start = ptr as u32 as usize;
    let raw = bytes.get(start..start.checked_add(4)?)?;
    Some(u32::from_le_bytes(raw.try_into().ok()?) as i32)
}

/// Shadows the preview1 function `$name` with wiggle's glue plus a note:
/// `$paths` are the guest strings read before the call, `$errno` its
/// result, `$bytes` the guest memory after it.
macro_rules! observe {
    ($linker:expr, $name:ident ( $($arg:ident : $ty:ty),* ), [$(($p:ident, $l:ident)),*],
     |$fs:ident, $paths:ident, $errno:ident, $bytes:ident| $record:block) => {
        $linker.func_wrap_async(
            "wasi_snapshot_preview1",
            stringify!($name),
            |mut caller: Caller<'_, SandboxData>, ($($arg,)*): ($($ty,)*)| {
                Box::new(async move {
                    let Some(Extern::Memory(memory)) = caller.get_export("memory") else {
                        wasmtime::bail!("missing required memory export");
                    };
                    let (bytes, data) = memory.data_and_store_mut(&mut caller);
                    let $paths: Vec<Option<String>> = vec![$(guest_str(bytes, $p, $l)),*];
                    let mut mem = wiggle::GuestMemory::Unshared(bytes);
                    let $errno = p1::wasi_snapshot_preview1::$name(&mut data.wasi_p1_ctx, &mut mem, $($arg),*).await?;
                    let wiggle::GuestMemory::Unshared($bytes) = mem else { unreachable!("built as unshared") };
                    let $fs = &mut data.fs;
                    $record
                    Ok($errno)
                })
            },
        )?;
    };
}

/// Replaces the preview1 functions that touch the filesystem in `linker`
/// (which must already hold preview1) with observing ones.
pub fn observe_filesystem(linker: &mut Linker<SandboxData>) -> anyhow::Result<()> {
    linker.allow_shadowing(true);
    observe!(linker, path_open(fd: i32, dirflags: i32, path: i32, path_len: i32, oflags: i32, rights: i64, inheriting: i64, fdflags: i32, opened: i32),
        [(path, path_len)], |fs, paths, errno, bytes| {
            let new_fd = (errno == ERRNO_SUCCESS).then(|| guest_u32(bytes, opened)).flatten();
            fs.opened(fd, paths[0].as_deref(), oflags, rights, errno, new_fd);
        });
    observe!(linker, fd_readdir(fd: i32, buf: i32, buf_len: i32, cookie: i64, used: i32), [], |fs, _paths, errno, _bytes| {
        fs.note(fd, Some(""), errno, Access::ReadDir);
    });
    observe!(linker, fd_close(fd: i32), [], |fs, _paths, errno, _bytes| {
        if errno == ERRNO_SUCCESS {
            fs.fds.remove(&fd);
        }
    });
    observe!(linker, fd_renumber(fd: i32, to: i32), [], |fs, _paths, errno, _bytes| {
        if errno == ERRNO_SUCCESS {
            fs.fds.remove(&to);
            if let Some(target) = fs.fds.remove(&fd) {
                fs.fds.insert(to, target);
            }
        }
    });
    observe!(linker, path_filestat_get(fd: i32, flags: i32, path: i32, path_len: i32, buf: i32), [(path, path_len)], |fs, paths, errno, _bytes| {
        fs.note(fd, paths[0].as_deref(), errno, Access::Inspect);
    });
    observe!(linker, path_readlink(fd: i32, path: i32, path_len: i32, buf: i32, buf_len: i32, used: i32), [(path, path_len)], |fs, paths, errno, _bytes| {
        fs.note(fd, paths[0].as_deref(), errno, Access::Inspect);
    });
    observe!(linker, path_filestat_set_times(fd: i32, flags: i32, path: i32, path_len: i32, atim: i64, mtim: i64, fst_flags: i32), [(path, path_len)], |fs, paths, errno, _bytes| {
        fs.note(fd, paths[0].as_deref(), errno, Access::Change);
    });
    observe!(linker, path_create_directory(fd: i32, path: i32, path_len: i32), [(path, path_len)], |fs, paths, errno, _bytes| {
        fs.note(fd, paths[0].as_deref(), errno, Access::Change);
    });
    observe!(linker, path_remove_directory(fd: i32, path: i32, path_len: i32), [(path, path_len)], |fs, paths, errno, _bytes| {
        fs.note(fd, paths[0].as_deref(), errno, Access::Change);
    });
    observe!(linker, path_unlink_file(fd: i32, path: i32, path_len: i32), [(path, path_len)], |fs, paths, errno, _bytes| {
        fs.note(fd, paths[0].as_deref(), errno, Access::Change);
    });
    observe!(linker, path_rename(fd: i32, old_path: i32, old_len: i32, new_fd: i32, new_path: i32, new_len: i32), [(old_path, old_len), (new_path, new_len)], |fs, paths, errno, _bytes| {
        fs.note(fd, paths[0].as_deref(), errno, Access::Change);
        fs.note(new_fd, paths[1].as_deref(), errno, Access::Change);
    });
    // The link's target is text stored in the link, not an access.
    observe!(linker, path_symlink(target: i32, target_len: i32, fd: i32, path: i32, path_len: i32), [(path, path_len)], |fs, paths, errno, _bytes| {
        fs.note(fd, paths[0].as_deref(), errno, Access::Change);
    });
    observe!(linker, path_link(old_fd: i32, old_flags: i32, old_path: i32, old_len: i32, new_fd: i32, new_path: i32, new_len: i32), [(old_path, old_len), (new_path, new_len)], |fs, paths, errno, _bytes| {
        fs.note(old_fd, paths[0].as_deref(), errno, Access::Inspect);
        fs.note(new_fd, paths[1].as_deref(), errno, Access::Change);
    });
    linker.allow_shadowing(false);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> FsTracker {
        FsTracker::new(vec!["/data".into(), "/out".into()])
    }

    fn dirs(set: &BTreeSet<Vec<String>>) -> Vec<String> {
        set.iter().map(|c| c.join("/")).collect()
    }

    #[test]
    fn files_count_and_note_their_directory() {
        let mut t = tracker();
        t.opened(3, Some("docs/api/a.txt"), 0, 2, ERRNO_SUCCESS, Some(5));
        t.opened(3, Some("top.txt"), 0, 2, ERRNO_SUCCESS, Some(6));
        t.opened(4, Some("r.txt"), OFLAGS_CREAT, RIGHTS_FD_WRITE, ERRNO_SUCCESS, Some(7));
        let [data, out] = &t.observed().grants[..] else { panic!() };
        assert_eq!((data.files_read, dirs(&data.read)), (2, vec!["".to_string(), "docs/api".to_string()]));
        assert_eq!((out.files_written, dirs(&out.write)), (1, vec!["".to_string()]));
    }

    #[test]
    fn paths_resolve_under_opened_directories_until_closed() {
        let mut t = tracker();
        t.opened(3, Some("docs"), OFLAGS_DIRECTORY, 0, ERRNO_SUCCESS, Some(5));
        t.note(5, Some(""), ERRNO_SUCCESS, Access::ReadDir);
        t.opened(5, Some("api/../guide/x.md"), 0, 2, ERRNO_SUCCESS, Some(6));
        t.fds.remove(&5);
        t.opened(5, Some("lost.txt"), 0, 2, ERRNO_SUCCESS, Some(7));
        assert_eq!(dirs(&t.observed().grants[0].read), vec!["docs", "docs/guide"]);
        assert_eq!(t.observed().grants[0].files_read, 1);
    }

    #[test]
    fn escapes_and_refusals_count_without_a_path() {
        let mut t = tracker();
        t.opened(3, Some("../etc/passwd"), 0, 2, 76, None);
        t.opened(3, Some("docs/secret"), 0, 2, ERRNO_NOTCAPABLE, None);
        t.opened(3, Some("missing.txt"), 0, 2, 44, None);
        let data = &t.observed().grants[0];
        assert_eq!((data.refused, data.files_read), (2, 0));
        assert_eq!(dirs(&data.read), vec![""], "a missing file still shows the directory was needed");
    }
}
