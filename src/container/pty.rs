//! PTY allocation for isolation level 1 and above (PLAN 4.4.3).
//!
//! The PTY is allocated **in the parent** and handed to the child as its
//! stdin/stdout/stderr, which is the only design that keeps `pre_exec`
//! async-signal-safe: `posix_openpt`/`grantpt`/`unlockpt` allocate and can read
//! `/dev/ptmx` state, so they must never run between `fork` and `exec`.
//!
//! The child becomes a session leader and claims the terminal itself:
//!
//! 1. parent: `posix_openpt` → `grantpt` → `unlockpt` → `open(slave)`;
//! 2. parent: `Command::stdin/stdout/stderr(slave)`, dropping its own slave for
//!    the read side so the master sees EOF once the container exits;
//! 3. child (supervisor, before `fork`): nothing PTY-specific;
//! 4. child (PID 1, in the new PID namespace): `setsid()` then
//!    `ioctl(fd 0, TIOCSCTTY, 0)` — both raw syscalls, both safe there.
//!
//! The parent reads the master until EOF/EIO and returns it as
//! [`crate::container::LaunchOutcome::output`].

use std::fs::File;
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};

use crate::container::ContainerError;

/// A connected PTY pair, both ends owned by the caller.
#[derive(Debug)]
pub struct PtyPair {
    /// Parent side.
    pub master: File,
    /// Child side (already opened; pass to the child's stdio).
    pub slave: File,
}

impl PtyPair {
    /// Allocate `master`/`slave` from `/dev/ptmx`.
    ///
    /// `grantpt`/`unlockpt` are used instead of `openpty(3)` so the code needs
    /// nothing beyond libc (no `-lutil`): on modern glibc `openpty` lives in
    /// libc, but not all tier-1 targets guarantee it.
    pub fn open() -> Result<Self, ContainerError> {
        // SAFETY: plain syscalls on freshly created descriptors; every failure
        // path closes what it opened.
        unsafe {
            let master_fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
            if master_fd < 0 {
                return Err(ContainerError::Pty(format!(
                    "posix_openpt: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if libc::grantpt(master_fd) != 0 {
                let err = std::io::Error::last_os_error();
                libc::close(master_fd);
                return Err(ContainerError::Pty(format!("grantpt: {err}")));
            }
            if libc::unlockpt(master_fd) != 0 {
                let err = std::io::Error::last_os_error();
                libc::close(master_fd);
                return Err(ContainerError::Pty(format!("unlockpt: {err}")));
            }
            let mut name = [0 as libc::c_char; 128];
            if libc::ptsname_r(master_fd, name.as_mut_ptr(), name.len()) != 0 {
                let err = std::io::Error::last_os_error();
                libc::close(master_fd);
                return Err(ContainerError::Pty(format!("ptsname_r: {err}")));
            }
            let slave_fd = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
            if slave_fd < 0 {
                let err = std::io::Error::last_os_error();
                libc::close(master_fd);
                return Err(ContainerError::Pty(format!("open pty slave: {err}")));
            }
            Ok(Self {
                master: File::from_raw_fd(master_fd),
                slave: File::from_raw_fd(slave_fd),
            })
        }
    }

    /// A raw handle to the master, for callers that need to poll it.
    pub fn master_fd(&self) -> RawFd {
        use std::os::fd::AsRawFd;
        self.master.as_raw_fd()
    }
}

/// Read the master side until the container closes its last slave descriptor.
///
/// Linux reports `EIO` rather than `0` once a PTY's last slave is gone; both are
/// treated as EOF.
pub fn read_to_end(master: &mut File) -> Result<Vec<u8>, ContainerError> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match master.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            // EIO: no slave is open any more.
            Err(err) if err.raw_os_error() == Some(libc::EIO) => break,
            Err(err) => return Err(ContainerError::Pty(format!("read pty master: {err}"))),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    #[test]
    fn pty_pair_is_a_tty() {
        let pair = PtyPair::open().unwrap();
        // SAFETY: querying an open fd owned by `pair`.
        let is_tty = unsafe { libc::isatty(pair.slave.as_raw_fd()) };
        assert_eq!(is_tty, 1, "slave side must be a terminal");
        assert!(pair.master_fd() >= 0);
    }

    #[test]
    fn bytes_written_to_slave_arrive_on_master() {
        let mut pair = PtyPair::open().unwrap();
        // Echo is on by default; writing on the slave is visible on the master
        // through the line discipline only after a newline, so send one.
        pair.slave.write_all(b"hello\n").unwrap();
        pair.slave.flush().unwrap();

        let mut buf = [0u8; 64];
        let n = pair.master.read(&mut buf).unwrap();
        assert!(std::str::from_utf8(&buf[..n]).unwrap().contains("hello"));
    }

    #[test]
    fn read_to_end_stops_when_the_slave_closes() {
        let PtyPair { mut master, slave } = PtyPair::open().unwrap();
        drop(slave);
        let bytes = read_to_end(&mut master).unwrap();
        assert!(bytes.is_empty());
    }
}
