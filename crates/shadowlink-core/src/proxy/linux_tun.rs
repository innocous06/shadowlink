//! Linux TUN device interface using native POSIX syscalls.
//!
//! Opens /dev/net/tun, configures a TUN interface via ioctl(TUNSETIFF),
//! and provides packet-level I/O for the Layer 3 VPN routing loop.
//!
//! Designed to be wrapped in `Arc` — both `start_reader` and `write_packet`
//! work from separate async tasks without requiring `&mut self`.

use anyhow::{anyhow, Result};
use std::fs::{File, OpenOptions};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[repr(C)]
struct Ifreq {
    ifr_name: [u8; 16],
    ifr_flags: i16,
}

const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const TUNSETPERSIST: libc::c_ulong = 0x400454cb;

/// A Linux TUN device for Layer 3 packet I/O.
///
/// Wrap in `Arc<LinuxTun>` to share between the reader task and the packet
/// writer inside the proxy session loop.
pub struct LinuxTun {
    /// Raw file descriptor — used by the blocking reader thread via libc::read.
    fd: RawFd,
    /// Owned file handle — keeps the fd alive and provides `Drop` cleanup.
    _file: Arc<Mutex<File>>,
}

// SAFETY: RawFd is just an i32; the kernel TUN fd is inherently thread-safe
// for concurrent read/write (one reader thread, one async writer is fine).
unsafe impl Send for LinuxTun {}
unsafe impl Sync for LinuxTun {}

impl LinuxTun {
    /// Open and configure a TUN interface with the given name.
    ///
    /// Requires CAP_NET_ADMIN (typically: run as root, or `setcap cap_net_admin`).
    pub fn new(name: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| anyhow!("Failed to open /dev/net/tun (are you root?): {}", e))?;

        let fd = file.as_raw_fd();

        let mut ifr = Ifreq {
            ifr_name: [0; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
        };

        let name_bytes = name.as_bytes();
        let len = name_bytes.len().min(15);
        ifr.ifr_name[..len].copy_from_slice(&name_bytes[..len]);

        let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr as *const Ifreq) };
        if ret < 0 {
            return Err(anyhow!(
                "ioctl(TUNSETIFF) failed — need CAP_NET_ADMIN or run as root"
            ));
        }

        // Make the TUN interface PERSISTENT — it survives fd close.
        // This means when the client disconnects and the fd drops, the kernel
        // keeps the interface alive with its IP address and routes intact.
        // On the next client connection, we re-open /dev/net/tun and reattach
        // to the same named interface — iptables and ip-addr stay configured.
        let persist_ret = unsafe { libc::ioctl(fd, TUNSETPERSIST, 1) };
        if persist_ret < 0 {
            // Non-fatal: older kernels may not support it. Log and continue.
            // Routing will still work for the current session.
            eprintln!("Warning: TUNSETPERSIST not supported — iptables rules \
                       must be re-applied after each client reconnect.");
        }

        Ok(Self {
            fd,
            _file: Arc::new(Mutex::new(file)),
        })
    }

    /// Spawn a background OS thread that reads raw IP packets from the TUN
    /// interface and sends them into an async `mpsc` channel.
    ///
    /// The thread exits when the channel receiver is dropped.
    pub fn start_reader(&self) -> mpsc::UnboundedReceiver<Vec<u8>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let fd = self.fd;

        std::thread::spawn(move || {
            // MTU 65535 covers all valid IP packet sizes.
            let mut buf = [0u8; 65535];
            loop {
                let n = unsafe {
                    libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n <= 0 {
                    // fd closed or error — exit thread cleanly.
                    break;
                }
                let data = buf[..n as usize].to_vec();
                if tx.send(data).is_err() {
                    // Receiver dropped — proxy session ended.
                    break;
                }
            }
        });

        rx
    }

    /// Write a raw IP packet into the TUN interface.
    ///
    /// Thread-safe: can be called from multiple async tasks concurrently.
    /// The Linux kernel serializes concurrent writes to a TUN fd safely.
    pub fn write_packet(&self, data: &[u8]) -> Result<()> {
        let n = unsafe {
            libc::write(
                self.fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
            )
        };
        if n < 0 {
            return Err(anyhow!("Failed to write to TUN device (errno: {})", unsafe {
                *libc::__errno_location()
            }));
        }
        Ok(())
    }
}

impl Drop for LinuxTun {
    fn drop(&mut self) {
        // _file owns the File, which closes the fd when dropped here.
        // No explicit close needed — the Arc<Mutex<File>> will do it.
    }
}
