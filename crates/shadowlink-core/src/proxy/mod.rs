pub mod socks5;
pub mod dialer;
pub mod dns;

#[cfg(target_os = "windows")]
pub mod wintun_ffi;

#[cfg(target_os = "windows")]
pub mod tun_device;

#[cfg(target_os = "linux")]
pub mod linux_tun;
