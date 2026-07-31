use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::Foundation::{HMODULE, HANDLE};

pub type WINTUN_ADAPTER_HANDLE = *mut c_void;
pub type WINTUN_SESSION_HANDLE = *mut c_void;

pub type WintunCreateAdapterFunc = unsafe extern "system" fn(
    Pool: *const u16,
    Name: *const u16,
    RequestedGUID: *const c_void,
    RebootRequired: *mut i32,
) -> WINTUN_ADAPTER_HANDLE;

pub type WintunCloseAdapterFunc = unsafe extern "system" fn(
    Adapter: WINTUN_ADAPTER_HANDLE,
);

pub type WintunStartSessionFunc = unsafe extern "system" fn(
    Adapter: WINTUN_ADAPTER_HANDLE,
    Capacity: u32,
) -> WINTUN_SESSION_HANDLE;

pub type WintunEndSessionFunc = unsafe extern "system" fn(
    Session: WINTUN_SESSION_HANDLE,
);

pub type WintunReceivePacketFunc = unsafe extern "system" fn(
    Session: WINTUN_SESSION_HANDLE,
    PacketSize: *mut u32,
) -> *mut u8;

pub type WintunReleaseReceivePacketFunc = unsafe extern "system" fn(
    Session: WINTUN_SESSION_HANDLE,
    Packet: *const u8,
);

pub type WintunAllocateSendPacketFunc = unsafe extern "system" fn(
    Session: WINTUN_SESSION_HANDLE,
    PacketSize: u32,
) -> *mut u8;

pub type WintunSendPacketFunc = unsafe extern "system" fn(
    Session: WINTUN_SESSION_HANDLE,
    Packet: *const u8,
);

pub type WintunGetReadWaitEventFunc = unsafe extern "system" fn(
    Session: WINTUN_SESSION_HANDLE,
) -> HANDLE;

pub struct WintunApi {
    pub CreateAdapter: WintunCreateAdapterFunc,
    pub close_adapter: WintunCloseAdapterFunc,
    pub StartSession: WintunStartSessionFunc,
    pub EndSession: WintunEndSessionFunc,
    pub ReceivePacket: WintunReceivePacketFunc,
    pub ReleaseReceivePacket: WintunReleaseReceivePacketFunc,
    pub AllocateSendPacket: WintunAllocateSendPacketFunc,
    pub SendPacket: WintunSendPacketFunc,
    pub GetReadWaitEvent: WintunGetReadWaitEventFunc,
}

unsafe impl Send for WintunApi {}
unsafe impl Sync for WintunApi {}

impl WintunApi {
    pub unsafe fn load(dll_path: &str) -> Result<Self, String> {
        use std::os::windows::ffi::OsStrExt;
        let mut path_u16: Vec<u16> = std::ffi::OsStr::new(dll_path).encode_wide().collect();
        path_u16.push(0);

        let hmodule = LoadLibraryW(path_u16.as_ptr());
        if hmodule.is_null() {
            return Err("Failed to load wintun.dll".to_string());
        }

        macro_rules! load_func {
            ($name:expr) => {{
                let sym = GetProcAddress(hmodule, $name.as_ptr());
                if sym.is_none() {
                    return Err(format!("Failed to find function {}", std::str::from_utf8($name).unwrap()));
                }
                std::mem::transmute(sym.unwrap())
            }};
        }

        Ok(WintunApi {
            CreateAdapter:        load_func!(b"WintunCreateAdapter\0"),
            close_adapter:        load_func!(b"WintunCloseAdapter\0"),
            StartSession:         load_func!(b"WintunStartSession\0"),
            EndSession:           load_func!(b"WintunEndSession\0"),
            ReceivePacket:        load_func!(b"WintunReceivePacket\0"),
            ReleaseReceivePacket: load_func!(b"WintunReleaseReceivePacket\0"),
            AllocateSendPacket:   load_func!(b"WintunAllocateSendPacket\0"),
            SendPacket:           load_func!(b"WintunSendPacket\0"),
            GetReadWaitEvent:     load_func!(b"WintunGetReadWaitEvent\0"),
        })
    }
}
