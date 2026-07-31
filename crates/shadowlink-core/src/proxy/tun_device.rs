use std::sync::Arc;
use tokio::sync::mpsc;
use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use anyhow::{anyhow, Result};

use super::wintun_ffi::{WintunApi, WINTUN_ADAPTER_HANDLE, WINTUN_SESSION_HANDLE};

pub struct TunDevice {
    api: Arc<WintunApi>,
    adapter: WINTUN_ADAPTER_HANDLE,
    session: WINTUN_SESSION_HANDLE,
}



// Ensure TunDevice can be sent across threads (Wintun handles are thread-safe)
unsafe impl Send for TunDevice {}
unsafe impl Sync for TunDevice {}

impl TunDevice {
    pub fn new(api: Arc<WintunApi>, name: &str) -> Result<Self> {
        let pool_name = format!("ShadowLink\0");
        let adapter_name = format!("{}\0", name);
        
        use std::os::windows::ffi::OsStrExt;
        let pool_u16: Vec<u16> = std::ffi::OsStr::new(&pool_name).encode_wide().collect();
        let name_u16: Vec<u16> = std::ffi::OsStr::new(&adapter_name).encode_wide().collect();

        // Create Adapter
        let adapter = unsafe {
            (api.CreateAdapter)(
                pool_u16.as_ptr(),
                name_u16.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };

        if adapter.is_null() {
            return Err(anyhow!("Failed to create Wintun adapter. Make sure to run as Administrator!"));
        }

        // Capacity: 8MB
        let capacity = 8 * 1024 * 1024;
        let session = unsafe { (api.StartSession)(adapter, capacity) };

        if session.is_null() {
            return Err(anyhow!("Failed to start Wintun session"));
        }

        Ok(Self { api, adapter, session })
    }

    /// Spawns a background thread to read from Wintun and sends packets to an async channel
    pub fn start_reader(&self) -> mpsc::UnboundedReceiver<Vec<u8>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let api = Arc::clone(&self.api);
        let session_ptr = self.session as usize;

        std::thread::spawn(move || {
            let session = session_ptr as WINTUN_SESSION_HANDLE;
            let wait_event = unsafe { (api.GetReadWaitEvent)(session) };
            
            loop {
                // Wait for packet
                unsafe {
                    WaitForSingleObject(wait_event, INFINITE);
                }

                loop {
                    let mut packet_size = 0u32;
                    let packet_ptr = unsafe { (api.ReceivePacket)(session, &mut packet_size) };
                    
                    if packet_ptr.is_null() {
                        // No more packets, wait again
                        break;
                    }

                    let packet_data = unsafe { std::slice::from_raw_parts(packet_ptr, packet_size as usize) };
                    let data = packet_data.to_vec();

                    unsafe { (api.ReleaseReceivePacket)(session, packet_ptr) };

                    if tx.send(data).is_err() {
                        return; // Receiver closed
                    }
                }
            }
        });

        rx
    }

    /// Synchronously write a packet to the Wintun adapter
    pub fn write_packet(&self, data: &[u8]) -> Result<()> {
        let packet_ptr = unsafe { (self.api.AllocateSendPacket)(self.session, data.len() as u32) };
        if packet_ptr.is_null() {
            return Err(anyhow!("Failed to allocate send packet — Wintun ring full?"));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), packet_ptr, data.len());
            (self.api.SendPacket)(self.session, packet_ptr);
        }

        Ok(())
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        // End the session first (flushes the ring buffers), then free the adapter.
        // Both calls are no-ops if the handles are already null.
        if !self.session.is_null() {
            unsafe { (self.api.EndSession)(self.session) };
            self.session = std::ptr::null_mut();
        }
        if !self.adapter.is_null() {
            unsafe {
                (self.api.close_adapter)(self.adapter);
            }
            self.adapter = std::ptr::null_mut();
        }
    }
}
