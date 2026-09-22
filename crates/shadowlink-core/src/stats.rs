use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::sync::Mutex;
use std::collections::VecDeque;

pub struct SessionStats {
    pub bytes_sent: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_recv: AtomicU64,
    connected_at: Instant,
    send_window: Mutex<VecDeque<(Instant, u64)>>,
    recv_window: Mutex<VecDeque<(Instant, u64)>>,
}

impl SessionStats {
    pub fn new() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_recv: AtomicU64::new(0),
            connected_at: Instant::now(),
            send_window: Mutex::new(VecDeque::new()),
            recv_window: Mutex::new(VecDeque::new()),
        }
    }
}

impl Default for SessionStats {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStats {

    pub fn record_send(&self, bytes: usize) {
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        if let Ok(mut w) = self.send_window.lock() {
            w.push_back((now, bytes as u64));
            let cutoff = now - std::time::Duration::from_secs(5);
            while w.front().map(|(t, _)| *t < cutoff).unwrap_or(false) { w.pop_front(); }
        }
    }

    pub fn record_recv(&self, bytes: usize) {
        self.bytes_recv.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_recv.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        if let Ok(mut w) = self.recv_window.lock() {
            w.push_back((now, bytes as u64));
            let cutoff = now - std::time::Duration::from_secs(5);
            while w.front().map(|(t, _)| *t < cutoff).unwrap_or(false) { w.pop_front(); }
        }
    }

    pub fn throughput_send_bps(&self) -> f64 {
        if let Ok(w) = self.send_window.lock() {
            let total: u64 = w.iter().map(|(_, b)| b).sum();
            // Use actual elapsed window span (capped at 5s) to avoid underreporting
            // during the first 5 seconds of a session.
            let window_secs = self.connected_at.elapsed().as_secs_f64().clamp(0.001, 5.0);
            total as f64 / window_secs
        } else {
            0.0
        }
    }

    pub fn throughput_recv_bps(&self) -> f64 {
        if let Ok(w) = self.recv_window.lock() {
            let total: u64 = w.iter().map(|(_, b)| b).sum();
            let window_secs = self.connected_at.elapsed().as_secs_f64().clamp(0.001, 5.0);
            total as f64 / window_secs
        } else {
            0.0
        }
    }

    pub fn duration(&self) -> std::time::Duration {
        self.connected_at.elapsed()
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn bytes_recv(&self) -> u64 {
        self.bytes_recv.load(Ordering::Relaxed)
    }
}
