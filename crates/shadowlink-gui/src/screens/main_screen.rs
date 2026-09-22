use eframe::egui;
use std::sync::{Arc, Mutex};
use crate::app::{AppState, ConnectionStatus};

pub fn show(ui: &mut egui::Ui, state: &Arc<Mutex<AppState>>, _rt: &tokio::runtime::Handle) {
    let mut state_guard = state.lock().unwrap();

    let (status_text, status_color) = match &state_guard.status {
        ConnectionStatus::Disconnected => (
            "[ Disconnected ]".to_string(),
            egui::Color32::GRAY,
        ),
        ConnectionStatus::Connecting(s) => (
            format!("[ Connecting to {}... ]", s),
            egui::Color32::YELLOW,
        ),
        ConnectionStatus::Connected { server, since } => {
            let dur = since.elapsed();
            let h = dur.as_secs() / 3600;
            let m = (dur.as_secs() % 3600) / 60;
            let s_sec = dur.as_secs() % 60;
            (
                format!("[ Connected ] {} ({:02}:{:02}:{:02})", server, h, m, s_sec),
                egui::Color32::GREEN,
            )
        }
        ConnectionStatus::Error(e) => (
            format!("[ Error ] {}", e),
            egui::Color32::RED,
        ),
    };

    ui.add_space(8.0);
    ui.colored_label(status_color, &status_text);

    if let Some(ref stats) = state_guard.stats {
        ui.horizontal(|ui| {
            ui.label(format!("Up: {:.1} KB/s", stats.throughput_send_bps() / 1024.0));
            ui.separator();
            ui.label(format!("Dn: {:.1} KB/s", stats.throughput_recv_bps() / 1024.0));
        });
    }

    ui.separator();
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Server Selection").strong());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("⟳ Probe Ping").clicked() {
                crate::app::probe_all_servers(Arc::clone(state), _rt);
            }
        });
    });

    let mut selected = state_guard.selected_server_idx;
    egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
        for (i, profile) in state_guard.server_profiles.iter().enumerate() {
            let rtt_label = match profile.rtt_ms {
                Some(ms) => format!("{} ms", ms),
                None => if profile.online { "0 ms".to_string() } else { "-- ms".to_string() },
            };
            let row_text = format!("{:<22} {:>8}", profile.name, rtt_label);
            let dot_color = if profile.online {
                egui::Color32::from_rgb(46, 204, 113)
            } else {
                egui::Color32::from_rgb(140, 140, 140)
            };
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 4.0, dot_color);
                if ui.selectable_label(i == selected, &row_text).clicked() {
                    selected = i;
                }
            });
        }
    });
    state_guard.selected_server_idx = selected;

    ui.separator();
    ui.horizontal(|ui| {
        ui.label("Mode:");
        let vpn_mode = state_guard.config.mode == "vpn";
        if ui.radio(!vpn_mode, "SOCKS5 Proxy").clicked() {
            state_guard.config.mode = "socks5".to_string();
        }
        if ui.radio(vpn_mode, "Full VPN").clicked() {
            state_guard.config.mode = "vpn".to_string();
        }
    });

    if state_guard.config.mode == "vpn" {
        ui.horizontal(|ui| {
            ui.label("Kill Switch:");
            ui.checkbox(&mut state_guard.config.kill_switch, "Block traffic on disconnect");
        });
    }

    ui.add_space(8.0);

    let is_connected = matches!(state_guard.status, ConnectionStatus::Connected { .. });
    let is_connecting = matches!(state_guard.status, ConnectionStatus::Connecting(_));

    if is_connected || is_connecting {
        if ui.add_sized([180.0, 36.0], egui::Button::new(
            egui::RichText::new("Disconnect").color(egui::Color32::WHITE)
        ).fill(egui::Color32::from_rgb(180, 40, 40))).clicked() {
            state_guard.status = ConnectionStatus::Disconnected;
            state_guard.stats = None;
        }
    } else {
        if ui.add_sized([180.0, 36.0], egui::Button::new(
            egui::RichText::new("Connect").color(egui::Color32::WHITE)
        ).fill(egui::Color32::from_rgb(30, 130, 90))).clicked() {
            if let Some(profile) = state_guard.server_profiles.get(state_guard.selected_server_idx) {
                let s_name = profile.name.clone();
                let s_addr = profile.addr.clone();
                state_guard.status = ConnectionStatus::Connecting(s_name.clone());
                
                let state_clone = Arc::clone(state);
                _rt.spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    if let Ok(mut g) = state_clone.lock() {
                        g.status = ConnectionStatus::Connected {
                            server: format!("{} ({})", s_name, s_addr),
                            since: std::time::Instant::now(),
                        };
                    }
                });
            }
        }
    }
}