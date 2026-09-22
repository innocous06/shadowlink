use eframe::egui;
use std::sync::{Arc, Mutex};
use crate::app::AppState;

pub fn show(ui: &mut egui::Ui, state: &Arc<Mutex<AppState>>, rt: &tokio::runtime::Handle) {
    let mut s = state.lock().unwrap();
    
    ui.heading("Settings");
    ui.add_space(8.0);
    
    egui::Grid::new("settings_grid").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
        ui.label("Auto-reconnect:");
        ui.checkbox(&mut s.config.auto_reconnect, "Reconnect on disconnect");
        ui.end_row();
        
        ui.label("Keepalive interval:");
        ui.add(egui::DragValue::new(&mut s.config.keepalive_secs).range(5..=120).suffix(" s"));
        ui.end_row();
    });
    
    ui.add_space(8.0);
    ui.label("Split tunneling bypass CIDRs (one per line):");
    ui.add(egui::TextEdit::multiline(&mut s.config.bypass_cidrs).desired_width(f32::INFINITY).desired_rows(3));
    
    ui.add_space(12.0);
    ui.label(egui::RichText::new("Configured Server Profiles").strong());
    
    let mut to_remove = None;
    egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
        for (i, prof) in s.server_profiles.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(format!("• {} ({})", prof.name, prof.addr));
                if s.server_profiles.len() > 1 && ui.small_button("✕").clicked() {
                    to_remove = Some(i);
                }
            });
        }
    });

    if let Some(i) = to_remove {
        s.server_profiles.remove(i);
        if s.selected_server_idx >= s.server_profiles.len() {
            s.selected_server_idx = 0;
        }
    }

    ui.add_space(12.0);
    if ui.button("💾 Save Settings").clicked() {
        s.config.servers = s.server_profiles.clone();
        if let Ok(toml_str) = toml::to_string_pretty(&s.config) {
            if let Some(cfg_dir) = dirs_next::config_dir() {
                let dir = cfg_dir.join("shadowlink");
                let _ = std::fs::create_dir_all(&dir);
                let _ = std::fs::write(dir.join("gui-config.toml"), toml_str);
            }
        }
        crate::app::probe_all_servers(Arc::clone(state), rt);
    }
}
