use eframe::egui;
use std::sync::{Arc, Mutex};
use crate::app::AppState;

pub fn show(ui: &mut egui::Ui, state: &Arc<Mutex<AppState>>) {
    let mut s = state.lock().unwrap();
    
    ui.horizontal(|ui| {
        ui.heading("Logs");
        if ui.button("Clear").clicked() { s.logs.clear(); }
        if ui.button("Copy All").clicked() {
            ui.output_mut(|o| o.copied_text = s.logs.join("\n"));
        }
    });
    ui.separator();
    
    egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
        for line in &s.logs {
            ui.add(egui::Label::new(egui::RichText::new(line).monospace().size(11.0)).wrap());
        }
        if s.logs.is_empty() {
            ui.colored_label(egui::Color32::GRAY, "No logs yet.");
        }
    });
}
