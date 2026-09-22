#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
mod app;
mod screens;

fn main() -> Result<(), eframe::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()
            .add_directive("shadowlink=info".parse().unwrap()))
        .init();
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([500.0, 480.0])
            .with_min_inner_size([400.0, 380.0])
            .with_title("ShadowLink")
            .with_icon(load_icon()),
        ..Default::default()
    };
    
    eframe::run_native(
        "ShadowLink",
        options,
        Box::new(|cc| Ok(Box::new(app::ShadowLinkApp::new(cc)))),
    )
}

fn load_icon() -> egui::IconData {
    egui::IconData { rgba: vec![0u8; 16*16*4], width: 16, height: 16 }
}
