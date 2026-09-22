use eframe::egui;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use shadowlink_core::stats::SessionStats;

pub enum Screen { Main, Settings, Logs }

#[derive(Clone, PartialEq)]
#[allow(dead_code)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting(String),
    Connected { server: String, since: Instant },
    Error(String),
}

pub struct AppState {
    pub status: ConnectionStatus,
    pub server_profiles: Vec<ServerProfileEntry>,
    pub selected_server_idx: usize,
    pub stats: Option<Arc<SessionStats>>,
    pub logs: Vec<String>,
    pub config: AppConfig,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerProfileEntry {
    pub name: String,
    pub addr: String,
    #[serde(skip)]
    pub rtt_ms: Option<u64>,
    #[serde(skip)]
    pub online: bool,
}

fn default_servers() -> Vec<ServerProfileEntry> {
    vec![
        ServerProfileEntry {
            name: "Primary Gateway".to_string(),
            addr: "127.0.0.1:8443".to_string(),
            rtt_ms: None,
            online: false,
        },
        ServerProfileEntry {
            name: "OCI Mumbai (Asia)".to_string(),
            addr: "10.0.0.1:443".to_string(),
            rtt_ms: None,
            online: false,
        },
        ServerProfileEntry {
            name: "AWS Frankfurt (EU)".to_string(),
            addr: "10.0.0.2:443".to_string(),
            rtt_ms: None,
            online: false,
        },
    ]
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct AppConfig {
    pub mode: String,
    pub kill_switch: bool,
    pub auto_reconnect: bool,
    pub keepalive_secs: u64,
    pub bypass_cidrs: String,
    #[serde(default = "default_servers")]
    pub servers: Vec<ServerProfileEntry>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            mode: "socks5".to_string(),
            kill_switch: false,
            auto_reconnect: true,
            keepalive_secs: 25,
            bypass_cidrs: "192.168.0.0/16\n10.0.0.0/8\n172.16.0.0/12".to_string(),
            servers: default_servers(),
        }
    }
}

pub struct ShadowLinkApp {
    pub current_screen: Screen,
    pub state: Arc<Mutex<AppState>>,
    pub rt: tokio::runtime::Handle,
}

impl ShadowLinkApp {
    pub fn new(_cc: &eframe::CreationContext) -> Self {
        let config = load_config_from_disk().unwrap_or_default();
        let profiles = config.servers.clone();
        let state = Arc::new(Mutex::new(AppState {
            status: ConnectionStatus::Disconnected,
            server_profiles: profiles,
            selected_server_idx: 0,
            stats: None,
            logs: Vec::new(),
            config,
        }));
        
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = rt.handle().clone();
        std::thread::spawn(move || rt.block_on(async { std::future::pending::<()>().await }));
        
        // Spawn async background latency probes on start
        probe_all_servers(Arc::clone(&state), &handle);

        Self { current_screen: Screen::Main, state, rt: handle }
    }
}

pub fn probe_all_servers(state: Arc<Mutex<AppState>>, rt: &tokio::runtime::Handle) {
    let profiles: Vec<(usize, String)> = {
        if let Ok(guard) = state.lock() {
            guard.server_profiles
                .iter()
                .enumerate()
                .map(|(i, p)| (i, p.addr.clone()))
                .collect()
        } else {
            return;
        }
    };

    for (idx, addr) in profiles {
        let state_clone = Arc::clone(&state);
        rt.spawn(async move {
            let start = Instant::now();
            let connect_res = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                tokio::net::TcpStream::connect(&addr),
            ).await;

            let (online, rtt_ms) = match connect_res {
                Ok(Ok(_stream)) => {
                    let rtt = start.elapsed().as_millis() as u64;
                    (true, Some(rtt))
                }
                _ => (false, None),
            };

            if let Ok(mut guard) = state_clone.lock() {
                if idx < guard.server_profiles.len() {
                    guard.server_profiles[idx].online = online;
                    guard.server_profiles[idx].rtt_ms = rtt_ms;
                }
            }
        });
    }
}

fn load_config_from_disk() -> Option<AppConfig> {
    if let Some(cfg_dir) = dirs_next::config_dir() {
        let path = cfg_dir.join("shadowlink").join("gui-config.toml");
        if let Ok(s) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str::<AppConfig>(&s) {
                return Some(cfg);
            }
        }
    }
    // Fallback: check if client-config.toml exists in working directory
    if let Ok(s) = std::fs::read_to_string("client-config.toml") {
        if let Ok(toml_val) = s.parse::<toml::Value>() {
            let mut cfg = AppConfig::default();
            if let Some(servers) = toml_val.get("servers").and_then(|v| v.as_array()) {
                let mut imported = Vec::new();
                for s_entry in servers {
                    if let (Some(name), Some(addr)) = (
                        s_entry.get("name").and_then(|v| v.as_str()),
                        s_entry.get("server_addr").and_then(|v| v.as_str()),
                    ) {
                        imported.push(ServerProfileEntry {
                            name: name.to_string(),
                            addr: addr.to_string(),
                            rtt_ms: None,
                            online: false,
                        });
                    }
                }
                if !imported.is_empty() {
                    cfg.servers = imported;
                }
            } else if let Some(addr) = toml_val.get("server_addr").and_then(|v| v.as_str()) {
                cfg.servers = vec![ServerProfileEntry {
                    name: "Configured Server".to_string(),
                    addr: addr.to_string(),
                    rtt_ms: None,
                    online: false,
                }];
            }
            return Some(cfg);
        }
    }
    None
}

impl eframe::App for ShadowLinkApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("⚡ ShadowLink");
                ui.separator();
                if ui.selectable_label(matches!(self.current_screen, Screen::Main), "Home").clicked() {
                    self.current_screen = Screen::Main;
                }
                if ui.selectable_label(matches!(self.current_screen, Screen::Settings), "⚙ Settings").clicked() {
                    self.current_screen = Screen::Settings;
                }
                if ui.selectable_label(matches!(self.current_screen, Screen::Logs), "📜 Logs").clicked() {
                    self.current_screen = Screen::Logs;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new("v2.0.0").small().color(egui::Color32::GRAY));
                });
            });
        });
        
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_screen {
                Screen::Main => crate::screens::main_screen::show(ui, &self.state, &self.rt),
                Screen::Settings => crate::screens::settings_screen::show(ui, &self.state, &self.rt),
                Screen::Logs => crate::screens::logs_screen::show(ui, &self.state),
            }
        });
        
        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }
}
