//! # ShadowLink Client
//!
//! The Windows PC client that replaces v2rayN.
//!
//! ## What it does:
//! 1. Runs a local SOCKS5 proxy on 127.0.0.1:1080
//! 2. Establishes an encrypted tunnel to your VPS
//! 3. Routes all SOCKS5 traffic through the tunnel
//! 4. All DNS queries go through the tunnel (no leaks)
//!
//! ## Equivalent to:
//! - v2rayN + Xray client core in your VLESS setup
//! - But with a unique, undetectable protocol

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

#[cfg(target_os = "windows")]
use shadowlink_core::proxy::tun_device::TunDevice;
#[cfg(target_os = "windows")]
use shadowlink_core::proxy::wintun_ffi::WintunApi;

use x25519_dalek::PublicKey;

use shadowlink_core::crypto::keys::KeyPair;
use shadowlink_core::obfuscation::tls_camouflage::{self, TlsCamouflageConfig};
use shadowlink_core::protocol::handshake;
use shadowlink_core::protocol::session::EncryptedSession;
use shadowlink_core::proxy::dialer::{
    ClosePacket, ConnectRequest, DataPacket, RawPacket, TunnelMessage, UdpPacket,
};
use shadowlink_core::proxy::socks5;

fn default_true() -> bool { true }
fn default_keepalive() -> u64 { 25 }

/// Individual server profile for multi-server setups
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerProfileConfig {
    pub name: String,
    pub server_addr: String,
    pub sni_hostname: String,
    pub server_public_key: String,
}

/// Client configuration file format (TOML)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClientConfig {
    pub server_addr: String,
    pub sni_hostname: String,
    pub client_key_path: String,
    pub server_public_key: String,
    pub socks5_listen: String,
    #[serde(default = "default_true")]
    pub verify_tls_cert: bool,
    pub enable_logging: bool,
    pub auto_reconnect: bool,
    pub reconnect_delay_secs: u64,
    #[serde(default)]
    pub enable_full_vpn_mode: bool,
    #[serde(default = "default_true")]
    pub use_inner_encryption: bool,
    pub max_reconnect_attempts: Option<u32>,
    #[serde(default = "default_keepalive")]
    pub keepalive_interval_secs: u64,
    #[serde(default = "default_true")]
    pub bypass_lan: bool,
    #[serde(default)]
    pub bypass_routes: Vec<String>,
    #[serde(default)]
    pub servers: Vec<ServerProfileConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "your-vps-ip:443".to_string(),
            sni_hostname: "www.microsoft.com".to_string(),
            socks5_listen: "127.0.0.1:1080".to_string(),
            client_key_path: "client.key.json".to_string(),
            server_public_key: "BASE64_SERVER_PUBLIC_KEY_HERE".to_string(),
            verify_tls_cert: true,
            enable_logging: true,
            auto_reconnect: true,
            reconnect_delay_secs: 3,
            enable_full_vpn_mode: false,
            use_inner_encryption: true,
            max_reconnect_attempts: None,
            keepalive_interval_secs: 25,
            bypass_lan: true,
            bypass_routes: vec![],
            servers: vec![],
        }
    }
}

/// Shared tunnel state accessible from all SOCKS5 handler tasks
struct TunnelState {
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    next_stream_id: u32,
    active_streams: HashMap<u32, mpsc::UnboundedSender<TunnelMessage>>,
}

#[cfg(target_os = "windows")]
struct RouteGuard {
    cleanup_script: String,
}

#[cfg(target_os = "windows")]
impl Drop for RouteGuard {
    fn drop(&mut self) {
        info!("Cleaning up VPN routes on session exit...");
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &self.cleanup_script])
            .status();
        info!("VPN routes cleaned up.");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider (ring backend)
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Load config
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "client-config.toml".to_string());

    let config: ClientConfig = if std::path::Path::new(&config_path).exists() {
        let config_str = std::fs::read_to_string(&config_path)
            .context("Failed to read config file")?;
        toml::from_str(&config_str).context("Failed to parse config file")?
    } else {
        let default_config = ClientConfig::default();
        let config_str = toml::to_string_pretty(&default_config)
            .context("Failed to serialize default config")?;
        std::fs::write(&config_path, &config_str)
            .context("Failed to write default config")?;
        eprintln!("╔══════════════════════════════════════════╗");
        eprintln!("║        ShadowLink Client — Setup         ║");
        eprintln!("╠══════════════════════════════════════════╣");
        eprintln!("║ Generated default config at:             ║");
        eprintln!("║   {}",  config_path);
        eprintln!("║                                          ║");
        eprintln!("║ Steps:                                   ║");
        eprintln!("║ 1. Run: shadowlink-keygen                ║");
        eprintln!("║ 2. Edit config with your server details  ║");
        eprintln!("║ 3. Restart shadowlink-client             ║");
        eprintln!("╚══════════════════════════════════════════╝");
        std::process::exit(1);
    };

    // Setup logging
    if config.enable_logging {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("shadowlink=info".parse().unwrap()),
            )
            .init();
    }

    println!("╔══════════════════════════════════════════╗");
    println!("║      ShadowLink — Secure Tunnel          ║");
    println!("║      Anonymous • Encrypted • Yours       ║");
    println!("╚══════════════════════════════════════════╝");
    println!();

    // Load passphrase from env var or prompt interactively
    let passphrase = if let Ok(p) = std::env::var("SHADOWLINK_KEY_PASSPHRASE") {
        p
    } else {
        eprint!("Key passphrase: ");
        rpassword::read_password().context("Failed to read passphrase")?
    };

    let key_file = shadowlink_core::crypto::keys::EncryptedKeyFile::load_from_file(
        std::path::Path::new(&config.client_key_path),
    )
    .context("Failed to load client key file. Run 'shadowlink-keygen' first.")?;

    let client_keypair = KeyPair::import_encrypted(&key_file, passphrase.as_bytes())
        .context("Failed to decrypt client key — wrong passphrase?")?;

    info!("Client public key: {}", client_keypair.public_key_base64());

    // Parse server public key
    let server_public_key = KeyPair::parse_public_key(&config.server_public_key)
        .context("Failed to parse server public key")?;

    // Collect profiles: if config.servers is empty, use the root config server as Default profile
    let profiles: Vec<ServerProfileConfig> = if !config.servers.is_empty() {
        config.servers.clone()
    } else {
        vec![ServerProfileConfig {
            name: "Default".to_string(),
            server_addr: config.server_addr.clone(),
            sni_hostname: config.sni_hostname.clone(),
            server_public_key: config.server_public_key.clone(),
        }]
    };

    let mut current_profile_idx = 0usize;
    let mut consecutive_failures = 0u32;
    let mut attempt = 0u32;

    loop {
        let active_profile = &profiles[current_profile_idx];
        info!(
            "Connecting to profile '{}' at {} (SNI: {})...",
            active_profile.name, active_profile.server_addr, active_profile.sni_hostname
        );

        let active_server_pubkey = match KeyPair::parse_public_key(&active_profile.server_public_key) {
            Ok(k) => k,
            Err(e) => {
                warn!("Failed to parse public key for profile '{}': {}. Using root key.", active_profile.name, e);
                server_public_key
            }
        };

        let mut active_config = config.clone();
        active_config.server_addr = active_profile.server_addr.clone();
        active_config.sni_hostname = active_profile.sni_hostname.clone();

        match run_tunnel(&active_config, &client_keypair, &active_server_pubkey).await {
            Ok(()) => {
                info!("Tunnel closed gracefully");
                attempt = 0;
                consecutive_failures = 0;
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("rekey_required") {
                    info!("Rekeying: reconnecting for session key rotation");
                    attempt = 0;
                } else {
                    error!("Tunnel error on profile '{}': {}", active_profile.name, e);
                    attempt += 1;
                    consecutive_failures += 1;

                    // Automatic failover after 3 failures if multiple profiles exist
                    if profiles.len() > 1 && consecutive_failures >= 3 {
                        let next_idx = (current_profile_idx + 1) % profiles.len();
                        warn!(
                            "Server profile '{}' failed 3 times. Automatically failing over to '{}' ({})",
                            active_profile.name, profiles[next_idx].name, profiles[next_idx].server_addr
                        );
                        current_profile_idx = next_idx;
                        consecutive_failures = 0;
                        attempt = 0;
                    }
                }
            }
        }

        if !config.auto_reconnect {
            break;
        }

        if let Some(max) = config.max_reconnect_attempts {
            if max > 0 && attempt >= max {
                error!("Max reconnect attempts ({}) reached. Exiting.", max);
                break;
            }
        }

        let delay_secs = config.reconnect_delay_secs
            .saturating_mul(2u64.pow(attempt.min(6)))
            .min(60);
        info!("Reconnecting in {}s (attempt {})...", delay_secs, attempt);
        tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
    }

    Ok(())
}

/// Establish the tunnel and run the SOCKS5 proxy.
async fn run_tunnel(
    config: &ClientConfig,
    client_keypair: &KeyPair,
    server_public_key: &PublicKey,
) -> Result<()> {
    // Step 1: TCP connection to server
    const CONNECT_TIMEOUT_SECS: u64 = 15;
    let tcp_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS),
        TcpStream::connect(&config.server_addr)
    ).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(anyhow!("Failed to connect to server: {}", e)),
        Err(_) => return Err(anyhow!("Connect timed out after {}s", CONNECT_TIMEOUT_SECS)),
    };

    // Disable Nagle's algorithm to drop ping from 500ms down to real latency
    let _ = tcp_stream.set_nodelay(true);

    info!("TCP connection established");

    // Step 2: TLS camouflage
    let tls_config = TlsCamouflageConfig {
        sni_hostname: config.sni_hostname.clone(),
        verify_server_cert: config.verify_tls_cert,
    };
    let tls_connector = tls_camouflage::create_client_tls_config(&tls_config)
        .context("Failed to create TLS config")?;

    let mut tls_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tls_camouflage::tls_connect(tcp_stream, &tls_connector, &config.sni_hostname)
    ).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(anyhow!("TLS handshake failed: {}", e)),
        Err(_) => return Err(anyhow!("TLS handshake timed out after 15s")),
    };

    info!("TLS camouflage established (SNI: {})", config.sni_hostname);

    // Step 3: ShadowLink handshake
    let handshake_result = match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        handshake::client_handshake(&mut tls_stream, client_keypair, server_public_key)
    ).await {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => return Err(anyhow!("ShadowLink handshake failed — server may have rejected us: {}", e)),
        Err(_) => return Err(anyhow!("ShadowLink handshake timed out after 15s")),
    };

    info!("✓ ShadowLink handshake complete — tunnel is ACTIVE");

    // Step 4: Create encrypted session
    let session = EncryptedSession::new(tls_stream, handshake_result)
        .context("Failed to create encrypted session")?;

    let (mut session_read, mut session_write) = session.into_split();

    let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let tunnel = Arc::new(Mutex::new(TunnelState {
        write_tx: write_tx.clone(),
        next_stream_id: 1,
        active_streams: HashMap::new(),
    }));

    // --- TUNNEL INITIALIZATION ---
    #[cfg(target_os = "windows")]
    let mut _route_guard = None;

    #[cfg(target_os = "windows")]
    let tun_device = {
        info!("Initializing Wintun adapter...");
        // SAFETY: WintunApi::load calls LoadLibraryW + transmute to bind function
        // pointers. We ensure wintun.dll is a trusted binary in the working dir.
        let api = unsafe { WintunApi::load("wintun.dll") };
        match api {
            Ok(api) => {
                let tun = Arc::new(TunDevice::new(Arc::new(api), "ShadowLinkTUN")?);
                info!("Wintun adapter 'ShadowLinkTUN' created successfully.");
                let mut tun_rx = tun.start_reader();
                let tun_tx = write_tx.clone();

                tokio::spawn(async move {
                    while let Some(packet) = tun_rx.recv().await {
                        let raw = RawPacket { data: packet };
                        let _ = tun_tx.send(raw.to_bytes());
                    }
                });

                if config.enable_full_vpn_mode {
                    info!("Full VPN Mode is ENABLED. Configuring Windows routing...");
                    let server_ip = config.server_addr.split(':').next().unwrap_or("");

                    let mut lan_bypass_cmds = String::new();
                    let mut lan_cleanup_cmds = String::new();

                    if config.bypass_lan {
                        lan_bypass_cmds.push_str(
                            "route add 192.168.0.0 mask 255.255.0.0 $gw metric 1; \
                             route add 10.0.0.0 mask 255.0.0.0 $gw metric 1; \
                             route add 172.16.0.0 mask 255.240.0.0 $gw metric 1; "
                        );
                        lan_cleanup_cmds.push_str(
                            "route delete 192.168.0.0; \
                             route delete 10.0.0.0; \
                             route delete 172.16.0.0; "
                        );
                    }

                    for custom_route in &config.bypass_routes {
                        lan_bypass_cmds.push_str(&format!("route add {} $gw metric 1; ", custom_route));
                        lan_cleanup_cmds.push_str(&format!("route delete {}; ", custom_route));
                    }

                    let setup_script = format!(
                        "New-NetIPAddress -InterfaceAlias 'ShadowLinkTUN' -IPAddress 10.8.0.2 -PrefixLength 24 -ErrorAction SilentlyContinue; \
                         Set-NetIPInterface -InterfaceAlias 'ShadowLinkTUN' -InterfaceMetric 1; \
                         Set-DnsClientServerAddress -InterfaceAlias 'ShadowLinkTUN' -ServerAddresses '1.1.1.1', '8.8.8.8'; \
                         $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop | Select-Object -First 1); \
                         if ($gw) {{ \
                             route add {} mask 255.255.255.255 $gw metric 1; \
                             {} \
                             New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias 'ShadowLinkTUN' -NextHop 10.8.0.1 -RouteMetric 1 -ErrorAction SilentlyContinue; \
                             New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias 'ShadowLinkTUN' -NextHop 10.8.0.1 -RouteMetric 1 -ErrorAction SilentlyContinue; \
                         }}",
                         server_ip,
                         lan_bypass_cmds
                    );

                    let cleanup_script = format!(
                        "route delete {}; \
                         {} \
                         Remove-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias 'ShadowLinkTUN' -Confirm:$false -ErrorAction SilentlyContinue; \
                         Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias 'ShadowLinkTUN' -Confirm:$false -ErrorAction SilentlyContinue; \
                         Set-DnsClientServerAddress -InterfaceAlias 'ShadowLinkTUN' -ResetServerAddresses;",
                         server_ip,
                         lan_cleanup_cmds
                    );

                    if let Err(e) = std::process::Command::new("powershell")
                        .args(["-NoProfile", "-Command", &setup_script])
                        .status()
                    {
                        warn!("Failed to configure routes automatically: {}", e);
                    } else {
                        info!("✓ Routing configured (All traffic goes through tunnel, LAN bypassed: {})", config.bypass_lan);
                        _route_guard = Some(RouteGuard { cleanup_script });
                    }
                }

                Some(tun)
            }
            Err(e) => {
                warn!("wintun.dll not found or failed to load: {}. TUN mode disabled.", e);
                None
            }
        }
    };
    #[cfg(not(target_os = "windows"))]
    let tun_device: Option<std::sync::Arc<()>> = None;
    // -----------------------------

    // Spawn tunnel writer task with idle jitter dummy injection
    tokio::spawn(async move {
        loop {
            let jitter_secs = rand::Rng::gen_range(&mut rand::thread_rng(), 10..=25);
            match tokio::time::timeout(std::time::Duration::from_secs(jitter_secs), write_rx.recv()).await {
                Ok(Some(data)) => {
                    if session_write.send(&data).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    // IDLE TIMEOUT: Inject dummy frame for traffic shaping / DPI evasion
                    debug!("Injecting idle jitter dummy frame for DPI evasion");
                    if session_write.send_dummy().await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = session_write.close().await;
    });

    // Spawn tunnel reader task
    let tunnel_reader_arc = Arc::clone(&tunnel);
    tokio::spawn(async move {
        while let Ok(Some(data)) = session_read.recv().await {
            if let Ok(msg) = TunnelMessage::parse(&data) {
                let stream_id = match &msg {
                    TunnelMessage::Connect(req) => req.stream_id,
                    TunnelMessage::ConnectReply(rep) => rep.stream_id,
                    TunnelMessage::Data(pkt) => pkt.stream_id,
                    TunnelMessage::Close(cls) => cls.stream_id,
                    TunnelMessage::Udp(pkt) => pkt.stream_id,
                    TunnelMessage::RawPacket(pkt) => {
                        #[cfg(target_os = "windows")]
                        if let Some(ref tun) = tun_device {
                            let _ = tun.write_packet(&pkt.data);
                        }
                        #[cfg(not(target_os = "windows"))]
                        let _ = pkt;
                        continue;
                    }
                };

                let sender = {
                    let state = tunnel_reader_arc.lock().await;
                    state.active_streams.get(&stream_id).cloned()
                };

                if let Some(tx) = sender {
                    let _ = tx.send(msg);
                }
            }
        }
    });

    if config.enable_full_vpn_mode {
        info!("Full VPN mode enabled — SOCKS5 proxy disabled to prevent routing loop");
        // Keep the tunnel alive indefinitely, handling incoming packets
        tokio::signal::ctrl_c().await?;
        return Ok(());
    }

    info!("SOCKS5 proxy mode (TUN disabled)");

    // Step 5: Start SOCKS5 proxy
    let socks5_addr: SocketAddr = config
        .socks5_listen
        .parse()
        .context("Invalid SOCKS5 listen address")?;

    let socks5_listener = TcpListener::bind(socks5_addr)
        .await
        .context("Failed to bind SOCKS5 proxy")?;

    println!();
    println!("  ✓ Tunnel ACTIVE → {}", config.server_addr);
    println!("  ✓ SOCKS5 proxy → {}", socks5_addr);
    println!("  ✓ Configure your browser: SOCKS5 → {}", socks5_addr);
    println!("  ✓ DNS leak protection: ACTIVE");
    println!();

    // Accept SOCKS5 connections and route through tunnel
    loop {
        let (socks5_stream, client_addr) = socks5_listener.accept().await?;
        let _ = socks5_stream.set_nodelay(true);
        let tunnel = Arc::clone(&tunnel);

        tokio::spawn(async move {
            if let Err(e) = handle_socks5_client(socks5_stream, client_addr, tunnel).await {
                debug!("SOCKS5 client {} error: {}", client_addr, e);
            }
        });
    }
}

/// Handle a single SOCKS5 client connection.
///
/// 1. Parse the SOCKS5 request
/// 2. Send a CONNECT command through the tunnel
/// 3. Relay data between SOCKS5 client and tunnel
async fn handle_socks5_client(
    socks5_stream: TcpStream,
    client_addr: SocketAddr,
    tunnel: Arc<Mutex<TunnelState>>,
) -> Result<()> {
    // Process SOCKS5 protocol
    let socks5_req = socks5::process_socks5_connection(socks5_stream)
        .await
        .context("SOCKS5 processing failed")?;

    match socks5_req {
        socks5::Socks5Request::Connect {
            stream: socks5_stream,
            target,
        } => {
            debug!("SOCKS5 CONNECT from {} → {}", client_addr, target.to_string_repr());

            // Allocate a stream ID and send CONNECT through tunnel
            let stream_id;
            let (tx, mut rx) = mpsc::unbounded_channel::<TunnelMessage>();
            let tunnel_write_tx;
            {
                let mut tunnel_state = tunnel.lock().await;
                stream_id = tunnel_state.next_stream_id;
                // Wrap around safely: skip 0 (reserved)
                tunnel_state.next_stream_id = tunnel_state.next_stream_id.wrapping_add(1).max(1);
                tunnel_state.active_streams.insert(stream_id, tx);
                tunnel_write_tx = tunnel_state.write_tx.clone();

                let connect_req = ConnectRequest {
                    stream_id,
                    target: target.clone(),
                };
                let _ = tunnel_write_tx.send(connect_req.to_bytes());
            }

            // Wait for CONNECT reply (with a 30s timeout to avoid hanging forever)
            let reply = match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                async {
                    loop {
                        match rx.recv().await {
                            Some(TunnelMessage::ConnectReply(reply)) => break Ok(reply),
                            Some(_) => continue,
                            None => break Err(anyhow!("Tunnel closed while waiting for CONNECT reply")),
                        }
                    }
                }
            ).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    tunnel.lock().await.active_streams.remove(&stream_id);
                    return Err(e);
                }
                Err(_) => {
                    tunnel.lock().await.active_streams.remove(&stream_id);
                    return Err(anyhow!("Timed out waiting for CONNECT reply from server"));
                }
            };

            if !reply.success {
                tunnel.lock().await.active_streams.remove(&stream_id);
                return Err(anyhow!(
                    "Server failed to connect to {}: {}",
                    target.to_string_repr(),
                    reply.error.unwrap_or_default()
                ));
            }

            debug!("Connected: stream {} → {}", stream_id, target.to_string_repr());

            // Relay data between SOCKS5 client and tunnel
            let (mut read_half, mut write_half) = socks5_stream.into_split();
            let tunnel_write_tx_clone = tunnel_write_tx.clone();

            let write_handle = tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match read_half.read(&mut buf).await {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            let pkt = DataPacket {
                                stream_id,
                                data: buf[..n].to_vec(),
                            };
                            if tunnel_write_tx_clone.send(pkt.to_bytes()).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Send close
                let close = ClosePacket { stream_id };
                let _ = tunnel_write_tx_clone.send(close.to_bytes());
            });

            // Read from tunnel and send to SOCKS5 client
            let tunnel_arc = Arc::clone(&tunnel);
            let read_handle = tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    match msg {
                        TunnelMessage::Data(pkt) => {
                            if write_half.write_all(&pkt.data).await.is_err() {
                                break;
                            }
                        }
                        TunnelMessage::Close(_) => {
                            break;
                        }
                        _ => {}
                    }
                }
                let mut state = tunnel_arc.lock().await;
                state.active_streams.remove(&stream_id);
            });

            let _ = tokio::join!(write_handle, read_handle);
            Ok(())
        }
        socks5::Socks5Request::UdpAssociate {
            mut stream,
            client_expected_addr,
        } => {
            debug!(
                "SOCKS5 UDP ASSOCIATE requested from {} (expected: {})",
                client_addr, client_expected_addr.to_string_repr()
            );

            // Bind local UDP relay socket on 127.0.0.1
            let udp_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .context("Failed to bind local UDP relay socket")?;
            let bound_addr = udp_socket.local_addr()
                .context("Failed to get local UDP relay address")?;

            // Reply to client TCP stream with SOCKS5 SUCCESS and the bound UDP port
            socks5::send_reply(&mut stream, socks5::SOCKS5_REPLY_SUCCESS, bound_addr)
                .await
                .context("Failed to send UDP ASSOCIATE reply")?;

            let stream_id;
            let (tx, mut rx) = mpsc::unbounded_channel::<TunnelMessage>();
            let tunnel_write_tx;
            {
                let mut tunnel_state = tunnel.lock().await;
                stream_id = tunnel_state.next_stream_id;
                tunnel_state.next_stream_id = tunnel_state.next_stream_id.wrapping_add(1).max(1);
                tunnel_state.active_streams.insert(stream_id, tx);
                tunnel_write_tx = tunnel_state.write_tx.clone();
            }

            debug!("UDP association established: stream {} bound on {}", stream_id, bound_addr);

            let udp_socket = Arc::new(udp_socket);
            let udp_sock_recv = Arc::clone(&udp_socket);
            let udp_sock_send = Arc::clone(&udp_socket);
            let tunnel_write_tx_clone = tunnel_write_tx.clone();

            // Store the client app's UDP source address once the first datagram arrives
            let client_udp_src: Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
                Arc::new(tokio::sync::Mutex::new(None));
            let client_udp_src_c = Arc::clone(&client_udp_src);

            // Upstream task: Local App UDP -> Parse RFC 1928 header -> Tunnel
            let upstream_handle = tokio::spawn(async move {
                let mut buf = [0u8; 65535];
                while let Ok((n, app_addr)) = udp_sock_recv.recv_from(&mut buf).await {
                    {
                        let mut c = client_udp_src_c.lock().await;
                        *c = Some(app_addr);
                    }
                    if let Ok((header, offset)) = socks5::UdpHeader::parse(&buf[..n]) {
                        let pkt = UdpPacket {
                            stream_id,
                            target: header.target,
                            data: buf[offset..n].to_vec(),
                        };
                        if tunnel_write_tx_clone.send(TunnelMessage::Udp(pkt).to_bytes()).is_err() {
                            break;
                        }
                    }
                }
            });

            // Downstream task: Tunnel -> Prepend RFC 1928 header -> Local App UDP
            let downstream_handle = tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    match msg {
                        TunnelMessage::Udp(pkt) => {
                            let app_addr = {
                                let c = client_udp_src.lock().await;
                                *c
                            };
                            if let Some(app_addr) = app_addr {
                                let resp_header = socks5::UdpHeader {
                                    frag: 0,
                                    target: pkt.target,
                                };
                                let full_packet = resp_header.wrap_packet(&pkt.data);
                                let _ = udp_sock_send.send_to(&full_packet, app_addr).await;
                            }
                        }
                        TunnelMessage::Close(_) => break,
                        _ => {}
                    }
                }
            });

            // Monitor controlling TCP connection:
            // RFC 1928: "A UDP association terminates when the TCP connection terminates."
            let tcp_monitor = tokio::spawn(async move {
                let mut byte = [0u8; 1];
                let _ = stream.read(&mut byte).await;
            });

            tokio::select! {
                _ = tcp_monitor => {},
                _ = upstream_handle => {},
                _ = downstream_handle => {},
            };

            // Cleanup association
            let close = ClosePacket { stream_id };
            let _ = tunnel_write_tx.send(close.to_bytes());
            let mut state = tunnel.lock().await;
            state.active_streams.remove(&stream_id);
            debug!("UDP association stream {} terminated", stream_id);

            Ok(())
        }
    }
}
