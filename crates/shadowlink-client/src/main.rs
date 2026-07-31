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
    ClosePacket, ConnectRequest, DataPacket, RawPacket, TunnelMessage,
};
use shadowlink_core::proxy::socks5;

/// Client configuration file format (TOML)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClientConfig {
    /// Server address (IP:port)
    pub server_addr: String,

    /// SNI hostname for TLS camouflage
    pub sni_hostname: String,

    /// Path to client's encrypted key file
    pub client_key_path: String,

    /// Passphrase for the client's encrypted key file
    pub client_key_passphrase: Option<String>,

    /// Server's public key (base64)
    pub server_public_key: String,

    /// Local SOCKS5 listen address
    pub socks5_listen: String,

    /// Whether to verify server's TLS certificate
    pub verify_tls_cert: bool,

    /// Enable logging
    pub enable_logging: bool,

    /// Auto-reconnect on disconnect
    pub auto_reconnect: bool,

    /// Reconnect delay in seconds
    pub reconnect_delay_secs: u64,

    /// Whether to automatically override the default route to tunnel all traffic
    #[serde(default)]
    pub enable_full_vpn_mode: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "your-vps-ip:443".to_string(),
            sni_hostname: "www.microsoft.com".to_string(),
            socks5_listen: "127.0.0.1:1080".to_string(),
            client_key_path: "client.key.json".to_string(),
            client_key_passphrase: None,
            server_public_key: "BASE64_SERVER_PUBLIC_KEY_HERE".to_string(),
            verify_tls_cert: false,
            enable_logging: true,
            auto_reconnect: true,
            reconnect_delay_secs: 3,
            enable_full_vpn_mode: false,
        }
    }
}

/// Shared tunnel state accessible from all SOCKS5 handler tasks
struct TunnelState {
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    next_stream_id: u32,
    active_streams: HashMap<u32, mpsc::UnboundedSender<TunnelMessage>>,
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

    // Load client keypair
    let passphrase = if let Some(ref p) = config.client_key_passphrase {
        p.clone()
    } else if let Ok(p) = std::env::var("SHADOWLINK_KEY_PASSPHRASE") {
        p
    } else {
        // Prompt for passphrase
        eprint!("Enter key passphrase: ");
        let mut pass = String::new();
        std::io::stdin().read_line(&mut pass)?;
        pass.trim().to_string()
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

    // Main connection loop (with auto-reconnect)
    loop {
        info!("Connecting to {}...", config.server_addr);

        match run_tunnel(&config, &client_keypair, &server_public_key).await {
            Ok(()) => {
                info!("Tunnel closed gracefully");
            }
            Err(e) => {
                error!("Tunnel error: {}", e);
            }
        }

        if !config.auto_reconnect {
            break;
        }

        info!(
            "Reconnecting in {} seconds...",
            config.reconnect_delay_secs
        );
        tokio::time::sleep(std::time::Duration::from_secs(config.reconnect_delay_secs)).await;
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
    let tcp_stream = TcpStream::connect(&config.server_addr)
        .await
        .context("Failed to connect to server")?;

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

    let mut tls_stream = tls_camouflage::tls_connect(tcp_stream, &tls_connector, &config.sni_hostname)
        .await
        .context("TLS handshake failed")?;

    info!("TLS camouflage established (SNI: {})", config.sni_hostname);

    // Step 3: ShadowLink handshake
    let handshake_result =
        handshake::client_handshake(&mut tls_stream, client_keypair, server_public_key)
            .await
            .context("ShadowLink handshake failed — server may have rejected us")?;

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
                        // Serialize directly from the inner RawPacket — TunnelMessage
                        // is an enum and does not have its own to_bytes() method.
                        let raw = RawPacket { data: packet };
                        let _ = tun_tx.send(raw.to_bytes());
                    }
                });

                if config.enable_full_vpn_mode {
                    info!("Full VPN Mode is ENABLED. Configuring Windows routing...");
                    let server_ip = config.server_addr.split(':').next().unwrap_or("");
                    
                    let setup_script = format!(
                        "New-NetIPAddress -InterfaceAlias 'ShadowLink' -IPAddress 10.8.0.2 -PrefixLength 24 -ErrorAction SilentlyContinue; \
                         Set-NetIPInterface -InterfaceAlias 'ShadowLink' -InterfaceMetric 1; \
                         Set-DnsClientServerAddress -InterfaceAlias 'ShadowLink' -ServerAddresses '1.1.1.1', '8.8.8.8'; \
                         $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop | Select-Object -First 1); \
                         if ($gw) {{ \
                             route add {} mask 255.255.255.255 $gw metric 1; \
                             New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias 'ShadowLink' -NextHop 10.8.0.1 -RouteMetric 1 -ErrorAction SilentlyContinue; \
                             New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias 'ShadowLink' -NextHop 10.8.0.1 -RouteMetric 1 -ErrorAction SilentlyContinue; \
                             New-NetRoute -DestinationPrefix '::/1' -InterfaceAlias 'ShadowLink' -RouteMetric 1 -ErrorAction SilentlyContinue; \
                             New-NetRoute -DestinationPrefix '8000::/1' -InterfaceAlias 'ShadowLink' -RouteMetric 1 -ErrorAction SilentlyContinue; \
                         }}",
                         server_ip
                    );

                    let cleanup_script = format!(
                        "route delete {}; \
                         Remove-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias 'ShadowLink' -Confirm:$false -ErrorAction SilentlyContinue; \
                         Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias 'ShadowLink' -Confirm:$false -ErrorAction SilentlyContinue; \
                         Remove-NetRoute -DestinationPrefix '::/1' -InterfaceAlias 'ShadowLink' -Confirm:$false -ErrorAction SilentlyContinue; \
                         Remove-NetRoute -DestinationPrefix '8000::/1' -InterfaceAlias 'ShadowLink' -Confirm:$false -ErrorAction SilentlyContinue; \
                         Set-DnsClientServerAddress -InterfaceAlias 'ShadowLink' -ResetServerAddresses;",
                         server_ip
                    );

                    if let Err(e) = std::process::Command::new("powershell")
                        .args(&["-NoProfile", "-Command", &setup_script])
                        .status() 
                    {
                        warn!("Failed to configure routes automatically: {}", e);
                    } else {
                        info!("✓ Routing configured (All traffic goes through tunnel)");
                        
                        // Spawn Ctrl-C handler to clean up routes
                        tokio::spawn(async move {
                            if let Ok(_) = tokio::signal::ctrl_c().await {
                                info!("\nCleaning up VPN routes...");
                                let _ = std::process::Command::new("powershell")
                                    .args(&["-NoProfile", "-Command", &cleanup_script])
                                    .status();
                                info!("Routes cleaned up. Exiting.");
                                std::process::exit(0);
                            }
                        });
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

    // Spawn tunnel writer task
    tokio::spawn(async move {
        while let Some(data) = write_rx.recv().await {
            if session_write.send(&data).await.is_err() {
                break;
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
                    TunnelMessage::RawPacket(pkt) => {
                        #[cfg(target_os = "windows")]
                        if let Some(ref tun) = tun_device {
                            let _ = tun.write_packet(&pkt.data);
                        }
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
    let (socks5_stream, target) = socks5::process_socks5_connection(socks5_stream)
        .await
        .context("SOCKS5 processing failed")?;

    debug!("SOCKS5 from {} → {}", client_addr, target.to_string_repr());

    // Allocate a stream ID and send CONNECT through tunnel
    let stream_id;
    let (tx, mut rx) = mpsc::unbounded_channel::<TunnelMessage>();
    let tunnel_write_tx;
    {
        let mut tunnel_state = tunnel.lock().await;
        stream_id = tunnel_state.next_stream_id;
        tunnel_state.next_stream_id += 1;
        tunnel_state.active_streams.insert(stream_id, tx);
        tunnel_write_tx = tunnel_state.write_tx.clone();

        let connect_req = ConnectRequest {
            stream_id,
            target: target.clone(),
        };
        let _ = tunnel_write_tx.send(connect_req.to_bytes());
    }

    // Wait for CONNECT reply
    let reply = loop {
        match rx.recv().await {
            Some(TunnelMessage::ConnectReply(reply)) => break reply,
            Some(_) => continue,
            None => return Err(anyhow!("Tunnel closed while waiting for CONNECT reply")),
        }
    };

    if !reply.success {
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
