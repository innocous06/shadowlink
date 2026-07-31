//! # ShadowLink Server
//!
//! The exit node that runs on your VPS.
//! Accepts authenticated ShadowLink connections and proxies traffic to the internet.
//!
//! ## Architecture
//! - TLS 1.3 listener on port 443 (looks like HTTPS to DPI)
//! - Probe-resistant: serves a decoy website to unauthorized connections
//! - Client authentication via Curve25519 public key whitelist
//! - Layer 3 VPN: TUN device created at startup so the interface exists immediately,
//!   allowing ExecStartPost to configure IP/routes before any client connects.
//!   RawPackets from the client are written to the TUN fd; replies from the
//!   internet flow back to whichever client is currently connected.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};
use x25519_dalek::PublicKey;

use shadowlink_core::crypto::keys::KeyPair;
use shadowlink_core::obfuscation::probe_resist::ProbeResistHandler;
use shadowlink_core::obfuscation::tls_camouflage;
use shadowlink_core::protocol::handshake;
use shadowlink_core::proxy::dialer::{
    ClosePacket, ConnectReply, DataPacket, TunnelMessage,
};
#[cfg(target_os = "linux")]
use shadowlink_core::proxy::dialer::RawPacket;
use shadowlink_core::proxy::socks5::TargetAddr;

/// Server configuration (TOML)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub server_key_path: String,
    pub server_key_passphrase: Option<String>,
    pub allowed_clients: Vec<String>,
    pub decoy_html_path: Option<String>,
    pub enable_logging: bool,
    pub dns_servers: Option<Vec<String>>,
    /// Enable Layer 3 TUN mode. Requires root / CAP_NET_ADMIN. Linux only.
    pub enable_tun_mode: bool,
    /// Name of the TUN interface (default: "shadowlink0")
    pub tun_interface_name: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".to_string(),
            tls_cert_path: "/etc/shadowlink/cert.pem".to_string(),
            tls_key_path: "/etc/shadowlink/key.pem".to_string(),
            server_key_path: "/etc/shadowlink/server.key.json".to_string(),
            server_key_passphrase: None,
            allowed_clients: vec![],
            decoy_html_path: None,
            enable_logging: true,
            dns_servers: None,
            enable_tun_mode: true,
            tun_interface_name: "shadowlink0".to_string(),
        }
    }
}

/// Shared server state — Arc-cloned into every connection handler task.
struct ServerState {
    server_keypair: KeyPair,
    allowed_clients: Vec<PublicKey>,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    probe_handler: ProbeResistHandler,

    /// The TUN device, created ONCE at server startup.
    /// Shared across all client sessions via Arc.
    /// On Linux only — None on other platforms or when TUN mode is disabled.
    #[cfg(target_os = "linux")]
    tun: Option<Arc<shadowlink_core::proxy::linux_tun::LinuxTun>>,

    /// The write channel to the currently-connected client.
    /// TUN reader task sends internet-reply RawPackets here.
    /// Replaced each time a new client connects (single-user VPN).
    #[cfg(target_os = "linux")]
    tun_client_tx: Arc<std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    let config: ServerConfig = if std::path::Path::new(&config_path).exists() {
        let s = std::fs::read_to_string(&config_path).context("Failed to read config")?;
        toml::from_str(&s).context("Failed to parse config")?
    } else {
        let default = ServerConfig::default();
        std::fs::write(&config_path, toml::to_string_pretty(&default)?)?;
        eprintln!("Generated default config at: {}", config_path);
        eprintln!("Please edit the config and restart.");
        std::process::exit(1);
    };

    if config.enable_logging {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("shadowlink=info".parse().unwrap()),
            )
            .init();
    }

    info!("ShadowLink Server starting...");

    let passphrase = if let Some(ref p) = config.server_key_passphrase {
        p.clone()
    } else if let Ok(p) = std::env::var("SHADOWLINK_KEY_PASSPHRASE") {
        p
    } else {
        eprintln!("ERROR: No key passphrase. Set server_key_passphrase in config or SHADOWLINK_KEY_PASSPHRASE env var.");
        std::process::exit(1);
    };

    let key_file = shadowlink_core::crypto::keys::EncryptedKeyFile::load_from_file(
        std::path::Path::new(&config.server_key_path),
    ).context("Failed to load server key file")?;

    let server_keypair = KeyPair::import_encrypted(&key_file, passphrase.as_bytes())
        .context("Failed to decrypt server key — wrong passphrase?")?;

    info!("Server public key: {}", server_keypair.public_key_base64());

    let allowed_clients: Vec<PublicKey> = config
        .allowed_clients.iter()
        .map(|b64| KeyPair::parse_public_key(b64))
        .collect::<Result<Vec<_>>>()
        .context("Failed to parse allowed client keys")?;

    info!("{} authorized client(s) configured", allowed_clients.len());

    let cert_pem = std::fs::read(&config.tls_cert_path).context("Failed to read TLS cert")?;
    let key_pem  = std::fs::read(&config.tls_key_path).context("Failed to read TLS key")?;
    let tls_acceptor = tls_camouflage::create_server_tls_config(&cert_pem, &key_pem)
        .context("Failed to create TLS config")?;

    let probe_handler = if let Some(ref html_path) = config.decoy_html_path {
        ProbeResistHandler::with_custom_html(std::fs::read_to_string(html_path)?)
    } else {
        ProbeResistHandler::new()
    };

    // -------------------------------------------------------------------------
    // LAYER 3 TUN — created HERE at server startup, not per-session.
    // This means `shadowlink0` exists as soon as the server starts, so
    // ExecStartPost / ip commands can configure its IP address immediately.
    // -------------------------------------------------------------------------
    #[cfg(target_os = "linux")]
    let tun_client_tx: Arc<std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>> =
        Arc::new(std::sync::Mutex::new(None));

    #[cfg(target_os = "linux")]
    let tun: Option<Arc<shadowlink_core::proxy::linux_tun::LinuxTun>> = if config.enable_tun_mode {
        match shadowlink_core::proxy::linux_tun::LinuxTun::new(&config.tun_interface_name) {
            Ok(t) => {
                info!("TUN interface '{}' created — ready for ip/route config", config.tun_interface_name);
                let tun_arc = Arc::new(t);

                // Spawn the TUN→Client reader loop.
                // It waits for IP packets from the internet and forwards them
                // to whichever client is currently connected (via tun_client_tx).
                let mut tun_rx = tun_arc.start_reader();
                let tx_ref = Arc::clone(&tun_client_tx);
                tokio::spawn(async move {
                    while let Some(pkt) = tun_rx.recv().await {
                        let raw = RawPacket { data: pkt };
                        let bytes = raw.to_bytes();
                        // Send to current client if one is connected
                        if let Ok(guard) = tx_ref.lock() {
                            if let Some(ref tx) = *guard {
                                let _ = tx.send(bytes);
                            }
                        }
                    }
                });

                Some(tun_arc)
            }
            Err(e) => {
                warn!("Failed to create TUN '{}': {}. TUN mode disabled — SOCKS5 only.", config.tun_interface_name, e);
                None
            }
        }
    } else {
        info!("Layer 3 TUN mode: DISABLED (SOCKS5 proxy mode only)");
        None
    };
    // -------------------------------------------------------------------------

    let state = Arc::new(ServerState {
        server_keypair,
        allowed_clients,
        tls_acceptor,
        probe_handler,
        #[cfg(target_os = "linux")]
        tun,
        #[cfg(target_os = "linux")]
        tun_client_tx,
    });

    let listen_addr: SocketAddr = config.listen_addr.parse().context("Invalid listen address")?;
    let listener = TcpListener::bind(listen_addr).await.context("Failed to bind")?;

    info!("Listening on {} (TLS + ShadowLink)", listen_addr);
    info!("Probe resistance: ACTIVE");

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok((stream, addr)) => (stream, addr),
            Err(e) => {
                error!("TCP accept failed: {}", e);
                continue;
            }
        };

        // Disable Nagle's algorithm to eliminate 500ms ping delays
        let _ = tcp_stream.set_nodelay(true);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(tcp_stream, peer_addr, state).await {
                debug!("Connection from {} ended: {}", peer_addr, e);
            }
        });
    }
}

async fn handle_connection(
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
) -> Result<()> {
    debug!("New connection from {}", peer_addr);

    let mut tls_stream = tls_camouflage::tls_accept(tcp_stream, &state.tls_acceptor)
        .await.context("TLS handshake failed")?;

    match handshake::server_handshake(&mut tls_stream, &state.server_keypair, &state.allowed_clients).await {
        Ok(session_keys) => {
            info!("Authenticated client from {}", peer_addr);
            let session = shadowlink_core::protocol::session::EncryptedSession::new(tls_stream, session_keys)
                .context("Failed to create encrypted session")?;
            handle_proxy_session(session, peer_addr, state).await
        }
        Err(e) => {
            warn!("Handshake failed from {} (serving decoy): {}", peer_addr, e);
            state.probe_handler.serve_decoy(&mut tls_stream).await.context("Decoy failed")?;
            Ok(())
        }
    }
}

async fn handle_proxy_session<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    session: shadowlink_core::protocol::session::EncryptedSession<S>,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
) -> Result<()> {
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;
    use tokio::sync::Mutex;

    let (mut session_read, mut session_write) = session.into_split();
    let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let active_streams: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Register this client as the TUN packet destination.
    // Internet replies will flow to this client's write_tx.
    #[cfg(target_os = "linux")]
    if state.tun.is_some() {
        if let Ok(mut guard) = state.tun_client_tx.lock() {
            *guard = Some(write_tx.clone());
            info!("Client {} registered as TUN destination", peer_addr);
        }
    }

    // Tunnel writer task
    tokio::spawn(async move {
        while let Some(data) = write_rx.recv().await {
            if session_write.send(&data).await.is_err() { break; }
        }
        let _ = session_write.close().await;
    });

    // Tunnel reader loop
    loop {
        let data = match session_read.recv().await {
            Ok(Some(d)) => d,
            Ok(None) => { info!("Client {} disconnected gracefully", peer_addr); break; }
            Err(e) => { debug!("Tunnel read error from {}: {}", peer_addr, e); break; }
        };

        let message = match TunnelMessage::parse(&data) {
            Ok(m) => m,
            Err(e) => { warn!("Invalid tunnel message from {}: {}", peer_addr, e); continue; }
        };

        match message {
            // ------------------------------------------------------------------
            // SOCKS5-style TCP streams
            // ------------------------------------------------------------------
            TunnelMessage::Connect(req) => {
                debug!("CONNECT stream {} → {}", req.stream_id, req.target.to_string_repr());
                let stream_id = req.stream_id;
                let target = req.target.clone();
                let write_tx_c = write_tx.clone();
                let streams_c = Arc::clone(&active_streams);

                tokio::spawn(async move {
                    match connect_to_target(&target).await {
                        Ok(ts) => {
                            let (mut tr, mut tw) = ts.into_split();
                            let (ttx, mut trx) = mpsc::unbounded_channel::<Vec<u8>>();
                            { streams_c.lock().await.insert(stream_id, ttx); }

                            let reply = ConnectReply { stream_id, success: true, error: None };
                            let _ = write_tx_c.send(reply.to_bytes());

                            let w = tokio::spawn(async move {
                                while let Some(d) = trx.recv().await {
                                    if tw.write_all(&d).await.is_err() { break; }
                                }
                            });
                            let wtx = write_tx_c.clone();
                            let r = tokio::spawn(async move {
                                let mut buf = [0u8; 8192];
                                loop {
                                    match tr.read(&mut buf).await {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            let pkt = DataPacket { stream_id, data: buf[..n].to_vec() };
                                            if wtx.send(pkt.to_bytes()).is_err() { break; }
                                        }
                                        Err(_) => break,
                                    }
                                }
                                let _ = wtx.send(ClosePacket { stream_id }.to_bytes());
                            });
                            let _ = tokio::join!(w, r);
                            streams_c.lock().await.remove(&stream_id);
                        }
                        Err(e) => {
                            let reply = ConnectReply { stream_id, success: false, error: Some(e.to_string()) };
                            let _ = write_tx_c.send(reply.to_bytes());
                        }
                    }
                });
            }

            TunnelMessage::Data(pkt) => {
                let streams = active_streams.lock().await;
                if let Some(tx) = streams.get(&pkt.stream_id) { let _ = tx.send(pkt.data); }
            }

            TunnelMessage::Close(c) => {
                debug!("Close stream {}", c.stream_id);
                active_streams.lock().await.remove(&c.stream_id);
            }

            // ------------------------------------------------------------------
            // Layer 3 VPN: raw IP packet from client → write to Linux TUN
            // The kernel routes it to the internet via iptables MASQUERADE.
            // ------------------------------------------------------------------
            TunnelMessage::RawPacket(pkt) => {
                #[cfg(target_os = "linux")]
                if let Some(ref tun) = state.tun {
                    if let Err(e) = tun.write_packet(&pkt.data) {
                        debug!("TUN write error: {}", e);
                    }
                }
                #[cfg(not(target_os = "linux"))]
                let _ = pkt;
            }

            TunnelMessage::ConnectReply(_) => {
                warn!("Unexpected ConnectReply from client");
            }
        }
    }

    // Deregister client as TUN destination when they disconnect
    #[cfg(target_os = "linux")]
    if state.tun.is_some() {
        if let Ok(mut guard) = state.tun_client_tx.lock() {
            *guard = None;
        }
    }

    Ok(())
}

async fn connect_to_target(target: &TargetAddr) -> Result<TcpStream> {
    let s = target.to_string_repr();
    let mut proxy_stream = match target {
        TargetAddr::Ipv4(ip, port) => TcpStream::connect((*ip, *port)).await.context(format!("Connect failed: {}", s))?,
        TargetAddr::Ipv6(ip, port) => TcpStream::connect((*ip, *port)).await.context(format!("Connect failed: {}", s))?,
        TargetAddr::Domain(d, p)   => TcpStream::connect(format!("{}:{}", d, p)).await.context(format!("Connect failed: {}", s))?,
    };

    let _ = proxy_stream.set_nodelay(true);
    Ok(proxy_stream)
}
