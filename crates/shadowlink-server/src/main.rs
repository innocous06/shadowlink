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
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};
use x25519_dalek::PublicKey;

use shadowlink_core::crypto::keys::KeyPair;
use shadowlink_core::obfuscation::probe_resist::ProbeResistHandler;
use shadowlink_core::obfuscation::tls_camouflage;
use shadowlink_core::protocol::handshake;
use shadowlink_core::proxy::dialer::{
    ClosePacket, ConnectReply, DataPacket, TunnelMessage, UdpPacket,
};
#[cfg(target_os = "linux")]
use shadowlink_core::proxy::dialer::RawPacket;
use shadowlink_core::proxy::socks5::TargetAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;

/// Token-bucket QoS rate limiter for bandwidth throttling per client
pub struct TokenBucket {
    rate_bytes_per_sec: u64,
    capacity_bytes: u64,
    tokens: AtomicI64,
    last_update: std::sync::Mutex<Instant>,
}

impl TokenBucket {
    pub fn new(rate_mbps: f64) -> Self {
        let rate_bytes_per_sec = (rate_mbps * 125_000.0).max(1024.0) as u64;
        let capacity_bytes = rate_bytes_per_sec.max(65536);
        Self {
            rate_bytes_per_sec,
            capacity_bytes,
            tokens: AtomicI64::new(capacity_bytes as i64),
            last_update: std::sync::Mutex::new(Instant::now()),
        }
    }

    pub async fn acquire(&self, bytes: usize) {
        let bytes = bytes as i64;
        loop {
            {
                let mut last = self.last_update.lock().unwrap();
                let now = Instant::now();
                let elapsed = now.duration_since(*last).as_secs_f64();
                if elapsed > 0.001 {
                    let new_tokens = (elapsed * self.rate_bytes_per_sec as f64) as i64;
                    if new_tokens > 0 {
                        let cur = self.tokens.load(Ordering::Relaxed);
                        let updated = (cur + new_tokens).min(self.capacity_bytes as i64);
                        self.tokens.store(updated, Ordering::Relaxed);
                        *last = now;
                    }
                }
            }

            let cur = self.tokens.fetch_sub(bytes, Ordering::Relaxed);
            if cur >= bytes {
                return;
            }

            let deficit = bytes - cur;
            let wait_secs = (deficit as f64 / self.rate_bytes_per_sec as f64).min(2.0);
            tokio::time::sleep(std::time::Duration::from_secs_f64(wait_secs)).await;
        }
    }
}

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
    /// Active web-server reverse-proxy fallback (e.g. "127.0.0.1:80")
    pub fallback_addr: Option<String>,
    /// Per-client bandwidth rate limit in Mbps (e.g. 50.0)
    pub client_rate_limit_mbps: Option<f64>,
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
            fallback_addr: None,
            client_rate_limit_mbps: None,
        }
    }
}

/// Shared server state — Arc-cloned into every connection handler task.
struct ServerState {
    server_keypair: KeyPair,
    allowed_clients: Vec<PublicKey>,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    probe_handler: ProbeResistHandler,
    client_rate_limit_mbps: Option<f64>,

    /// The TUN device, created ONCE at server startup.
    /// Shared across all client sessions via Arc.
    /// On Linux only — None on other platforms or when TUN mode is disabled.
    #[cfg(target_os = "linux")]
    tun: Option<Arc<shadowlink_core::proxy::linux_tun::LinuxTun>>,

    /// The write channel to the currently-connected client.
    /// TUN reader task sends internet-reply RawPackets here.
    /// Replaced each time a new client connects (single-user VPN).
    #[cfg(target_os = "linux")]
    tun_client_tx: Arc<tokio::sync::Mutex<std::collections::HashMap<Ipv4Addr, tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>>,
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
        let custom_html = std::fs::read_to_string(html_path).ok();
        ProbeResistHandler::with_fallback(config.fallback_addr.clone(), custom_html)
    } else {
        ProbeResistHandler::with_fallback(config.fallback_addr.clone(), None)
    };

    // -------------------------------------------------------------------------
    // LAYER 3 TUN — created HERE at server startup, not per-session.
    // This means `shadowlink0` exists as soon as the server starts, so
    // ExecStartPost / ip commands can configure its IP address immediately.
    // -------------------------------------------------------------------------
    #[cfg(target_os = "linux")]
    let tun_client_tx: Arc<tokio::sync::Mutex<std::collections::HashMap<Ipv4Addr, tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

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
                        if pkt.len() < 20 { continue; } // too short for IPv4
                        let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                        let raw = RawPacket { data: pkt };
                        let bytes = raw.to_bytes();
                        let guard = tx_ref.lock().await;
                        if let Some(tx) = guard.get(&dst_ip) {
                            let _ = tx.send(bytes);
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
        client_rate_limit_mbps: config.client_rate_limit_mbps,
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

    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        handshake::server_handshake(&mut tls_stream, &state.server_keypair, &state.allowed_clients),
    ).await {
        Ok(Ok(session_keys)) => {
            info!("Authenticated client from {}", peer_addr);
            let session = shadowlink_core::protocol::session::EncryptedSession::new(tls_stream, session_keys)
                .context("Failed to create encrypted session")?;
            handle_proxy_session(session, peer_addr, state).await
        }
        Ok(Err(e)) => {
            warn!("Handshake failed from {} (serving fallback/decoy): {}", peer_addr, e);
            state.probe_handler.handle_unauthenticated(&mut tls_stream).await.context("Fallback/decoy failed")?;
            Ok(())
        }
        Err(_) => {
            warn!("Handshake timed out from {} (serving fallback/decoy)", peer_addr);
            let _ = state.probe_handler.handle_unauthenticated(&mut tls_stream).await;
            Err(anyhow::anyhow!("Handshake timed out from {}", peer_addr))
        }
    }
}

async fn handle_proxy_session<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    session: shadowlink_core::protocol::session::EncryptedSession<S>,
    peer_addr: SocketAddr,
    #[allow(unused_variables)]
    state: Arc<ServerState>,
) -> Result<()> {
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;
    use tokio::sync::Mutex;

    type ActiveUdpStreams = Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<(TargetAddr, Vec<u8>)>>>>;
    let (mut session_read, mut session_write) = session.into_split();
    let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let active_streams: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let active_udp_streams: ActiveUdpStreams =
        Arc::new(Mutex::new(HashMap::new()));

    let rate_limiter = state.client_rate_limit_mbps.map(|mbps| Arc::new(TokenBucket::new(mbps)));
    let write_limiter = rate_limiter.clone();
    let read_limiter = rate_limiter;

    #[allow(unused_mut, unused_variables)]
    let mut client_tun_ip: Option<Ipv4Addr> = None;

    // Tunnel writer task
    tokio::spawn(async move {
        while let Some(data) = write_rx.recv().await {
            if let Some(ref limiter) = write_limiter {
                limiter.acquire(data.len()).await;
            }
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

        if let Some(ref limiter) = read_limiter {
            limiter.acquire(data.len()).await;
        }

        let message = match TunnelMessage::parse(&data) {
            Ok(m) => m,
            Err(e) => { warn!("Invalid tunnel message from {}: {}", peer_addr, e); continue; }
        };

        match message {
            // ------------------------------------------------------------------
            // SOCKS5-style TCP streams
            // ------------------------------------------------------------------
            TunnelMessage::Connect(req) => {
                const MAX_STREAMS_PER_CLIENT: usize = 512;
                if active_streams.lock().await.len() >= MAX_STREAMS_PER_CLIENT {
                    warn!("Stream limit ({}) reached for client {}", MAX_STREAMS_PER_CLIENT, peer_addr);
                    let reply = ConnectReply {
                        stream_id: req.stream_id,
                        success: false,
                        error: Some("Stream limit reached".to_string()),
                    };
                    let _ = write_tx.send(reply.to_bytes());
                    continue;
                }

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

            TunnelMessage::Udp(pkt) => {
                let stream_id = pkt.stream_id;
                let target = pkt.target;
                let data = pkt.data;

                let tx = {
                    let mut streams = active_udp_streams.lock().await;
                    if let Some(tx) = streams.get(&stream_id) {
                        tx.clone()
                    } else {
                        match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                            Ok(sock) => {
                                let sock = Arc::new(sock);
                                let (utx, mut urx) = mpsc::unbounded_channel::<(TargetAddr, Vec<u8>)>();
                                streams.insert(stream_id, utx.clone());

                                let sock_send = Arc::clone(&sock);
                                let sock_recv = Arc::clone(&sock);
                                let write_tx_udp = write_tx.clone();
                                let udp_streams_c = Arc::clone(&active_udp_streams);

                                tokio::spawn(async move {
                                    while let Some((tgt, payload)) = urx.recv().await {
                                        match resolve_target_udp(&tgt).await {
                                            Ok(dest_addr) => {
                                                let _ = sock_send.send_to(&payload, dest_addr).await;
                                            }
                                            Err(e) => {
                                                debug!("Failed to resolve UDP target {}: {}", tgt.to_string_repr(), e);
                                            }
                                        }
                                    }
                                });

                                tokio::spawn(async move {
                                    let mut buf = [0u8; 65535];
                                    while let Ok(Ok((n, src_addr))) = tokio::time::timeout(
                                        std::time::Duration::from_secs(60),
                                        sock_recv.recv_from(&mut buf),
                                    ).await {
                                        let reply = UdpPacket {
                                            stream_id,
                                            target: TargetAddr::from(src_addr),
                                            data: buf[..n].to_vec(),
                                        };
                                        if write_tx_udp.send(TunnelMessage::Udp(reply).to_bytes()).is_err() {
                                            break;
                                        }
                                    }
                                    udp_streams_c.lock().await.remove(&stream_id);
                                });

                                utx
                            }
                            Err(e) => {
                                warn!("Failed to bind outbound UDP socket: {}", e);
                                continue;
                            }
                        }
                    }
                };

                let _ = tx.send((target, data));
            }

            TunnelMessage::Close(c) => {
                debug!("Close stream {}", c.stream_id);
                active_streams.lock().await.remove(&c.stream_id);
                active_udp_streams.lock().await.remove(&c.stream_id);
            }

            // ------------------------------------------------------------------
            // Layer 3 VPN: raw IP packet from client → write to Linux TUN
            // The kernel routes it to the internet via iptables MASQUERADE.
            // ------------------------------------------------------------------
            TunnelMessage::RawPacket(pkt) => {
                #[cfg(target_os = "linux")]
                if let Some(ref tun) = state.tun {
                    if pkt.data.len() >= 20 && client_tun_ip.is_none() {
                        let src_ip = Ipv4Addr::new(pkt.data[12], pkt.data[13], pkt.data[14], pkt.data[15]);
                        let mut guard = state.tun_client_tx.lock().await;
                        guard.insert(src_ip, write_tx.clone());
                        info!("Client registered at TUN IP: {}", src_ip);
                        client_tun_ip = Some(src_ip);
                    }
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
    if let Some(ip) = client_tun_ip {
        let mut guard = state.tun_client_tx.lock().await;
        guard.remove(&ip);
    }

    Ok(())
}

async fn resolve_target_udp(target: &TargetAddr) -> Result<SocketAddr> {
    match target {
        TargetAddr::Ipv4(ip, port) => Ok(SocketAddr::new((*ip).into(), *port)),
        TargetAddr::Ipv6(ip, port) => Ok(SocketAddr::new((*ip).into(), *port)),
        TargetAddr::Domain(d, p) => {
            let addr_str = format!("{}:{}", d, p);
            let mut addrs = tokio::net::lookup_host(&addr_str).await
                .context(format!("DNS lookup failed for {}", addr_str))?;
            addrs.next().ok_or_else(|| anyhow::anyhow!("No IP address found for {}", d))
        }
    }
}

async fn connect_to_target(target: &TargetAddr) -> Result<TcpStream> {
    let s = target.to_string_repr();
    let proxy_stream = match target {
        TargetAddr::Ipv4(ip, port) => TcpStream::connect((*ip, *port)).await.context(format!("Connect failed: {}", s))?,
        TargetAddr::Ipv6(ip, port) => TcpStream::connect((*ip, *port)).await.context(format!("Connect failed: {}", s))?,
        TargetAddr::Domain(d, p)   => TcpStream::connect(format!("{}:{}", d, p)).await.context(format!("Connect failed: {}", s))?,
    };

    let _ = proxy_stream.set_nodelay(true);
    Ok(proxy_stream)
}
