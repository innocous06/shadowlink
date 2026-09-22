#[cfg(target_os = "android")]
pub mod android_ffi {
    use jni::objects::{JClass, JString};
    use jni::JNIEnv;
    use jni::sys::jint;
    use std::os::fd::{FromRawFd, RawFd};
    use tokio::io::unix::AsyncFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tracing::{info, error, debug};
    
    use crate::crypto::keys::KeyPair;
    use crate::protocol::handshake;
    use crate::protocol::session::EncryptedSession;
    use crate::proxy::dialer::{RawPacket, TunnelMessage};
    use crate::obfuscation::tls_camouflage;

    // The JNI function that Kotlin will call to start the VPN
    #[no_mangle]
    pub extern "system" fn Java_com_example_shadowlink_ShadowLinkVpnService_startTunnel<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass,
        server_ip_port: JString,
        tun_fd: jint,
        client_private_key_b64: JString,
        server_public_key_b64: JString,
    ) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        
        let server_addr: String = match env.get_string(&server_ip_port) {
            Ok(s) => s.into(),
            Err(e) => {
                error!("Failed to get server address string: {}", e);
                return;
            }
        };
        let client_priv_b64: String = match env.get_string(&client_private_key_b64) {
            Ok(s) => s.into(),
            Err(e) => {
                error!("Failed to get client private key string: {}", e);
                return;
            }
        };
        let server_pub_b64: String = match env.get_string(&server_public_key_b64) {
            Ok(s) => s.into(),
            Err(e) => {
                error!("Failed to get server public key string: {}", e);
                return;
            }
        };
        let fd = tun_fd as RawFd;

        rt.block_on(async {
            // Set TUN file descriptor to non-blocking
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }

            let async_fd = match AsyncFd::new(fd) {
                Ok(f) => Arc::new(f),
                Err(e) => {
                    error!("Failed to create AsyncFd from TUN: {}", e);
                    return;
                }
            };

            info!("Starting Android TUN Loop on fd {}", fd);

            use base64::Engine;
            let client_priv_bytes = match base64::engine::general_purpose::STANDARD.decode(&client_priv_b64) {
                Ok(b) => b,
                Err(e) => {
                    error!("Invalid base64 client key: {}", e);
                    return;
                }
            };
            let client_priv_arr: [u8; 32] = match client_priv_bytes.try_into() {
                Ok(b) => b,
                Err(_) => {
                    error!("Client private key must be 32 bytes");
                    return;
                }
            };
            let client_kp = KeyPair::from_secret_bytes(client_priv_arr);
            let server_pk = match KeyPair::parse_public_key(&server_pub_b64) {
                Ok(pk) => pk,
                Err(e) => {
                    error!("Invalid server public key: {}", e);
                    return;
                }
            };

            // Connect TCP to VPS
            let tcp_stream = match TcpStream::connect(&server_addr).await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to connect to VPS at {}: {}", server_addr, e);
                    return;
                }
            };
            let _ = tcp_stream.set_nodelay(true);

            // Derive SNI hostname from server address or fallback to decoy
            let sni_hostname = server_addr.split(':').next().unwrap_or("www.google.com");
            
            let mut root_cert_store = rustls::RootCertStore::empty();
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
            
            let mut tls_stream = match tls_camouflage::tls_connect(tcp_stream, &connector, sni_hostname).await {
                Ok(s) => s,
                Err(e) => {
                    error!("TLS connect failed: {}", e);
                    return;
                }
            };

            // Perform ShadowLink handshake
            let handshake_result = match handshake::client_handshake(&mut tls_stream, &client_kp, &server_pk).await {
                Ok(res) => res,
                Err(e) => {
                    error!("Handshake failed: {}", e);
                    return;
                }
            };

            let session = match EncryptedSession::new(tls_stream, handshake_result) {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to initialize encrypted session: {}", e);
                    return;
                }
            };
            let (mut session_read, mut session_write) = session.into_split();

            let (tun_tx, mut tun_rx) = mpsc::unbounded_channel::<Vec<u8>>();

            let async_fd_clone = async_fd.clone();
            tokio::spawn(async move {
                loop {
                    match session_read.recv().await {
                        Ok(Some(data)) => {
                            if let Ok(msg) = TunnelMessage::parse(&data) {
                                if let TunnelMessage::RawPacket(pkt) = msg {
                                    if let Ok(mut guard) = async_fd_clone.writable().await {
                                        let res = unsafe {
                                            libc::write(fd, pkt.data.as_ptr() as *const libc::c_void, pkt.data.len())
                                        };
                                        if res < 0 {
                                            debug!("Android TUN write error: errno {}", unsafe { *libc::__errno_location() });
                                        }
                                        guard.clear_ready();
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            break;
                        }
                        Err(e) => {
                            error!("Session read error: {}", e);
                            break;
                        }
                    }
                }
            });

            let fd_copy = fd;
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let mut guard = match async_fd.readable().await {
                        Ok(g) => g,
                        Err(e) => {
                            error!("AsyncFd readable error: {}", e);
                            break;
                        }
                    };
                    let n = unsafe {
                        libc::read(fd_copy, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                    };
                    if n > 0 {
                        let data = buf[..n as usize].to_vec();
                        if tun_tx.send(data).is_err() {
                            break;
                        }
                    } else if n < 0 {
                        debug!("Android TUN read error: errno {}", unsafe { *libc::__errno_location() });
                        break;
                    }
                    guard.clear_ready();
                }
            });

            while let Some(packet_data) = tun_rx.recv().await {
                let pkt = RawPacket { data: packet_data };
                let payload = pkt.to_bytes();
                if let Err(e) = session_write.send(&payload).await {
                    error!("Session write error: {}", e);
                    break;
                }
            }
        });
    }
}
