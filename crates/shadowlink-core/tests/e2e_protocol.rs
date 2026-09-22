use shadowlink_core::{protocol::{handshake, session::EncryptedSession}, crypto::keys::KeyPair};
use tokio::io::duplex;

#[tokio::test]
async fn test_full_session_roundtrip() {
    let server_kp = KeyPair::generate();
    let client_kp = KeyPair::generate();
    let allowed = vec![*client_kp.public_key()];
    let server_pub = *server_kp.public_key();
    
    let (mut c_stream, mut s_stream) = duplex(65536);
    
    let c = tokio::spawn(async move {
        let hr = handshake::client_handshake(&mut c_stream, &client_kp, &server_pub).await.unwrap();
        let mut sess = EncryptedSession::new(c_stream, hr).unwrap();
        sess.send(b"hello from client").await.unwrap();
        let reply = sess.recv().await.unwrap().unwrap();
        assert_eq!(reply, b"hello from server");
        sess.close().await.unwrap();
    });
    
    let s = tokio::spawn(async move {
        let hr = handshake::server_handshake(&mut s_stream, &server_kp, &allowed).await.unwrap();
        let mut sess = EncryptedSession::new(s_stream, hr).unwrap();
        let msg = sess.recv().await.unwrap().unwrap();
        assert_eq!(msg, b"hello from client");
        sess.send(b"hello from server").await.unwrap();
        let _ = sess.recv().await;
    });
    
    c.await.unwrap();
    s.await.unwrap();
}
