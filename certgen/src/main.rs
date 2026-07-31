fn main() { 
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap(); 
    std::fs::write("../test-cert.pem", cert.cert.pem()).unwrap(); 
    std::fs::write("../test-key.pem", cert.signing_key.serialize_pem()).unwrap(); 
}
