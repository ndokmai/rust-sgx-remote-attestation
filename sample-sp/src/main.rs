use std::io::Read;
use std::time::Duration;
use ra_sp::{SpRaContext, SpConfig};
use ra_common::tcp::{tcp_accept, tcp_connect};
use sgx_crypto::secure_channel::SecureChannel;

fn parse_config_file(path: &str) -> SpConfig {
    serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap()
}

fn main() {
    let client_port = 1234;
    let mut client_stream = tcp_accept(client_port)
        .expect("SP: Client connection failed");
    eprintln!("SP: connected to client.");
    let config = parse_config_file("data/settings.json");
    let context = SpRaContext::init(config).unwrap();
    let result = context.do_attestation(&mut client_stream).unwrap();

    // talk to enclave directly from now on
    let enclave_port = 1235;
    let localhost = "localhost";
    let timeout = Duration::from_secs(5);
    let enclave_stream = tcp_connect(localhost, enclave_port, timeout)
        .expect("SP: Enclave connection failed");

    // establish secure channel with enclave
    let mut secure_channel = SecureChannel::new(enclave_stream, &result.master_key);
    let mut msg = vec![0u8; 6];
    secure_channel.read_exact(&mut msg[..]).unwrap();
    eprintln!("SP: message from Enclave = \"{}\"", std::str::from_utf8(&msg[..]).unwrap());

    eprintln!("SP: done!");
}
