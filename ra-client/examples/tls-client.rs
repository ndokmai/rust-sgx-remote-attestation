use ra_client::ClientRaContext;
use ra_common::tcp::tcp_connect;
use std::time::Duration;

fn main() {
    let enclave_port = 7777;
    let sp_port = 1234;
    let localhost = "localhost";
    let timeout = Duration::from_secs(5);

    let mut enclave_stream =
        tcp_connect(localhost, enclave_port, timeout).expect("Client: Enclave connection failed");
    eprintln!("Client: connected to enclave.");

    let mut sp_stream =
        tcp_connect(localhost, sp_port, timeout).expect("Client: SP connection failed");
    eprintln!("Client: connected to SP.");

    let context = ClientRaContext::init().unwrap();
    context
        .do_attestation(&mut enclave_stream, &mut sp_stream)
        .unwrap();
    eprintln!("Client: done!");
}
