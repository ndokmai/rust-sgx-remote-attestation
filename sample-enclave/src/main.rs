mod sp_vkey;

use std::io::Write;
use ra_common::tcp::tcp_accept;
use ra_enclave::EnclaveRaContext;
use sgx_crypto::secure_channel::SecureChannel;
use crate::sp_vkey::SP_VKEY_PEM;

fn main() {
    let client_port = 7777;
    let mut client_stream = tcp_accept(client_port)
        .expect("Enclave: Client connection failed");
    eprintln!("Enclave: connected to client.");
    let context = EnclaveRaContext::init(SP_VKEY_PEM).unwrap();
    let (_signing_key, master_key) = 
        context.do_attestation(&mut client_stream).unwrap();

    // talk to SP directly from now on
    let sp_port = 1235;
    let sp_stream = tcp_accept(sp_port)
        .expect("Enclave: SP connection failed");

    // establish secure channel with enclave
    let mut secure_channel = SecureChannel::new(sp_stream, &master_key);
    secure_channel.write_all("Hello!".as_bytes()).unwrap();
    eprintln!("Enclave: done!");
}
