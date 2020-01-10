mod sp_vkey;

use ra_common::tcp::tcp_accept;
use ra_enclave::EnclaveRaContext;
use crate::sp_vkey::SP_VKEY_PEM;

fn main() {
    let enclave_port = 1234;
    let mut client_stream = tcp_accept(enclave_port)
        .expect("Enclave: Client connection failed");
    eprintln!("Enclave: connected to client.");
    let context = EnclaveRaContext::init(SP_VKEY_PEM).unwrap();
    let (_secret_key, _mac_key) = context.do_attestation(&mut client_stream).unwrap();
    eprintln!("Enclave: done!");
}
