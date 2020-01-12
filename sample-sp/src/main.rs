use ra_sp::{SpRaContext, SpConfig};
use ra_common::tcp::tcp_accept;

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
    let _result = context.do_attestation(&mut client_stream).unwrap();
    eprintln!("SP: done!");
}
