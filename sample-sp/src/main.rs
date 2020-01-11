use ra_sp::{SpRaContext, SpConfig};
use ra_common::tcp::tcp_accept;

type AsyncResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn parse_config_file(path: &str) -> SpConfig {
    serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap()
}

#[tokio::main]
async fn main() -> AsyncResult<()> {
    let client_port = 1235;
    let mut client_stream = tcp_accept(client_port)
        .expect("SP: Client connection failed");
    eprintln!("SP: connected to client.");
    let config = parse_config_file("data/settings.json");
    let context = SpRaContext::init(&config).unwrap();
    let (_secret_key, _mac_key) = context.do_attestation(&mut client_stream).await?;
    eprintln!("SP: done!");
    Ok(())
}
