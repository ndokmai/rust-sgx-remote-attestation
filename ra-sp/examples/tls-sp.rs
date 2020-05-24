use byteorder::{NetworkEndian, ReadBytesExt};
use ra_common::tcp::{tcp_accept, tcp_connect};
use ra_sp::{SpConfig, SpRaContext};
use sgx_crypto::random::{entropy_new, Rng};
use sgx_crypto::tls_psk::client;
use std::io::Read;
use std::time::Duration;

fn parse_config_file(path: &str) -> SpConfig {
    serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap()
}

fn main() {
    let client_port = 1234;
    let mut client_stream = tcp_accept(client_port).expect("SP: Client connection failed");
    eprintln!("SP: connected to client.");
    let config = parse_config_file("examples/data/settings.json");
    let mut entropy = entropy_new();
    let context = SpRaContext::init(config, &mut entropy).unwrap();
    let result = context.do_attestation(&mut client_stream).unwrap();

    // talk to enclave directly from now on
    let enclave_port = 1235;
    let localhost = "localhost";
    let timeout = Duration::from_secs(5);
    let mut enclave_stream =
        tcp_connect(localhost, enclave_port, timeout).expect("SP: Enclave connection failed");

    // establish TLS-PSK with enclave; SP is the client
    let mut rng = Rng::new(&mut entropy).unwrap();
    let config = client::config(&mut rng, &result.master_key).unwrap();
    let mut ctx = client::context(&config).unwrap();

    // begin secure communication
    let mut session = ctx.establish(&mut enclave_stream, None).unwrap();
    let len = session.read_u32::<NetworkEndian>().unwrap() as usize;
    let mut msg = vec![0u8; len];
    session.read_exact(&mut msg[..]).unwrap();
    let msg = std::str::from_utf8(msg.as_slice()).unwrap();
    let msg_ref = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Pellentesque non placerat risus, et lobortis quam. Mauris velit lorem, elementum id neque a, aliquet tempus turpis. Nam eu congue urna, in semper quam. Ut tristique gravida nunc nec feugiat. Proin tincidunt massa a arcu volutpat, sagittis dignissim velit convallis. Cras ac finibus lorem, nec congue felis. Pellentesque fermentum vitae ipsum sed gravida. Nulla consectetur sit amet erat a pellentesque. Donec non velit sem. Sed eu metus felis. Nullam efficitur consequat ante, ut commodo nisi pharetra consequat. Ut accumsan eget ligula laoreet dictum. Maecenas tristique porta convallis. Suspendisse tempor sodales velit, ac luctus urna varius eu. Ut ultrices urna vestibulum vestibulum euismod. Vivamus eu sapien urna.";
    assert_eq!(msg, msg_ref);
    eprintln!("SP: message from Enclave = \"{}\"", msg);
    eprintln!("SP: done!");
}
