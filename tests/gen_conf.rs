use shadowsocks::{Address, ServerConfig};
use std::io::BufRead;

#[test]
fn gen_ss_config() {
    let data = std::fs::read("sub2.txt").unwrap();
    let data = base64::decode(data).unwrap();

    for line in data.lines().flatten() {
        let sc = ServerConfig::from_url(&line).unwrap();

        println!("{{");
        match sc.addr() {
            Address::SocketAddress(socket) => {
                println!("address: \"{}\",", socket.ip());
                println!("port: {},", socket.port());
            }
            Address::DomainNameAddress(dn, port) => {
                println!("address: \"{}\",", dn);
                println!("port: {},", port);
            }
        }
        println!("password: \"{}\",", sc.password());
        println!("method: \"{}\"", sc.kind());
        println!("}}");
    }
}
