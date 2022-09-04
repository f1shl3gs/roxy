use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use rand::{thread_rng, Rng};
use resolver::Resolver;
use shadowsocks::{Address, ServerConfig, UdpSocketControlData};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::Message;
use trust_dns_proto::serialize::binary::BinEncodable;

pub struct Client {
    timeout: Duration,
    attempts: usize,
}

impl Client {
    pub async fn lookup(
        &self,
        svr: &ServerConfig,
        mut msg: Message,
    ) -> Result<Message, ProtoError> {
        let resolver = Resolver::system();

        msg.set_id(thread_rng().gen());

        let mut cli = shadowsocks::ProxySocket::connect(svr, &resolver)
            .await
            .expect("Connect to dns server");
        cli.set_timeouts(Some(Duration::from_secs(5)), Some(Duration::from_secs(5)));

        let remote = Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(8, 8, 8, 8),
            53,
        )));
        let n = cli
            .send(
                &remote,
                &msg.to_bytes().unwrap(),
                &UdpSocketControlData::default(),
            )
            .await
            .unwrap();

        println!("send {} bytes to {:?}", n, svr.addr());

        let mut recv_buf = [0u8; 256];
        let (n, _, _) = cli.recv(&mut recv_buf).await.unwrap();

        println!("recv {} bytes", n);

        Message::from_vec(&recv_buf)
    }
}
