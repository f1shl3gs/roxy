use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use byte_string::ByteStr;
use resolver::Resolver;
use shadowsocks::UdpSocketControlData;
use shadowsocks::{Address, ConnectOpts, ProxyStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time;
use tokio::time::Instant;

use crate::upstream::balancer::Server;

#[derive(Debug)]
pub enum CheckType {
    Tcp,
    Udp,
}

pub struct Checker {
    server: Arc<Server>,
    typ: CheckType,
    resolver: Resolver,
    timeout: Duration,
    connect_opts: ConnectOpts,
}

impl Checker {
    pub fn new(server: Arc<Server>, typ: CheckType, resolver: Resolver, timeout: Duration) -> Self {
        Self {
            server,
            typ,
            resolver,
            timeout,
            connect_opts: Default::default(),
        }
    }

    /// Checks server's score and update into Score
    pub async fn check_update_score(self) {
        let score = self.check_delay().await.unwrap_or(0);
        match self.typ {
            CheckType::Tcp => self.server.tcp_score().push_score(score),
            CheckType::Udp => self.server.udp_score().push_score(score),
        };

        trace!(
            message = "updated remote server score",
            r#type = ?self.typ,
            addr = ?self.server.config().addr(),
            score
        );
    }

    async fn check_request(&self) -> io::Result<()> {
        match self.typ {
            CheckType::Tcp => self.check_request_tcp_firefox().await,
            CheckType::Udp => self.check_request_udp().await,
        }
    }

    /// Detect TCP connectivity with Firefox's http://detectportal.firefox.com/success.txt
    async fn check_request_tcp_firefox(&self) -> io::Result<()> {
        static GET_BODY: &[u8] = b"GET /success.txt HTTP/1.1\r\nHost: detectportal.firefox.com\r\nConnection: close\r\nAccept: */*\r\n\r\n";

        let addr = Address::DomainNameAddress("detectportal.firefox.com".to_owned(), 80);
        let mut stream = ProxyStream::connect(
            self.server.config(),
            addr,
            &self.resolver,
            &self.connect_opts,
        )
        .await?;

        stream.write_all(GET_BODY).await?;

        let mut reader = BufReader::new(stream);

        let mut buf = Vec::new();
        reader.read_until(b'\n', &mut buf).await?;

        static EXPECTED_HTTP_STATUS_LINE: &[u8] = b"HTTP/1.1 200 OK\r\n";
        if buf != EXPECTED_HTTP_STATUS_LINE {
            use std::io::{Error, ErrorKind};

            debug!(
                "unexpected response from http://detectportal.firefox.com/success.txt, {:?}",
                ByteStr::new(&buf)
            );

            let err = Error::new(
                ErrorKind::InvalidData,
                "unexpected response from http://detectportal.firefox.com/success.txt",
            );
            return Err(err);
        }

        Ok(())
    }

    async fn check_request_udp(&self) -> io::Result<()> {
        // TransactionID: 0x1234
        // Flags: 0x0100 RD
        // Questions: 0x0001
        // Answer RRs: 0x0000
        // Authority RRs: 0x0000
        // Additional RRs: 0x0000
        // Queries
        //    - QNAME: \x07 firefox \x03 com \x00
        //    - QTYPE: 0x0001 A
        //    - QCLASS: 0x0001 IN
        static DNS_QUERY: &[u8] =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07firefox\x03com\x00\x00\x01\x00\x01";

        let addr = Address::SocketAddress(SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53));
        let conf = self.server.config();

        let client = shadowsocks::ProxySocket::connect(conf, &self.resolver).await?;
        let mut control = UdpSocketControlData::default();
        control.client_session_id = rand::random::<u64>();
        control.packet_id = 1;
        client.send(&addr, DNS_QUERY, &control).await?;

        // 128 bytes is big enough for this workload, actually only 77 byte received.
        // and this will help reduce memory from 60M to 14M.
        let mut buffer = [0u8; 128];
        let (n, ..) = client.recv(&mut buffer).await?;

        let answer = &buffer[..n];
        // DNS packet must have at least 6 * 2 bytes
        if answer.len() < 12 || &answer[0..2] != b"\x12\x34" {
            use std::io::{Error, ErrorKind};

            debug!(
                message = "unexpected response from 8.8.8.8:53",
                resp = ?ByteStr::new(answer)
            );

            return Err(Error::new(
                ErrorKind::InvalidData,
                "unexpected response from 8.8.8.8:53",
            ));
        }

        Ok(())
    }

    async fn check_delay(&self) -> io::Result<u32> {
        let start = Instant::now();

        // Send HTTP GET and read the first byte
        let result = time::timeout(self.timeout, self.check_request()).await;

        let elapsed = Instant::now() - start;
        let elapsed = elapsed.as_secs() as u32 * 1000 + elapsed.subsec_millis(); // Convert to ms

        match result {
            Ok(Ok(_)) => {
                // Got the result ... record its time
                trace!(
                    message = "checked remote server success",
                    r#type = ?self.typ,
                    addr = ?self.server.config().addr(),
                    elapsed
                );

                Ok(elapsed)
            }
            Ok(Err(err)) => {
                debug!(
                    message = "failed to check server",
                    r#type = ?self.typ,
                    addr = ?self.server.config().addr(),
                    ?err
                );

                // Note: connection / handshake error, server is down
                Err(err)
            }
            Err(_) => {
                use std::io::ErrorKind;

                // Timeout
                trace!(
                    message = "check remote server timed out",
                    r#type = ?self.typ,
                    addr = ?self.server.config().addr(),
                    elapsed
                );

                // Note: timeout exceeded. Count as error
                Err(ErrorKind::TimedOut.into())
            }
        }
    }
}
