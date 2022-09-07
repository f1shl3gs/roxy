use std::io;
use std::sync::Arc;
use std::time::Duration;

use byte_string::ByteStr;
use resolver::Resolver;
use shadowsocks::{Address, ConnectOpts, ProxyStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time;
use tokio::time::Instant;

use super::Server;

pub struct Checker {
    server: Arc<Server>,
    resolver: Resolver,
    timeout: Duration,
    connect_opts: ConnectOpts,
}

impl Checker {
    pub fn new(server: Arc<Server>, resolver: Resolver, timeout: Duration) -> Self {
        Self {
            server,
            resolver,
            timeout,
            connect_opts: Default::default(),
        }
    }

    /// Checks server's score and update into Score
    pub async fn check_update_score(self) {
        let score = self.check_delay().await.unwrap_or(0);
        self.server.push_latency(score);

        trace!(
            message = "updated remote server score",
            addr = ?self.server.config().addr(),
            score
        );
    }

    async fn check_request(&self) -> io::Result<()> {
        self.check_request_tcp_firefox().await
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
                    addr = ?self.server.config().addr(),
                    elapsed
                );

                Ok(elapsed)
            }
            Ok(Err(err)) => {
                debug!(
                    message = "failed to check server",
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
                    addr = ?self.server.config().addr(),
                    elapsed
                );

                // Note: timeout exceeded. Count as error
                Err(ErrorKind::TimedOut.into())
            }
        }
    }
}
