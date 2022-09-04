use std::fmt::Formatter;
use std::io;
use std::io::{Cursor, Read};
use std::str::Utf8Error;
use std::string::FromUtf8Error;

use byteorder::ByteOrder;
use byteorder::NetworkEndian;
use hyper::body::Buf;
use memchr::memchr;
use tokio::net::TcpStream;
use trust_dns_resolver::error::ResolveError;

const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),

    Resolve(ResolveError),

    UnknownProtocol,

    HostNotFound,

    InvalidRequestHeader(Utf8Error),

    InvalidSNI(FromUtf8Error),

    TlsExtensionMissing,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl std::error::Error for Error {}

impl From<ResolveError> for Error {
    fn from(err: ResolveError) -> Self {
        Self::Resolve(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<Utf8Error> for Error {
    fn from(err: Utf8Error) -> Self {
        Self::InvalidRequestHeader(err)
    }
}

pub async fn destination_addr(stream: &mut TcpStream) -> Result<(String, u16), Error> {
    let mut buf = [0; 1024];

    // TODO: something wrong might happened, retry this?
    let n = stream.peek(&mut buf).await?;
    let mut port = 80;

    let domain = match buf[0] {
        // 22 is Handshake
        // https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1
        22 => {
            port = 443;
            tls_sni(&buf)
        }
        b'G' | b'P' | b'D' | b'H' | b'C' | b'O' | b'T' => http_host(&buf).map(Into::into),
        _ => return Err(Error::UnknownProtocol),
    }?;

    Ok((domain, port))
}

fn http_host(buf: &[u8]) -> Result<&str, Error> {
    let mut start = 0;

    loop {
        let next = memchr(b'\n', &buf[start..]).ok_or(Error::HostNotFound)?;
        if next == 0 {
            break;
        }

        if next < 5 {
            start = start + next + 1;
            continue;
        }

        if buf[start..start + 5] != [b'H', b'o', b's', b't', b':'] {
            start = start + next + 1;
            continue;
        }

        let s = std::str::from_utf8(&buf[start + 5..start + next])?;

        return Ok(s.trim());
    }

    Err(Error::HostNotFound)
}

trait ReadExt: Read {
    fn read_u8(&mut self) -> io::Result<u8> {
        let mut buf = [0u8; 1];
        self.read(&mut buf)?;

        Ok(buf[0])
    }

    fn read_u24(&mut self) -> io::Result<u32> {
        let mut buf = [0; 3];
        self.read_exact(&mut buf)?;

        Ok(NetworkEndian::read_u24(&buf))
    }

    fn read_u16(&mut self) -> io::Result<u16> {
        let mut buf = [0; 2];
        self.read_exact(&mut buf)?;

        Ok(NetworkEndian::read_u16(&buf))
    }
}

impl<T: Read> ReadExt for T {}

const EXTENSION_TYPE_SNI: u16 = 0;
const NAME_TYPE_HOST_NAME: u8 = 0;

// for more detail see
// https://www.rfc-editor.org/rfc/rfc5246#section-7.4
fn tls_sni(buf: &[u8]) -> Result<String, Error> {
    let mut reader = Cursor::new(buf);

    // Parse TLSPlaintext
    // See https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1
    //
    // struct {
    //     ContentType type;
    //     ProtocolVersion version;
    //     uint16 length;
    //     opaque fragment[TLSPlaintext.length];
    // } TLSPlaintext;
    reader.advance(1 + 2); // content type + protocol version
                           // TODO: the length can be used to check if we got enough buf for parse
    let _len = reader.read_u16()?;

    // Parse Handshake
    // See: https://www.rfc-editor.org/rfc/rfc5246#section-7.4
    //
    // struct {
    //           HandshakeType msg_type;    /* handshake type */
    //           uint24 length;             /* bytes in message */
    //           select (HandshakeType) {
    //               case hello_request:       HelloRequest;
    //               case client_hello:        ClientHello;
    //               case server_hello:        ServerHello;
    //               case certificate:         Certificate;
    //               case server_key_exchange: ServerKeyExchange;
    //               case certificate_request: CertificateRequest;
    //               case server_hello_done:   ServerHelloDone;
    //               case certificate_verify:  CertificateVerify;
    //               case client_key_exchange: ClientKeyExchange;
    //               case finished:            Finished;
    //           } body;
    //       } Handshake;
    let msg_type = reader.read_u8()?;
    if msg_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(Error::UnknownProtocol);
    }
    let msg_length = reader.read_u24()?; // length

    // Parse ClientHelloMessage
    // See: https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2
    //
    // struct {
    //     ProtocolVersion client_version;  // 2 * u8
    //     Random random;                   // u32 + 28byte
    //     SessionID session_id;
    //     CipherSuite cipher_suites<2..2^16-2>;
    //     CompressionMethod compression_methods<1..2^8-1>;
    //     select (extensions_present) {
    //         case false:
    //             struct {};
    //         case true:
    //             Extension extensions<0..2^16-1>;
    //     };
    // } ClientHello;

    // client_version + random
    reader.advance(2 + (4 + 28));

    // session id
    let sess_len = reader.read_u8()?;
    reader.advance(sess_len as usize);

    // cipher suites
    let cs_len = reader.read_u16()?;
    reader.advance(cs_len as usize);

    // compression methods
    let cm_len = reader.read_u8()?;
    reader.advance(cm_len as usize);

    // parse Extensions so we can get SNI
    // https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.4
    //
    // struct {
    //     ExtensionType extension_type;
    //     opaque extension_data<0..2^16-1>;
    // } Extension;
    let ext_len = reader.read_u16()?;
    if ext_len == 0 {
        return Err(Error::TlsExtensionMissing);
    }

    loop {
        // Extension type & length
        let ext_typ = reader.read_u16()?; // values should be 0, 1, 2, 3, 4, 5 or 65535
        let ext_len = reader.read_u16()?;
        if ext_typ != EXTENSION_TYPE_SNI {
            reader.advance(ext_len as usize);
            continue;
        }

        // ServerNameList
        let snl_len = reader.read_u16()?;
        loop {
            // NameType & length
            let name_type = reader.read_u8()?;
            if name_type != NAME_TYPE_HOST_NAME {
                reader.advance(2);
                continue;
            }

            let name_len = reader.read_u16()?;
            let mut buf = vec![0; name_len.into()];
            reader.read_exact(&mut buf)?;

            return String::from_utf8(buf).map_err(Error::InvalidSNI);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parse_http_host() {
        let tests = [(
            "GET /images/logo.png HTTP/1.1\nHost: www.example.com\nAccept-Language: en\n",
            "www.example.com",
        )];

        for (input, want) in tests {
            let got = http_host(input.as_bytes()).unwrap();
            assert_eq!(
                got, want,
                "input: {}\n\ngot:  {}\n\nwant: {}",
                input, got, want
            )
        }
    }

    #[test]
    fn parse_https() {
        let data = include_bytes!("../../../tests/https.bin");

        let n = tls_sni(data).unwrap();
        assert_eq!("mail.google.com", n);
    }
}
