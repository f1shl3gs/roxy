use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, task};

use bytes::Bytes;
use futures::ready;
use tokio::io::{AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::crypto::utils::generate_nonce;
use crate::crypto::{CipherCategory, CipherKind};
use crate::tcp::{aead, aead2022};

/// TCP shadowsocks protocol error
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Aead(#[from] aead::ProtocolError),
    #[error(transparent)]
    Aead2022(#[from] aead2022::ProtocolError),
}

impl From<ProtocolError> for io::Error {
    fn from(err: ProtocolError) -> io::Error {
        match err {
            ProtocolError::Io(err) => err,
            ProtocolError::Aead(err) => err.into(),
            ProtocolError::Aead2022(err) => err.into(),
        }
    }
}

pub enum DecryptedReader {
    Aead(aead::DecryptedReader),
    Aead2022(aead2022::DecryptedReader),
}

impl DecryptedReader {
    /// Create a new reader for reading encrypted data
    pub fn new(kind: CipherKind, key: &[u8]) -> DecryptedReader {
        match kind.category() {
            CipherCategory::Aead => DecryptedReader::Aead(aead::DecryptedReader::new(kind, key)),
            CipherCategory::Aead2022 => {
                DecryptedReader::Aead2022(aead2022::DecryptedReader::new(kind, key))
            }
        }
    }

    fn user_key(&self) -> Option<&[u8]> {
        match *self {
            DecryptedReader::Aead(_) => None,
            DecryptedReader::Aead2022(ref reader) => reader.user_key(),
        }
    }

    pub fn request_nonce(&self) -> Option<&[u8]> {
        match *self {
            DecryptedReader::Aead(_) => None,
            DecryptedReader::Aead2022(ref reader) => reader.request_salt(),
        }
    }

    pub fn poll_read_decrypted(
        &mut self,
        cx: &mut Context<'_>,
        stream: &mut TcpStream,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), ProtocolError>> {
        match *self {
            DecryptedReader::Aead(ref mut reader) => reader
                .poll_read_decrypted(cx, stream, buf)
                .map_err(Into::into),
            DecryptedReader::Aead2022(ref mut reader) => reader
                .poll_read_decrypted(cx, stream, buf)
                .map_err(Into::into),
        }
    }

    pub fn handshaked(&self) -> bool {
        match *self {
            DecryptedReader::Aead(ref reader) => reader.handshaked(),
            DecryptedReader::Aead2022(ref reader) => reader.handshaked(),
        }
    }
}

pub enum EncryptedWriter {
    Aead(aead::EncryptedWriter),
    Aead2022(aead2022::EncryptedWriter),
}

/// Get sent IV(stream) or Salt (AEAD, AEAD2022)
impl EncryptedWriter {
    pub fn new(kind: CipherKind, key: &[u8], nonce: &[u8], identity_keys: &[Bytes]) -> Self {
        match kind.category() {
            CipherCategory::Aead => {
                EncryptedWriter::Aead(aead::EncryptedWriter::new(kind, key, nonce))
            }
            CipherCategory::Aead2022 => EncryptedWriter::Aead2022(
                aead2022::EncryptedWriter::with_identity(kind, key, nonce, identity_keys),
            ),
        }
    }

    fn nonce(&self) -> &[u8] {
        match *self {
            EncryptedWriter::Aead(ref writer) => writer.salt(),
            EncryptedWriter::Aead2022(ref writer) => writer.salt(),
        }
    }

    /// Reset cipher with authenticated user key
    pub fn reset_cipher_with_key(&mut self, key: &[u8]) {
        match *self {
            EncryptedWriter::Aead2022(ref mut writer) => writer.reset_cipher_with_key(key),
            _ => panic!("only AEAD-2022 cipher could authenticate with multiple users"),
        }
    }

    /// Attempt to write encrypted data to `stream`
    pub fn poll_write_encrypted<S>(
        &mut self,
        cx: &mut Context<'_>,
        stream: &mut S,
        buf: &[u8],
    ) -> Poll<Result<usize, ProtocolError>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        match *self {
            EncryptedWriter::Aead(ref mut writer) => writer
                .poll_write_encrypted(cx, stream, buf)
                .map_err(Into::into),
            EncryptedWriter::Aead2022(ref mut writer) => writer
                .poll_write_encrypted(cx, stream, buf)
                .map_err(Into::into),
        }
    }
}

/// A bidirectional stream for read/write encrypted data in shadowsocks' tunnel
pub struct CryptoStream {
    stream: TcpStream,
    dec: DecryptedReader,
    enc: EncryptedWriter,
    kind: CipherKind,
    handshaked: bool,
}

impl CryptoStream {
    pub fn from_stream(stream: TcpStream, kind: CipherKind, key: &[u8]) -> CryptoStream {
        static EMPTY_IDENTITY: [Bytes; 0] = [];

        // No matter the cipher is aead or aead2022
        let prev_len = kind.salt_len();

        let iv = {
            // TODO: unique nonce!?
            //
            // Shadowsocks-rust do not check if the salt is unique by default.
            let mut local_salt = vec![0u8; prev_len];
            generate_nonce(kind, &mut local_salt);
            local_salt
        };

        Self {
            stream,
            dec: DecryptedReader::new(kind, key),
            enc: EncryptedWriter::new(kind, key, &iv, &EMPTY_IDENTITY),
            kind,
            handshaked: false,
        }
    }

    /// Get remaining bytes in the current data chunk
    ///
    /// Returning (DataChunkCount, RemainingBytes)
    pub fn current_data_chunk_remaining(&self) -> (u64, usize) {
        if let DecryptedReader::Aead2022(ref dec) = self.dec {
            dec.current_data_chunk_remaining()
        } else {
            panic!("only AEAD-2022 protocol has data chunk counter");
        }
    }

    pub fn kind(&self) -> CipherKind {
        self.kind
    }

    /// Get sent IV or Salt
    #[inline]
    pub fn sent_nonce(&self) -> &[u8] {
        self.enc.nonce()
    }

    /// Received request salt from server -- AEAD2022
    #[inline]
    pub fn received_request_nonce(&self) -> Option<&[u8]> {
        self.dec.request_nonce()
    }

    pub fn poll_read_decrypted(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), ProtocolError>> {
        let CryptoStream {
            ref mut dec,
            ref mut enc,
            ref mut stream,
            ref mut handshaked,
            ..
        } = *self;

        ready!(dec.poll_read_decrypted(cx, stream, buf))?;

        if !*handshaked && dec.handshaked() {
            *handshaked = true;

            // Reset writer cipher with authenticated user key
            if let Some(user_key) = dec.user_key() {
                enc.reset_cipher_with_key(user_key);
            }
        }

        Ok(()).into()
    }

    pub fn poll_write_encrypted(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ProtocolError>> {
        let CryptoStream {
            ref mut enc,
            ref mut stream,
            ..
        } = *self;

        enc.poll_write_encrypted(cx, stream, buf)
    }

    #[inline]
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ProtocolError>> {
        Pin::new(&mut self.stream)
            .poll_flush(cx)
            .map_err(Into::into)
    }

    #[inline]
    pub fn poll_shutdown(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), ProtocolError>> {
        Pin::new(&mut self.stream)
            .poll_shutdown(cx)
            .map_err(Into::into)
    }
}
