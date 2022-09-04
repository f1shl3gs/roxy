use std::net::SocketAddr;

use trust_dns_proto::error::{ProtoErrorKind, ProtoResult};
use trust_dns_proto::op::{Edns, Header, Message, Query};
use trust_dns_proto::rr::Record;
use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder};
use trust_dns_proto::xfer::SerialMessage;

/// An incoming request to the DNS catalog
pub struct Request {
    // message fields
    pub(crate) header: Header,
    pub(crate) query: Query,
    answers: Vec<Record>,
    name_servers: Vec<Record>,
    additionals: Vec<Record>,
    sig0: Vec<Record>,
    edns: Option<Edns>,

    /// Source address of the Client
    src: SocketAddr,
}

impl Request {
    /// Return the request header
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Question carries the query name and other query parameters.
    pub fn query(&self) -> &Query {
        &self.query
    }

    pub fn from_message(message: SerialMessage, src: SocketAddr) -> ProtoResult<Self> {
        let mut decoder = BinDecoder::new(message.bytes());
        let mut header = Header::read(&mut decoder)?;

        // get all counts before header moves
        let query_count = header.query_count() as usize;
        if query_count != 1 {
            return Err(ProtoErrorKind::BadQueryCount(query_count).into());
        }
        let answer_count = header.answer_count() as usize;
        let name_server_count = header.name_server_count() as usize;
        let additional_count = header.additional_count() as usize;

        let mut queries = Vec::with_capacity(query_count);
        for _ in 0..query_count {
            let q = Query::read(&mut decoder)?;
            queries.push(q);
        }
        let (answers, _, _) = Message::read_records(&mut decoder, answer_count, false)?;
        let (name_servers, _, _) = Message::read_records(&mut decoder, name_server_count, false)?;
        let (additionals, edns, sig0) =
            Message::read_records(&mut decoder, additional_count, true)?;

        // need to grab error code from EDNS (which might have a higher value)
        if let Some(edns) = &edns {
            let high_response_code = edns.rcode_high();
            header.merge_response_code(high_response_code);
        }

        Ok(Self {
            header,
            query: queries.pop().unwrap(),
            answers,
            name_servers,
            additionals,
            sig0,
            edns,
            src,
        })
    }
}
