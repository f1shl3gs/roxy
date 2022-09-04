use std::net::SocketAddr;

use trust_dns_proto::error::ProtoResult;
use trust_dns_proto::op::message::EmitAndCount;
use trust_dns_proto::op::{message, Edns, Header, Query, ResponseCode};
use trust_dns_proto::rr::Record;
use trust_dns_proto::serialize::binary::{BinEncodable, BinEncoder};
use trust_dns_proto::xfer::SerialMessage;

use crate::dns::server::request::Request;

/// A EncodableMessage with borrowed data for Responses in the Server
#[derive(Debug)]
pub struct Response<'q> {
    header: Header,
    pub(crate) query: &'q Query,
    pub answers: Vec<Record>,
    pub name_servers: Vec<Record>,
    pub soa: Vec<Record>,
    pub additionals: Vec<Record>,
    pub sig0: Vec<Record>,
    pub edns: Option<Edns>,
}

struct QueriesEmitAndCount<'q> {
    query: &'q Query,
}

impl<'q> EmitAndCount for QueriesEmitAndCount<'q> {
    fn emit(&mut self, encoder: &mut BinEncoder<'_>) -> ProtoResult<usize> {
        self.query.emit(encoder)?;

        // 1 standards for number of queries in this segment
        Ok(1)
    }
}

impl<'q> Response<'q> {
    pub fn new(
        header: Header,
        query: &'q Query,
        answers: Vec<Record>,
        name_servers: Vec<Record>,
        soa: Vec<Record>,
        additionals: Vec<Record>,
        sig0: Vec<Record>,
        edns: Option<Edns>,
    ) -> Self {
        Self {
            header,
            query,
            answers,
            name_servers,
            soa,
            additionals,
            sig0,
            edns,
        }
    }

    pub fn no_records(header: Header, query: &'q Query) -> Response<'q> {
        Self {
            header,
            query,
            answers: vec![],
            name_servers: vec![],
            soa: vec![],
            additionals: vec![],
            sig0: vec![],
            edns: None,
        }
    }

    pub fn error(req: &'q Request, code: ResponseCode) -> Response<'q> {
        let mut header = Header::response_from_request(req.header());
        header.set_response_code(code);

        Self {
            header,
            query: req.query(),
            answers: vec![],
            name_servers: vec![],
            soa: vec![],
            additionals: vec![],
            sig0: vec![],
            edns: None,
        }
    }

    pub fn from_request(req: &'q Request) -> Self {
        Self {
            header: req.header,
            query: &req.query,
            answers: vec![],
            name_servers: vec![],
            soa: vec![],
            additionals: vec![],
            sig0: vec![],
            edns: None,
        }
    }

    pub fn message(self, src: SocketAddr) -> ProtoResult<SerialMessage> {
        let mut buf = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buf);
        encoder.set_max_size(512);

        // let queries = vec![self.query];
        let mut queries = QueriesEmitAndCount { query: self.query };
        message::emit_message_parts(
            &self.header,
            &mut queries,
            &mut self.answers.iter(),
            &mut self.name_servers.iter(),
            &mut self.additionals.iter(),
            self.edns.as_ref(),
            &self.sig0,
            &mut encoder,
        )?;

        Ok(SerialMessage::new(buf, src))
    }
}
