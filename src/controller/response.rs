use hyper::header::CONTENT_TYPE;
use hyper::{Body, Response, StatusCode};

pub trait IntoResponse<T>: Sized {
    fn into_resp(self) -> T;
}

impl<T> IntoResponse<Response<Body>> for T
where
    T: serde::Serialize,
{
    fn into_resp(self) -> Response<Body> {
        let data = serde_json::to_vec(&self).expect("serialize object");

        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(data))
            .unwrap()
    }
}

/// Impl `IntoResponse<Response<Body>> for T: serde::Serialize` is conflict with StatusCode,
/// Cause serde::Serialize is already implement for StatusCode in `serde`
/// https://github.com/rust-lang/rust/issues/31844
pub fn err_resp(status: StatusCode, err: impl std::error::Error) -> Response<Body> {
    let body = err.to_string();

    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from(body))
        .unwrap()
}
