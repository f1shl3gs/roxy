use std::io::{Error, IoSlice};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
pub struct FlowStat {
    recv: AtomicUsize,
    sent: AtomicUsize,
}

impl FlowStat {
    pub fn incr_sent(&self, n: usize) {
        self.sent.fetch_add(n, Ordering::Relaxed);
    }

    pub fn incr_recv(&self, n: usize) {
        self.recv.fetch_add(n, Ordering::Relaxed);
    }

    pub fn load(&self) -> (usize, usize) {
        let sent = self.sent.load(Ordering::Relaxed);
        let recv = self.recv.load(Ordering::Relaxed);

        (recv, sent)
    }
}

pin_project! {
    pub struct MonProxyStream<S> {
        #[pin]
        inner: S,

        flow_stat: Arc<FlowStat>
    }
}

impl<S> MonProxyStream<S> {
    #[inline]
    pub fn from_stream(stream: S, flow_stat: Arc<FlowStat>) -> Self {
        Self {
            inner: stream,
            flow_stat,
        }
    }
}

impl<S> AsyncRead for MonProxyStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();

        match this.inner.poll_read(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len();
                this.flow_stat.incr_recv(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }
}

impl<S> AsyncWrite for MonProxyStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let this = self.project();

        match this.inner.poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.flow_stat.incr_sent(n);
                Poll::Ready(Ok(n))
            }
            pr => pr,
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().inner.poll_shutdown(cx)
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }
}
