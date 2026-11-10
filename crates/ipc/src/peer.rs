use std::collections::{BTreeMap, BTreeSet};
use std::mem::take;
use std::net::{Shutdown, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU64, Ordering}, mpsc::{self, SyncSender}};
use std::thread;
use std::time::{Duration, Instant};
use crate::{Frame, Request, RpcError, RpcResult, read_frame, write_frame};

const MAX_PENDING: usize = 64;
const MAX_INBOUND: usize = 16;

pub trait Handler: Send + Sync + 'static {
    fn handle(&self, request: Request) -> RpcResult;
    fn disconnected(&self) {}
}

#[derive(Clone)]
pub struct Peer(Arc<Inner>);

struct Inner {
    writer: Mutex<TcpStream>,
    pending: Mutex<BTreeMap<u64, SyncSender<RpcResult>>>,
    next_id: AtomicU64,
    inbound: Mutex<BTreeSet<u64>>,
    closed: AtomicBool
}

struct InboundGuard {
    peer: Peer,
    id: u64
}

impl Drop for InboundGuard {
    fn drop(&mut self) {
        self.peer.0.inbound.lock().unwrap().remove(&self.id);
    }
}

impl Peer {
    pub fn attach(mut reader: TcpStream, handler: Arc<dyn Handler>) -> Result<Self, RpcError> {
        reader.set_nonblocking(false).map_err(|err| RpcError::new("io", err.to_string()))?;
        reader.set_nodelay(true).map_err(|err| RpcError::new("io", err.to_string()))?;
        if reader.write_timeout().map_err(|err| RpcError::new("io", err.to_string()))?.is_none() {
            reader.set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(|err| RpcError::new("io", err.to_string()))?;
        }

        let peer = Self(Arc::new(Inner {
            writer: Mutex::new(reader.try_clone().map_err(|err| RpcError::new("io", err.to_string()))?),
            pending: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            inbound: Mutex::new(BTreeSet::new()),
            closed: AtomicBool::new(false)
        }));
        let receiver = peer.clone();
        thread::Builder::new().name("naga-ipc-reader".into()).spawn(move || {
            loop {
                match read_frame::<Frame>(&mut reader) {
                    Ok(Frame::Reply { id, result }) => {
                        if let Some(channel) = receiver.0.pending.lock().unwrap().remove(&id) {
                            let _ = channel.send(result);
                        }
                    }
                    Ok(Frame::Request { id, request }) => {
                        let mut inbound = receiver.0.inbound.lock().unwrap();
                        if inbound.contains(&id) { break }
                        if inbound.len() >= MAX_INBOUND {
                            drop(inbound);
                            let _ = receiver.send(&Frame::Reply {
                                id, result: Err(RpcError::new("busy", "inbound concurrency limit"))
                            });
                            continue
                        }

                        inbound.insert(id);
                        drop(inbound);
                        let worker = receiver.clone();
                        let handler = handler.clone();
                        let reservation = InboundGuard { peer: worker.clone(), id };
                        if thread::Builder::new().name("naga-ipc-request".into()).spawn(move || {
                            let _reservation = reservation;
                            let result = catch_unwind(AssertUnwindSafe(|| handler.handle(request)))
                                .unwrap_or_else(|_| Err(RpcError::new("handler_panic", "IPC handler panicked")));
                            let _ = worker.send(&Frame::Reply { id, result });
                        }).is_err() {
                            break
                        }
                    }
                    _ => break
                }
            }
            receiver.close();
            let _ = catch_unwind(AssertUnwindSafe(|| handler.disconnected()));
        }).map_err(|err| RpcError::new("thread", err.to_string()))?;
        Ok(peer)
    }

    pub fn call(&self, request: Request, timeout: Duration) -> RpcResult {
        self.call_inner(request, timeout, None)
    }

    pub fn call_cancellable(&self, request: Request, timeout: Duration, cancellation: &AtomicBool) -> RpcResult {
        self.call_inner(request, timeout, Some(cancellation))
    }

    fn call_inner(&self, request: Request, timeout: Duration, cancellation: Option<&AtomicBool>) -> RpcResult {
        if self.is_closed() {
            return Err(RpcError::new("disconnected", "module IPC connection is closed"))
        }

        let id = self.0.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::sync_channel(1);
        {
            let mut pending = self.0.pending.lock().unwrap();
            if self.is_closed() {
                return Err(RpcError::new("disconnected", "module IPC connection is closed"))
            }
            if pending.len() >= MAX_PENDING {
                return Err(RpcError::new("busy", "outbound concurrency limit"))
            }
            pending.insert(id, sender);
        }
        if let Err(err) = self.send(&Frame::Request { id, request }) {
            self.0.pending.lock().unwrap().remove(&id);
            return Err(err)
        }

        let deadline = Instant::now() + timeout;
        let result = loop {
            if cancellation.is_some_and(|flag| flag.load(Ordering::Acquire)) {
                break Err(RpcError::new("cancelled", "module request cancelled"))
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break Err(RpcError::new("timeout", "module request timed out"))
            }
            match receiver.recv_timeout(remaining.min(Duration::from_millis(25))) {
                Ok(result) => break result,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(RpcError::new("disconnected", "module IPC connection closed"))
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        };
        self.0.pending.lock().unwrap().remove(&id);
        result
    }

    pub fn is_closed(&self) -> bool {
        self.0.closed.load(Ordering::Acquire)
    }

    pub fn close(&self) {
        if self.0.closed.swap(true, Ordering::AcqRel) { return }
        let _ = self.0.writer.lock().unwrap().shutdown(Shutdown::Both);
        for (_, sender) in take(&mut *self.0.pending.lock().unwrap()) {
            let _ = sender.send(Err(RpcError::new("disconnected", "module IPC connection closed")));
        }
    }

    fn send(&self, frame: &Frame) -> Result<(), RpcError> {
        let result = write_frame(&mut *self.0.writer.lock().unwrap(), frame);
        if result.is_err() { self.close() }
        result
    }
}
