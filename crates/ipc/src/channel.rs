use std::collections::VecDeque;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use getrandom::fill;
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 8] = b"NAGACH01";
const MAX_FRAME: usize = 1048576;
const MAX_QUEUE_BYTES: usize = 16777216;
const AUTH_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Copy, Clone)]
pub enum OverflowPolicy {
    DropOldest,
    Disconnect
}

#[derive(Copy, Clone)]
pub struct ChannelOptions {
    pub max_frame_bytes: usize,
    pub queue_capacity: usize,
    pub overflow: OverflowPolicy
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelEndpoint {
    pub address: SocketAddr,
    pub token: [u8; 32],
    pub max_frame_bytes: usize
}

pub struct ChannelListener {
    listener: TcpListener,
    endpoint: ChannelEndpoint,
    options: ChannelOptions,
    used: bool
}

#[derive(Default)]
struct Queue {
    frames: VecDeque<Vec<u8>>,
    closed: bool
}

struct SharedQueue {
    state: Mutex<Queue>,
    available: Condvar
}

struct ChannelInner {
    writer: Mutex<TcpStream>,
    queue: Arc<SharedQueue>,
    reader: Mutex<Option<JoinHandle<()>>>,
    max_frame: usize
}

#[derive(Clone)]
pub struct DirectChannel {
    inner: Arc<ChannelInner>
}

impl Default for ChannelOptions {
    fn default() -> Self {
        Self { max_frame_bytes: 65536, queue_capacity: 32, overflow: OverflowPolicy::Disconnect }
    }
}

impl ChannelOptions {
    fn validate(self) -> Result<Self> {
        if self.max_frame_bytes == 0 || self.max_frame_bytes > MAX_FRAME || self.queue_capacity == 0
            || self.max_frame_bytes.checked_mul(self.queue_capacity).is_none_or(|bytes| bytes > MAX_QUEUE_BYTES) {
            return Err(invalid("invalid direct channel budgets"))
        }
        Ok(self)
    }
}

impl ChannelListener {
    pub fn bind(options: ChannelOptions) -> Result<Self> {
        let options = options.validate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let mut token = [0; 32];
        fill(&mut token).map_err(|err| Error::other(err.to_string()))?;
        let endpoint = ChannelEndpoint {
            address: listener.local_addr()?, token, max_frame_bytes: options.max_frame_bytes
        };
        Ok(Self { listener, endpoint, options, used: false })
    }

    pub fn endpoint(&self) -> ChannelEndpoint {
        self.endpoint.clone()
    }

    pub fn accept(&mut self, timeout: Duration) -> Result<DirectChannel> {
        if self.used { return Err(invalid("direct channel endpoint was already consumed")) }
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| invalid("invalid timeout"))?;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            match self.listener.accept() {
                Ok((mut stream, address)) => {
                    if !address.ip().is_loopback() { continue }
                    stream.set_nonblocking(false)?;
                    stream.set_read_timeout(Some(remaining.min(AUTH_TIMEOUT)))?;
                    stream.set_write_timeout(Some(remaining.min(AUTH_TIMEOUT)))?;
                    let mut auth = [0; 40];
                    if stream.read_exact(&mut auth).is_err() { continue }
                    let mismatch = auth[..8].iter().zip(MAGIC)
                        .fold(0u8, |value, (left, right)| value | (left ^ right))
                        | auth[8..].iter().zip(self.endpoint.token)
                            .fold(0u8, |value, (left, right)| value | (left ^ right));
                    if mismatch != 0 { continue }
                    stream.write_all(&[1])?;
                    self.used = true;
                    return DirectChannel::from_stream(stream, self.options)
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                Err(err) => return Err(err)
            }
        }
        Err(Error::new(ErrorKind::TimedOut, "direct channel accept timed out"))
    }
}

impl DirectChannel {
    pub fn connect(endpoint: &ChannelEndpoint, timeout: Duration) -> Result<Self> {
        Self::connect_with_options(endpoint, timeout, ChannelOptions {
            max_frame_bytes: endpoint.max_frame_bytes,
            queue_capacity: 32.min(MAX_QUEUE_BYTES / endpoint.max_frame_bytes.max(1)),
            ..ChannelOptions::default()
        })
    }

    pub fn connect_with_options(endpoint: &ChannelEndpoint, timeout: Duration, options: ChannelOptions) -> Result<Self> {
        let options = options.validate()?;
        if !endpoint.address.ip().is_loopback() || endpoint.max_frame_bytes != options.max_frame_bytes {
            return Err(invalid("direct endpoint must be loopback with matching frame budget"))
        }
        let mut stream = TcpStream::connect_timeout(&endpoint.address, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.write_all(MAGIC)?;
        stream.write_all(&endpoint.token)?;
        let mut reply = [0];
        stream.read_exact(&mut reply)?;
        if reply != [1] {
            return Err(Error::new(ErrorKind::PermissionDenied, "direct channel authentication failed"))
        }
        Self::from_stream(stream, options)
    }

    fn from_stream(mut stream: TcpStream, options: ChannelOptions) -> Result<Self> {
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(Some(AUTH_TIMEOUT))?;
        stream.set_nodelay(true)?;
        let writer = stream.try_clone()?;
        let queue = Arc::new(SharedQueue { state: Mutex::new(Queue::default()), available: Condvar::new() });
        let incoming = queue.clone();
        let reader = thread::Builder::new().name("naga-direct-channel".into()).spawn(move || {
            loop {
                let mut length = [0; 4];
                if stream.read_exact(&mut length).is_err() { break }
                let length = u32::from_be_bytes(length) as usize;
                if length > options.max_frame_bytes { break }
                let mut frame = vec![0; length];
                if stream.read_exact(&mut frame).is_err() { break }
                let mut state = incoming.state.lock().unwrap();
                if state.closed { break }
                if state.frames.len() == options.queue_capacity {
                    match options.overflow {
                        OverflowPolicy::DropOldest => { state.frames.pop_front(); }
                        OverflowPolicy::Disconnect => break
                    }
                }
                state.frames.push_back(frame);
                incoming.available.notify_one();
            }
            let _ = stream.shutdown(Shutdown::Both);
            let mut state = incoming.state.lock().unwrap();
            state.closed = true;
            incoming.available.notify_all();
        })?;
        Ok(Self {
            inner: Arc::new(ChannelInner {
                writer: Mutex::new(writer), queue, reader: Mutex::new(Some(reader)), max_frame: options.max_frame_bytes
            })
        })
    }

    pub fn send(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.inner.max_frame { return Err(invalid("direct frame exceeds budget")) }
        if self.is_closed() { return Err(Error::new(ErrorKind::BrokenPipe, "direct channel is closed")) }
        let mut writer = self.inner.writer.lock().map_err(|_| Error::other("channel writer failed"))?;
        let result = writer.write_all(&(bytes.len() as u32).to_be_bytes()).and_then(|_| writer.write_all(bytes));
        drop(writer);
        if result.is_err() { self.close() }
        result
    }

    pub fn receive(&self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        let queue = &self.inner.queue;
        let state = queue.state.lock().map_err(|_| Error::other("channel reader failed"))?;
        let (mut state, _) = queue.available.wait_timeout_while(state, timeout, |state| {
            state.frames.is_empty() && !state.closed
        }).map_err(|_| Error::other("channel reader failed"))?;
        if let Some(frame) = state.frames.pop_front() { return Ok(Some(frame)) }
        if state.closed { return Err(Error::new(ErrorKind::UnexpectedEof, "direct channel is closed")) }
        Ok(None)
    }

    pub fn is_closed(&self) -> bool {
        self.inner.queue.state.lock().map(|state| state.closed).unwrap_or(true)
    }

    pub fn close(&self) {
        self.inner.close();
    }
}

impl ChannelInner {
    fn close(&self) {
        if let Ok(mut queue) = self.queue.state.lock() {
            queue.closed = true;
            queue.frames.clear();
            self.queue.available.notify_all();
        }
        if let Ok(writer) = self.writer.lock() {
            let _ = writer.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for ChannelInner {
    fn drop(&mut self) {
        self.close();
        if let Ok(reader) = self.reader.get_mut() && let Some(reader) = reader.take() {
            let _ = reader.join();
        }
    }
}

fn invalid(message: &str) -> Error {
    Error::new(ErrorKind::InvalidInput, message)
}
