use std::collections::BTreeMap;
#[cfg(unix)]
use std::env;
use std::io::{BufReader, ErrorKind, Read};
#[cfg(unix)]
use std::iter::once;
use std::net::TcpListener;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use getrandom::fill as fill_random;
use hex::encode as encode_hex;
use naga_ipc::{
    BootTicket, DiagnosticLevel, Frame, PROTOCOL_VERSION, Peer, Request, read_frame, write_frame
};
use naga_model::{ModuleKey, Platform, ResolvedModule};
use serde_json::{Map, Value};

use crate::{
    Configuration, CoreError, DiagnosticOrigin, process_tree::ProcessTree, router::Router
};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 134217728;

struct OwnedChild {
    process: Child,
    tree: Option<ProcessTree>,
    outputs: Vec<JoinHandle<()>>
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(tree) = &mut self.tree {
            tree.terminate();
        }
        let _ = self.process.kill();
        let _ = self.process.wait();
        for output in self.outputs.drain(..) {
            let _ = output.join();
        }
    }
}

pub(crate) struct ModuleProcess {
    child: OwnedChild,
    pub peer: Peer
}

impl ModuleProcess {
    pub fn spawn(
        module: &ResolvedModule, root: &Path, files: &BTreeMap<String, String>, host: &Path, config: &Configuration,
        router: &Arc<Router>, cancellation: &AtomicBool
    ) -> Result<Self, CoreError> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let mut random = [0; 32];
        fill_random(&mut random).map_err(|error| CoreError::Lifecycle(error.to_string()))?;
        let token = encode_hex(random);
        let ticket = BootTicket {
            protocol: PROTOCOL_VERSION,
            address: listener.local_addr()?.to_string(),
            token: token.clone(),
            key: module.key.clone(),
            manifest: module.manifest.clone(),
            root: root.to_path_buf(),
            files: files.clone(),
            configuration: config.module_configuration.get(&module.key.to_string()).cloned().unwrap_or_else(|| Value::Object(Map::new())),
            request_timeout_ms: config.request_timeout_ms
        };
        let library = &module.manifest.libraries[&Platform::current()?];
        let primary = root.join(library.library_path.as_ref());
        let mut command = Command::new(host);
        command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).current_dir(primary.parent().unwrap());
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);
        #[cfg(unix)]
        command.process_group(0);
        #[cfg(unix)] {
            let mut directories = Vec::new();
            for path in once(&library.library_path).chain(&library.load_libraries) {
                let path = root.join(path.as_ref());
                let parent = path.parent().unwrap().to_path_buf();
                if !directories.contains(&parent) {
                    directories.push(parent);
                }
            }
            command.env("LD_LIBRARY_PATH", env::join_paths(directories).map_err(|error| CoreError::Configuration(error.to_string()))?);
        }
        let mut child = OwnedChild {
            process: command.spawn()?,
            tree: None,
            outputs: Vec::new()
        };
        child.tree = Some(ProcessTree::attach(&child.process)?);
        let pid = child.process.id();
        if let Some(output) = child.process.stdout.take() {
            child.outputs.push(capture(output, router.clone(), module.key.clone(), DiagnosticLevel::Info));
        }
        if let Some(output) = child.process.stderr.take() {
            child.outputs.push(capture(output, router.clone(), module.key.clone(), DiagnosticLevel::Warn));
        }
        let mut input = child.process.stdin.take().ok_or_else(|| CoreError::Lifecycle("host stdin unavailable".into()))?;
        write_frame(&mut input, &ticket)?;
        drop(input);
        let deadline = Instant::now() + Duration::from_millis(config.startup_timeout_ms);
        let (sender, ready) = mpsc::sync_channel(1);
        router.prepare(&module.key, sender);
        let stream = loop {
            if cancellation.load(Ordering::Acquire) { return Err(CoreError::Lifecycle("startup cancelled".into())) }
            if child.process.try_wait()?.is_some() {
                return Err(CoreError::Lifecycle(format!("{} host exited before authentication", module.key)))
            }
            if Instant::now() >= deadline { return Err(CoreError::Lifecycle(format!("{} host authentication timed out", module.key))) }
            match listener.accept() {
                Ok((mut stream, address)) if address.ip().is_loopback() => {
                    stream.set_nonblocking(false)?;
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    stream.set_read_timeout(Some(remaining))?;
                    stream.set_write_timeout(Some(remaining))?;
                    let authenticated = read_frame::<Frame>(&mut stream).is_ok_and(|frame| expected_hello(frame, &token, &module.key));
                    if !authenticated { continue }
                    write_frame(&mut stream, &Frame::Accepted { protocol: PROTOCOL_VERSION })?;
                    stream.set_read_timeout(None)?;
                    stream.set_write_timeout(Some(Duration::from_millis(config.request_timeout_ms)))?;
                    break stream;
                }
                Ok(_) => continue,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => return Err(error.into())
            }
        };
        let peer = Peer::attach(stream, router.handler(module.key.clone()))?;
        router.attach(&module.key, peer.clone(), pid);
        loop {
            if cancellation.load(Ordering::Acquire) {
                peer.close();
                return Err(CoreError::Lifecycle("startup cancelled".into()))
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match ready.recv_timeout(remaining.min(Duration::from_millis(25))) {
                Ok(()) => break,
                Err(mpsc::RecvTimeoutError::Timeout) if !remaining.is_zero() => {}
                _ => {
                    peer.close();
                    return Err(CoreError::Lifecycle(format!("{} native ABI initialization timed out or failed", module.key)))
                }
            }
        }
        Ok(Self { child, peer })
    }

    pub fn exited(&mut self) -> Result<bool, CoreError> {
        Ok(self.peer.is_closed())
    }

    pub fn terminate(&mut self) {
        self.peer.close();
        if let Some(tree) = &mut self.child.tree {
            tree.terminate();
        }
        let _ = self.child.process.kill();
        let _ = self.child.process.wait();
    }

    pub fn stop(&mut self, timeout: Duration) {
        let _ = self.peer.call(Request::Stop, timeout);
        self.peer.close();
        if let Some(tree) = &mut self.child.tree {
            tree.terminate();
        }
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.child.process.try_wait().is_ok_and(|status| status.is_some()) { return }
            thread::sleep(Duration::from_millis(5));
        }
        let _ = self.child.process.kill();
        let _ = self.child.process.wait();
    }
}

fn expected_hello(frame: Frame, token: &str, key: &ModuleKey) -> bool {
    matches!(frame, Frame::Hello { protocol: PROTOCOL_VERSION, token: supplied, key: supplied_key } if supplied == token && &supplied_key == key)
}

fn capture(reader: impl Read + Send + 'static, router: Arc<Router>, key: ModuleKey, level: DiagnosticLevel) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut buffer = [0; 4096];
        let mut pending = Vec::with_capacity(4096);
        while let Ok(count) = reader.read(&mut buffer) {
            if count == 0 { break }
            for byte in &buffer[..count] {
                if *byte == b'\n' {
                    record_output(&router, &key, level, &pending);
                    pending.clear();
                } else {
                    pending.push(*byte);
                    if pending.len() == 4096 {
                        record_output(&router, &key, level, &pending);
                        pending.clear();
                    }
                }
            }
        }
        record_output(&router, &key, level, &pending);
    })
}

fn record_output(router: &Router, key: &ModuleKey, level: DiagnosticLevel, bytes: &[u8]) {
    let message = String::from_utf8_lossy(bytes);
    let message = message.trim_end_matches('\r');
    if message.is_empty() { return }
    let (level, message) = match message.strip_prefix("naga-host: trace: ") {
        Some(message) => (DiagnosticLevel::Trace, message),
        None if message.starts_with("naga-host: ") => (DiagnosticLevel::Error, message),
        None => (level, message)
    };
    router.record_from(key, DiagnosticOrigin::Host, level, message.into());
}

#[cfg(test)]
mod tests {
    use naga_ipc::{Frame, PROTOCOL_VERSION};
    use naga_model::ModuleKey;
    use serde_json::{from_value, json};

    use super::expected_hello;

    #[test]
    fn authentication_rejects_wrong_key_token_and_protocol() {
        let key: ModuleKey = from_value(json!({
            "package_id": "test.package", "package_version": "1.0.0", "module_id": "module"
        })).unwrap();
        let token = "a".repeat(64);
        assert!(expected_hello(
            Frame::Hello {
                protocol: PROTOCOL_VERSION,
                token: token.clone(),
                key: key.clone()
            },
            &token,
            &key
        ));
        for mode in 0..3 {
            let mut supplied_key = key.clone();
            if mode == 0 {
                supplied_key.module_id = "other".to_owned().try_into().unwrap();
            }
            let supplied_token = if mode == 1 {
                "b".repeat(64)
            } else {
                token.clone()
            };
            let protocol = if mode == 2 {
                PROTOCOL_VERSION + 1
            } else {
                PROTOCOL_VERSION
            };
            assert!(!expected_hello(
                Frame::Hello {
                    protocol,
                    token: supplied_token,
                    key: supplied_key
                },
                &token,
                &key
            ));
        }
        assert!(!expected_hello(
            Frame::Accepted {
                protocol: PROTOCOL_VERSION
            },
            &token,
            &key
        ));
    }
}
