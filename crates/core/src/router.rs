mod services;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc::{self, Sender, SyncSender}
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use naga_abi::MAX_ABI_BYTES;
use naga_ipc::{
    DiagnosticLevel, Handler, HostEvent, Peer, Request, RpcError, RpcResult, ServiceDescriptor
};
use naga_model::{ModuleKey, ResolvedGraph, ResolvedModule};
use semver::Version;
use serde_json::{Value, json, to_vec};

use crate::{
    Configuration, Diagnostic, DiagnosticOrigin, LifecycleState, ModuleSnapshot, ServiceRegistry
};

struct Slot {
    descriptor: ResolvedModule,
    state: LifecycleState,
    peer: Option<Peer>,
    ready: Option<SyncSender<()>>,
    services: BTreeSet<(String, Version)>,
    subscriptions: BTreeSet<String>,
    events: Option<Sender<QueuedEvent>>,
    event_count: Arc<AtomicUsize>,
    pid: Option<u32>
}

struct QueuedEvent {
    event: Arc<HostEvent>,
    counter: Arc<AtomicUsize>,
    bytes: Arc<AtomicUsize>
}

impl Drop for QueuedEvent {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
        self.bytes.fetch_sub(self.event.payload.len(), Ordering::AcqRel);
    }
}

pub(crate) struct Router {
    slots: Mutex<BTreeMap<ModuleKey, Slot>>,
    diagnostics: Mutex<VecDeque<Diagnostic>>,
    configuration: Configuration,
    event_bytes: Arc<AtomicUsize>,
    local_services: ServiceRegistry,
    closed: AtomicBool
}

impl Router {
    pub fn new(graph: &ResolvedGraph, configuration: &Configuration, local_services: ServiceRegistry) -> Arc<Self> {
        let slots = graph.modules.iter().map(|(key, descriptor)| {
            let slot = Slot {
                descriptor: descriptor.clone(),
                state: LifecycleState::Verified,
                peer: None,
                ready: None,
                services: BTreeSet::new(),
                subscriptions: BTreeSet::new(),
                events: None,
                event_count: Arc::new(AtomicUsize::new(0)),
                pid: None
            };
            (key.clone(), slot)
        }).collect();
        Arc::new(Self {
            slots: Mutex::new(slots),
            diagnostics: Mutex::new(VecDeque::new()),
            configuration: configuration.clone(),
            event_bytes: Arc::new(AtomicUsize::new(0)),
            local_services,
            closed: AtomicBool::new(false)
        })
    }

    pub fn handler(self: &Arc<Self>, key: ModuleKey) -> Arc<dyn Handler> {
        Arc::new(ModuleHandler {
            router: Arc::downgrade(self),
            key
        })
    }

    pub fn prepare(&self, key: &ModuleKey, ready: SyncSender<()>) {
        let mut slots = self.slots.lock().unwrap();
        let slot = slots.get_mut(key).unwrap();
        slot.state = LifecycleState::Starting;
        slot.ready = Some(ready);
    }

    pub fn attach(self: &Arc<Self>, key: &ModuleKey, peer: Peer, pid: u32) {
        let (sender, receiver) = mpsc::channel::<QueuedEvent>();
        {
            let mut slots = self.slots.lock().unwrap();
            let slot = slots.get_mut(key).unwrap();
            slot.peer = Some(peer.clone());
            slot.pid = Some(pid);
            slot.events = Some(sender);
        }
        let weak = Arc::downgrade(self);
        let owner = key.clone();
        thread::spawn(move || {
            for item in receiver {
                let Some(router) = weak.upgrade() else { break };
                let active = router.slots.lock().unwrap().get(&owner).is_some_and(|slot| {
                    slot.state == LifecycleState::Running && slot.subscriptions.contains(&item.event.topic)
                });
                if active && let Err(error) = peer.call(Request::DeliverEvent((*item.event).clone()), router.timeout()) {
                    router.record(&owner, DiagnosticLevel::Warn, format!("event delivery failed: {error}"));
                    if matches!(error.code.as_str(), "timeout" | "disconnected" | "native_panic") {
                        router.set_state(&owner, LifecycleState::Failed);
                        peer.close();
                    }
                }
            }
        });
    }

    pub fn set_state(&self, key: &ModuleKey, state: LifecycleState) {
        {
            let mut slots = self.slots.lock().unwrap();
            let slot = slots.get_mut(key).unwrap();
            if slot.state == state { return }
            slot.state = state;
            if matches!(state, LifecycleState::Stopped | LifecycleState::Failed) {
                slot.services.clear();
                slot.subscriptions.clear();
                slot.events = None;
                slot.ready = None;
            }
        }
        if matches!(state, LifecycleState::Stopped | LifecycleState::Failed) {
            self.local_services.release(key);
        }
        let level = if state == LifecycleState::Failed {
            DiagnosticLevel::Error
        } else {
            DiagnosticLevel::Info
        };
        self.record(key, level, format!("lifecycle: {state:?}"));
        let _ = self.publish(key, "core.lifecycle", to_vec(&state).unwrap_or_default(), true);
    }

    pub fn peer(&self, key: &ModuleKey) -> Option<Peer> {
        self.slots.lock().unwrap().get(key).and_then(|slot| slot.peer.clone())
    }
    pub fn state(&self, key: &ModuleKey) -> LifecycleState {
        self.slots.lock().unwrap()[key].state
    }
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.configuration.request_timeout_ms)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    pub fn snapshots(&self) -> Vec<ModuleSnapshot> {
        self.slots.lock().unwrap().iter().map(|(key, slot)| ModuleSnapshot {
            key: key.clone(),
            state: slot.state,
            services: slot.services.iter().map(|(name, version)| ServiceDescriptor {
                name: name.clone(),
                version: version.clone()
            }).collect(),
            pid: slot.pid
        }).collect()
    }

    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        self.diagnostics.lock().unwrap().iter().cloned().collect()
    }

    pub fn record(&self, key: &ModuleKey, level: DiagnosticLevel, message: String) {
        self.record_from(key, DiagnosticOrigin::Core, level, message);
    }

    pub fn record_from(&self, key: &ModuleKey, origin: DiagnosticOrigin, level: DiagnosticLevel, message: String) {
        let mut diagnostics = self.diagnostics.lock().unwrap();
        if diagnostics.len() == self.configuration.diagnostic_capacity {
            diagnostics.pop_front();
        }
        diagnostics.push_back(Diagnostic {
            timestamp_ms: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),
            module: key.clone(),
            level,
            message,
            origin
        });
    }

    fn publish(&self, source: &ModuleKey, topic: &str, payload: Vec<u8>, internal: bool) -> RpcResult {
        if topic.is_empty() || topic.len() > 256 || (!internal && topic.starts_with("core.")) || payload.len() > MAX_ABI_BYTES {
            return Err(RpcError::new("invalid_argument", "invalid event topic or payload"))
        }
        let slots = self.slots.lock().unwrap();
        let targets: Vec<_> = slots.values().filter(|slot| {
            slot.state == LifecycleState::Running && slot.subscriptions.contains(topic) && slot.events.is_some()
        }).collect();
        let reserved = payload.len().checked_mul(targets.len()).ok_or_else(|| RpcError::new("busy", "event budget overflow"))?;
        if targets.iter().any(|slot| {
            slot.event_count.load(Ordering::Acquire) >= self.configuration.event_queue_capacity
        }) || reserved > self.configuration.event_queue_bytes.saturating_sub(self.event_bytes.load(Ordering::Acquire)) {
            return Err(RpcError::new("busy", "event queue capacity exceeded"))
        }
        let event = Arc::new(HostEvent {
            source: source.clone(),
            topic: topic.into(),
            payload
        });
        for slot in &targets {
            slot.event_count.fetch_add(1, Ordering::AcqRel);
            self.event_bytes.fetch_add(event.payload.len(), Ordering::AcqRel);
            let queued = QueuedEvent {
                event: event.clone(),
                counter: slot.event_count.clone(),
                bytes: self.event_bytes.clone()
            };
            let _ = slot.events.as_ref().unwrap().send(queued);
        }
        Ok(json!({ "recipients": targets.len() }))
    }

    fn handle(&self, owner: &ModuleKey, request: Request) -> RpcResult {
        if matches!(self.state(owner), LifecycleState::Failed | LifecycleState::Stopped)
            && !matches!(&request, Request::Diagnostic { .. } | Request::UnregisterService(_) | Request::Unsubscribe { .. }) {
            return Err(RpcError::new("lifecycle", "module is no longer active"))
        }
        match request {
            Request::HostReady => {
                let mut slots = self.slots.lock().unwrap();
                let slot = slots.get_mut(owner).unwrap();
                if slot.state != LifecycleState::Starting {
                    return Err(RpcError::new("lifecycle", "duplicate or unexpected host-ready message"))
                }
                slot.state = LifecycleState::Ready;
                if let Some(ready) = slot.ready.take() {
                    let _ = ready.send(());
                }
                Ok(Value::Null)
            }
            Request::RegisterService(service) => self.service_registration(owner, service, true),
            Request::UnregisterService(service) => self.service_registration(owner, service, false),
            Request::CallService {
                name,
                requirement,
                operation,
                payload
            } => self.call_service(Some(owner), &name, &requirement, &operation, payload),
            Request::Subscribe { topic } => {
                if topic.is_empty() || topic.len() > 256 { return Err(RpcError::new("invalid_argument", "invalid event topic")) }
                self.slots.lock().unwrap().get_mut(owner).unwrap().subscriptions.insert(topic);
                Ok(Value::Null)
            }
            Request::Unsubscribe { topic } => {
                self.slots.lock().unwrap().get_mut(owner).unwrap().subscriptions.remove(&topic);
                Ok(Value::Null)
            }
            Request::Publish { topic, payload } => self.publish(owner, &topic, payload, false),
            Request::Diagnostic { level, message } => {
                if message.len() > 65536 { return Err(RpcError::new("invalid_argument", "diagnostic is too large")) }
                self.record_from(owner, DiagnosticOrigin::Module, level, message);
                Ok(Value::Null)
            }
            _ => Err(RpcError::new("dependency_denied", "request direction is not allowed"))
        }
    }

    fn service_registration(&self, owner: &ModuleKey, service: ServiceDescriptor, add: bool) -> RpcResult {
        let mut slots = self.slots.lock().unwrap();
        let slot = slots.get_mut(owner).unwrap();
        if !slot.descriptor.manifest.provides.iter().any(|provided| provided.name == service.name && provided.version == service.version) {
            return Err(RpcError::new("dependency_denied", "service was not declared in the manifest"))
        }
        if add {
            if slot.state == LifecycleState::Stopping { return Err(RpcError::new("lifecycle", "module is stopping")) }
            if !slot.services.insert((service.name, service.version)) {
                return Err(RpcError::new("invalid_argument", "service already registered"))
            }
        } else {
            slot.services.remove(&(service.name, service.version));
        }
        Ok(Value::Null)
    }

    fn disconnected(&self, key: &ModuleKey) {
        if !matches!(self.state(key), LifecycleState::Stopped | LifecycleState::Stopping | LifecycleState::Failed) {
            self.set_state(key, LifecycleState::Failed);
        }
    }
}

struct ModuleHandler {
    router: Weak<Router>,
    key: ModuleKey
}

impl Handler for ModuleHandler {
    fn handle(&self, request: Request) -> RpcResult {
        self.router.upgrade().ok_or_else(|| RpcError::new("disconnected", "Core stopped"))?.handle(&self.key, request)
    }

    fn disconnected(&self) {
        if let Some(router) = self.router.upgrade() {
            router.disconnected(&self.key);
        }
    }
}
