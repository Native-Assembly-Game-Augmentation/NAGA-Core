use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering}
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use getrandom::fill as fill_random;
use hex::encode as encode_hex;
use naga_ipc::{DiagnosticLevel, Request};
use naga_model::{ModuleKey, Platform, ResolvedGraph, resolve_with_services};
use naga_package::{VerifiedPackage, inspect};
use serde_json::from_value;

use crate::{
    Configuration, CoreError, Diagnostic, DiagnosticOrigin, LifecycleState, ModuleSnapshot,
    RuntimeContext, ServiceRegistry, StartupFailure, abi_version, process::ModuleProcess,
    router::Router
};

pub struct ModuleManager {
    router: Arc<Router>,
    graph: ResolvedGraph,
    processes: Arc<Mutex<BTreeMap<ModuleKey, ModuleProcess>>>,
    monitor_stop: Arc<AtomicBool>,
    monitor: Option<JoinHandle<()>>,
    configuration: Configuration,
    session_directory: PathBuf,
    context: Arc<RuntimeContext>
}

impl ModuleManager {
    pub fn plan(configuration: &Configuration) -> Result<ResolvedGraph, CoreError> {
        Self::plan_with_services(configuration, &ServiceRegistry::default())
    }

    pub fn plan_with_services(configuration: &Configuration, services: &ServiceRegistry) -> Result<ResolvedGraph, CoreError> {
        let (_, graph) = prepare(configuration, services)?;
        Ok(graph)
    }

    pub fn start(configuration: Configuration) -> Result<Self, CoreError> {
        Self::start_cancellable(configuration, &AtomicBool::new(false))
    }

    pub fn start_cancellable(configuration: Configuration, cancellation: &AtomicBool) -> Result<Self, CoreError> {
        Self::start_with_context(configuration, cancellation, Arc::new(RuntimeContext::default()))
    }

    pub fn start_with_context(
        configuration: Configuration, cancellation: &AtomicBool, context: Arc<RuntimeContext>
    ) -> Result<Self, CoreError> {
        let (packages, graph) = prepare(&configuration, &context.services)?;
        let host = match &configuration.host_binary {
            Some(path) => fs::canonicalize(path)?,
            None => env::current_exe()?.with_file_name(if cfg!(windows) {
                "naga-host.exe"
            } else {
                "naga-host"
            })
        };
        if !host.is_file() { return Err(CoreError::Configuration("naga-host executable is missing".into())) }
        fs::create_dir_all(&configuration.data_directory)?;
        let mut random = [0; 16];
        fill_random(&mut random).map_err(|error| CoreError::Lifecycle(error.to_string()))?;
        let session_directory = fs::canonicalize(&configuration.data_directory)?.join(format!("session-{}", encode_hex(random)));
        fs::create_dir(&session_directory)?;
        let mut roots = BTreeMap::new();
        for package in &packages {
            let root = session_directory.join(&package.digest);
            package.extract(&root)?;
            roots.insert((package.manifest.package.id.clone(), package.manifest.package.version.clone()), root);
        }
        let router = Router::new(&graph, &configuration, context.services.clone());
        let mut processes = BTreeMap::new();
        for key in &graph.startup_order {
            let module = &graph.modules[key];
            let root = &roots[&(key.package_id.clone(), key.package_version.clone())];
            let package = find_package(&packages, key);
            let result = (|| {
                if cancellation.load(Ordering::Acquire) { return Err(CoreError::Lifecycle("startup cancelled".into())) }
                if module.dependencies.iter().any(|dependency| router.state(dependency) != LifecycleState::Running) {
                    return Err(CoreError::Lifecycle(format!("{key} dependency is not running")))
                }
                let process = ModuleProcess::spawn(module, root, &package.checksum_files, &host, &configuration, &router, cancellation)?;
                processes.insert(key.clone(), process);
                router.peer(key).unwrap().call_cancellable(
                    Request::Start, Duration::from_millis(configuration.startup_timeout_ms), cancellation
                )?;
                let snapshot = router.snapshots().into_iter().find(|snapshot| &snapshot.key == key).unwrap();
                if module.manifest.provides.iter().any(|declared| {
                    !snapshot.services.iter().any(|service| {
                        service.name == declared.name && service.version == declared.version
                    })
                }) {
                    return Err(CoreError::Lifecycle(format!("{key} did not register its declared services")))
                }
                router.set_state(key, LifecycleState::Running);
                Ok(())
            })();
            if let Err(error) = result {
                let before_rollback = router.diagnostics();
                let detail = |origin| {
                    before_rollback.iter().rev().find(|entry| {
                        &entry.module == key && entry.origin == origin && matches!(entry.level, DiagnosticLevel::Error)
                    }).map(|entry| entry.message.clone())
                };
                let message = detail(DiagnosticOrigin::Module).or_else(|| detail(DiagnosticOrigin::Host))
                    .unwrap_or_else(|| error.to_string());
                router.set_state(key, LifecycleState::Failed);
                stop_all(&mut processes, &graph, &router, configuration.shutdown_timeout_ms);
                let _ = context.diagnostics.save(&session_directory, &router.diagnostics());
                return Err(CoreError::Startup(Box::new(StartupFailure {
                    module: key.clone(),
                    message,
                    diagnostics: router.diagnostics(),
                    modules: router.snapshots(),
                    session_directory,
                    cause: Box::new(error)
                })));
            }
        }
        let processes = Arc::new(Mutex::new(processes));
        let monitor_stop = Arc::new(AtomicBool::new(false));
        let weak_processes = Arc::downgrade(&processes);
        let monitor_router = router.clone();
        let monitor_graph = graph.clone();
        let cancelled = monitor_stop.clone();
        let timeout = configuration.shutdown_timeout_ms;
        let monitor = thread::spawn(move || {
            while !cancelled.load(Ordering::Acquire) {
                let Some(processes) = weak_processes.upgrade() else { break };
                {
                    let mut processes = processes.lock().unwrap();
                    let mut failed = BTreeSet::new();
                    for (key, process) in processes.iter_mut() {
                        if monitor_router.state(key) == LifecycleState::Running
                            && (process.exited().unwrap_or(true) || process.peer.is_closed()) {
                            monitor_router.set_state(key, LifecycleState::Failed);
                        }
                        if monitor_router.state(key) == LifecycleState::Failed {
                            failed.insert(key.clone());
                        }
                    }
                    loop {
                        let before = failed.len();
                        for (key, module) in &monitor_graph.modules {
                            if module.dependencies.iter().any(|dependency| failed.contains(dependency)) {
                                failed.insert(key.clone());
                            }
                        }
                        if before == failed.len() { break }
                    }
                    for key in monitor_graph.startup_order.iter().rev().filter(|key| failed.contains(*key)) {
                        if monitor_router.state(key) != LifecycleState::Failed {
                            monitor_router.record(key, DiagnosticLevel::Error, "dependency failed; stopping dependent module".into());
                            monitor_router.set_state(key, LifecycleState::Stopping);
                            if let Some(process) = processes.get_mut(key) {
                                process.stop(Duration::from_millis(timeout));
                            }
                            monitor_router.set_state(key, LifecycleState::Failed);
                        } else if let Some(process) = processes.get_mut(key) {
                            process.terminate();
                        }
                    }
                }
                thread::sleep(Duration::from_millis(25));
            }
        });
        Ok(Self {
            router,
            graph,
            processes,
            monitor_stop,
            monitor: Some(monitor),
            configuration,
            session_directory,
            context
        })
    }

    pub fn snapshots(&self) -> Vec<ModuleSnapshot> {
        self.router.snapshots()
    }
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        self.router.diagnostics()
    }
    pub fn session_directory(&self) -> &Path {
        &self.session_directory
    }

    pub fn call(&self, name: &str, requirement: &str, operation: &str, payload: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let value = self.router.call_service(None, name, requirement, operation, payload)?;
        from_value(value).map_err(|error| CoreError::Lifecycle(error.to_string()))
    }

    pub fn shutdown(&mut self) -> Result<(), CoreError> {
        if self.monitor_stop.swap(true, Ordering::AcqRel) { return Ok(()) }
        if let Some(monitor) = self.monitor.take() {
            let _ = monitor.join();
        }
        stop_all(&mut self.processes.lock().unwrap(), &self.graph, &self.router, self.configuration.shutdown_timeout_ms);
        self.router.close();
        self.context.diagnostics.save(&self.session_directory, &self.router.diagnostics())?;
        Ok(())
    }

    pub fn call_module(
        &self, module: &ModuleKey, name: &str, requirement: &str, operation: &str, payload: Vec<u8>
    ) -> Result<Vec<u8>, CoreError> {
        let value = self.router.call_targeted(None, Some(module), name, requirement, operation, payload)?;
        from_value(value).map_err(|error| CoreError::Lifecycle(error.to_string()))
    }
}

fn prepare(configuration: &Configuration, services: &ServiceRegistry) -> Result<(Vec<VerifiedPackage>, ResolvedGraph), CoreError> {
    configuration.validate()?;
    let packages: Vec<_> = configuration.packages.iter().map(|path| inspect(path, &configuration.trust, &configuration.package_limits))
        .collect::<Result<_, _>>()?;
    let manifests: Vec<_> = packages.iter().map(|package| {
        let mut manifest = package.manifest.clone();
        manifest.modules.retain(|module| {
            !configuration.disabled_modules.iter().any(|disabled| {
                disabled.package_id == manifest.package.id && disabled.module_id == module.id
            })
        });
        manifest
    }).filter(|manifest| !manifest.modules.is_empty()).collect();
    let roots: Vec<_> = configuration.root_modules.iter().filter(|key| {
        !configuration.disabled_modules.iter().any(|disabled| disabled.matches(key))
    }).cloned().collect();
    let graph = if roots.is_empty() && (!configuration.start_all_modules || !configuration.root_modules.is_empty()) {
        ResolvedGraph {
            modules: BTreeMap::new(),
            startup_order: Vec::new()
        }
    } else {
        resolve_with_services(&manifests, &abi_version(), Platform::current()?, &roots, &services.contracts())?
    };
    if graph.modules.len() > configuration.max_modules { return Err(CoreError::Configuration("module process limit exceeded".into())) }
    Ok((packages, graph))
}

impl Drop for ModuleManager {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn find_package<'a>(packages: &'a [VerifiedPackage], key: &ModuleKey) -> &'a VerifiedPackage {
    packages.iter().find(|package| {
        package.manifest.package.id == key.package_id && package.manifest.package.version == key.package_version
    }).unwrap()
}

fn stop_all(processes: &mut BTreeMap<ModuleKey, ModuleProcess>, graph: &ResolvedGraph, router: &Router, timeout_ms: u64) {
    for key in graph.startup_order.iter().rev() {
        if let Some(process) = processes.get_mut(key) {
            let failed = router.state(key) == LifecycleState::Failed;
            if !failed {
                router.set_state(key, LifecycleState::Stopping);
            }
            process.stop(Duration::from_millis(timeout_ms));
            if !failed {
                router.set_state(key, LifecycleState::Stopped);
            }
        }
    }
    processes.clear();
}
