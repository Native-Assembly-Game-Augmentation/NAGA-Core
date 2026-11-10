mod packages;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, atomic::AtomicBool};

use naga_model::{PackageId, ResolvedGraph};
use naga_package::inspect;
use serde_json::Value;

use self::packages::{freeze, identity_map, remap_roots};
use crate::{
    Configuration, ConfigurationStore, CoreError, ModuleManager, ModuleSelector, RuntimeContext,
    StoredConfiguration
};

#[derive(Default)]
pub struct ModuleChanges {
    pub install: Vec<PathBuf>,
    pub remove: Vec<PackageId>,
    pub enable: Vec<ModuleSelector>,
    pub disable: Vec<ModuleSelector>,
    pub configure: BTreeMap<String, Value>
}

pub struct TransactionPlan {
    base_revision: u64,
    configuration: Configuration,
    graph: ResolvedGraph,
    digests: BTreeMap<PathBuf, String>
}

impl TransactionPlan {
    pub fn base_revision(&self) -> u64 {
        self.base_revision
    }
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    pub fn graph(&self) -> &ResolvedGraph {
        &self.graph
    }
}

pub trait RuntimeDriver: Send {
    fn activate(&mut self, configuration: &Configuration) -> Result<(), CoreError>;
    fn deactivate(&mut self) -> Result<(), CoreError>;
}

pub struct NativeRuntime {
    manager: Option<ModuleManager>,
    context: Arc<RuntimeContext>
}

impl NativeRuntime {
    pub fn new(context: Arc<RuntimeContext>) -> Self {
        Self {
            manager: None,
            context
        }
    }
    pub fn manager(&self) -> Option<&ModuleManager> {
        self.manager.as_ref()
    }
}

impl RuntimeDriver for NativeRuntime {
    fn activate(&mut self, configuration: &Configuration) -> Result<(), CoreError> {
        if self.manager.is_some() { return Err(failed("runtime is already active")) }
        self.manager = Some(ModuleManager::start_with_context(configuration.clone(), &AtomicBool::new(false), self.context.clone())?);
        Ok(())
    }

    fn deactivate(&mut self) -> Result<(), CoreError> {
        if let Some(mut manager) = self.manager.take() {
            manager.shutdown()?;
        }
        Ok(())
    }
}

pub struct ModuleTransactionManager<D: RuntimeDriver> {
    stored: StoredConfiguration,
    store: Arc<dyn ConfigurationStore>,
    context: Arc<RuntimeContext>,
    runtime: D,
    healthy: bool
}

impl<D: RuntimeDriver> ModuleTransactionManager<D> {
    pub fn open(
        initial: Configuration, store: Arc<dyn ConfigurationStore>, context: Arc<RuntimeContext>, mut runtime: D
    ) -> Result<Self, CoreError> {
        let stored = match store.load()? {
            Some(stored) => stored,
            None => {
                let configuration = freeze(&initial)?;
                ModuleManager::plan_with_services(&configuration, &context.services)?;
                store.commit(None, &configuration)?
            }
        };
        ModuleManager::plan_with_services(&stored.configuration, &context.services)?;
        runtime.activate(&stored.configuration)?;
        Ok(Self {
            stored,
            store,
            context,
            runtime,
            healthy: true
        })
    }

    pub fn current(&self) -> &StoredConfiguration {
        &self.stored
    }
    pub fn runtime(&self) -> &D {
        &self.runtime
    }
    pub fn is_healthy(&self) -> bool {
        self.healthy
    }

    pub fn plan(&self, changes: ModuleChanges) -> Result<TransactionPlan, CoreError> {
        let mut next = self.stored.configuration.clone();
        let before = identity_map(&next)?;
        let mut packages: BTreeMap<_, _> = before.iter().map(|(id, (_, path))| (id.clone(), path.clone())).collect();
        let mut changed = BTreeSet::new();
        for path in &changes.install {
            let package = inspect(path, &next.trust, &next.package_limits)?;
            if !changed.insert(package.manifest.package.id.clone()) { return Err(failed("duplicate package change")) }
            packages.insert(package.manifest.package.id, path.canonicalize()?);
        }
        for id in &changes.remove {
            if !changed.insert(id.clone()) || packages.remove(id).is_none() { return Err(failed("invalid package removal")) }
        }
        next.packages = packages.into_values().collect();
        remap_roots(&mut next, &before)?;
        let mut disabled: BTreeSet<_> = next.disabled_modules.iter().cloned().collect();
        for selector in &changes.enable {
            disabled.remove(selector);
            if !next.start_all_modules || !next.root_modules.is_empty() {
                let key = packages::find_module(&next, selector)?;
                if !next.root_modules.contains(&key) {
                    next.root_modules.push(key);
                }
            }
        }
        for selector in &changes.disable {
            packages::find_module(&next, selector)?;
            if changes.enable.contains(selector) { return Err(failed("module is both enabled and disabled")) }
            disabled.insert(selector.clone());
        }
        next.disabled_modules = disabled.into_iter().collect();
        next.module_configuration.extend(changes.configure);
        let graph = ModuleManager::plan_with_services(&next, &self.context.services)?;
        let digests = next.packages.iter().map(|path| {
            let package = inspect(path, &next.trust, &next.package_limits)?;
            Ok((path.clone(), package.digest))
        }).collect::<Result<_, CoreError>>()?;
        Ok(TransactionPlan {
            base_revision: self.stored.revision,
            configuration: next,
            graph,
            digests
        })
    }

    pub fn apply(&mut self, plan: TransactionPlan) -> Result<&StoredConfiguration, CoreError> {
        if !self.healthy { return Err(failed("runtime requires recovery")) }
        if plan.base_revision != self.stored.revision || self.store.load()?.map(|value| value.revision) != Some(self.stored.revision) {
            return Err(failed("transaction plan is stale"))
        }
        for (path, digest) in &plan.digests {
            if inspect(path, &plan.configuration.trust, &plan.configuration.package_limits)?.digest != *digest {
                return Err(failed("package changed after transaction planning"))
            }
        }
        let next = freeze(&plan.configuration)?;
        ModuleManager::plan_with_services(&next, &self.context.services)?;
        if let Err(error) = self.runtime.deactivate() { return self.restore(error) }
        self.healthy = false;
        let outcome = self.runtime.activate(&next).and_then(|()| self.store.commit(Some(self.stored.revision), &next));
        match outcome {
            Ok(stored) => {
                self.stored = stored;
                self.healthy = true;
                Ok(&self.stored)
            }
            Err(error) => self.restore(error)
        }
    }

    pub fn recover(&mut self) -> Result<(), CoreError> {
        self.healthy = false;
        self.runtime.deactivate()?;
        let stored = self.store.load()?.ok_or_else(|| failed("committed configuration is unavailable"))?;
        ModuleManager::plan_with_services(&stored.configuration, &self.context.services)?;
        self.runtime.activate(&stored.configuration)?;
        self.stored = stored;
        self.healthy = true;
        Ok(())
    }

    fn restore(&mut self, cause: CoreError) -> Result<&StoredConfiguration, CoreError> {
        let rollback = self.recover();
        match rollback {
            Ok(()) => {
                self.healthy = true;
                Err(failed(format!("transaction failed; committed runtime restored: {cause}")))
            }
            Err(error) => Err(failed(format!("transaction failed: {cause}; rollback failed: {error}")))
        }
    }
}

impl<D: RuntimeDriver> Drop for ModuleTransactionManager<D> {
    fn drop(&mut self) {
        let _ = self.runtime.deactivate();
    }
}

fn failed(message: impl Into<String>) -> CoreError {
    CoreError::Lifecycle(message.into())
}
