use std::collections::{BTreeMap, BTreeSet};
use semver::Version;
use serde::{Deserialize, Serialize};
use crate::manifest::{Manifest, ModuleManifest, Platform, ServiceContract};
use crate::{ModelError, ModuleKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedModule {
    pub key: ModuleKey,
    pub manifest: ModuleManifest,
    pub dependencies: Vec<ModuleKey>
}

#[derive(Debug, Clone)]
pub struct ResolvedGraph {
    pub modules: BTreeMap<ModuleKey, ResolvedModule>,
    pub startup_order: Vec<ModuleKey>
}

pub fn resolve(packages: &[Manifest], abi: &Version, platform: Platform) -> Result<ResolvedGraph, ModelError> {
    resolve_with_roots(packages, abi, platform, &[])
}

pub fn resolve_with_roots(packages: &[Manifest], abi: &Version, platform: Platform,
                          roots: &[ModuleKey]) -> Result<ResolvedGraph, ModelError> {
    resolve_with_services(packages, abi, platform, roots, &[])
}

pub fn resolve_with_services(packages: &[Manifest], abi: &Version, platform: Platform,
                             roots: &[ModuleKey], local_services: &[ServiceContract]) -> Result<ResolvedGraph, ModelError> {
    let mut modules = BTreeMap::new();
    for pkg in packages {
        pkg.validate()?;
        for module in &pkg.modules {
            if module.provides.iter().any(|provided|
                local_services.iter().any(|local| local.name == provided.name)
            ) {
                return Err(ModelError::Resolution("module attempts to shadow a local service".into()))
            }

            let key = ModuleKey {
                package_id: pkg.package.id.clone(),
                package_version: pkg.package.version.clone(),
                module_id: module.id.clone()
            };

            if modules.insert(key.clone(), ResolvedModule {
                key, manifest: module.clone(), dependencies: Vec::new()
            }).is_some() {
                return Err(ModelError::Resolution(
                    "duplicate package version and module identity".into()
                ))
            }
        }
    }

    let mut pending: Vec<_> = if roots.is_empty() {
        modules.keys().cloned().collect()
    } else { roots.to_vec() };

    let mut selected = BTreeSet::new();

    while let Some(node) = pending.pop() {
        if !selected.insert(node.clone()) { continue }

        let key = &node;
        let module = modules.get(key).ok_or_else(|| ModelError::Resolution(format!("unknown root {key}")))?;

        if module.manifest.abi_min.major != abi.major || &module.manifest.abi_min > abi { return Err(
            ModelError::Resolution(format!("{key} requires ABI {} (host {abi})", module.manifest.abi_min))
        ) }

        if !module.manifest.libraries.contains_key(&platform) { return Err(ModelError::Resolution(
            format!("{key} has no {} library", platform.directory())
        )) }

        let mut dependencies = Vec::new();
        for dependency in &modules[key].manifest.dependencies {
            let selected = modules.values().filter(|candidate|
                candidate.key.package_id == dependency.package_id
                    && candidate.key.module_id == dependency.module_id
                    && dependency.version.matches(&candidate.manifest.version)
                    && compatible(candidate, abi, platform)
                    && dependency.package_version.as_ref().is_none_or(|req| req.matches(&candidate.key.package_version))
            ).max_by(|left, right|
                left.manifest.version.cmp(&right.manifest.version).then_with(|| left.key.cmp(&right.key))
            ).ok_or_else(|| ModelError::Resolution(format!(
                "{key} is missing {} / {} {}",
                dependency.package_id, dependency.module_id, dependency.version
            )))?;

            dependencies.push(selected.key.clone())
        }

        let declared: BTreeSet<_> = dependencies.iter().cloned().collect();
        for requires in &modules[key].manifest.requires_services {
            if local_services.iter().any(|local|
                local.name == requires.name && requires.version.matches(&local.version)
            ) { continue }

            let selected = modules.values().flat_map(|candidate|
                candidate.manifest.provides.iter().map(move |service| (candidate, service))
            ).filter(|(candidate, service)|
                &candidate.key != key && compatible(candidate, abi, platform)
                    && service.name == requires.name && requires.version.matches(&service.version)
            ).max_by(|(left, left_service), (right, right_service)|
                declared.contains(&left.key).cmp(&declared.contains(&right.key))
                    .then_with(|| left_service.version.cmp(&right_service.version))
                    .then_with(|| left.key.cmp(&right.key))
            ).ok_or_else(|| ModelError::Resolution(format!(
                "{key} is missing service {} {}", requires.name, requires.version
            )))?;

            dependencies.push(selected.0.key.clone());
        }

        dependencies.sort();
        dependencies.dedup();
        pending.extend(dependencies.iter().cloned());
        modules.get_mut(key).unwrap().dependencies = dependencies;
    }

    let modules: BTreeMap<_, _> = modules.into_iter().filter(|(key, _)| selected.contains(key)).collect();
    let keys: Vec<_> = modules.keys().cloned().collect();
    let mut order = Vec::new();
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for key in keys {
        visit(&key, &modules, &mut visiting, &mut visited, &mut order)?;
    }

    Ok(ResolvedGraph {
        modules,
        startup_order: order
    })
}

fn compatible(module: &ResolvedModule, abi: &Version, platform: Platform) -> bool {
    module.manifest.abi_min.major == abi.major && &module.manifest.abi_min <= abi
        && module.manifest.libraries.contains_key(&platform)
}

fn visit(key: &ModuleKey, modules: &BTreeMap<ModuleKey, ResolvedModule>,
         visiting: &mut BTreeSet<ModuleKey>, visited: &mut BTreeSet<ModuleKey>,
         order: &mut Vec<ModuleKey>) -> Result<(), ModelError> {
    if visited.contains(key) { return Ok(()) }

    if !visiting.insert(key.clone()) { return Err(ModelError::Resolution(format!("dependency cycle at {key}"))) }

    for dependency in &modules[key].dependencies {
        visit(dependency, modules, visiting, visited, order)?
    }

    visiting.remove(key);
    visited.insert(key.clone());
    order.push(key.clone());

    Ok(())
}
