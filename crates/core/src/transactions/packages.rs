use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::copy;
use std::path::PathBuf;

use getrandom::fill as fill_random;
use hex::encode as encode_hex;
use naga_model::{Manifest, ModuleKey, PackageId};
use naga_package::inspect;
use semver::Version;

use crate::{Configuration, CoreError, ModuleSelector};

type PackageMap = BTreeMap<PackageId, (Manifest, PathBuf)>;

pub(super) fn identity_map(configuration: &Configuration) -> Result<PackageMap, CoreError> {
    let mut packages = BTreeMap::new();
    for path in &configuration.packages {
        let package = inspect(path, &configuration.trust, &configuration.package_limits)?;
        if packages.insert(package.manifest.package.id.clone(), (package.manifest, path.canonicalize()?)).is_some() {
            return Err(CoreError::Configuration("transactions require one active version per package ID".into()))
        }
    }
    Ok(packages)
}

pub(super) fn find_module(configuration: &Configuration, selector: &ModuleSelector) -> Result<ModuleKey, CoreError> {
    let packages = identity_map(configuration)?;
    let manifest = &packages.get(&selector.package_id).ok_or_else(|| missing(selector))?.0;
    if !manifest.modules.iter().any(|module| module.id == selector.module_id) { return Err(missing(selector)) }
    Ok(ModuleKey {
        package_id: selector.package_id.clone(),
        package_version: manifest.package.version.clone(),
        module_id: selector.module_id.clone()
    })
}

pub(super) fn remap_roots(next: &mut Configuration, before: &PackageMap) -> Result<(), CoreError> {
    let after = identity_map(next)?;
    let mut roots = Vec::new();
    for old in &next.root_modules {
        let Some((package, _)) = after.get(&old.package_id) else { continue };
        if !package.modules.iter().any(|module| module.id == old.module_id) {
            return Err(CoreError::Configuration(format!("updated package removed active module {}", old.module_id)))
        }
        roots.push(ModuleKey {
            package_version: package.package.version.clone(),
            ..old.clone()
        });
    }
    if !next.root_modules.is_empty() && roots.is_empty() {
        next.start_all_modules = false;
    }
    next.root_modules = roots;
    for (id, (package, _)) in &after {
        let Some((old, _)) = before.get(id) else { continue };
        if old.package.version == package.package.version { continue }
        migrate_configuration(next, package, &old.package.version);
    }
    Ok(())
}

fn migrate_configuration(configuration: &mut Configuration, package: &Manifest, previous: &Version) {
    for module in &package.modules {
        let key = ModuleKey {
            package_id: package.package.id.clone(),
            package_version: previous.clone(),
            module_id: module.id.clone()
        };
        if let Some(value) = configuration.module_configuration.remove(&key.to_string()) {
            let next = ModuleKey { package_version: package.package.version.clone(), ..key };
            configuration.module_configuration.entry(next.to_string()).or_insert(value);
        }
    }
}

pub(super) fn freeze(configuration: &Configuration) -> Result<Configuration, CoreError> {
    let mut frozen = configuration.clone();
    let cache = configuration.data_directory.join("packages");
    fs::create_dir_all(&cache)?;
    frozen.data_directory = configuration.data_directory.canonicalize()?;
    let cache = cache.canonicalize()?;
    frozen.packages.clear();
    for source in &configuration.packages {
        let package = inspect(source, &configuration.trust, &configuration.package_limits)?;
        let destination = cache.join(format!("{}.nmod", package.digest));
        if !destination.exists() {
            let mut random = [0; 16];
            fill_random(&mut random).map_err(|error| CoreError::Lifecycle(error.to_string()))?;
            let temporary = cache.join(format!("{}.staging.nmod", encode_hex(random)));
            let result = (|| {
                let mut output = OpenOptions::new().create_new(true).write(true).open(&temporary)?;
                copy(&mut File::open(source)?, &mut output)?;
                output.sync_all()?;
                drop(output);
                let verified = inspect(&temporary, &configuration.trust, &configuration.package_limits)?;
                if verified.digest != package.digest { return Err(CoreError::Configuration("package changed during staging".into())) }
                fs::rename(&temporary, &destination)?;
                Ok(())
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result?;
        }
        if inspect(&destination, &configuration.trust, &configuration.package_limits)?.digest != package.digest {
            return Err(CoreError::Configuration("cached package integrity failed".into()))
        }
        frozen.packages.push(destination);
    }
    Ok(frozen)
}

fn missing(selector: &ModuleSelector) -> CoreError {
    CoreError::Configuration(format!("unknown module {}/{}", selector.package_id, selector.module_id))
}
