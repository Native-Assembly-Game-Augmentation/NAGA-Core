use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering}
};
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use ctrlc::set_handler;
use ed25519_dalek::SigningKey;
use getrandom::fill as fill_random;
use hex::{decode as decode_hex, encode as encode_hex};
use naga_core::{Configuration, ModuleManager};
use naga_package::{PackSigner, PackageLimits, TrustPolicy, inspect, pack};
use serde_json::{Value, from_slice, json, to_string_pretty};

#[derive(Parser)]
#[command(version, about = "Native module platform")]
struct Arguments {
    #[command(subcommand)]
    command: Command
}

#[derive(Subcommand)]
enum Command {
    Pack {
        directory: PathBuf,
        output: PathBuf,
        #[arg(long, requires = "key_id")]
        secret_key: Option<PathBuf>,
        #[arg(long, requires = "secret_key")]
        key_id: Option<String>
    },
    Inspect {
        package: PathBuf,
        #[arg(long)]
        trust: Option<PathBuf>
    },
    Plan {
        config: PathBuf
    },
    Keygen {
        secret: PathBuf,
        public: PathBuf
    },
    Run {
        config: PathBuf,
        #[arg(long)]
        duration_ms: Option<u64>,
        #[arg(long)]
        call: Option<String>,
        #[arg(long, default_value = "^1")]
        requirement: String,
        #[arg(long, default_value = "probe")]
        operation: String,
        #[arg(long, default_value = "{}")]
        payload: String
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("NAGA: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    match Arguments::parse().command {
        Command::Pack {
            directory,
            output,
            secret_key,
            key_id
        } => {
            let signer = match secret_key {
                Some(path) => Some(PackSigner {
                    key_id: key_id.unwrap(),
                    secret: read_key(&path)?
                }),
                None => None
            };
            pack(&directory, &output, signer.as_ref())?;
            println!("{}", json!({ "package": output, "packed": true }));
        }
        Command::Inspect { package, trust } => {
            let trust: TrustPolicy = match trust {
                Some(path) => from_slice(&fs::read(path)?)?,
                None => TrustPolicy::default()
            };
            let verified = inspect(&package, &trust, &PackageLimits::default())?;
            println!(
                "{}",
                to_string_pretty(
                    &json!({ "manifest": verified.manifest, "signature": verified.signature, "sha256": verified.digest, "files": verified.checksum_files.len() })
                )?
            );
        }
        Command::Plan { config } => {
            let config = Configuration::load(&config)?;
            let graph = ModuleManager::plan(&config)?;
            println!(
                "{}",
                to_string_pretty(
                    &json!({ "startup_order": graph.startup_order, "modules": graph.modules.values().collect::<Vec<_>>() })
                )?
            );
        }
        Command::Keygen { secret, public } => {
            let mut bytes = [0; 32];
            fill_random(&mut bytes).map_err(|error| error.to_string())?;
            let key = SigningKey::from_bytes(&bytes);
            create_file(&secret, encode_hex(bytes).as_bytes(), true)?;
            create_file(&public, encode_hex(key.verifying_key().to_bytes()).as_bytes(), false)?;
            println!("{}", json!({ "public_key_file": public, "secret_key_file": secret }));
        }
        Command::Run {
            config,
            duration_ms,
            call,
            requirement,
            operation,
            payload
        } => {
            let mut manager = ModuleManager::start(Configuration::load(&config)?)?;
            println!("{}", json!({ "event": "running", "modules": manager.snapshots() }));
            if let Some(name) = call {
                let bytes = manager.call(&name, &requirement, &operation, payload.into_bytes())?;
                let value = from_slice::<Value>(&bytes).unwrap_or_else(|_| json!({ "hex": encode_hex(bytes) }));
                println!("{}", json!({ "event": "call_result", "value": value }));
            } else {
                let stop = Arc::new(AtomicBool::new(false));
                let signal = stop.clone();
                set_handler(move || signal.store(true, Ordering::Release))?;
                let start = Instant::now();
                while !stop.load(Ordering::Acquire)
                    && duration_ms.is_none_or(|duration| start.elapsed() < Duration::from_millis(duration)) {
                    thread::sleep(Duration::from_millis(25));
                }
            }
            manager.shutdown()?;
            println!(
                "{}",
                json!({ "event": "stopped", "diagnostics": manager.diagnostics(), "session": manager.session_directory() })
            );
        }
    }
    Ok(())
}

fn read_key(path: &PathBuf) -> Result<[u8; 32], Box<dyn Error>> {
    decode_hex(fs::read_to_string(path)?.trim())?.try_into().map_err(|_| "expected a 32-byte hexadecimal key".into())
}

fn create_file(path: &PathBuf, bytes: &[u8], secret: bool) -> Result<(), Box<dyn Error>> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        options.mode(if secret { 384 } else { 420 });
    }
    #[cfg(not(unix))]
    let _ = secret;
    options.open(path)?.write_all(bytes)?;
    Ok(())
}
