//! CLI mode for dnsblk.
//!
//! Runs the eBPF DNS blocker as a foreground process, logging blocked
//! domain events and status messages through the `log` crate facade.

use std::{
    collections::HashMap as StdHashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Instant,
};

use anyhow::Result;
use clap::Parser;

use dnsblk::{check_domain, is_root, run_blocker, validate_block_event, WorkerHandle, WorkerMsg};

/// DNS-blocking CLI that attaches an eBPF tc classifier to block DNS queries
/// for domains in the deny list.
#[derive(Parser)]
#[command(name = "dnsblk", about = "eBPF DNS blocker — CLI mode")]
struct Args {
    /// Network interface to attach the eBPF filter to
    #[arg(default_value = "eth0", short, long)]
    interface: String,

    /// Deny list file (one domain per line, '#' for comments)
    list: PathBuf,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("LOG", "info")).init();

    if !validate_block_event() {
        log::error!("BlockEvent size mismatch with eBPF — rebuild eBPF first");
        std::process::exit(1);
    }

    if !is_root() {
        log::error!("This program requires root privileges. Please run with sudo.");
        std::process::exit(1);
    }

    let args = Args::parse();
    match run_cli(args) {
        Ok(()) => {}
        Err(e) => {
            log::error!("{e:#}");
            std::process::exit(1);
        }
    }
}

/// Entry point for CLI mode.
fn run_cli(args: Args) -> Result<()> {
    if !args.list.exists() {
        anyhow::bail!("Deny list file not found: {}", args.list.display());
    }

    let (tx, rx) = mpsc::channel::<WorkerMsg>();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let ifaces = vec![args.interface];
    let deny_file = args.list;

    let join = thread::spawn(move || {
        let result = run_blocker(&ifaces, &deny_file, tx.clone(), stop_clone);
        if let Err(err) = result {
            let _ = tx.send(WorkerMsg::Error(format!("{err:#}")));
        }
        let _ = tx.send(WorkerMsg::Stopped);
    });

    let handle = WorkerHandle { stop, join };

    let stop_signal = handle.stop.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build();
        let Ok(rt) = rt else {
            log::error!("Failed to create signal runtime");
            return;
        };
        rt.block_on(async {
            let _ = tokio::signal::ctrl_c().await;
        });
        log::info!("Shutting down...");
        stop_signal.store(true, Ordering::Relaxed);
    });

    let mut recent_domains: StdHashMap<String, (Instant, u32)> = StdHashMap::new();

    loop {
        match rx.recv() {
            Ok(WorkerMsg::Info(line)) => {
                log::info!("{line}");
            }
            Ok(WorkerMsg::Blocked(line)) => {
                let domain = line.find(" : ").map_or(line.as_str(), |i| &line[i + 3..]);
                let now = Instant::now();
                if let Some(count) = check_domain(&mut recent_domains, domain, now) {
                    if count > 0 {
                        log::info!("{line} ({count})");
                    } else {
                        log::info!("{line}");
                    }
                }
            }
            Ok(WorkerMsg::Error(line)) => {
                log::error!("{line}");
            }
            Ok(WorkerMsg::Stopped) | Err(_) => {
                break;
            }
        }
    }

    handle.join.join().ok();
    Ok(())
}
