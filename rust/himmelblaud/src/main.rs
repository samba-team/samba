/*
   Unix SMB/CIFS implementation.

   Himmelblau daemon

   Copyright (C) David Mulder 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Ignore unused/dead code when running cargo test
#![cfg_attr(test, allow(unused_imports))]
#![cfg_attr(test, allow(dead_code))]

use clap::{Arg, ArgAction, Command};
use dbg::*;
use himmelblau::graph::Graph;
use himmelblau::BrokerClientApplication;
use idmap::Idmap;
use kanidm_hsm_crypto::soft::SoftTpm;
use kanidm_hsm_crypto::{BoxedDynTpm, Tpm};
use param::LoadParm;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Mutex;

mod constants;
use constants::DEFAULT_ODC_PROVIDER;
mod cache;
mod himmelblaud;
use cache::{GroupCache, PrivateCache, UidCache, UserCache};
mod utils;

#[cfg(not(test))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let clap_args = Command::new("himmelblaud")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Samba Himmelblau Authentication Daemon")
        .arg(
            Arg::new("debuglevel")
                .help("Set debug level")
                .short('d')
                .long("debuglevel")
                .value_parser(
                    clap::value_parser!(u16).range(0..(MAX_DEBUG_LEVEL as i64)),
                )
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("debug-stdout")
                .help("Send debug output to standard output")
                .long("debug-stdout")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("configfile")
                .help("Use alternative configuration file")
                .short('s')
                .long("configfile")
                .action(ArgAction::Set),
        )
        .get_matches();

    let stop_now = Arc::new(AtomicBool::new(false));
    let terminate_now = Arc::clone(&stop_now);
    let quit_now = Arc::clone(&stop_now);
    let interrupt_now = Arc::clone(&stop_now);

    async {
        // Set the command line debug level
        if let Some(debuglevel) = clap_args.get_one::<u16>("debuglevel") {
            debuglevel_set!(*debuglevel);
        }

        // Initialize the LoadParm from the command line specified config file
        let lp = match LoadParm::new(
            clap_args
                .get_one::<String>("configfile")
                .map(|x| x.as_str()),
        ) {
            Ok(lp) => lp,
            Err(e) => {
                eprintln!("Failed loading smb.conf: {:?}", e);
                return ExitCode::FAILURE;
            }
        };

        // Check that the realm is configured. This the bare minimum for
        // himmelblaud, since a device join can happen at authentication time,
        // but we need to know the permitted enrollment domain.
        let realm = match lp.realm() {
            Ok(Some(realm)) => realm,
            _ => {
                eprintln!(
                    "The realm MUST be set in the \
                    smb.conf to start himmelblaud"
                );
                return ExitCode::FAILURE;
            }
        };

        // Setup logging, either to the configured logfile, or to stdout, depending
        // on what is specified on the command line.
        match clap_args.get_flag("debug-stdout") {
            true => setup_logging(env!("CARGO_PKG_NAME"), DEBUG_STDOUT),
            false => {
                setup_logging(env!("CARGO_PKG_NAME"), DEBUG_FILE);
                match lp.logfile() {
                    Ok(Some(logfile)) => debug_set_logfile(&logfile),
                    _ => {
                        eprintln!("Failed to determine logfile name");
                        return ExitCode::FAILURE;
                    }
                }
            }
        }

        // Determine the unix socket path
        let sock_dir_str = match lp.winbindd_socket_directory() {
            Ok(Some(sock_dir)) => sock_dir,
            _ => return ExitCode::FAILURE,
        };
        let sock_dir = Path::new(&sock_dir_str);
        let mut sock_path = PathBuf::from(sock_dir);
        sock_path.push("hb_pipe");
        let sock_path = match sock_path.to_str() {
            Some(sock_path) => sock_path,
            None => return ExitCode::FAILURE,
        };

        // Initialize the Himmelblau cache
        let private_cache_path = match lp.private_path("himmelblau.tdb") {
            Ok(Some(private_cache_path)) => private_cache_path,
            _ => {
                DBG_ERR!("Failed to determine private cache path");
                return ExitCode::FAILURE;
            }
        };
        let mut private_dir = Path::new(&private_cache_path).to_path_buf();
        private_dir.pop();
        if !private_dir.exists() {
            DBG_ERR!(
                "The private directory '{}' does not exist",
                private_dir.display()
            );
            return ExitCode::FAILURE;
        }
        let mut pcache = match PrivateCache::new(&private_cache_path) {
            Ok(cache) => cache,
            Err(e) => {
                DBG_ERR!(
                    "Failed to open the himmelblau private cache: {:?}",
                    e
                );
                return ExitCode::FAILURE;
            }
        };

        let cache_dir = match lp.cache_directory() {
            Ok(Some(cache_dir)) => cache_dir,
            _ => {
                DBG_ERR!("Failed to determine cache directory");
                return ExitCode::FAILURE;
            }
        };
        if !Path::new(&cache_dir).exists() {
            DBG_ERR!("The cache directory '{}' does not exist", cache_dir);
            return ExitCode::FAILURE;
        }

        let user_cache_path = Path::new(&cache_dir)
            .join("himmelblau_users.tdb")
            .display()
            .to_string();
        let user_cache = match UserCache::new(&user_cache_path) {
            Ok(cache) => cache,
            Err(e) => {
                DBG_ERR!("Failed to open the himmelblau user cache: {:?}", e);
                return ExitCode::FAILURE;
            }
        };

        let uid_cache_path = Path::new(&cache_dir)
            .join("himmelblau_uid_map.tdb")
            .display()
            .to_string();
        let uid_cache = match UidCache::new(&uid_cache_path) {
            Ok(cache) => cache,
            Err(e) => {
                DBG_ERR!("Failed to open the himmelblau uid cache: {:?}", e);
                return ExitCode::FAILURE;
            }
        };

        let group_cache_path = Path::new(&cache_dir)
            .join("himmelblau_groups.tdb")
            .display()
            .to_string();
        let group_cache = match GroupCache::new(&group_cache_path) {
            Ok(cache) => cache,
            Err(e) => {
                DBG_ERR!("Failed to open the himmelblau group cache: {:?}", e);
                return ExitCode::FAILURE;
            }
        };

        // Check for and create the hsm pin if required.
        let hsm_pin_path = match lp.himmelblaud_hsm_pin_path() {
            Ok(Some(hsm_pin_path)) => hsm_pin_path,
            _ => {
                DBG_ERR!("Failed loading hsm pin path.");
                return ExitCode::FAILURE;
            }
        };
        let mut hsm_pin_dir = Path::new(&hsm_pin_path).to_path_buf();
        hsm_pin_dir.pop();
        if !hsm_pin_dir.exists() {
            DBG_ERR!(
                "The hsm pin directory '{}' does not exist",
                hsm_pin_dir.display()
            );
            return ExitCode::FAILURE;
        }
        let auth_value =
            match utils::hsm_pin_fetch_or_create(&hsm_pin_path).await {
                Ok(auth_value) => auth_value,
                Err(e) => {
                    DBG_ERR!("{:?}", e);
                    return ExitCode::FAILURE;
                }
            };

        // Setup the HSM and its machine key
        let mut hsm: BoxedDynTpm = BoxedDynTpm::new(SoftTpm::new());

        let loadable_machine_key = match pcache
            .loadable_machine_key_fetch_or_create(&mut hsm, &auth_value)
        {
            Ok(lmk) => lmk,
            Err(e) => {
                DBG_ERR!("{:?}", e);
                return ExitCode::FAILURE;
            }
        };

        let res = hsm.machine_key_load(&auth_value, &loadable_machine_key);
        let machine_key = match res {
            Ok(machine_key) => machine_key,
            Err(e) => {
                DBG_ERR!("Unable to load machine root key: {:?}", e);
                DBG_INFO!("This can occur if you have changed your HSM pin.");
                DBG_INFO!(
                    "To proceed, run `tdbtool erase {}`",
                    private_cache_path
                );
                DBG_INFO!("The host will forget domain enrollments.");
                return ExitCode::FAILURE;
            }
        };

        // Get the transport key for a joined domain
        let loadable_transport_key =
            pcache.loadable_transport_key_fetch(&realm);

        // Get the certificate key for a joined domain
        let loadable_cert_key = pcache.loadable_cert_key_fetch(&realm);

        // Contact the odc provider to get the authority host and tenant id
        let graph = match Graph::new(DEFAULT_ODC_PROVIDER, &realm).await {
            Ok(graph) => graph,
            Err(e) => {
                DBG_ERR!("Failed initializing the graph: {:?}", e);
                return ExitCode::FAILURE;
            }
        };
        let authority_host = graph.authority_host();
        let tenant_id = graph.tenant_id();
        let authority = format!("https://{}/{}", authority_host, tenant_id);

        let client = match BrokerClientApplication::new(
            Some(&authority),
            loadable_transport_key,
            loadable_cert_key,
        ) {
            Ok(client) => client,
            Err(e) => {
                DBG_ERR!("Failed initializing the broker: {:?}", e);
                return ExitCode::FAILURE;
            }
        };

        let mut idmap = match Idmap::new() {
            Ok(idmap) => idmap,
            Err(e) => {
                DBG_ERR!("Failed initializing the idmapper: {:?}", e);
                return ExitCode::FAILURE;
            }
        };
        // Configure the idmap range
        let (low, high) = match lp.idmap_range(&realm) {
            Ok(res) => res,
            Err(e) => {
                DBG_ERR!("Failed fetching idmap range: {:?}", e);
                return ExitCode::FAILURE;
            }
        };
        if let Err(e) = idmap.add_gen_domain(&realm, &tenant_id, (low, high)) {
            DBG_ERR!("Failed adding the domain idmap range: {:?}", e);
            return ExitCode::FAILURE;
        }

        let resolver = Arc::new(Mutex::new(himmelblaud::Resolver::new(
            &realm,
            &tenant_id,
            lp,
            idmap,
            graph,
            pcache,
            user_cache,
            uid_cache,
            group_cache,
            hsm,
            machine_key,
            client,
        )));

        // Listen for incoming requests from PAM and NSS
        let listener = match UnixListener::bind(sock_path) {
            Ok(listener) => listener,
            Err(e) => {
                DBG_ERR!("Failed setting up the socket listener: {:?}", e);
                return ExitCode::FAILURE;
            }
        };

        let server = tokio::spawn(async move {
            while !stop_now.load(Ordering::Relaxed) {
                let resolver_ref = resolver.clone();
                match listener.accept().await {
                    Ok((socket, _addr)) => {
                        tokio::spawn(async move {
                            if let Err(e) = himmelblaud::handle_client(
                                socket,
                                resolver_ref.clone(),
                            )
                            .await
                            {
                                DBG_ERR!(
                                    "handle_client error occurred: {:?}",
                                    e
                                );
                            }
                        });
                    }
                    Err(e) => {
                        DBG_ERR!("Error while handling connection: {:?}", e);
                    }
                }
            }
        });

        let terminate_task = tokio::spawn(async move {
            match signal(SignalKind::terminate()) {
                Ok(mut stream) => {
                    stream.recv().await;
                    terminate_now.store(true, Ordering::Relaxed);
                }
                Err(e) => {
                    DBG_ERR!("Failed registering terminate signal: {}", e);
                }
            };
        });

        let quit_task = tokio::spawn(async move {
            match signal(SignalKind::quit()) {
                Ok(mut stream) => {
                    stream.recv().await;
                    quit_now.store(true, Ordering::Relaxed);
                }
                Err(e) => {
                    DBG_ERR!("Failed registering quit signal: {}", e);
                }
            };
        });

        let interrupt_task = tokio::spawn(async move {
            match signal(SignalKind::interrupt()) {
                Ok(mut stream) => {
                    stream.recv().await;
                    interrupt_now.store(true, Ordering::Relaxed);
                }
                Err(e) => {
                    DBG_ERR!("Failed registering interrupt signal: {}", e);
                }
            };
        });

        DBG_INFO!("Server started ...");

        tokio::select! {
            _ = server => {
                DBG_DEBUG!("Main listener task is terminating");
            },
            _ = terminate_task => {
                DBG_DEBUG!("Received signal to terminate");
            },
            _ = quit_task => {
                DBG_DEBUG!("Received signal to quit");
            },
            _ = interrupt_task => {
                DBG_DEBUG!("Received signal to interrupt");
            }
        }

        ExitCode::SUCCESS
    }
    .await
}
