use anyhow::{anyhow, Context, Result};
use hal_core::PortableIdentity;
use hal_storage::ClientStorage;
use hal_sync::{HomeSecret, HomeStack, PeerRuntime, PollDispatcher};
use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::{Arc, Mutex};
use std::{
    collections::HashSet,
    io::IsTerminal,
    path::{Path, PathBuf},
};
use tokio::io::{AsyncBufReadExt, BufReader};
use zeroize::Zeroizing;

const STORAGE_KEY: &[u8] = b"HAL VPS relay SQLCipher key v1";

fn configure_cli() -> Result<bool> {
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--relay-mode" => {}
            "--wss-url" => {
                let url = args
                    .next()
                    .ok_or_else(|| anyhow!("--wss-url requires a URL"))?;
                if !(url.starts_with("https://") || url.starts_with("wss://")) {
                    return Err(anyhow!("--wss-url must use https:// or wss://"));
                }
                std::env::set_var("HAL_WSS_URL", url);
            }
            "--help" | "-h" => {
                println!("Usage: hal-relay [--relay-mode] [--wss-url <https://|wss:// URL>]");
                return Ok(false);
            }
            _ => return Err(anyhow!("unknown argument: {argument}")),
        }
    }
    Ok(true)
}

fn required_file_path(name: &str) -> Result<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("{name} must point to a mounted secret file"))
}

fn read_secret(path: &Path, name: &str) -> Result<String> {
    let value = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {name}"))?
        .trim()
        .to_owned();
    if value.is_empty() {
        return Err(anyhow!("{name} is empty"));
    }
    Ok(value)
}

async fn run() -> Result<()> {
    let identity_path = required_file_path("HAL_IDENTITY_SEED_FILE")?;
    let seed_phrase = Zeroizing::new(read_secret(&identity_path, "identity seed file")?);
    let identity = PortableIdentity::from_seed_phrase(seed_phrase.as_str())
        .context("invalid identity seed")?;
    let (private_key, _) = PortableIdentity::keypair_from_seed_phrase(seed_phrase.as_str())
        .context("could not derive identity signing key")?;
    let private_key = Zeroizing::new(private_key);

    let data_dir = std::env::var_os("HAL_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/hal-relay"));
    std::fs::create_dir_all(&data_dir).context("could not create relay data directory")?;
    let mut storage_key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(STORAGE_KEY), private_key.as_ref())
        .expand(b"client-storage", storage_key.as_mut())
        .map_err(|_| anyhow!("could not derive relay storage key"))?;
    let storage = Arc::new(Mutex::new(
        ClientStorage::open(data_dir.join("client.sqlite3"), &*storage_key)
            .context("could not open encrypted relay storage")?,
    ));

    let home_stack_path = std::env::var_os("HAL_HOME_STACK_FILE").map(PathBuf::from);
    let home_secret_path = std::env::var_os("HAL_HOME_SECRET_FILE").map(PathBuf::from);
    let saved_home = match (home_stack_path, home_secret_path) {
        (Some(stack_path), Some(secret_path)) => Some((
            read_secret(&stack_path, "home stack file")?,
            read_secret(&secret_path, "home secret file")?,
        )),
        (None, None) => None,
        _ => {
            return Err(anyhow!(
                "HAL_HOME_STACK_FILE and HAL_HOME_SECRET_FILE must be configured together"
            ));
        }
    };

    let port = PeerRuntime::configured_peer_port()?;
    let mut runtime = PeerRuntime::start_with_storage_and_port(
        identity.identity_id.clone(),
        *private_key,
        "hal-vps-relay".to_string(),
        Arc::clone(&storage),
        port,
    )
    .await
    .with_context(|| format!("could not start PeerRuntime on port {port}"))?;

    if let Some((stack_json, secret_hex)) = saved_home {
        let home_stack: HomeStack =
            serde_json::from_str(&stack_json).context("home stack file contains invalid JSON")?;
        let secret_bytes = Zeroizing::new(
            hex::decode(secret_hex).context("home secret file must contain hexadecimal bytes")?,
        );
        let secret_array: [u8; 32] = secret_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("home secret must contain exactly 32 bytes"))?;
        runtime
            .register_home_stack(&home_stack, HomeSecret::from_bytes(secret_array))
            .await
            .context("could not register relay Home Stack")?;
        log::info!("Relay Home Stack loaded");
    } else {
        log::warn!("No Home Stack configured; trusted-client relay policy will reject requests");
    }

    runtime
        .start_discovery(Some(Arc::clone(&storage)), 900)
        .await
        .context("could not start endpoint discovery")?;
    runtime
        .start_dispatch_loop(Arc::new(PollDispatcher::default()))
        .await
        .context("could not start relay dispatch loop")?;
    runtime
        .enable_relay_mode()
        .await
        .context("could not enable trusted relay mode")?;

    log::info!(
        "HAL headless relay ready: identity={}, public_key={}, TCP port={port}",
        runtime.identity_id,
        runtime.public_key
    );
    log::info!("Start WSS SAS pairing from the client; the six-digit code is session-specific.");
    if !std::io::stdin().is_terminal() {
        log::warn!("Relay stdin is not interactive; SAS pairing confirmations require a terminal.");
    }

    let mut input = BufReader::new(tokio::io::stdin()).lines();
    let mut input_open = std::io::stdin().is_terminal();
    let mut reported_sessions = HashSet::new();
    let mut prompt_poll = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed while waiting for shutdown signal")?;
                break;
            }
            _ = prompt_poll.tick() => {
                for prompt in runtime.pending_sas_pairing_prompts().await {
                    if reported_sessions.insert(prompt.session_id.clone()) {
                        log::info!(
                            "WSS SAS pairing: peer={}, session_id={}, code={}",
                            prompt.peer_identity_id,
                            prompt.session_id,
                            prompt.code
                        );
                        log::info!(
                            "Compare this code with the client, then type `confirm {}` or `reject {}` here.",
                            prompt.session_id,
                            prompt.session_id
                        );
                    }
                }
            }
            line = input.next_line(), if input_open => {
                match line.context("could not read relay pairing command")? {
                    Some(line) => {
                        let mut parts = line.split_whitespace();
                        let command = parts.next();
                        let session_id = parts.next();
                        let extra = parts.next();
                        match (command, session_id, extra) {
                            (Some("confirm"), Some(session_id), None)
                                if reported_sessions.contains(session_id) =>
                            {
                                runtime.confirm_sas_pairing(session_id, true).await
                                    .with_context(|| format!("could not confirm SAS session {session_id}"))?;
                                reported_sessions.remove(session_id);
                                log::info!("SAS confirmation sent for session {session_id}");
                            }
                            (Some("reject"), Some(session_id), None)
                                if reported_sessions.contains(session_id) =>
                            {
                                runtime.confirm_sas_pairing(session_id, false).await
                                    .with_context(|| format!("could not reject SAS session {session_id}"))?;
                                reported_sessions.remove(session_id);
                                log::info!("SAS session {session_id} rejected");
                            }
                            (None, _, _) => {}
                            _ => log::warn!("Unknown relay command; use `confirm <session_id>` or `reject <session_id>` for a displayed SAS session"),
                        }
                    }
                    None => input_open = false,
                }
            }
        }
    }
    log::info!("Shutdown requested; stopping HAL headless relay");
    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match configure_cli() {
        Ok(true) => {}
        Ok(false) => return,
        Err(error) => {
            log::error!("Invalid command line: {error:#}");
            std::process::exit(2);
        }
    }
    if let Err(error) = run().await {
        log::error!("HAL headless relay failed: {error:#}");
        std::process::exit(1);
    }
}
