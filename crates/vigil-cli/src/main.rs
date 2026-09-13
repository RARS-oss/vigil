//! vigil — scan an LLM-application target with a versioned attack payload set and emit a signed,
//! reproducible receipt; verify one offline with `vigil verify`.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use vigil_core as vc;

#[derive(Parser)]
#[command(
    name = "vigil",
    version,
    about = "OWASP LLM Top-10 red-team scanner with Ed25519-signed, reproducible receipts"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Inspect the built-in payload registry.
    Payloads(PayloadsArgs),
    /// Run a payload set against a target and write a signed receipt.
    Scan(ScanArgs),
    /// Verify a receipt offline: signature, digest, and event chain.
    Verify(VerifyArgs),
    /// Print the public key for a signing seed (creating it if absent).
    Keygen(KeygenArgs),
}

#[derive(Parser)]
struct PayloadsArgs {
    #[command(subcommand)]
    cmd: PayloadsCmd,
}

#[derive(Subcommand)]
enum PayloadsCmd {
    /// List every payload's id, technique, and description.
    List,
    /// Print the set's version, content-addressed root, and staleness.
    Info,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum AdapterKind {
    /// Any OpenAI-compatible `/chat/completions` endpoint.
    Openai,
    /// Echoes prompts back verbatim. For exercising the harness offline — not a real target.
    Echo,
}

#[derive(Parser)]
struct ScanArgs {
    #[arg(long, value_enum, default_value = "openai")]
    adapter: AdapterKind,
    /// Base URL for the openai adapter, e.g. https://api.openai.com/v1 or http://localhost:11434/v1.
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long, default_value = "gpt-4o-mini")]
    model: String,
    #[arg(long, env = "VIGIL_TARGET_API_KEY")]
    api_key: Option<String>,
    /// System prompt to configure the target with on every probe (the target's own configuration,
    /// not part of the attack).
    #[arg(long)]
    system_prompt: Option<String>,
    #[arg(long, default_value = "vigil-receipt.json")]
    out: PathBuf,
    /// Ed25519 signing seed file. Default: ~/.vigil/ed25519.seed (created if absent).
    #[arg(long)]
    key: Option<PathBuf>,
    /// Emit a compact JSON summary to stdout instead of the human-readable report.
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct VerifyArgs {
    /// Path to a vigil-receipt.json.
    receipt: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct KeygenArgs {
    #[arg(long)]
    key: Option<PathBuf>,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Payloads(a) => cmd_payloads(a),
        Cmd::Scan(a) => cmd_scan(a),
        Cmd::Verify(a) => cmd_verify(a),
        Cmd::Keygen(a) => cmd_keygen(a),
    }
}

fn cmd_payloads(a: PayloadsArgs) -> Result<()> {
    let set = vc::PayloadSet::builtin_llm01();
    match a.cmd {
        PayloadsCmd::List => {
            for p in &set.payloads {
                println!("{:<40} {:<24} {}", p.id, p.technique, p.description);
            }
        }
        PayloadsCmd::Info => {
            let now = now_epoch();
            let age = set.age_days(now);
            println!("version {}", set.version);
            println!("root    {}", set.root);
            println!("count   {}", set.payloads.len());
            println!(
                "age     {} day(s){}",
                age,
                if set.is_stale(now) {
                    format!("  ** STALE (>{} days) **", vc::STALE_AFTER_DAYS)
                } else {
                    String::new()
                }
            );
        }
    }
    Ok(())
}

fn build_adapter(a: &ScanArgs) -> Result<Box<dyn vc::TargetAdapter>> {
    match a.adapter {
        AdapterKind::Echo => Ok(Box::new(vc::EchoAdapter)),
        AdapterKind::Openai => {
            let base_url = a
                .base_url
                .clone()
                .context("--base-url is required for the openai adapter")?;
            let mut adapter = vc::OpenAiCompatAdapter::new(base_url, a.model.clone());
            if let Some(k) = &a.api_key {
                adapter = adapter.with_api_key(k.clone());
            }
            Ok(Box::new(adapter))
        }
    }
}

fn cmd_scan(a: ScanArgs) -> Result<()> {
    let adapter = build_adapter(&a)?;
    let set = vc::PayloadSet::builtin_llm01();
    let body = vc::run_scan(adapter.as_ref(), &set, a.system_prompt.as_deref());

    let key_path = a.key.clone().unwrap_or_else(default_key_path);
    let seed = load_or_create_seed(&key_path)?;
    let receipt = vc::sign(body, &seed);

    fs::write(&a.out, serde_json::to_vec_pretty(&receipt)?)
        .with_context(|| format!("writing receipt to {}", a.out.display()))?;

    if a.json {
        println!("{}", serde_json::to_string(&receipt.body.summary)?);
    } else {
        let s = &receipt.body.summary;
        let m = &receipt.body.manifest;
        println!("target      {} ({})", m.target.endpoint, m.target.kind);
        println!(
            "payload set {} (root {}…, age {}d{})",
            m.payload_set_version,
            &m.payload_set_root[..12.min(m.payload_set_root.len())],
            m.payload_set_age_days,
            if m.payload_set_stale { ", STALE" } else { "" }
        );
        println!(
            "results     {} total, {} injected, {} resisted, {} inconclusive, {} errored",
            s.total, s.injected, s.resisted, s.inconclusive, s.errored
        );
        println!(
            "receipt     {} (pubkey {}…)",
            a.out.display(),
            &receipt.pubkey[..12.min(receipt.pubkey.len())]
        );
    }
    Ok(())
}

fn cmd_verify(a: VerifyArgs) -> Result<()> {
    let raw = fs::read(&a.receipt).with_context(|| format!("reading {}", a.receipt.display()))?;
    let receipt: vc::SignedScanReceipt =
        serde_json::from_slice(&raw).context("parsing receipt json")?;
    let report = vc::verify(&receipt);

    if a.json {
        println!(
            "{}",
            serde_json::json!({
                "sig_ok": report.sig_ok,
                "digest_ok": report.digest_ok,
                "chain_ok": report.chain_ok,
                "intact": report.intact(),
                "notes": report.notes,
            })
        );
    } else {
        println!(
            "signature   {}",
            if report.sig_ok { "ok" } else { "FAILED" }
        );
        println!(
            "digest      {}",
            if report.digest_ok { "ok" } else { "FAILED" }
        );
        println!(
            "event chain {}",
            if report.chain_ok { "ok" } else { "FAILED" }
        );
        for n in &report.notes {
            println!("  - {n}");
        }
        println!(
            "verdict     {}",
            if report.intact() {
                "INTACT"
            } else {
                "TAMPERED"
            }
        );
    }

    if !report.intact() {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_keygen(a: KeygenArgs) -> Result<()> {
    let key_path = a.key.unwrap_or_else(default_key_path);
    let seed = load_or_create_seed(&key_path)?;
    println!("pubkey {}", vc::pubkey_hex(&seed));
    println!("seed   {}", key_path.display());
    Ok(())
}

fn default_key_path() -> PathBuf {
    let base = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join(".vigil").join("ed25519.seed")
}

/// Load a 32-byte Ed25519 seed from `path` (raw 32 bytes or 64 hex chars), creating one if absent.
fn load_or_create_seed(path: &Path) -> Result<[u8; 32]> {
    if path.exists() {
        let raw = fs::read(path).with_context(|| format!("reading key {}", path.display()))?;
        if raw.len() == 32 {
            return Ok(<[u8; 32]>::try_from(raw).unwrap());
        }
        let txt = String::from_utf8_lossy(&raw);
        if let Some(seed) = vc::seed_from_hex(&txt) {
            return Ok(seed);
        }
        bail!(
            "key file {} is neither 32 raw bytes nor 64 hex chars",
            path.display()
        );
    }
    let seed = vc::generate_seed();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, vc::seed_to_hex(&seed))
        .with_context(|| format!("writing key {}", path.display()))?;
    Ok(seed)
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before 1970")
        .as_secs()
}
