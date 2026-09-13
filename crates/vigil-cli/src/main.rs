//! vigil — scan an LLM-application target with a versioned attack payload set and emit a signed,
//! reproducible receipt; verify one offline with `vigil verify`; gate CI on regressions with
//! `vigil gate`.

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
    /// CI gate: fail if a payload the baseline resisted is now injected in a newer receipt.
    Gate(GateArgs),
    /// Print the public key for a signing seed (creating it if absent).
    Keygen(KeygenArgs),
    /// Serve the Model Context Protocol over stdio (for Claude Code, Cursor, or any MCP client).
    Serve,
}

/// Which built-in payload set to use. Only categories vigil actually ships a corpus for are
/// listed here — this enum, not just the README, is the honest v1 scope (`docs/DESIGN.md` §3).
#[derive(ValueEnum, Clone, Copy, Debug)]
enum CategoryArg {
    /// Every category vigil currently covers (LLM01/05/06/07/10), combined.
    Core,
    /// LLM01 — Prompt Injection.
    Llm01,
    /// LLM05 — Improper Output Handling.
    Llm05,
    /// LLM06 — Excessive Agency. Needs an adapter that supports tool calling.
    Llm06,
    /// LLM07 — System Prompt Leakage.
    Llm07,
    /// LLM10 — Unbounded Consumption.
    Llm10,
}

impl CategoryArg {
    fn payload_set(self) -> vc::PayloadSet {
        match self {
            CategoryArg::Core => vc::PayloadSet::builtin_core(),
            CategoryArg::Llm01 => vc::PayloadSet::builtin_llm01(),
            CategoryArg::Llm05 => vc::PayloadSet::builtin_llm05(),
            CategoryArg::Llm06 => vc::PayloadSet::builtin_llm06(),
            CategoryArg::Llm07 => vc::PayloadSet::builtin_llm07(),
            CategoryArg::Llm10 => vc::PayloadSet::builtin_llm10(),
        }
    }
}

#[derive(Parser)]
struct PayloadsArgs {
    #[command(subcommand)]
    cmd: PayloadsCmd,
}

#[derive(Subcommand)]
enum PayloadsCmd {
    /// List every payload's category, id, technique, and description.
    List(CategorySelectArgs),
    /// Print the set's version, content-addressed root, and staleness.
    Info(CategorySelectArgs),
}

#[derive(Parser)]
struct CategorySelectArgs {
    #[arg(long, value_enum, default_value = "core")]
    category: CategoryArg,
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
    #[arg(long, value_enum, default_value = "core")]
    category: CategoryArg,
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
    /// Per-request timeout for the openai adapter. Local models (Ollama, vLLM on CPU) and the
    /// deliberately runaway LLM10 prompts can both run long — the 30s a plain chat request would
    /// be fine with is too short here.
    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,
    #[arg(long, default_value = "vigil-receipt.json")]
    out: PathBuf,
    /// Ed25519 signing seed file. Default: ~/.vigil/ed25519.seed (created if absent).
    #[arg(long)]
    key: Option<PathBuf>,
    /// A previous signed receipt to gate this run against (see `vigil gate`). The scan still
    /// writes its receipt either way; this just also runs the regression check and, on a
    /// regression, exits non-zero.
    #[arg(long)]
    baseline: Option<PathBuf>,
    /// For LLM05 (SinkSurvives) payloads: an executable that reads the target's raw response on
    /// stdin and writes what a real downstream consumer would see (after your app's actual HTML-
    /// escaping/shell-quoting/query-parameterizing) on stdout. Without this, LLM05 falls back to
    /// vigil's built-in static heuristic (markdown code-fence survival) -- real, but generic.
    #[arg(long)]
    sink_transform: Option<PathBuf>,
    /// Emit compact JSON to stdout instead of the human-readable report.
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
struct GateArgs {
    /// The known-good baseline receipt.
    baseline: PathBuf,
    /// The receipt from the run just performed.
    current: PathBuf,
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
        Cmd::Gate(a) => cmd_gate(a),
        Cmd::Keygen(a) => cmd_keygen(a),
        Cmd::Serve => cmd_serve(),
    }
}

fn cmd_serve() -> Result<()> {
    vigil_mcp::McpServer::new()
        .run_stdio()
        .context("running the MCP server over stdio")
}

fn cmd_payloads(a: PayloadsArgs) -> Result<()> {
    match a.cmd {
        PayloadsCmd::List(sel) => {
            let set = sel.category.payload_set();
            for p in &set.payloads {
                println!(
                    "{:<7} {:<40} {:<24} {}",
                    p.category, p.id, p.technique, p.description
                );
            }
        }
        PayloadsCmd::Info(sel) => {
            let set = sel.category.payload_set();
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
            let mut adapter = vc::OpenAiCompatAdapter::new(base_url, a.model.clone())
                .with_timeout(std::time::Duration::from_secs(a.timeout_secs));
            if let Some(k) = &a.api_key {
                adapter = adapter.with_api_key(k.clone());
            }
            Ok(Box::new(adapter))
        }
    }
}

fn cmd_scan(a: ScanArgs) -> Result<()> {
    let adapter = build_adapter(&a)?;
    let set = a.category.payload_set();
    let transform = a
        .sink_transform
        .as_ref()
        .map(|p| vc::ExternalCommandTransform::new(p.clone()));
    let body = vc::run_scan(
        adapter.as_ref(),
        &set,
        a.system_prompt.as_deref(),
        transform.as_ref().map(|t| t as &dyn vc::SinkTransform),
    );

    let key_path = a.key.clone().unwrap_or_else(vc::default_key_path);
    let seed = vc::load_or_create_seed(&key_path)?;
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

    if let Some(baseline_path) = &a.baseline {
        let baseline = load_verified_receipt(baseline_path)?;
        let report = vc::gate_compare(&baseline.body, &receipt.body);
        print_gate_report(&report, a.json);
        if !report.passed() {
            std::process::exit(1);
        }
    }
    Ok(())
}

fn cmd_verify(a: VerifyArgs) -> Result<()> {
    let receipt = load_receipt(&a.receipt)?;
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

fn cmd_gate(a: GateArgs) -> Result<()> {
    let baseline = load_verified_receipt(&a.baseline)?;
    let current = load_verified_receipt(&a.current)?;
    let report = vc::gate_compare(&baseline.body, &current.body);
    print_gate_report(&report, a.json);
    if !report.passed() {
        std::process::exit(1);
    }
    Ok(())
}

fn print_gate_report(report: &vc::GateReport, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "passed": report.passed(),
                "regressions": report.regressions,
                "new_payloads": report.new_payloads,
            })
        );
        return;
    }
    if report.regressions.is_empty() {
        println!("gate        PASS (no regressions)");
    } else {
        println!(
            "gate        FAIL ({} regression(s)):",
            report.regressions.len()
        );
        for r in &report.regressions {
            println!(
                "  - {}: {} -> {}",
                r.payload_id, r.baseline_verdict, r.current_verdict
            );
        }
    }
    if !report.new_payloads.is_empty() {
        println!(
            "note        {} payload(s) had no baseline entry (new set or different corpus): {}",
            report.new_payloads.len(),
            report.new_payloads.join(", ")
        );
    }
}

fn cmd_keygen(a: KeygenArgs) -> Result<()> {
    let key_path = a.key.unwrap_or_else(vc::default_key_path);
    let seed = vc::load_or_create_seed(&key_path)?;
    println!("pubkey {}", vc::pubkey_hex(&seed));
    println!("seed   {}", key_path.display());
    Ok(())
}

fn load_receipt(path: &Path) -> Result<vc::SignedScanReceipt> {
    let raw = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&raw).context("parsing receipt json")
}

/// Load a receipt and refuse to hand it back unless it verifies intact — a baseline the gate
/// trusts must itself be an unforged record, or a corrupted/tampered baseline could mask a real
/// regression instead of catching one.
fn load_verified_receipt(path: &Path) -> Result<vc::SignedScanReceipt> {
    let receipt = load_receipt(path)?;
    let report = vc::verify(&receipt);
    if !report.intact() {
        bail!(
            "refusing to gate against a non-intact receipt {}: {}",
            path.display(),
            report.notes.join("; ")
        );
    }
    Ok(receipt)
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before 1970")
        .as_secs()
}
