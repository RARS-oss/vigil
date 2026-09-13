//! Minimal MCP server (JSON-RPC 2.0) exposing vigil's scan/verify/gate/payloads registry.
//!
//! Mirrors `tabularium-mcp`'s shape (same org, same pattern, reused deliberately per
//! `docs/DESIGN.md` §2's "reuse, not rebuild"): newline-delimited JSON on stdin/stdout
//! ([`McpServer::run_stdio`]), no async runtime, only the `tools` capability, everything
//! diagnostic to stderr. This closes the "vigil is only a shell-exec CLI" gap: any MCP client
//! (Claude Code, Cursor, or a custom agent runtime) can drive a scan as a tool call instead of
//! spawning the binary and parsing its stdout.
//!
//! A `vigil_scan` call is not fast — it blocks on network round-trips to the target for every
//! payload in the set. That's inherent to what the tool does, not a transport bug; a client
//! calling it should expect a long-running tool call, same as it would shelling out to `vigil
//! scan` directly.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use std::io::{BufRead, Write};

use vigil_core as vc;

pub const SERVER_NAME: &str = "vigil";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SUPPORTED_PROTOCOLS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
pub const DEFAULT_PROTOCOL: &str = "2025-06-18";

pub const INSTRUCTIONS: &str = "\
vigil red-team-scans LLM applications and signs the result. Every vigil_scan call produces an \
Ed25519-signed receipt (also written to disk) covering the exact payload-set version, every raw \
prompt/response, and a verdict per payload -- a checkable artifact, not a bare pass/fail.

Discipline:
1. Before scanning, call vigil_payloads_info to see the payload set's version and whether it's \
   flagged stale -- a stale set is a known, surfaced condition (docs/DESIGN.md claim C1), not \
   something to silently trust.
2. vigil_scan with adapter=echo never touches the network -- use it to sanity-check a payload \
   set or a workflow before pointing at a real target.
3. LLM06 (excessive agency) payloads need an adapter with tool-calling support (adapter=openai \
   has it); against one that doesn't, those probes come back inconclusive/errored honestly \
   rather than being silently skipped.
4. Use vigil_scan's baseline_path (or vigil_gate directly) to fail a CI-style check on \
   regression: a payload that used to be resisted and is now injected. A fix (injected -> \
   resisted) never fails the gate. Gating refuses a baseline that doesn't verify intact.
5. Never treat an injected verdict as certain: every scoring rule is a documented heuristic \
   (marker match, response size, sink survival, tool name) -- read the transcript in the \
   receipt file for anything borderline.";

pub struct McpServer {
    initialized: bool,
    protocol: String,
    log: bool,
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum McpError {
    Invalid(String),
    Internal(String),
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpError::Invalid(m) | McpError::Internal(m) => write!(f, "{m}"),
        }
    }
}

pub type Result<T> = std::result::Result<T, McpError>;

fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message.into()}})
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    arg_str(args, key)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| McpError::Invalid(format!("missing required string argument '{key}'")))
}

fn arg_u64(args: &Value, key: &str) -> Option<u64> {
    args.get(key).and_then(|v| v.as_u64())
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before 1970")
        .as_secs()
}

/// Parse a `category` argument into a built-in payload set (default `"core"`).
fn payload_set_for_arg(args: &Value) -> Result<vc::PayloadSet> {
    match arg_str(args, "category").unwrap_or("core") {
        "core" => Ok(vc::PayloadSet::builtin_core()),
        "llm01" => Ok(vc::PayloadSet::builtin_llm01()),
        "llm05" => Ok(vc::PayloadSet::builtin_llm05()),
        "llm06" => Ok(vc::PayloadSet::builtin_llm06()),
        "llm07" => Ok(vc::PayloadSet::builtin_llm07()),
        "llm10" => Ok(vc::PayloadSet::builtin_llm10()),
        other => Err(McpError::Invalid(format!(
            "unknown category '{other}' (core|llm01|llm05|llm06|llm07|llm10)"
        ))),
    }
}

fn load_verified_receipt(path: &Path) -> Result<vc::SignedScanReceipt> {
    let raw = std::fs::read(path)
        .map_err(|e| McpError::Invalid(format!("reading {}: {e}", path.display())))?;
    let receipt: vc::SignedScanReceipt = serde_json::from_slice(&raw)
        .map_err(|e| McpError::Invalid(format!("parsing {}: {e}", path.display())))?;
    let report = vc::verify(&receipt);
    if !report.intact() {
        return Err(McpError::Invalid(format!(
            "refusing to gate against a non-intact receipt {}: {}",
            path.display(),
            report.notes.join("; ")
        )));
    }
    Ok(receipt)
}

/// Tool definitions as advertised in `tools/list`.
pub fn tool_definitions() -> Vec<Value> {
    let category_enum = json!(["core", "llm01", "llm05", "llm06", "llm07", "llm10"]);
    vec![
        json!({
            "name": "vigil_payloads_list",
            "description": "List every payload's id, OWASP category, technique, and description for a built-in payload set.",
            "inputSchema": {
                "type": "object",
                "properties": {"category": {"type": "string", "enum": category_enum, "default": "core"}}
            }
        }),
        json!({
            "name": "vigil_payloads_info",
            "description": "Version, content-hash root, payload count, and staleness (docs/DESIGN.md claim C1) for a built-in payload set.",
            "inputSchema": {
                "type": "object",
                "properties": {"category": {"type": "string", "enum": category_enum, "default": "core"}}
            }
        }),
        json!({
            "name": "vigil_scan",
            "description": "Run a payload set against a target and write a signed receipt. Blocks on network calls to the target for the whole run. Returns the manifest, summary counts, the receipt file path, and its public key; the full receipt (every transcript) is at out_path for the caller to read if needed.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "category": {"type": "string", "enum": category_enum, "default": "core"},
                    "adapter": {"type": "string", "enum": ["openai", "echo"], "default": "openai", "description": "'echo' never touches the network -- use it to sanity-check a payload set offline."},
                    "base_url": {"type": "string", "description": "Required for the openai adapter, e.g. http://localhost:11434/v1"},
                    "model": {"type": "string", "default": "gpt-4o-mini"},
                    "api_key": {"type": "string", "description": "Bearer token for the target, if it needs one. Never written into the receipt."},
                    "system_prompt": {"type": "string", "description": "Sent as the target's own system message on every probe -- the target's configuration, not part of the attack. LLM07 results are weak evidence without one (nothing real to leak)."},
                    "timeout_secs": {"type": "integer", "default": 120, "minimum": 1},
                    "out_path": {"type": "string", "description": "Where to write the signed receipt. Default: a fresh path under the OS temp dir, returned in the result."},
                    "key_path": {"type": "string", "description": "Ed25519 signing seed file. Default: ~/.vigil/ed25519.seed (created if absent)."},
                    "baseline_path": {"type": "string", "description": "Gate this run against a previous signed receipt: fail if a payload it resisted is now injected. Refuses a baseline that doesn't verify intact."},
                    "sink_transform_command": {"type": "string", "description": "For LLM05 payloads: an executable that reads the raw response on stdin and writes what a real downstream consumer would see (after your app's actual escaping/quoting) on stdout. Without this, LLM05 uses vigil's built-in static heuristic."}
                }
            }
        }),
        json!({
            "name": "vigil_verify",
            "description": "Verify a receipt offline: signature, digest, event chain. Pass exactly one of receipt_path or receipt_json.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "receipt_path": {"type": "string"},
                    "receipt_json": {"type": "object", "description": "An already-loaded signed receipt, e.g. one just returned by vigil_scan."}
                }
            }
        }),
        json!({
            "name": "vigil_gate",
            "description": "CI gate: compare two signed receipts and fail if a payload the baseline resisted is now injected. Refuses (does not silently gate) if either receipt fails to verify.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "baseline_path": {"type": "string"},
                    "current_path": {"type": "string"}
                },
                "required": ["baseline_path", "current_path"]
            }
        }),
        json!({
            "name": "vigil_keygen",
            "description": "Print (creating if absent) the Ed25519 public key used to sign receipts.",
            "inputSchema": {
                "type": "object",
                "properties": {"key_path": {"type": "string"}}
            }
        }),
        json!({
            "name": "vigil_info",
            "description": "Server version, default signing key path/public key, and which OWASP categories have a built-in payload set.",
            "inputSchema": {"type": "object", "properties": {}}
        }),
    ]
}

impl McpServer {
    pub fn new() -> Self {
        McpServer {
            initialized: false,
            protocol: DEFAULT_PROTOCOL.to_string(),
            log: std::env::var("VIGIL_LOG")
                .map(|v| v == "1")
                .unwrap_or(false),
        }
    }

    /// Handle one line of input. Returns a response line for requests, nothing for notifications.
    pub fn handle_line(&mut self, line: &str) -> Option<String> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return Some(
                    rpc_error(Value::Null, -32700, format!("parse error: {e}")).to_string(),
                )
            }
        };
        self.handle_message(msg).map(|r| r.to_string())
    }

    /// Handle one already-parsed JSON-RPC message.
    pub fn handle_message(&mut self, msg: Value) -> Option<Value> {
        if msg.is_array() {
            return Some(rpc_error(
                Value::Null,
                -32600,
                "batch requests are not supported",
            ));
        }
        let id = msg.get("id").cloned().filter(|v| !v.is_null());
        let Some(method) = msg
            .get("method")
            .and_then(|m| m.as_str())
            .map(|s| s.to_string())
        else {
            return id.map(|id| rpc_error(id, -32600, "invalid request: missing method"));
        };
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        if self.log {
            eprintln!("[vigil-mcp] <- {method}");
        }
        match (method.as_str(), id) {
            ("initialize", Some(id)) => Some(rpc_result(id, self.initialize(&params))),
            ("initialize", None) => None,
            ("notifications/initialized", _) => {
                self.initialized = true;
                None
            }
            ("ping", Some(id)) => Some(rpc_result(id, json!({}))),
            ("tools/list", Some(id)) => Some(rpc_result(id, json!({"tools": tool_definitions()}))),
            ("tools/call", Some(id)) => Some(self.tools_call(id, &params)),
            (m, Some(id)) if m.starts_with("notifications/") => {
                Some(rpc_error(id, -32600, "notifications must not carry an id"))
            }
            (_, None) => None,
            (m, Some(id)) => Some(rpc_error(id, -32601, format!("method not found: {m}"))),
        }
    }

    fn initialize(&mut self, params: &Value) -> Value {
        let requested = params
            .get("protocolVersion")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_PROTOCOL);
        self.protocol = if SUPPORTED_PROTOCOLS.contains(&requested) {
            requested.to_string()
        } else {
            DEFAULT_PROTOCOL.to_string()
        };
        json!({
            "protocolVersion": self.protocol,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": INSTRUCTIONS,
        })
    }

    fn tools_call(&mut self, id: Value, params: &Value) -> Value {
        let Some(name) = params.get("name").and_then(|n| n.as_str()) else {
            return rpc_error(id, -32602, "tools/call requires 'name'");
        };
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        match self.call_tool(name, &args) {
            Ok(value) => {
                let text = serde_json::to_string_pretty(&value).unwrap_or_default();
                rpc_result(
                    id,
                    json!({"content": [{"type": "text", "text": text}], "structuredContent": value, "isError": false}),
                )
            }
            Err(McpError::Invalid(m)) if m.starts_with("unknown tool") => rpc_error(id, -32602, m),
            Err(e) => rpc_result(
                id,
                json!({"content": [{"type": "text", "text": format!("error: {e}")}], "isError": true}),
            ),
        }
    }

    /// Dispatch a tool call. Public so hosts can embed the server without the transport.
    pub fn call_tool(&mut self, name: &str, args: &Value) -> Result<Value> {
        match name {
            "vigil_payloads_list" => self.call_payloads_list(args),
            "vigil_payloads_info" => self.call_payloads_info(args),
            "vigil_scan" => self.call_scan(args),
            "vigil_verify" => self.call_verify(args),
            "vigil_gate" => self.call_gate(args),
            "vigil_keygen" => self.call_keygen(args),
            "vigil_info" => self.call_info(),
            other => Err(McpError::Invalid(format!("unknown tool '{other}'"))),
        }
    }

    fn call_payloads_list(&self, args: &Value) -> Result<Value> {
        let set = payload_set_for_arg(args)?;
        let items: Vec<Value> = set
            .payloads
            .iter()
            .map(|p| {
                json!({
                    "id": p.id,
                    "category": p.category.to_string(),
                    "technique": p.technique,
                    "description": p.description,
                })
            })
            .collect();
        Ok(json!({"version": set.version, "count": items.len(), "items": items}))
    }

    fn call_payloads_info(&self, args: &Value) -> Result<Value> {
        let set = payload_set_for_arg(args)?;
        let now = now_epoch();
        Ok(json!({
            "version": set.version,
            "root": set.root,
            "count": set.payloads.len(),
            "age_days": set.age_days(now),
            "stale": set.is_stale(now),
        }))
    }

    fn call_scan(&self, args: &Value) -> Result<Value> {
        let set = payload_set_for_arg(args)?;

        let adapter: Box<dyn vc::TargetAdapter> = match arg_str(args, "adapter").unwrap_or("openai")
        {
            "echo" => Box::new(vc::EchoAdapter),
            "openai" => {
                let base_url = arg_str(args, "base_url").ok_or_else(|| {
                    McpError::Invalid("base_url is required for the openai adapter".into())
                })?;
                let model = arg_str(args, "model").unwrap_or("gpt-4o-mini");
                let timeout = arg_u64(args, "timeout_secs").unwrap_or(120);
                let mut a = vc::OpenAiCompatAdapter::new(base_url, model)
                    .with_timeout(Duration::from_secs(timeout));
                if let Some(k) = arg_str(args, "api_key") {
                    a = a.with_api_key(k);
                }
                Box::new(a)
            }
            other => {
                return Err(McpError::Invalid(format!(
                    "unknown adapter '{other}' (openai|echo)"
                )))
            }
        };

        let transform = arg_str(args, "sink_transform_command")
            .map(|cmd| vc::ExternalCommandTransform::new(PathBuf::from(cmd)));
        let system_prompt = arg_str(args, "system_prompt");
        let body = vc::run_scan(
            adapter.as_ref(),
            &set,
            system_prompt,
            transform.as_ref().map(|t| t as &dyn vc::SinkTransform),
        );

        let key_path = arg_str(args, "key_path")
            .map(PathBuf::from)
            .unwrap_or_else(vc::default_key_path);
        let seed =
            vc::load_or_create_seed(&key_path).map_err(|e| McpError::Internal(e.to_string()))?;
        let receipt = vc::sign(body, &seed);

        let out_path = arg_str(args, "out_path")
            .map(PathBuf::from)
            .unwrap_or_else(default_scan_out_path);
        let bytes =
            serde_json::to_vec_pretty(&receipt).map_err(|e| McpError::Internal(e.to_string()))?;
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| McpError::Internal(format!("creating {}: {e}", parent.display())))?;
        }
        std::fs::write(&out_path, &bytes)
            .map_err(|e| McpError::Internal(format!("writing {}: {e}", out_path.display())))?;

        let mut result = json!({
            "manifest": receipt.body.manifest,
            "summary": receipt.body.summary,
            "pubkey": receipt.pubkey,
            "out_path": out_path.display().to_string(),
        });

        if let Some(baseline_path) = arg_str(args, "baseline_path") {
            let baseline = load_verified_receipt(Path::new(baseline_path))?;
            let gate = vc::gate_compare(&baseline.body, &receipt.body);
            result["gate"] = json!({
                "passed": gate.passed(),
                "regressions": gate.regressions,
                "new_payloads": gate.new_payloads,
            });
        }
        Ok(result)
    }

    fn call_verify(&self, args: &Value) -> Result<Value> {
        let receipt: vc::SignedScanReceipt = if let Some(path) = arg_str(args, "receipt_path") {
            let raw = std::fs::read(path)
                .map_err(|e| McpError::Invalid(format!("reading {path}: {e}")))?;
            serde_json::from_slice(&raw)
                .map_err(|e| McpError::Invalid(format!("parsing {path}: {e}")))?
        } else if let Some(inline) = args.get("receipt_json") {
            serde_json::from_value(inline.clone())
                .map_err(|e| McpError::Invalid(format!("parsing receipt_json: {e}")))?
        } else {
            return Err(McpError::Invalid(
                "provide receipt_path or receipt_json".into(),
            ));
        };
        let report = vc::verify(&receipt);
        Ok(json!({
            "sig_ok": report.sig_ok,
            "digest_ok": report.digest_ok,
            "chain_ok": report.chain_ok,
            "intact": report.intact(),
            "notes": report.notes,
        }))
    }

    fn call_gate(&self, args: &Value) -> Result<Value> {
        let baseline_path = require_str(args, "baseline_path")?;
        let current_path = require_str(args, "current_path")?;
        let baseline = load_verified_receipt(Path::new(baseline_path))?;
        let current = load_verified_receipt(Path::new(current_path))?;
        let report = vc::gate_compare(&baseline.body, &current.body);
        Ok(json!({
            "passed": report.passed(),
            "regressions": report.regressions,
            "new_payloads": report.new_payloads,
        }))
    }

    fn call_keygen(&self, args: &Value) -> Result<Value> {
        let key_path = arg_str(args, "key_path")
            .map(PathBuf::from)
            .unwrap_or_else(vc::default_key_path);
        let seed =
            vc::load_or_create_seed(&key_path).map_err(|e| McpError::Internal(e.to_string()))?;
        Ok(json!({
            "pubkey": vc::pubkey_hex(&seed),
            "key_path": key_path.display().to_string(),
        }))
    }

    fn call_info(&self) -> Result<Value> {
        let key_path = vc::default_key_path();
        let pubkey = key_path
            .exists()
            .then(|| vc::load_or_create_seed(&key_path).ok())
            .flatten()
            .map(|s| vc::pubkey_hex(&s));
        let core_categories: Vec<Value> = vc::BUILTIN_CATEGORIES
            .iter()
            .map(|c| json!({"category": c.to_string(), "label": c.label()}))
            .collect();
        Ok(json!({
            "server": SERVER_NAME,
            "version": SERVER_VERSION,
            "protocol": self.protocol,
            "initialized": self.initialized,
            "default_key_path": key_path.display().to_string(),
            "pubkey": pubkey,
            "core_categories": core_categories,
        }))
    }

    /// Serve stdin/stdout until EOF.
    pub fn run_stdio(&mut self) -> std::io::Result<()> {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for line in stdin.lock().lines() {
            let line = line?;
            if let Some(resp) = self.handle_line(&line) {
                out.write_all(resp.as_bytes())?;
                out.write_all(b"\n")?;
                out.flush()?;
            }
        }
        Ok(())
    }
}

/// A fresh, collision-resistant default path for a scan's receipt when the caller doesn't give
/// one: under the OS temp dir, named by wall-clock nanoseconds so concurrent scans don't collide.
fn default_scan_out_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("vigil-receipt-{nanos}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(s: &mut McpServer, id: u64, method: &str, params: Value) -> Value {
        let line =
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
        serde_json::from_str(&s.handle_line(&line).expect("request gets a response")).unwrap()
    }

    fn call(s: &mut McpServer, id: u64, tool: &str, args: Value) -> Value {
        let r = req(
            s,
            id,
            "tools/call",
            json!({"name": tool, "arguments": args}),
        );
        r["result"].clone()
    }

    #[test]
    fn handshake_and_tool_list() {
        let mut s = McpServer::new();
        let r = req(
            &mut s,
            1,
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "claude-code", "version": "1"}}),
        );
        assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(r["result"]["serverInfo"]["name"], SERVER_NAME);
        assert!(s
            .handle_line(
                &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string()
            )
            .is_none());

        let r = req(&mut s, 2, "tools/list", json!({}));
        let names: Vec<&str> = r["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"vigil_scan") && names.contains(&"vigil_verify"));

        let r = req(&mut s, 3, "ping", json!({}));
        assert_eq!(r["result"], json!({}));

        let r = req(&mut s, 4, "nope/method", json!({}));
        assert_eq!(r["error"]["code"], -32601);

        let r: Value = serde_json::from_str(&s.handle_line("{not json").unwrap()).unwrap();
        assert_eq!(r["error"]["code"], -32700);

        let r = req(
            &mut s,
            5,
            "initialize",
            json!({"protocolVersion": "1999-01-01"}),
        );
        assert_eq!(r["result"]["protocolVersion"], DEFAULT_PROTOCOL);
    }

    #[test]
    fn unknown_tool_is_invalid_params() {
        let mut s = McpServer::new();
        let bad = req(
            &mut s,
            1,
            "tools/call",
            json!({"name": "vigil_nope", "arguments": {}}),
        );
        assert_eq!(bad["error"]["code"], -32602);
    }

    #[test]
    fn payloads_list_and_info_roundtrip() {
        let mut s = McpServer::new();
        let list = call(
            &mut s,
            1,
            "vigil_payloads_list",
            json!({"category": "llm06"}),
        );
        assert_eq!(list["isError"], false, "{list}");
        assert_eq!(
            list["structuredContent"]["items"].as_array().unwrap().len(),
            6
        );

        let info = call(
            &mut s,
            2,
            "vigil_payloads_info",
            json!({"category": "core"}),
        );
        assert_eq!(info["isError"], false, "{info}");
        assert_eq!(info["structuredContent"]["count"], 36);
        assert_eq!(info["structuredContent"]["stale"], false);

        let bad = call(
            &mut s,
            3,
            "vigil_payloads_info",
            json!({"category": "llm02"}),
        );
        assert_eq!(bad["isError"], true, "LLM02 has no built-in set yet");
    }

    #[test]
    fn scan_with_echo_adapter_writes_a_verifiable_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("receipt.json");
        let key_path = dir.path().join("key.seed");
        let mut s = McpServer::new();

        let scan = call(
            &mut s,
            1,
            "vigil_scan",
            json!({
                "category": "llm01",
                "adapter": "echo",
                "out_path": out_path.display().to_string(),
                "key_path": key_path.display().to_string(),
            }),
        );
        assert_eq!(scan["isError"], false, "{scan}");
        assert_eq!(
            scan["structuredContent"]["out_path"],
            out_path.display().to_string()
        );
        assert!(out_path.exists());

        let verify = call(
            &mut s,
            2,
            "vigil_verify",
            json!({"receipt_path": out_path.display().to_string()}),
        );
        assert_eq!(verify["isError"], false, "{verify}");
        assert_eq!(verify["structuredContent"]["intact"], true);
    }

    #[test]
    fn scan_missing_base_url_for_openai_adapter_is_an_error() {
        let mut s = McpServer::new();
        let scan = call(&mut s, 1, "vigil_scan", json!({"adapter": "openai"}));
        assert_eq!(scan["isError"], true);
    }

    #[test]
    fn verify_rejects_a_tampered_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("receipt.json");
        let key_path = dir.path().join("key.seed");
        let mut s = McpServer::new();

        call(
            &mut s,
            1,
            "vigil_scan",
            json!({
                "category": "llm01", "adapter": "echo",
                "out_path": out_path.display().to_string(),
                "key_path": key_path.display().to_string(),
            }),
        );

        let mut receipt: Value =
            serde_json::from_slice(&std::fs::read(&out_path).unwrap()).unwrap();
        receipt["body"]["results"][0]["verdict"] = json!("resisted");
        std::fs::write(&out_path, serde_json::to_vec(&receipt).unwrap()).unwrap();

        let verify = call(
            &mut s,
            2,
            "vigil_verify",
            json!({"receipt_path": out_path.display().to_string()}),
        );
        assert_eq!(verify["structuredContent"]["intact"], false);
    }

    #[test]
    fn gate_on_two_identical_scans_passes_and_a_non_intact_baseline_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.seed");
        let a_path = dir.path().join("a.json");
        let b_path = dir.path().join("b.json");
        let mut s = McpServer::new();

        for path in [&a_path, &b_path] {
            let r = call(
                &mut s,
                1,
                "vigil_scan",
                json!({
                    "category": "llm06", "adapter": "echo",
                    "out_path": path.display().to_string(),
                    "key_path": key_path.display().to_string(),
                }),
            );
            assert_eq!(r["isError"], false, "{r}");
        }

        let gate = call(
            &mut s,
            2,
            "vigil_gate",
            json!({"baseline_path": a_path.display().to_string(), "current_path": b_path.display().to_string()}),
        );
        assert_eq!(gate["isError"], false, "{gate}");
        assert_eq!(gate["structuredContent"]["passed"], true);

        // Tamper the baseline: gate must refuse rather than silently comparing against it.
        let mut receipt: Value = serde_json::from_slice(&std::fs::read(&a_path).unwrap()).unwrap();
        receipt["body"]["results"][0]["verdict"] = json!("injected");
        std::fs::write(&a_path, serde_json::to_vec(&receipt).unwrap()).unwrap();

        let gate = call(
            &mut s,
            3,
            "vigil_gate",
            json!({"baseline_path": a_path.display().to_string(), "current_path": b_path.display().to_string()}),
        );
        assert_eq!(
            gate["isError"], true,
            "a tampered baseline must be refused: {gate}"
        );
    }

    #[test]
    fn keygen_is_idempotent_and_info_reports_the_same_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.seed");
        let mut s = McpServer::new();

        let a = call(
            &mut s,
            1,
            "vigil_keygen",
            json!({"key_path": key_path.display().to_string()}),
        );
        let b = call(
            &mut s,
            2,
            "vigil_keygen",
            json!({"key_path": key_path.display().to_string()}),
        );
        assert_eq!(
            a["structuredContent"]["pubkey"], b["structuredContent"]["pubkey"],
            "a second keygen call must reuse the same key"
        );
    }

    #[test]
    fn info_reports_core_categories() {
        let mut s = McpServer::new();
        let info = call(&mut s, 1, "vigil_info", json!({}));
        assert_eq!(info["isError"], false, "{info}");
        let cats: Vec<&str> = info["structuredContent"]["core_categories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["category"].as_str().unwrap())
            .collect();
        assert!(cats.contains(&"LLM01") && cats.contains(&"LLM06"));
    }
}
