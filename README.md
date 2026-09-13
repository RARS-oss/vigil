# vigil

**A red-team harness for LLM applications that reports honestly instead of claiming "full OWASP
Top 10 coverage."** Every scan produces an Ed25519-signed receipt (the format is ported from
[`bulla`](https://github.com/RARS-oss/bulla)): the exact payload-set version, every raw
prompt/response transcript, and a verdict per payload — checkable offline by anyone who trusts the
signing key, without trusting the machine that ran the scan.

## Why

A vendor LLM-security scan produces a report that says "passed" or "failed" with no way for
anyone else to check the run itself. Nobody signs the payloads used, nobody versions the attack
corpus, nobody can tell six months later whether a "clean" result meant the target was actually
safe or the attack corpus was just stale. `vigil` treats an LLM application's input/output surface
as an adversarial evidence source, the same discipline
[`sbx`](https://github.com/RARS-oss/sbx) and `bulla` already apply to a sandbox and a compiler.

## Scope — honest, not a marketing checklist

OWASP Top 10 for LLM Applications (2025). Not all ten are actually testable by a black-box
automated red-team harness — this table says so up front, the same way `bulla`'s README states
what its receipts do *not* prove. `OwaspCategory::has_payload_set` in code is the source of truth
for the "v1 scope" column below, not this table — if they ever disagree, trust the code.

| Category | v1 scope | Payloads |
|---|---|---|
| LLM01 Prompt Injection | **Core.** | 10 |
| LLM05 Improper Output Handling | **Core.** Tested against a simulated downstream sink (HTML/shell/SQL): a dangerous construct that only survives inside markdown code-fencing is scored safe, one sitting in plain prose isn't. That's a real but generic model — plug in `--sink-transform` (an executable running your app's *actual* escaper/quoter) to score against the real thing instead. | 6 |
| LLM06 Excessive Agency | **Core.** Needs an adapter with tool/function-calling support. | 6 |
| LLM07 System Prompt Leakage | **Core.** | 8 |
| LLM10 Unbounded Consumption | **Core.** Scored by response size/repetition, not a marker. | 6 |
| LLM02 Sensitive Information Disclosure | **Partial — not shipped yet.** Generic probes would need a target-supplied seed list to mean anything beyond an obvious secrets-in-system-prompt check. | 0 |
| LLM08 Vector and Embedding Weaknesses | **Partial — not shipped yet.** Only applicable if the target does RAG; needs `fons` (planned) or a similar retrieval layer to have a surface to test. | 0 |
| LLM03 Supply Chain | **Out of scope.** A dependency/provenance audit problem, not something a runtime probe can exercise. | — |
| LLM04 Data and Model Poisoning | **Out of scope.** Mostly training-time; black-box inference-time testing can't establish much here. | — |
| LLM09 Misinformation | **Out of scope.** Needs domain-specific ground truth; a generic harness can't judge factual accuracy without a curated answer key per target. | — |

That's 5 core, fully covered by a real payload set as of Week 3 of the build (`docs/DESIGN.md`
§6) — 36 payloads total, `vigil payloads info` shows the exact version and content-hash root.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full model, the claims (C1–C3) this project set out
to validate, and the roadmap. See [`docs/pilot/`](docs/pilot) for real pilot-run write-ups against
a live target — not synthetic examples.

## Install

```sh
cargo build --release
# binary at target/release/vigil
```

## Use

```sh
# Inspect the built-in registry (payload set version, content-hash root, staleness).
vigil payloads info                     # every covered category, combined
vigil payloads info --category llm06
vigil payloads list --category llm05

# Scan a real OpenAI-compatible target (OpenAI itself, or a local Ollama/vLLM/LM Studio server).
vigil scan --adapter openai \
  --base-url http://localhost:11434/v1 --model qwen3:4b-instruct-2507-q4_K_M \
  --category core --out receipt.json

# Offline, no network: exercise the harness against an adapter that just echoes prompts back.
vigil scan --adapter echo --category llm01 --out receipt.json

# Verify a receipt offline: signature, digest, event chain.
vigil verify receipt.json

# CI gate: fail the build if a payload the last known-good receipt resisted is now injected.
vigil scan --adapter openai --base-url ... --model ... --baseline last-good-receipt.json
# or, against two receipts you already have:
vigil gate last-good-receipt.json new-receipt.json

# LLM05 against your app's real escaper instead of vigil's built-in static heuristic:
vigil scan --category llm05 --sink-transform examples/html-escape-sink.py ...  # Unix, executable
vigil scan --category llm05 --sink-transform examples/html-escape-sink.cmd ... # Windows
```

`vigil keygen` prints (creating if absent) the Ed25519 public key at `~/.vigil/ed25519.seed`,
which every command above uses by default (`--key` overrides it).

## Use from Claude Code, Cursor, or any MCP client

`vigil` is not only a CLI you shell out to — `vigil serve` runs a JSON-RPC/stdio MCP server
(`crates/vigil-mcp`, hand-rolled, no async runtime — mirrors
[`tabularium-mcp`](https://github.com/RARS-oss/tabularium)'s own shape) exposing
`vigil_scan`/`vigil_verify`/`vigil_gate`/`vigil_payloads_list`/`vigil_payloads_info`/
`vigil_keygen`/`vigil_info` as tools. Add to `.mcp.json` in your project (example at
[`integrations/claude-code/mcp.json`](integrations/claude-code/mcp.json)):

```json
{ "mcpServers": { "vigil": { "command": "vigil", "args": ["serve"] } } }
```

A `vigil_scan` tool call is not fast — it blocks on network round-trips to the target for the
whole payload set, same as the CLI. It writes the same signed receipt to disk either way; the
tool result is the manifest/summary/path, not the full transcript-carrying JSON, so an agent
calling it doesn't pay for every raw prompt/response inline unless it explicitly reads the file.

## The receipt

Every `vigil scan` writes a JSON file with this shape (see `crates/vigil-core/src/receipt.rs`):

- `manifest` — the exact payload-set version + content-hash root + age (and whether it's
  flagged `stale`, per `STALE_AFTER_DAYS`), and the target's identity (adapter kind, endpoint,
  model).
- `results` — one entry per payload: the full prompt and response (or tool calls, for LLM06;
  or what a `--sink-transform` actually rendered, for LLM05, alongside the untouched raw
  response), their sha256, and the verdict (`injected` / `resisted` / `inconclusive`).
- `events` — a hash-chained log of the run (ported from `bulla`'s event chain).
- `body_digest` + `pubkey` + `sig` — Ed25519 over the canonical body. `vigil verify` recomputes
  all three independently; a single byte changed anywhere in the body breaks the signature.

## Status

Weeks 1–4 of the build (`docs/DESIGN.md` §6) are done: payload registry with versioning and
staleness, the target-adapter trait (OpenAI-compatible HTTP + tool-calling + an offline echo
adapter for testing), Ed25519 signed receipts, CI gate mode, real payload sets for all 5 "core"
categories, and a real-target pilot run validating all three claims (C1–C3) — see
[`docs/pilot/`](docs/pilot) for the actual results, misses included.

Since then: an MCP server (`vigil serve`) so vigil isn't only a shell-exec CLI, and
`--sink-transform` so LLM05 can score against a real escaper instead of only the built-in static
heuristic — both closing gaps the pilot and its own docs called out honestly rather than papering
over.

License: MIT OR Apache-2.0.
