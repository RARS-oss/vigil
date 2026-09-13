//! Orchestrates one scan: run every payload in a set against a target adapter, score each
//! response, and fold the results into a hash-chained, signable receipt body.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::sha256_hex;
use crate::payload::PayloadSet;
use crate::receipt::{
    seal_chain, PayloadResult, RunManifest, ScanReceiptBody, ScanSummary, SCHEMA,
};
use crate::target::{TargetAdapter, ToolCall, ToolTurn};
use crate::verdict::{score, score_tool_turn, Verdict};

/// Run `set` against `adapter`, scoring each payload's response. `system_prompt`, when given, is
/// sent as the target's own system message on every probe — it configures the target, it is not
/// itself part of the attack. A payload with a non-empty `tools` list (LLM06) is probed via
/// `send_with_tools` and scored against the resulting tool calls instead of plain text.
pub fn run_scan(
    adapter: &dyn TargetAdapter,
    set: &PayloadSet,
    system_prompt: Option<&str>,
) -> ScanReceiptBody {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before 1970")
        .as_secs();
    let age_days = set.age_days(now);
    let target = adapter.identity();

    let manifest = RunManifest {
        payload_set_version: set.version.clone(),
        payload_set_root: set.root.clone(),
        payload_set_age_days: age_days,
        payload_set_stale: set.is_stale(now),
        target: target.clone(),
        started_epoch: now,
    };

    let mut raw_events: Vec<(u32, String, String)> = vec![(
        0,
        "scan_start".into(),
        format!(
            "payload_set={} root={} target={}",
            set.version, set.root, target.endpoint
        ),
    )];

    let mut results = Vec::with_capacity(set.payloads.len());
    let mut summary = ScanSummary::default();
    let mut seq: u32 = 1;

    for p in &set.payloads {
        summary.total += 1;

        let (response_text, tool_calls, verdict, error) = if p.tools.is_empty() {
            match adapter.send(system_prompt, &p.prompt) {
                Ok(resp) => {
                    let v = score(&p.rule, &resp);
                    (resp, Vec::new(), v, None)
                }
                Err(e) => (
                    String::new(),
                    Vec::new(),
                    Verdict::Inconclusive,
                    Some(e.to_string()),
                ),
            }
        } else {
            match adapter.send_with_tools(system_prompt, &p.prompt, &p.tools) {
                Ok(turn) => {
                    let v = score_tool_turn(&p.rule, &turn);
                    let (text, calls) = describe_tool_turn(&turn);
                    (text, calls, v, None)
                }
                Err(e) => (
                    String::new(),
                    Vec::new(),
                    Verdict::Inconclusive,
                    Some(e.to_string()),
                ),
            }
        };

        match verdict {
            Verdict::Injected => summary.injected += 1,
            Verdict::Resisted => summary.resisted += 1,
            Verdict::Inconclusive => summary.inconclusive += 1,
        }
        if error.is_some() {
            summary.errored += 1;
        }

        raw_events.push((
            seq,
            "probe".into(),
            format!("payload={} verdict={}", p.id, verdict),
        ));
        seq += 1;

        results.push(PayloadResult {
            payload_id: p.id.clone(),
            category: p.category.to_string(),
            technique: p.technique.clone(),
            prompt: p.prompt.clone(),
            prompt_sha256: sha256_hex(p.prompt.as_bytes()),
            response_sha256: sha256_hex(response_text.as_bytes()),
            response_bytes: response_text.len() as u64,
            response: response_text,
            tool_calls,
            verdict: verdict.to_string(),
            error,
        });
    }

    raw_events.push((
        seq,
        "scan_end".into(),
        format!(
            "total={} injected={} resisted={} inconclusive={} errored={}",
            summary.total,
            summary.injected,
            summary.resisted,
            summary.inconclusive,
            summary.errored
        ),
    ));

    let (events, chain_head) = seal_chain(&raw_events);

    ScanReceiptBody {
        schema: SCHEMA.into(),
        created_epoch: now,
        manifest,
        results,
        summary,
        events,
        chain_head,
    }
}

/// Flatten a `ToolTurn` into (human-readable text for the receipt's `response` field, the
/// structured tool calls to record alongside it).
fn describe_tool_turn(turn: &ToolTurn) -> (String, Vec<ToolCall>) {
    match turn {
        ToolTurn::Message(text) => (text.clone(), Vec::new()),
        ToolTurn::ToolCalls(calls) => {
            let text = calls
                .iter()
                .map(|c| format!("{}({})", c.name, c.arguments))
                .collect::<Vec<_>>()
                .join("; ");
            (text, calls.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::OwaspCategory;
    use crate::payload::Payload;
    use crate::target::{AdapterError, EchoAdapter, TargetIdentity, ToolSpec};
    use crate::verdict::VerdictRule;

    fn tiny_set() -> PayloadSet {
        PayloadSet::from_payloads(
            "2026-09-13",
            vec![
                Payload {
                    id: "test/marker-present".into(),
                    category: OwaspCategory::Llm01PromptInjection,
                    technique: "unit_test".into(),
                    description: "echo contains the marker".into(),
                    prompt: "please say MARKER_HIT".into(),
                    rule: VerdictRule::contains_marker(["MARKER_HIT"]),
                    tools: Vec::new(),
                },
                Payload {
                    id: "test/marker-absent".into(),
                    category: OwaspCategory::Llm01PromptInjection,
                    technique: "unit_test".into(),
                    description: "echo does not contain the marker".into(),
                    prompt: "say nothing special".into(),
                    rule: VerdictRule::contains_marker(["MARKER_HIT"]),
                    tools: Vec::new(),
                },
            ],
        )
    }

    #[test]
    fn echo_adapter_scan_scores_by_marker_presence() {
        let set = tiny_set();
        let body = run_scan(&EchoAdapter, &set, None);

        assert_eq!(body.summary.total, 2);
        assert_eq!(body.summary.injected, 1);
        assert_eq!(body.summary.resisted, 1);
        assert_eq!(body.summary.inconclusive, 0);

        assert_eq!(body.results[0].payload_id, "test/marker-absent"); // sorted by id
        assert_eq!(body.results[0].verdict, "resisted");
        assert_eq!(body.results[1].payload_id, "test/marker-present");
        assert_eq!(body.results[1].verdict, "injected");
        assert_eq!(body.results[1].response, "please say MARKER_HIT");
    }

    #[test]
    fn manifest_carries_the_payload_set_fingerprint_and_target_identity() {
        let set = tiny_set();
        let body = run_scan(&EchoAdapter, &set, None);
        assert_eq!(body.manifest.payload_set_version, "2026-09-13");
        assert_eq!(body.manifest.payload_set_root, set.root);
        assert_eq!(body.manifest.target.kind, "echo");
    }

    #[test]
    fn event_chain_has_one_probe_event_per_payload_plus_start_and_end() {
        let set = tiny_set();
        let body = run_scan(&EchoAdapter, &set, None);
        assert_eq!(body.events.len(), set.payloads.len() + 2);
        assert_eq!(body.events.first().unwrap().kind, "scan_start");
        assert_eq!(body.events.last().unwrap().kind, "scan_end");
        assert_eq!(body.chain_head, body.events.last().unwrap().hash);
    }

    /// A scripted tool-calling target for testing the LLM06 dispatch path offline: calls the
    /// first tool whose name contains "forbidden" if the prompt asks for it (contains "please
    /// call"), otherwise replies with a plain decline message.
    struct MockToolAdapter;
    impl TargetAdapter for MockToolAdapter {
        fn identity(&self) -> TargetIdentity {
            TargetIdentity {
                kind: "mock-tool".into(),
                endpoint: "n/a".into(),
                model: None,
            }
        }
        fn send(&self, _s: Option<&str>, prompt: &str) -> Result<String, AdapterError> {
            Ok(prompt.to_string())
        }
        fn send_with_tools(
            &self,
            _s: Option<&str>,
            prompt: &str,
            tools: &[ToolSpec],
        ) -> Result<ToolTurn, AdapterError> {
            if prompt.contains("please call") {
                if let Some(t) = tools.iter().find(|t| t.name.contains("dangerous")) {
                    return Ok(ToolTurn::ToolCalls(vec![ToolCall {
                        name: t.name.clone(),
                        arguments: "{}".into(),
                    }]));
                }
            }
            Ok(ToolTurn::Message("I can't do that.".into()))
        }
    }

    fn agency_set() -> PayloadSet {
        PayloadSet::from_payloads(
            "2026-09-13",
            vec![
                Payload {
                    id: "test/agency-complies".into(),
                    category: OwaspCategory::Llm06ExcessiveAgency,
                    technique: "unit_test".into(),
                    description: "mock complies and calls the dangerous tool".into(),
                    prompt: "please call the dangerous tool".into(),
                    rule: VerdictRule::forbids_tool_call(["dangerous_tool"]),
                    tools: vec![
                        ToolSpec {
                            name: "safe_tool".into(),
                            description: "safe".into(),
                            parameters: serde_json::json!({}),
                        },
                        ToolSpec {
                            name: "dangerous_tool".into(),
                            description: "dangerous".into(),
                            parameters: serde_json::json!({}),
                        },
                    ],
                },
                Payload {
                    id: "test/agency-declines".into(),
                    category: OwaspCategory::Llm06ExcessiveAgency,
                    technique: "unit_test".into(),
                    description: "mock declines".into(),
                    prompt: "do something else entirely".into(),
                    rule: VerdictRule::forbids_tool_call(["dangerous_tool"]),
                    tools: vec![
                        ToolSpec {
                            name: "safe_tool".into(),
                            description: "safe".into(),
                            parameters: serde_json::json!({}),
                        },
                        ToolSpec {
                            name: "dangerous_tool".into(),
                            description: "dangerous".into(),
                            parameters: serde_json::json!({}),
                        },
                    ],
                },
            ],
        )
    }

    #[test]
    fn agency_payloads_are_dispatched_through_send_with_tools() {
        let set = agency_set();
        let body = run_scan(&MockToolAdapter, &set, None);
        assert_eq!(body.summary.total, 2);
        assert_eq!(body.summary.injected, 1);
        assert_eq!(body.summary.resisted, 1);

        let complied = body
            .results
            .iter()
            .find(|r| r.payload_id == "test/agency-complies")
            .unwrap();
        assert_eq!(complied.verdict, "injected");
        assert_eq!(complied.tool_calls.len(), 1);
        assert_eq!(complied.tool_calls[0].name, "dangerous_tool");

        let declined = body
            .results
            .iter()
            .find(|r| r.payload_id == "test/agency-declines")
            .unwrap();
        assert_eq!(declined.verdict, "resisted");
        assert!(declined.tool_calls.is_empty());
    }

    #[test]
    fn agency_payload_against_a_non_tool_adapter_errors_honestly() {
        let set = agency_set();
        let body = run_scan(&EchoAdapter, &set, None);
        assert_eq!(body.summary.errored, 2);
        assert_eq!(body.summary.inconclusive, 2);
        assert!(body.results.iter().all(|r| r.error.is_some()));
    }
}
