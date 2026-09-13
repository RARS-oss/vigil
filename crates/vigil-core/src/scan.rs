//! Orchestrates one scan: run every payload in a set against a target adapter, score each
//! response, and fold the results into a hash-chained, signable receipt body.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::sha256_hex;
use crate::payload::PayloadSet;
use crate::receipt::{
    seal_chain, PayloadResult, RunManifest, ScanReceiptBody, ScanSummary, SCHEMA,
};
use crate::target::TargetAdapter;
use crate::verdict::{score, Verdict};

/// Run `set` against `adapter`, scoring each payload's response. `system_prompt`, when given, is
/// sent as the target's own system message on every probe — it configures the target, it is not
/// itself part of the attack.
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

        let (response, verdict, error) = match adapter.send(system_prompt, &p.prompt) {
            Ok(resp) => {
                let v = score(&p.success_markers, &resp);
                (resp, v, None)
            }
            Err(e) => (String::new(), Verdict::Inconclusive, Some(e.to_string())),
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
            response_sha256: sha256_hex(response.as_bytes()),
            response_bytes: response.len() as u64,
            response,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::OwaspCategory;
    use crate::payload::Payload;
    use crate::target::EchoAdapter;

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
                    success_markers: vec!["MARKER_HIT".into()],
                },
                Payload {
                    id: "test/marker-absent".into(),
                    category: OwaspCategory::Llm01PromptInjection,
                    technique: "unit_test".into(),
                    description: "echo does not contain the marker".into(),
                    prompt: "say nothing special".into(),
                    success_markers: vec!["MARKER_HIT".into()],
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
}
