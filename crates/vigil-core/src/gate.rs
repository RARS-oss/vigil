//! CI gate mode (`docs/DESIGN.md` §4): compare a fresh scan against a trusted baseline receipt
//! and flag regressions — "don't deploy if a new injection vector opened up," not just a one-off
//! report. The gate only ever flags a payload flipping *toward* `injected`; a payload that used to
//! be `injected` and is now `resisted` is progress, not something to fail a build over.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::receipt::ScanReceiptBody;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Regression {
    pub payload_id: String,
    pub baseline_verdict: String,
    pub current_verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GateReport {
    /// A payload the baseline did NOT report `injected` for, that the current run does.
    pub regressions: Vec<Regression>,
    /// Payload ids in the current run with no matching baseline entry (a newly added payload, or
    /// a baseline from a different/older payload set) — reported for visibility, never gated on.
    pub new_payloads: Vec<String>,
}

impl GateReport {
    pub fn passed(&self) -> bool {
        self.regressions.is_empty()
    }
}

/// Compare `current` against `baseline` and report any payload that flipped to `injected`.
pub fn compare(baseline: &ScanReceiptBody, current: &ScanReceiptBody) -> GateReport {
    let baseline_verdicts: HashMap<&str, &str> = baseline
        .results
        .iter()
        .map(|r| (r.payload_id.as_str(), r.verdict.as_str()))
        .collect();

    let mut report = GateReport::default();
    for r in &current.results {
        match baseline_verdicts.get(r.payload_id.as_str()) {
            Some(&baseline_verdict) => {
                if baseline_verdict != "injected" && r.verdict == "injected" {
                    report.regressions.push(Regression {
                        payload_id: r.payload_id.clone(),
                        baseline_verdict: baseline_verdict.to_string(),
                        current_verdict: r.verdict.clone(),
                    });
                }
            }
            None => report.new_payloads.push(r.payload_id.clone()),
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{seal_chain, PayloadResult, RunManifest, ScanSummary, SCHEMA};
    use crate::target::TargetIdentity;

    fn body_from(verdicts: &[(&str, &str)]) -> ScanReceiptBody {
        let results: Vec<PayloadResult> = verdicts
            .iter()
            .map(|(id, verdict)| PayloadResult {
                payload_id: id.to_string(),
                category: "LLM01".into(),
                technique: "unit_test".into(),
                prompt: "p".into(),
                prompt_sha256: crate::crypto::sha256_hex(b"p"),
                response: "r".into(),
                response_sha256: crate::crypto::sha256_hex(b"r"),
                response_bytes: 1,
                verdict: verdict.to_string(),
                error: None,
            })
            .collect();
        let (events, chain_head) = seal_chain(&[(0, "scan_start".into(), "test".into())]);
        ScanReceiptBody {
            schema: SCHEMA.into(),
            created_epoch: 0,
            manifest: RunManifest {
                payload_set_version: "2026-01-01".into(),
                payload_set_root: "deadbeef".into(),
                payload_set_age_days: 0,
                payload_set_stale: false,
                target: TargetIdentity {
                    kind: "echo".into(),
                    endpoint: "n/a".into(),
                    model: None,
                },
                started_epoch: 0,
            },
            results,
            summary: ScanSummary::default(),
            events,
            chain_head,
        }
    }

    #[test]
    fn no_change_passes() {
        let baseline = body_from(&[("a", "resisted"), ("b", "injected")]);
        let current = body_from(&[("a", "resisted"), ("b", "injected")]);
        let report = compare(&baseline, &current);
        assert!(report.passed());
        assert!(report.regressions.is_empty());
    }

    #[test]
    fn resisted_to_injected_is_a_regression() {
        let baseline = body_from(&[("a", "resisted")]);
        let current = body_from(&[("a", "injected")]);
        let report = compare(&baseline, &current);
        assert!(!report.passed());
        assert_eq!(report.regressions.len(), 1);
        assert_eq!(report.regressions[0].payload_id, "a");
    }

    #[test]
    fn injected_to_resisted_is_not_a_regression() {
        let baseline = body_from(&[("a", "injected")]);
        let current = body_from(&[("a", "resisted")]);
        let report = compare(&baseline, &current);
        assert!(report.passed(), "a fix must not fail the gate");
    }

    #[test]
    fn a_payload_missing_from_the_baseline_is_reported_but_not_gated() {
        let baseline = body_from(&[("a", "resisted")]);
        let current = body_from(&[("a", "resisted"), ("b", "injected")]);
        let report = compare(&baseline, &current);
        assert!(report.passed());
        assert_eq!(report.new_payloads, vec!["b".to_string()]);
    }

    #[test]
    fn inconclusive_baseline_still_gates_on_injected() {
        let baseline = body_from(&[("a", "inconclusive")]);
        let current = body_from(&[("a", "injected")]);
        let report = compare(&baseline, &current);
        assert!(!report.passed());
    }
}
