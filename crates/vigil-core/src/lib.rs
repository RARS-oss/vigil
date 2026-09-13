//! vigil-core — payload registry, target-adapter trait, and the signed scan-receipt model.
//!
//! See `docs/DESIGN.md` for the project's scope and claims. This crate stays free of any CLI or
//! I/O beyond the target adapters themselves, so it can be unit-tested end to end with
//! `target::EchoAdapter` and no network.

pub mod category;
pub mod crypto;
pub mod gate;
pub mod payload;
pub mod receipt;
pub mod scan;
pub mod sink;
pub mod target;
pub mod verdict;

pub use category::OwaspCategory;
pub use crypto::{generate_seed, pubkey_hex, seed_from_hex, seed_to_hex, sha256_hex};
pub use gate::{compare as gate_compare, GateReport, Regression};
pub use payload::{Payload, PayloadSet, BUILTIN_CATEGORIES, STALE_AFTER_DAYS};
pub use receipt::{
    sign, verify, Event, PayloadResult, RunManifest, ScanReceiptBody, ScanSummary,
    SignedScanReceipt, VerifyReport,
};
pub use scan::run_scan;
pub use sink::SinkKind;
pub use target::{
    AdapterError, EchoAdapter, OpenAiCompatAdapter, TargetAdapter, TargetIdentity, ToolCall,
    ToolSpec, ToolTurn,
};
pub use verdict::{score, score_tool_turn, Verdict, VerdictRule};
