# vigil — design

## 1. Problem

The industry answers "is this LLM application secure?" with a checklist and a PDF. OWASP
publishes a real, well-researched Top 10 for LLM Applications — but every vendor scan against it
produces a report that says "passed" or "failed" with no way for anyone else to check the run
itself. Nobody signs the payloads used, nobody versions the attack corpus, nobody can tell six
months later whether a "clean" result meant the target was actually safe or the attack corpus was
just stale.

`sbx` and `bulla` already treat a compiler and a sandbox as adversarial evidence sources — nothing
here has pointed that same discipline at an LLM application's own input surface. `vigil` does.

## 2. What to build on (reuse, not rebuild)

| Repo | What to take from it |
|---|---|
| [`bulla`](https://github.com/RARS-oss/bulla) | Its Ed25519 signed-receipt format, directly. A vigil scan result should be the same shape of artifact as a bulla execution receipt: policy hash, content-addressed manifest of inputs (here: the payload set), the raw transcripts, a hash-chained log, Ed25519 signature. Don't reinvent this — import or port the receipt crate. |
| [`tabularium`](https://github.com/RARS-oss/tabularium) | The validity-check pattern (`file_hash`, `TTL`) applied to the payload corpus instead of to memories: a payload set has a version and can go stale exactly the way a memory can. Also the honest scoping discipline in its `DESIGN.md` and `docs/DOGFOODING-NOTES.md` — read both before writing vigil's own design doc, they're the template for how this project should report real findings (including "the naive fix was a trap" style write-ups). Its real H2 finding (a default config silently allowed trust-spoofing; the first fix was itself unsafe in the real topology; the correct fix moved the invariant into code) is the direct personal precedent for what vigil is meant to find systematically in *other* systems — not the same attack surface (that was agent-to-memory trust, not LLM prompt injection), but the same failure shape: a default that looks safe and isn't, caught by testing against something real instead of trusting the design. |
| [`sbx`](https://github.com/RARS-oss/sbx) | Not code reuse — the underlying stance: never trust the executor/target to self-report correctly, always verify from an independent, adversarial position. |

## 3. Scope — honest OWASP coverage, not a marketing checklist

OWASP Top 10 for LLM Applications (2025): LLM01 Prompt Injection, LLM02 Sensitive Information
Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling,
LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses,
LLM09 Misinformation, LLM10 Unbounded Consumption.
(Source: [OWASP GenAI Security Project](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/).)

Not all ten are actually testable by a black-box automated red-team harness. Say so up front,
the same way `bulla`'s README states what its receipts do *not* prove:

| Category | v1 scope |
|---|---|
| LLM01 Prompt Injection | **Core.** Directly testable — this is the harness's primary target. |
| LLM07 System Prompt Leakage | **Core.** Directly testable via extraction payloads. |
| LLM06 Excessive Agency | **Core.** Testable against any target with tool/function-calling access — probe whether it can be talked into calling tools outside its intended scope. |
| LLM05 Improper Output Handling | **Core.** Testable if the target's output flows anywhere downstream (rendered HTML, executed code, a DB query) — probe for unsanitized pass-through. |
| LLM10 Unbounded Consumption | **Core.** Testable — crafted inputs that trigger runaway generation, recursive tool calls, resource exhaustion. |
| LLM02 Sensitive Information Disclosure | **Partial.** Testable for obvious leakage (secrets in system prompt, PII regurgitation) with generic probes; anything domain-specific needs a target-supplied seed list. |
| LLM08 Vector and Embedding Weaknesses | **Partial.** Only applicable if the target does RAG; needs `fons` (planned) or a similar retrieval layer to even have a surface to test. |
| LLM03 Supply Chain | **Out of scope for v1.** This is a dependency/provenance audit problem, not something a runtime red-team probe can exercise. |
| LLM04 Data and Model Poisoning | **Out of scope for v1.** Mostly a training-time concern; black-box inference-time testing can't establish much here. |
| LLM09 Misinformation | **Out of scope for v1.** Needs domain-specific ground truth to score against; a generic harness can't judge factual accuracy without a curated answer key per target. |

That's 5 core + 2 partial + 3 explicitly out of scope. A README that claims "full OWASP Top 10
coverage" without this table is exactly the kind of unverifiable claim this whole project exists
to replace.

## 4. Model

- **Payload registry**: each attack payload is versioned and content-hashed, same idea as
  tabularium's `file_hash` check but applied to the corpus itself, so a scan result can say
  *which exact payload set* produced it, and a stale corpus is a known, flagged state rather than
  a silent one.
- **Target adapter**: a thin interface to the system under test (an HTTP endpoint, an OpenAI-
  compatible API, an agent's tool-call surface) — the harness stays target-agnostic.
- **Run manifest**: binds payload-set version + target identity + timestamp, content-addressed.
- **Receipt**: Ed25519-signed (ported from `bulla`), covering the manifest, every raw
  transcript, and the verdict per payload — checkable offline by anyone who trusts the public key,
  without trusting the machine that ran the scan.
- **CI gate mode**: exit non-zero on a new payload category passing that previously failed —
  "don't deploy if a new injection vector opened up," not just a one-off report.

## 5. Claims (to validate for real, not assert)

- **C1 (coverage honesty).** The tool never reports "clean" without naming the exact payload-set
  version and its age; a stale payload set is flagged, not silently trusted.
- **C2 (real target, real result).** At least one of the five "core" categories is run against a
  real, non-toy LLM application (not a synthetic mock) before this is called done, with the
  transcript and verdict shown, misses included — same rule tabularium's H3 pilot followed.
- **C3 (reproducibility).** Re-running the same payload set against the same target state
  produces a byte-identical receipt (modulo the target's own non-determinism, which should itself
  be measured and reported, not assumed away).

## 6. Roadmap

1. **Week 1:** payload registry + versioning, target adapter interface, LLM01 (prompt injection)
   payload set, receipt format ported from `bulla`.
2. **Week 2:** LLM07 (system prompt leakage) + LLM10 (unbounded consumption) payload sets; CI
   gate mode.
3. **Week 3:** LLM06 (excessive agency) — needs a tool-calling test harness, the hardest core
   category; LLM05 (output handling) against at least one real downstream sink.
4. **Week 4:** run against a real target end-to-end (C2), write up the result honestly (including
   what it missed), partial LLM02/LLM08 coverage if time allows, README with the scope table
   from section 3 front and center.

Status: not started. This file is the starting point — read `tabularium`'s `DESIGN.md` and
`docs/DOGFOODING-NOTES.md` first for the reporting voice and the honesty conventions before
writing a line of code.
