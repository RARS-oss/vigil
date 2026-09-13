//! OWASP Top 10 for LLM Applications (2025) — the category vocabulary vigil scores against.
//!
//! Which of these vigil can actually claim coverage for is a v1 scope decision, not a technical
//! fact about the enum: see `docs/DESIGN.md` §3. `has_payload_set` is the honest, checkable
//! version of that table — it says what vigil ships a corpus for *today*, not what the harness
//! could theoretically test.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwaspCategory {
    Llm01PromptInjection,
    Llm02SensitiveInfoDisclosure,
    Llm03SupplyChain,
    Llm04DataModelPoisoning,
    Llm05ImproperOutputHandling,
    Llm06ExcessiveAgency,
    Llm07SystemPromptLeakage,
    Llm08VectorEmbeddingWeaknesses,
    Llm09Misinformation,
    Llm10UnboundedConsumption,
}

impl OwaspCategory {
    pub fn code(self) -> &'static str {
        match self {
            OwaspCategory::Llm01PromptInjection => "LLM01",
            OwaspCategory::Llm02SensitiveInfoDisclosure => "LLM02",
            OwaspCategory::Llm03SupplyChain => "LLM03",
            OwaspCategory::Llm04DataModelPoisoning => "LLM04",
            OwaspCategory::Llm05ImproperOutputHandling => "LLM05",
            OwaspCategory::Llm06ExcessiveAgency => "LLM06",
            OwaspCategory::Llm07SystemPromptLeakage => "LLM07",
            OwaspCategory::Llm08VectorEmbeddingWeaknesses => "LLM08",
            OwaspCategory::Llm09Misinformation => "LLM09",
            OwaspCategory::Llm10UnboundedConsumption => "LLM10",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            OwaspCategory::Llm01PromptInjection => "Prompt Injection",
            OwaspCategory::Llm02SensitiveInfoDisclosure => "Sensitive Information Disclosure",
            OwaspCategory::Llm03SupplyChain => "Supply Chain",
            OwaspCategory::Llm04DataModelPoisoning => "Data and Model Poisoning",
            OwaspCategory::Llm05ImproperOutputHandling => "Improper Output Handling",
            OwaspCategory::Llm06ExcessiveAgency => "Excessive Agency",
            OwaspCategory::Llm07SystemPromptLeakage => "System Prompt Leakage",
            OwaspCategory::Llm08VectorEmbeddingWeaknesses => "Vector and Embedding Weaknesses",
            OwaspCategory::Llm09Misinformation => "Misinformation",
            OwaspCategory::Llm10UnboundedConsumption => "Unbounded Consumption",
        }
    }

    /// v1 scope per `docs/DESIGN.md` §3: does vigil ship a payload set for this category yet?
    /// LLM01 (Week 1); LLM07 + LLM10 (Week 2); LLM05 + LLM06 (Week 3) do. Keep this in sync with
    /// §3's table when a new set ships — this function, not the README prose, is what
    /// `vigil payloads info` reports.
    pub fn has_payload_set(self) -> bool {
        matches!(
            self,
            OwaspCategory::Llm01PromptInjection
                | OwaspCategory::Llm05ImproperOutputHandling
                | OwaspCategory::Llm06ExcessiveAgency
                | OwaspCategory::Llm07SystemPromptLeakage
                | OwaspCategory::Llm10UnboundedConsumption
        )
    }
}

impl std::fmt::Display for OwaspCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_the_week1_through_3_categories_have_a_payload_set() {
        let covered: Vec<_> = [
            OwaspCategory::Llm01PromptInjection,
            OwaspCategory::Llm02SensitiveInfoDisclosure,
            OwaspCategory::Llm03SupplyChain,
            OwaspCategory::Llm04DataModelPoisoning,
            OwaspCategory::Llm05ImproperOutputHandling,
            OwaspCategory::Llm06ExcessiveAgency,
            OwaspCategory::Llm07SystemPromptLeakage,
            OwaspCategory::Llm08VectorEmbeddingWeaknesses,
            OwaspCategory::Llm09Misinformation,
            OwaspCategory::Llm10UnboundedConsumption,
        ]
        .into_iter()
        .filter(|c| c.has_payload_set())
        .collect();
        assert_eq!(
            covered,
            vec![
                OwaspCategory::Llm01PromptInjection,
                OwaspCategory::Llm05ImproperOutputHandling,
                OwaspCategory::Llm06ExcessiveAgency,
                OwaspCategory::Llm07SystemPromptLeakage,
                OwaspCategory::Llm10UnboundedConsumption,
            ]
        );
    }
}
