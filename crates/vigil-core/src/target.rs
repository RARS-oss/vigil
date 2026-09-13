//! The target adapter: a thin interface to the system under test, so the harness stays
//! target-agnostic (`docs/DESIGN.md` §4) — an HTTP endpoint, an OpenAI-compatible API, or (future)
//! an agent's tool-call surface, all behind one trait.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetIdentity {
    /// Adapter kind, e.g. "openai-compat" or "echo". Not a security boundary, just a receipt label.
    pub kind: String,
    pub endpoint: String,
    pub model: Option<String>,
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("request to target failed: {0}")]
    Request(String),
    #[error("target response was not valid JSON: {0}")]
    BadResponse(String),
    #[error("target response had no message content")]
    EmptyResponse,
}

pub trait TargetAdapter {
    fn identity(&self) -> TargetIdentity;
    /// Send one probe. `system_prompt`, when present, is sent as the target's system message —
    /// vigil never injects anything into it; it's the caller's own target configuration.
    fn send(&self, system_prompt: Option<&str>, user_prompt: &str) -> Result<String, AdapterError>;
}

/// Echoes the user prompt back verbatim. Deliberately not a real target — it exists to exercise
/// the harness and receipt path offline (unit/integration tests, `vigil scan --adapter echo`).
/// Never use it to back the C2 claim (`docs/DESIGN.md` §5): that requires a real target.
pub struct EchoAdapter;

impl TargetAdapter for EchoAdapter {
    fn identity(&self) -> TargetIdentity {
        TargetIdentity {
            kind: "echo".into(),
            endpoint: "n/a".into(),
            model: None,
        }
    }

    fn send(
        &self,
        _system_prompt: Option<&str>,
        user_prompt: &str,
    ) -> Result<String, AdapterError> {
        Ok(user_prompt.to_string())
    }
}

/// Any OpenAI-compatible `/chat/completions` endpoint — OpenAI itself, or a self-hosted
/// Ollama/vLLM/LM Studio server. One adapter behind the trait, not a special case.
pub struct OpenAiCompatAdapter {
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub timeout: std::time::Duration,
}

impl OpenAiCompatAdapter {
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            model: model.into(),
            api_key: None,
            timeout: std::time::Duration::from_secs(30),
        }
    }

    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl TargetAdapter for OpenAiCompatAdapter {
    fn identity(&self) -> TargetIdentity {
        TargetIdentity {
            kind: "openai-compat".into(),
            endpoint: self.base_url.clone(),
            model: Some(self.model.clone()),
        }
    }

    fn send(&self, system_prompt: Option<&str>, user_prompt: &str) -> Result<String, AdapterError> {
        let mut messages = Vec::new();
        if let Some(s) = system_prompt {
            messages.push(serde_json::json!({"role": "system", "content": s}));
        }
        messages.push(serde_json::json!({"role": "user", "content": user_prompt}));
        let body = serde_json::json!({
            "model": self.model,
            "messages": messages,
        });

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let mut req = ureq::post(&url).timeout(self.timeout);
        if let Some(k) = &self.api_key {
            req = req.set("Authorization", &format!("Bearer {k}"));
        }
        let resp = req
            .send_json(body)
            .map_err(|e| AdapterError::Request(e.to_string()))?;
        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| AdapterError::BadResponse(e.to_string()))?;
        json["choices"][0]["message"]["content"]
            .as_str()
            .map(str::to_string)
            .ok_or(AdapterError::EmptyResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_adapter_returns_the_prompt_verbatim() {
        let a = EchoAdapter;
        assert_eq!(a.send(None, "hello").unwrap(), "hello");
        assert_eq!(a.identity().kind, "echo");
    }

    #[test]
    fn openai_adapter_identity_reports_endpoint_and_model() {
        let a = OpenAiCompatAdapter::new("http://localhost:11434/v1", "llama3");
        let id = a.identity();
        assert_eq!(id.kind, "openai-compat");
        assert_eq!(id.endpoint, "http://localhost:11434/v1");
        assert_eq!(id.model, Some("llama3".to_string()));
    }
}
