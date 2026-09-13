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

/// One tool/function the target is offered on a probe (LLM06's tool-calling surface).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema for the tool's arguments, in the shape OpenAI-compatible APIs expect.
    pub parameters: serde_json::Value,
}

/// One tool call the target made, as reported by the API (name + raw JSON arguments string).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCall {
    pub name: String,
    pub arguments: String,
}

/// A tool-calling turn's result: either a plain message, or one or more tool invocations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ToolTurn {
    Message(String),
    ToolCalls(Vec<ToolCall>),
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("request to target failed: {0}")]
    Request(String),
    #[error("target response was not valid JSON: {0}")]
    BadResponse(String),
    #[error("target response had no message content")]
    EmptyResponse,
    #[error("this adapter does not support tool calling")]
    ToolCallingUnsupported,
}

pub trait TargetAdapter {
    fn identity(&self) -> TargetIdentity;
    /// Send one probe. `system_prompt`, when present, is sent as the target's system message —
    /// vigil never injects anything into it; it's the caller's own target configuration.
    fn send(&self, system_prompt: Option<&str>, user_prompt: &str) -> Result<String, AdapterError>;

    /// Send one probe with a declared tool/function-calling surface (LLM06 — excessive agency).
    /// Adapters that don't support tool calling keep this default, which reports the gap plainly
    /// (an `errored` result) rather than silently skipping the probe or pretending to test it.
    fn send_with_tools(
        &self,
        _system_prompt: Option<&str>,
        _user_prompt: &str,
        _tools: &[ToolSpec],
    ) -> Result<ToolTurn, AdapterError> {
        Err(AdapterError::ToolCallingUnsupported)
    }
}

/// Echoes the user prompt back verbatim. Deliberately not a real target — it exists to exercise
/// the harness and receipt path offline (unit/integration tests, `vigil scan --adapter echo`).
/// Never use it to back the C2 claim (`docs/DESIGN.md` §5): that requires a real target. It does
/// not support tool calling (LLM06 probes against it come back `errored`, honestly).
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

    fn post(&self, body: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let mut req = ureq::post(&url).timeout(self.timeout);
        if let Some(k) = &self.api_key {
            req = req.set("Authorization", &format!("Bearer {k}"));
        }
        let resp = req
            .send_json(body)
            .map_err(|e| AdapterError::Request(e.to_string()))?;
        resp.into_json()
            .map_err(|e| AdapterError::BadResponse(e.to_string()))
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

        let json = self.post(body)?;
        json["choices"][0]["message"]["content"]
            .as_str()
            .map(str::to_string)
            .ok_or(AdapterError::EmptyResponse)
    }

    fn send_with_tools(
        &self,
        system_prompt: Option<&str>,
        user_prompt: &str,
        tools: &[ToolSpec],
    ) -> Result<ToolTurn, AdapterError> {
        let mut messages = Vec::new();
        if let Some(s) = system_prompt {
            messages.push(serde_json::json!({"role": "system", "content": s}));
        }
        messages.push(serde_json::json!({"role": "user", "content": user_prompt}));

        let tool_defs: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    }
                })
            })
            .collect();

        let body = serde_json::json!({
            "model": self.model,
            "messages": messages,
            "tools": tool_defs,
            "tool_choice": "auto",
        });

        let json = self.post(body)?;
        let message = &json["choices"][0]["message"];

        if let Some(calls) = message["tool_calls"].as_array() {
            if !calls.is_empty() {
                let parsed: Vec<ToolCall> = calls
                    .iter()
                    .filter_map(|c| {
                        let name = c["function"]["name"].as_str()?.to_string();
                        let arguments = c["function"]["arguments"]
                            .as_str()
                            .unwrap_or("")
                            .to_string();
                        Some(ToolCall { name, arguments })
                    })
                    .collect();
                if !parsed.is_empty() {
                    return Ok(ToolTurn::ToolCalls(parsed));
                }
            }
        }

        message["content"]
            .as_str()
            .map(|s| ToolTurn::Message(s.to_string()))
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
    fn echo_adapter_does_not_support_tool_calling() {
        let a = EchoAdapter;
        let err = a.send_with_tools(None, "hello", &[]).unwrap_err();
        assert!(matches!(err, AdapterError::ToolCallingUnsupported));
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
