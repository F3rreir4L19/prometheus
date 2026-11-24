//! Model configuration, schema and deterministic redaction. Provider I/O is deferred.

use domain::{AssetId, EvidenceId, ProgramId};
use hmac::{Hmac, Mac};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmProvider {
    OpenAi,
    Gemini,
    OpenAiCompatible,
    OpenRouter,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderProfile {
    pub provider: LlmProvider,
    pub endpoint: String,
    pub model: String,
    pub credential_env: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DailyBudget {
    pub requests: u64,
    pub tokens: u64,
    pub cost_microunits: u64,
    pub currency: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelBrokerConfig {
    pub program_id: ProgramId,
    pub batch: ProviderProfile,
    pub advanced: Option<ProviderProfile>,
    pub budget: DailyBudget,
    pub prompt_version: String,
    pub schema_version: String,
    pub redaction_version: String,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageDisposition {
    Dismiss,
    NeedsEvidence,
    NeedsHumanReview,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TriageResult {
    pub asset_id: AssetId,
    pub evidence_ids: Vec<EvidenceId>,
    pub disposition: TriageDisposition,
}

#[derive(Debug, Error)]
pub enum RedactionError {
    #[error("redaction requires an HMAC key with at least 32 bytes")]
    ShortKey,
    #[error("cannot write redaction token")]
    Format(#[from] std::fmt::Error),
}

/// An opaque program-scoped token. It retains no original input bytes.
pub struct RedactedText(String);

impl RedactedText {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct Redactor(Hmac<Sha256>);

impl Redactor {
    pub fn new(key: &[u8]) -> Result<Self, RedactionError> {
        if key.len() < 32 {
            return Err(RedactionError::ShortKey);
        }
        Hmac::new_from_slice(key)
            .map(Self)
            .map_err(|_| RedactionError::ShortKey)
    }

    /// Mask a whole untrusted field. Selective masking requires a future field allowlist.
    pub fn mask(&self, program: &ProgramId, field: &[u8]) -> Result<RedactedText, RedactionError> {
        use std::fmt::Write;

        let mut mac = self.0.clone();
        mac.update(b"prometheus-redaction-v1\0");
        mac.update(&(program.0.len() as u64).to_be_bytes());
        mac.update(program.0.as_bytes());
        mac.update(field);
        let mut token = String::from("hmac-sha256:");
        for byte in mac.finalize().into_bytes() {
            write!(token, "{byte:02x}")?;
        }
        Ok(RedactedText(token))
    }
}

/// Offline model interface for fixtures and evaluation. References still require repository checks.
pub trait ModelBroker {
    type Error;

    fn triage_redacted(
        &self,
        asset: &AssetId,
        evidence: &[EvidenceId],
        input: &RedactedText,
    ) -> Result<TriageResult, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_token_is_deterministic_and_program_scoped() -> Result<(), RedactionError> {
        let redactor = Redactor::new(&[42; 32])?;
        let p1 = ProgramId("one".into());
        let p2 = ProgramId("two".into());
        let secret = b"token-sample";
        let a = redactor.mask(&p1, secret)?;
        assert_eq!(a.as_str(), redactor.mask(&p1, secret)?.as_str());
        assert_ne!(a.as_str(), redactor.mask(&p2, secret)?.as_str());
        assert!(!a.as_str().contains("token-sample"));
        assert!(Redactor::new(b"short").is_err());
        Ok(())
    }

    #[test]
    fn triage_disallows_tool_or_target_fields() {
        let value = r#"{"asset_id":"a","evidence_ids":["ev"],"disposition":"dismiss","target":"example.com"}"#;
        assert!(serde_json::from_str::<TriageResult>(value).is_err());
        let schema = schemars::schema_for!(TriageResult);
        assert_eq!(schema.as_value()["additionalProperties"], false);
    }
}
