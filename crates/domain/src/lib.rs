//! Shared identifiers and state. Times are Unix seconds in UTC.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

macro_rules! id {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
            #[serde(transparent)]
            pub struct $name(pub String);
        )+
    };
}

id!(
    ProgramId,
    ScopeSnapshotId,
    ScopeRuleId,
    AssetId,
    ObservationId,
    CandidateFindingId,
    EvidenceId,
    ApprovalId,
    AuditEventId,
    JobId,
    ToolRunId,
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Passive,
    Dns,
    Http,
    Crawl,
    SafeScan,
    Oob,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Allow,
    Deny,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Program {
    pub id: ProgramId,
    pub platform: String,
    pub external_program_id: Option<String>,
    pub state: String,
    pub policy_profile: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeSource {
    ManualReviewed,
    PlatformNative,
    DiscoveryFeed,
    Inferred,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSnapshot {
    pub id: ScopeSnapshotId,
    pub program_id: ProgramId,
    pub source: ScopeSource,
    pub valid_from: u64,
    pub expires_at: u64,
    pub supersedes_id: Option<ScopeSnapshotId>,
    pub rules: Vec<ScopeRule>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Domain,
    Wildcard,
    UrlPrefix,
    Ip,
    Cidr,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRule {
    pub id: ScopeRuleId,
    pub effect: Effect,
    pub kind: TargetKind,
    pub target: String,
    pub actions: Vec<Action>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Asset {
    pub id: AssetId,
    pub program_id: ProgramId,
    pub kind: String,
    pub canonical_key: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Observation {
    pub id: ObservationId,
    pub asset_id: AssetId,
    pub scope_snapshot_id: ScopeSnapshotId,
    pub observed_at: u64,
    pub collector: String,
    pub exact_hash: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaKind {
    NewAsset,
    ReactivatedAsset,
    ScopeChanged,
    ChangedAsset,
    AbsentAsset,
}

impl DeltaKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NewAsset => "new_asset",
            Self::ReactivatedAsset => "reactivated_asset",
            Self::ScopeChanged => "scope_changed",
            Self::ChangedAsset => "changed_asset",
            Self::AbsentAsset => "absent_asset",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaDetected {
    pub kind: DeltaKind,
    pub scope_snapshot_id: ScopeSnapshotId,
    pub asset_id: Option<AssetId>,
    pub observation_id: Option<ObservationId>,
    pub occurred_at: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionCompleteness {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaCounts {
    pub new_assets: u64,
    pub reactivated_assets: u64,
    pub scope_changes: u64,
    pub changed_assets: u64,
    pub absent_assets: u64,
}

impl DeltaCounts {
    pub fn record(&mut self, kind: DeltaKind) {
        match kind {
            DeltaKind::NewAsset => self.new_assets += 1,
            DeltaKind::ReactivatedAsset => self.reactivated_assets += 1,
            DeltaKind::ScopeChanged => self.scope_changes += 1,
            DeltaKind::ChangedAsset => self.changed_assets += 1,
            DeltaKind::AbsentAsset => self.absent_assets += 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CandidateFinding {
    pub id: CandidateFindingId,
    pub asset_id: AssetId,
    pub finding_type: String,
    pub state: TriageState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Evidence {
    pub id: EvidenceId,
    pub candidate_id: CandidateFindingId,
    pub observation_id: ObservationId,
    pub redacted_blob_ref: String,
    pub provenance: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Consumed,
    Expired,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Approval {
    pub id: ApprovalId,
    pub scope_snapshot_id: ScopeSnapshotId,
    pub operation_hash: String,
    pub nonce: String,
    pub expires_at: u64,
    pub state: ApprovalState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditEvent {
    pub id: AuditEventId,
    pub scope_snapshot_id: ScopeSnapshotId,
    pub occurred_at: u64,
    pub decision: Decision,
    pub event_type: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageState {
    Observed,
    Candidate,
    EvidenceComplete,
    HumanReviewRequired,
    ApprovedForValidation,
    HumanValidated,
    ReportReady,
    HumanApprovedForSubmission,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid triage transition from {from:?} to {to:?}")]
pub struct InvalidTransition {
    pub from: TriageState,
    pub to: TriageState,
}

impl TriageState {
    pub fn transition(self, to: Self) -> Result<Self, InvalidTransition> {
        use TriageState::*;
        if matches!(
            (self, to),
            (Observed, Candidate)
                | (Candidate, EvidenceComplete)
                | (EvidenceComplete, HumanReviewRequired)
                | (HumanReviewRequired, ApprovedForValidation)
                | (ApprovedForValidation, HumanValidated)
                | (HumanValidated, ReportReady)
                | (ReportReady, HumanApprovedForSubmission)
        ) {
            Ok(to)
        } else {
            Err(InvalidTransition { from: self, to })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TriageState::*;

    #[test]
    fn triage_cannot_skip_human_review() {
        assert!(EvidenceComplete.transition(ApprovedForValidation).is_err());
        assert!(ReportReady.transition(HumanApprovedForSubmission).is_ok());
        assert!(Observed.transition(Candidate).is_ok());
    }
}
