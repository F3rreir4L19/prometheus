-- WAL, foreign_keys, busy_timeout, and recursive_triggers are connection settings.
CREATE TABLE programs (
    id TEXT PRIMARY KEY NOT NULL,
    platform TEXT NOT NULL,
    external_program_id TEXT,
    state TEXT NOT NULL,
    policy_profile TEXT NOT NULL,
    UNIQUE (platform, external_program_id)
);

CREATE TABLE scope_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    program_id TEXT NOT NULL REFERENCES programs (id),
    source TEXT NOT NULL CHECK (source IN ('manual_reviewed', 'platform_native')),
    source_hash TEXT NOT NULL,
    fetched_at INTEGER NOT NULL CHECK (fetched_at >= 0),
    valid_from INTEGER NOT NULL CHECK (valid_from >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > valid_from),
    supersedes_id TEXT CHECK (supersedes_id <> id),
    UNIQUE (program_id, id),
    FOREIGN KEY (program_id, supersedes_id) REFERENCES scope_snapshots (program_id, id)
);

CREATE TABLE scope_rules (
    id TEXT NOT NULL,
    scope_snapshot_id TEXT NOT NULL REFERENCES scope_snapshots (id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    target_type TEXT NOT NULL CHECK (target_type IN ('domain', 'wildcard', 'url_prefix', 'ip', 'cidr')),
    target TEXT NOT NULL,
    action_policy_json TEXT NOT NULL CHECK (json_valid(action_policy_json)),
    limits_json TEXT CHECK (limits_json IS NULL OR json_valid(limits_json)),
    provenance TEXT NOT NULL,
    PRIMARY KEY (scope_snapshot_id, id),
    UNIQUE (scope_snapshot_id, ordinal)
);

CREATE TABLE program_scope_heads (
    program_id TEXT PRIMARY KEY NOT NULL,
    scope_snapshot_id TEXT NOT NULL,
    FOREIGN KEY (program_id, scope_snapshot_id) REFERENCES scope_snapshots (program_id, id)
);

CREATE TABLE assets (
    id TEXT PRIMARY KEY NOT NULL,
    program_id TEXT NOT NULL REFERENCES programs (id),
    kind TEXT NOT NULL,
    canonical_key TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL CHECK (last_seen_at >= first_seen_at),
    UNIQUE (program_id, kind, canonical_key),
    UNIQUE (program_id, id)
);

CREATE TABLE observations (
    id TEXT PRIMARY KEY NOT NULL,
    program_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    scope_snapshot_id TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    collector TEXT NOT NULL,
    status TEXT NOT NULL,
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
    exact_hash TEXT,
    structural_hash TEXT,
    simhash BLOB CHECK (simhash IS NULL OR length(simhash) = 8),
    redacted_blob_ref TEXT,
    UNIQUE (program_id, id),
    FOREIGN KEY (program_id, asset_id) REFERENCES assets (program_id, id),
    FOREIGN KEY (program_id, scope_snapshot_id) REFERENCES scope_snapshots (program_id, id)
);

CREATE TABLE asset_relations (
    program_id TEXT NOT NULL,
    src_asset_id TEXT NOT NULL,
    dst_asset_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    PRIMARY KEY (src_asset_id, dst_asset_id, relation_type, observation_id),
    FOREIGN KEY (program_id, src_asset_id) REFERENCES assets (program_id, id),
    FOREIGN KEY (program_id, dst_asset_id) REFERENCES assets (program_id, id),
    FOREIGN KEY (program_id, observation_id) REFERENCES observations (program_id, id)
);

CREATE TABLE endpoints (
    id TEXT PRIMARY KEY NOT NULL,
    web_asset_id TEXT NOT NULL REFERENCES assets (id),
    canonical_route TEXT NOT NULL,
    route_shape TEXT NOT NULL,
    param_signature TEXT NOT NULL,
    UNIQUE (web_asset_id, canonical_route, param_signature)
);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY NOT NULL,
    scope_snapshot_id TEXT NOT NULL REFERENCES scope_snapshots (id),
    occurred_at INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'UNKNOWN')),
    details_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details_json)),
    UNIQUE (scope_snapshot_id, id)
);

CREATE TABLE jobs (
    id TEXT PRIMARY KEY NOT NULL,
    scope_snapshot_id TEXT NOT NULL REFERENCES scope_snapshots (id),
    action TEXT NOT NULL CHECK (action IN ('passive', 'dns', 'http', 'crawl', 'safe_scan', 'oob')),
    policy_decision_id TEXT NOT NULL,
    UNIQUE (scope_snapshot_id, id),
    FOREIGN KEY (scope_snapshot_id, policy_decision_id) REFERENCES audit_events (scope_snapshot_id, id)
);

CREATE TABLE tool_runs (
    id TEXT PRIMARY KEY NOT NULL,
    job_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    tool_sha256 TEXT NOT NULL CHECK (length(tool_sha256) = 64),
    scope_snapshot_id TEXT NOT NULL,
    policy_decision_id TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    finished_at INTEGER CHECK (finished_at IS NULL OR finished_at >= started_at),
    exit_metadata_json TEXT CHECK (exit_metadata_json IS NULL OR json_valid(exit_metadata_json)),
    FOREIGN KEY (scope_snapshot_id, job_id) REFERENCES jobs (scope_snapshot_id, id),
    FOREIGN KEY (scope_snapshot_id, policy_decision_id) REFERENCES audit_events (scope_snapshot_id, id)
);

CREATE TABLE candidate_findings (
    id TEXT PRIMARY KEY NOT NULL,
    program_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'observed', 'candidate', 'evidence_complete', 'human_review_required',
        'approved_for_validation', 'human_validated', 'report_ready', 'human_approved_for_submission'
    )),
    novelty_score REAL,
    evidence_score REAL,
    created_at INTEGER NOT NULL,
    triage_version TEXT NOT NULL,
    UNIQUE (program_id, id),
    FOREIGN KEY (program_id, asset_id) REFERENCES assets (program_id, id)
);

CREATE TABLE evidences (
    id TEXT PRIMARY KEY NOT NULL,
    program_id TEXT NOT NULL,
    candidate_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    redacted_blob_ref TEXT NOT NULL,
    reproducibility TEXT NOT NULL,
    provenance TEXT NOT NULL,
    UNIQUE (candidate_id, id),
    FOREIGN KEY (program_id, candidate_id) REFERENCES candidate_findings (program_id, id),
    FOREIGN KEY (program_id, observation_id) REFERENCES observations (program_id, id)
);

CREATE TABLE llm_calls (
    id TEXT PRIMARY KEY NOT NULL,
    program_id TEXT NOT NULL REFERENCES programs (id),
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    input_tokens INTEGER CHECK (input_tokens >= 0),
    output_tokens INTEGER CHECK (output_tokens >= 0),
    cost_microunits INTEGER CHECK (cost_microunits >= 0),
    currency TEXT
);

CREATE TABLE reviews (
    id TEXT PRIMARY KEY NOT NULL,
    program_id TEXT NOT NULL,
    candidate_id TEXT NOT NULL,
    reviewer_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    reviewed_at INTEGER NOT NULL,
    UNIQUE (program_id, id),
    FOREIGN KEY (program_id, candidate_id) REFERENCES candidate_findings (program_id, id)
);

CREATE TABLE approvals (
    id TEXT PRIMARY KEY NOT NULL,
    program_id TEXT NOT NULL,
    review_id TEXT NOT NULL,
    scope_snapshot_id TEXT NOT NULL,
    operation_hash TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
    state TEXT NOT NULL CHECK (state IN ('pending', 'consumed', 'expired', 'rejected')),
    consumed_at INTEGER,
    CHECK ((state = 'consumed') = (consumed_at IS NOT NULL)),
    CHECK (consumed_at IS NULL OR (consumed_at >= issued_at AND consumed_at < expires_at)),
    FOREIGN KEY (program_id, review_id) REFERENCES reviews (program_id, id),
    FOREIGN KEY (program_id, scope_snapshot_id) REFERENCES scope_snapshots (program_id, id)
);

CREATE TABLE report_drafts (
    id TEXT PRIMARY KEY NOT NULL,
    candidate_id TEXT NOT NULL REFERENCES candidate_findings (id),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    redacted_blob_ref TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (candidate_id, revision),
    UNIQUE (candidate_id, id)
);

CREATE TABLE report_evidences (
    candidate_id TEXT NOT NULL,
    report_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    claim_key TEXT NOT NULL,
    PRIMARY KEY (report_id, evidence_id, claim_key),
    FOREIGN KEY (candidate_id, report_id) REFERENCES report_drafts (candidate_id, id),
    FOREIGN KEY (candidate_id, evidence_id) REFERENCES evidences (candidate_id, id)
);

CREATE TABLE dedup_clusters (
    id TEXT PRIMARY KEY NOT NULL,
    program_id TEXT NOT NULL REFERENCES programs (id),
    algorithm_version TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (program_id, id)
);

CREATE TABLE dedup_memberships (
    program_id TEXT NOT NULL,
    cluster_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    joined_at INTEGER NOT NULL,
    removed_at INTEGER CHECK (removed_at IS NULL OR removed_at >= joined_at),
    PRIMARY KEY (cluster_id, observation_id, joined_at),
    FOREIGN KEY (program_id, cluster_id) REFERENCES dedup_clusters (program_id, id),
    FOREIGN KEY (program_id, observation_id) REFERENCES observations (program_id, id)
);

CREATE INDEX snapshots_by_program ON scope_snapshots (program_id, valid_from);
CREATE INDEX observations_by_asset_time ON observations (asset_id, observed_at DESC);
CREATE INDEX observations_by_snapshot ON observations (scope_snapshot_id);
CREATE INDEX observations_by_hash ON observations (program_id, exact_hash);
CREATE INDEX relations_by_destination ON asset_relations (dst_asset_id);
CREATE INDEX tool_runs_by_job ON tool_runs (job_id);
CREATE INDEX candidates_by_state ON candidate_findings (program_id, state);
CREATE INDEX evidences_by_candidate ON evidences (candidate_id);
CREATE INDEX llm_calls_by_program_time ON llm_calls (program_id, created_at);
CREATE INDEX llm_calls_by_cache ON llm_calls (program_id, cache_key);
CREATE INDEX reviews_by_candidate ON reviews (candidate_id);
CREATE INDEX approvals_by_expiry ON approvals (state, expires_at);
CREATE INDEX audit_by_snapshot_time ON audit_events (scope_snapshot_id, occurred_at);
CREATE UNIQUE INDEX live_cluster_membership
    ON dedup_memberships (cluster_id, observation_id) WHERE removed_at IS NULL;

CREATE TRIGGER snapshots_no_update BEFORE UPDATE ON scope_snapshots
BEGIN SELECT RAISE(ABORT, 'scope snapshots are immutable'); END;
CREATE TRIGGER snapshots_no_delete BEFORE DELETE ON scope_snapshots
BEGIN SELECT RAISE(ABORT, 'scope snapshots are immutable'); END;
CREATE TRIGGER rules_no_update BEFORE UPDATE ON scope_rules
BEGIN SELECT RAISE(ABORT, 'scope rules are immutable'); END;
CREATE TRIGGER rules_no_delete BEFORE DELETE ON scope_rules
BEGIN SELECT RAISE(ABORT, 'scope rules are immutable'); END;
CREATE TRIGGER observations_no_update BEFORE UPDATE ON observations
BEGIN SELECT RAISE(ABORT, 'observations are immutable'); END;
CREATE TRIGGER observations_no_delete BEFORE DELETE ON observations
BEGIN SELECT RAISE(ABORT, 'observations are immutable'); END;
CREATE TRIGGER jobs_no_update BEFORE UPDATE ON jobs
BEGIN SELECT RAISE(ABORT, 'job identity and scope are immutable'); END;
CREATE TRIGGER jobs_no_delete BEFORE DELETE ON jobs
BEGIN SELECT RAISE(ABORT, 'job identity and scope are immutable'); END;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;

CREATE TABLE scope_publications (
    scope_snapshot_id TEXT PRIMARY KEY NOT NULL REFERENCES scope_snapshots (id)
);

CREATE TRIGGER publications_no_update BEFORE UPDATE ON scope_publications
BEGIN SELECT RAISE(ABORT, 'published scopes are immutable'); END;
CREATE TRIGGER publications_no_delete BEFORE DELETE ON scope_publications
BEGIN SELECT RAISE(ABORT, 'published scopes are immutable'); END;
CREATE TRIGGER rules_no_insert_after_publication BEFORE INSERT ON scope_rules
WHEN EXISTS (SELECT 1 FROM scope_publications WHERE scope_snapshot_id = NEW.scope_snapshot_id)
BEGIN SELECT RAISE(ABORT, 'published scope cannot accept more rules'); END;

CREATE TRIGGER head_publish_after_insert AFTER INSERT ON program_scope_heads
BEGIN INSERT OR IGNORE INTO scope_publications VALUES (NEW.scope_snapshot_id); END;
CREATE TRIGGER head_publish_after_update AFTER UPDATE ON program_scope_heads
BEGIN INSERT OR IGNORE INTO scope_publications VALUES (NEW.scope_snapshot_id); END;

-- A displaced revision remains sealed and cannot be reactivated.
CREATE TRIGGER head_no_reactivation_insert BEFORE INSERT ON program_scope_heads
WHEN EXISTS (SELECT 1 FROM scope_publications WHERE scope_snapshot_id = NEW.scope_snapshot_id)
BEGIN SELECT RAISE(ABORT, 'scope revision has already been published'); END;

CREATE TRIGGER head_no_reactivation_update BEFORE UPDATE OF scope_snapshot_id ON program_scope_heads
WHEN OLD.scope_snapshot_id <> NEW.scope_snapshot_id
AND EXISTS (SELECT 1 FROM scope_publications WHERE scope_snapshot_id = NEW.scope_snapshot_id)
BEGIN SELECT RAISE(ABORT, 'scope revision has already been published'); END;

CREATE TRIGGER jobs_require_allow BEFORE INSERT ON jobs
WHEN NOT EXISTS (
    SELECT 1 FROM audit_events a
    JOIN program_scope_heads h ON h.scope_snapshot_id = a.scope_snapshot_id
    JOIN scope_snapshots s ON s.id = h.scope_snapshot_id
    WHERE a.id = NEW.policy_decision_id
      AND s.id = NEW.scope_snapshot_id
      AND a.decision = 'ALLOW'
      AND s.valid_from <= a.occurred_at AND a.occurred_at < s.expires_at
)
BEGIN SELECT RAISE(ABORT, 'job requires an allow decision on the active revision'); END;
