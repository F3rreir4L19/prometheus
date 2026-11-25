CREATE TABLE passive_admission (
    lane TEXT PRIMARY KEY NOT NULL,
    boot_id TEXT NOT NULL,
    available_at_ms INTEGER NOT NULL CHECK (available_at_ms >= 0),
    last_admission_at_ms INTEGER CHECK (last_admission_at_ms >= 0)
);

CREATE TRIGGER live_observations_require_tool_run BEFORE INSERT ON observations
WHEN NEW.collector IN ('crtsh', 'crtsh_loopback', 'subfinder') AND NOT EXISTS (
    SELECT 1 FROM tool_runs t
    JOIN jobs j ON j.id = t.job_id AND j.scope_snapshot_id = t.scope_snapshot_id
    JOIN program_scope_heads h ON h.scope_snapshot_id = t.scope_snapshot_id
    JOIN scope_snapshots s ON s.id = h.scope_snapshot_id
    WHERE t.id = NEW.tool_run_id AND t.tool = NEW.collector
      AND json_extract(t.exit_metadata_json, '$.completeness') = 'partial'
      AND j.action = 'passive' AND h.program_id = NEW.program_id
      AND t.scope_snapshot_id = NEW.scope_snapshot_id
      AND s.valid_from <= NEW.observed_at AND NEW.observed_at < s.expires_at
      AND NEW.observed_at <= t.started_at AND t.finished_at < s.expires_at
      AND NEW.status = 'present' AND length(NEW.exact_hash) = 64
)
BEGIN SELECT RAISE(ABORT, 'live observation requires a scoped positive tool run and hash'); END;

CREATE TRIGGER live_runs_are_partial BEFORE INSERT ON passive_runs
WHEN NEW.collector IN ('crtsh', 'crtsh_loopback', 'subfinder') AND (
    NEW.completeness <> 'partial' OR NOT EXISTS (
        SELECT 1 FROM tool_runs t WHERE t.id = NEW.id AND t.finished_at IS NOT NULL
          AND json_extract(t.exit_metadata_json, '$.completeness') = 'partial'
    )
)
BEGIN SELECT RAISE(ABORT, 'live passive sources provide partial inventory'); END;

CREATE TRIGGER live_tool_runs_no_update BEFORE UPDATE ON tool_runs
WHEN OLD.tool IN ('crtsh', 'crtsh_loopback', 'subfinder') OR NEW.tool IN ('crtsh', 'crtsh_loopback', 'subfinder')
BEGIN
    SELECT CASE WHEN NOT (
        OLD.finished_at IS NULL AND NEW.finished_at IS NOT NULL
        AND COALESCE(json_extract(OLD.exit_metadata_json, '$.kind') = 'dispatch', 0)
        AND OLD.id = NEW.id AND OLD.job_id = NEW.job_id AND OLD.tool = NEW.tool
        AND OLD.tool_version = NEW.tool_version AND OLD.tool_sha256 = NEW.tool_sha256
        AND OLD.scope_snapshot_id = NEW.scope_snapshot_id
        AND OLD.policy_decision_id = NEW.policy_decision_id AND OLD.started_at = NEW.started_at
        AND OLD.exit_metadata_json IS NEW.exit_metadata_json
    ) THEN RAISE(ABORT, 'live tool runs are immutable after completion') END;
END;

CREATE TRIGGER live_tool_runs_no_delete BEFORE DELETE ON tool_runs
WHEN OLD.tool IN ('crtsh', 'crtsh_loopback', 'subfinder')
BEGIN SELECT RAISE(ABORT, 'live tool runs are immutable'); END;
