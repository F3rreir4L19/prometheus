ALTER TABLE observations ADD COLUMN tool_run_id TEXT REFERENCES tool_runs (id);

CREATE TABLE passive_runs (
    id TEXT PRIMARY KEY NOT NULL REFERENCES tool_runs (id),
    program_id TEXT NOT NULL,
    scope_snapshot_id TEXT NOT NULL,
    collector TEXT NOT NULL,
    observed_at INTEGER NOT NULL CHECK (observed_at >= 0),
    input_hash TEXT NOT NULL CHECK (length(input_hash) = 64),
    completeness TEXT NOT NULL CHECK (completeness IN ('complete', 'partial')),
    deltas_json TEXT NOT NULL CHECK (json_valid(deltas_json) AND json_type(deltas_json) = 'array'),
    UNIQUE (program_id, collector, observed_at),
    FOREIGN KEY (program_id, scope_snapshot_id) REFERENCES scope_snapshots (program_id, id)
);

CREATE INDEX passive_runs_by_snapshot ON passive_runs (scope_snapshot_id, collector);
CREATE INDEX observation_by_asset_collector_time
    ON observations (asset_id, collector, observed_at DESC, id DESC);
CREATE INDEX assets_by_program_kind_id ON assets (program_id, kind, id);

CREATE TRIGGER passive_observations_require_tool_run BEFORE INSERT ON observations
WHEN NEW.collector = 'local_inventory' AND NOT EXISTS (
    SELECT 1 FROM tool_runs t
    JOIN jobs j ON j.id = t.job_id AND j.scope_snapshot_id = t.scope_snapshot_id
    JOIN program_scope_heads h ON h.scope_snapshot_id = t.scope_snapshot_id
    JOIN scope_snapshots s ON s.id = h.scope_snapshot_id
    WHERE t.id = NEW.tool_run_id AND t.tool = 'local_inventory'
      AND j.action = 'passive' AND h.program_id = NEW.program_id
      AND t.scope_snapshot_id = NEW.scope_snapshot_id
      AND s.valid_from <= NEW.observed_at AND NEW.observed_at < s.expires_at
      AND s.valid_from <= t.started_at AND t.started_at < s.expires_at
      AND NEW.observed_at <= t.started_at
      AND NEW.status IN ('present', 'absent') AND length(NEW.exact_hash) = 64
)
BEGIN SELECT RAISE(ABORT, 'passive observation requires a scoped tool run and hash'); END;

CREATE TRIGGER passive_runs_require_tool_run BEFORE INSERT ON passive_runs
WHEN NOT EXISTS (
    SELECT 1 FROM tool_runs t
    JOIN jobs j ON j.id = t.job_id AND j.scope_snapshot_id = t.scope_snapshot_id
    JOIN program_scope_heads h ON h.scope_snapshot_id = t.scope_snapshot_id
    JOIN scope_snapshots s ON s.id = h.scope_snapshot_id
    WHERE t.id = NEW.id AND t.tool = NEW.collector AND j.action = 'passive'
      AND h.program_id = NEW.program_id AND t.scope_snapshot_id = NEW.scope_snapshot_id
      AND s.valid_from <= NEW.observed_at AND NEW.observed_at < s.expires_at
      AND s.valid_from <= t.started_at AND t.started_at < s.expires_at
      AND NEW.observed_at <= t.started_at
)
BEGIN SELECT RAISE(ABORT, 'passive run requires a scoped tool run'); END;

CREATE TRIGGER passive_runs_no_update BEFORE UPDATE ON passive_runs
BEGIN SELECT RAISE(ABORT, 'passive runs are immutable'); END;
CREATE TRIGGER passive_runs_no_delete BEFORE DELETE ON passive_runs
BEGIN SELECT RAISE(ABORT, 'passive runs are immutable'); END;
CREATE TRIGGER local_inventory_tool_runs_no_update BEFORE UPDATE ON tool_runs
WHEN OLD.tool = 'local_inventory' OR NEW.tool = 'local_inventory'
BEGIN SELECT RAISE(ABORT, 'local inventory tool runs are immutable'); END;
CREATE TRIGGER local_inventory_tool_runs_no_delete BEFORE DELETE ON tool_runs
WHEN OLD.tool = 'local_inventory'
BEGIN SELECT RAISE(ABORT, 'local inventory tool runs are immutable'); END;
