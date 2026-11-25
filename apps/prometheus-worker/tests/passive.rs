use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{ensure, Result};
use serde_json::Value;

fn worker() -> Command {
    Command::new(env!("CARGO_BIN_EXE_prometheus-worker"))
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
}

fn report(output: Output) -> Result<Value> {
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout)?;
    for raw in [
        "payments.example.com",
        "staged.example.com",
        "api.example.com",
        "münchen.example",
        "sample-secret",
    ] {
        assert!(!text.contains(raw));
    }
    Ok(serde_json::from_str(&text)?)
}

#[test]
fn dry_run_simulates_without_opening_database() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let db = temp.path().join("inventory.sqlite");
    let summary = report(
        worker()
            .args(["passive-sync", "--scope"])
            .arg(fixture("lab-passive-scope.yaml"))
            .args(["--dry-run", "--fixture"])
            .arg(fixture("passive-domains.txt"))
            .arg("--db")
            .arg(&db)
            .output()?,
    )?;
    assert_eq!(summary["dry_run"], true);
    assert_eq!(summary["inventory"]["allowed"], 2);
    assert_eq!(summary["inventory"]["denied"], 1);
    assert_eq!(summary["inventory"]["unknown"], 1);
    assert_eq!(summary["inventory"]["duplicates"], 1);
    assert_eq!(summary["deltas"]["new_assets"], 0);
    assert!(!db.exists());
    Ok(())
}

#[test]
fn persisted_inventory_keeps_discovery_separate_and_replays_deltas() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let db = temp.path().join("inventory.sqlite");
    let scope = fixture("lab-passive-scope.yaml");
    let index = temp.path().join("index.json");
    fs::write(
        &index,
        r#"[{"targets":{"in_scope":[{"asset_type":"URL","asset_identifier":"staged.example.com"},{"asset_type":"URL","asset_identifier":"payments.example.com"}]}}]"#,
    )?;
    let publication = report(
        worker()
            .args(["publish-scope", "--scope"])
            .arg(&scope)
            .arg("--db")
            .arg(&db)
            .output()?,
    )?;
    assert_eq!(publication["published"], true);

    let collect = |inventory: &Path, key: &str, at: &str| {
        worker()
            .args(["passive-sync", "--scope"])
            .arg(&scope)
            .arg("--db")
            .arg(&db)
            .arg("--inventory")
            .arg(inventory)
            .arg("--discovery-index")
            .arg(&index)
            .args(["--run-key", key, "--observed-at", at, "--complete"])
            .output()
    };
    let inventory = fixture("passive-domains.txt");
    let first = report(collect(&inventory, "first", "10")?)?;
    assert_eq!(first["discovery"]["allowed"], 1);
    assert_eq!(first["discovery"]["denied"], 1);
    assert_eq!(first["deltas"]["new_assets"], 2);
    assert_eq!(first["completeness"], "complete");
    assert_eq!(first["replayed"], false);

    let replay = report(collect(&inventory, "first", "10")?)?;
    assert_eq!(replay["deltas"], first["deltas"]);
    assert_eq!(replay["replayed"], true);

    let partial = temp.path().join("partial.txt");
    fs::write(&partial, b"https://api.example.com/?key=sample-secret\n")?;
    let malformed = report(collect(&partial, "partial", "11")?)?;
    assert_eq!(malformed["inventory"]["malformed"], 1);
    assert_eq!(malformed["completeness"], "partial");
    assert_eq!(malformed["deltas"]["absent_assets"], 0);
    Ok(())
}
