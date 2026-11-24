use std::{io::Write, path::Path, process::Command};

use serde_json::{json, Value};

#[test]
fn redacts_input_and_stops_at_blocked_hop() -> anyhow::Result<()> {
    let mut input = tempfile::NamedTempFile::new()?;
    writeln!(
        input,
        "https://api.example.com/path?token=raw-sample -> https://payments.example.com/ -> https://www.example.com/"
    )?;
    input.write_all(b"\xff\n")?;

    let scope = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/lab-scope.yaml");
    let output = Command::new(env!("CARGO_BIN_EXE_prometheus-worker"))
        .args(["shadow-mode", "--scope"])
        .arg(scope)
        .arg("--targets")
        .arg(input.path())
        .args(["--action", "http"])
        .output()?;
    assert!(output.status.success());
    let audit = String::from_utf8(output.stdout)?;
    assert!(!audit.contains("raw-sample"));
    assert!(!audit.contains("payments.example.com"));
    let rows = audit
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0]["decision"], "ALLOW");
    assert_eq!(rows[1]["decision"], "DENY");
    assert_eq!(rows[1]["hop"], 1);
    assert_eq!(rows[2]["reason"], "malformed_target");
    assert_eq!(
        rows[3],
        json!({"summary": {"allow": 1, "deny": 1, "unknown": 1}})
    );
    Ok(())
}
