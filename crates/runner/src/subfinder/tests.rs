use std::{fs, path::Path, process};

use sha2::{Digest, Sha256};

use super::*;
use crate::{
    process::PROCESS_TEST_LOCK,
    test_support::{reviewed_scope, TestGate},
    ToolManifest,
};

const STUB: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    const char *flags[] = {"-d", "example.test", "-silent", "-oJ", "-duc", "-s",
        "hackertarget", "-rsr", "4194304", "-t", "1"};
    if (argc != 12 || getenv("PATH") || !getenv("HOME") || !getenv("XDG_CONFIG_HOME")) return 90;
    for (int i = 1; i < argc; ++i) if (strcmp(argv[i], flags[i - 1])) return 91;
    puts("{\"host\":\"App.example.test\",\"source\":\"stub\"}");
    puts("not json");
    puts("{\"host\":\"$(printf should-not-be-run)\"}");
    puts("{\"host\":\"outside.invalid\"}");
    return 0;
}
"#;

fn stub(
    dir: &Path,
    basename: &str,
    source: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let binary = dir.join(basename);
    let program = binary.with_extension("c");
    fs::write(&program, source)?;
    if !process::Command::new("cc")
        .args(["-std=c99", "-o"])
        .arg(&binary)
        .arg(program)
        .status()?
        .success()
    {
        return Err("could not compile synthetic ELF stub".into());
    }
    Ok(binary)
}

fn pin(binary: &Path, digest: [u8; 32]) -> Result<SubfinderPin, Box<dyn std::error::Error>> {
    let sha256: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let document = format!(
        r#"
version: 1
subfinder:
  path: {binary:?}
  version: {SUBFINDER_CONTRACT_VERSION}
  sha256: '{sha256}'
  intrusiveness: passive
"#
    );
    Ok(serde_yaml::from_str::<ToolManifest>(&document)?.into_subfinder()?)
}

#[tokio::test]
async fn validates_the_digest_and_gate_before_launching_the_fixed_command(
) -> Result<(), Box<dyn std::error::Error>> {
    let _test = PROCESS_TEST_LOCK.lock().await;
    let dir = tempfile::tempdir()?;
    let binary = stub(dir.path(), "subfinder-stub", STUB)?;
    let digest = Sha256::digest(fs::read(&binary)?).into();
    let engine = reviewed_scope("subfinder", [60; 4])?;
    let request = PassiveRequest::new(&engine, engine.snapshot_id(), 15, "example.test")?;
    let rate = Arc::new(PassiveRateLimiter::new());
    let gate = TestGate::default();
    let unpinned = SubfinderCollector::new(pin(&binary, [0; 32])?, rate.clone())?;
    assert_eq!(
        unpinned.collect(&request, &gate).await.err(),
        Some(CollectionError::InvalidManifest)
    );
    assert!(gate.checks.borrow().is_empty());

    let collector = SubfinderCollector::new(pin(&binary, digest)?, rate)?;
    let blocked = TestGate {
        blocked: true,
        ..TestGate::default()
    };
    assert_eq!(
        collector.collect(&request, &blocked).await.err(),
        Some(CollectionError::PolicyHold)
    );
    assert_eq!(*blocked.checks.borrow(), [SOURCE]);
    let batch = collector.collect(&request, &gate).await?;
    assert_eq!(batch.candidates, ["app.example.test", "outside.invalid"]);
    assert_eq!(batch.malformed, 2);
    Ok(())
}

#[tokio::test]
async fn uses_reserved_pressure_exit_codes_and_ignores_stderr_content(
) -> Result<(), Box<dyn std::error::Error>> {
    let _test = PROCESS_TEST_LOCK.lock().await;
    let dir = tempfile::tempdir()?;
    let binary = stub(dir.path(), "pressured", "#include <stdio.h>\nint main(void) { fputs(\"fake provider output\\n\", stderr); return 53; }\n")?;
    let digest = Sha256::digest(fs::read(&binary)?).into();
    let engine = reviewed_scope("subfinder", [60; 4])?;
    let request = PassiveRequest::new(&engine, engine.snapshot_id(), 15, "example.test")?;
    let gate = TestGate::default();
    let collector =
        SubfinderCollector::new(pin(&binary, digest)?, Arc::new(PassiveRateLimiter::new()))?;
    assert_eq!(
        collector.collect(&request, &gate).await.err(),
        Some(CollectionError::ProviderPressure(503))
    );
    assert_eq!(*gate.deferred.borrow(), [(SOURCE, Duration::from_secs(5))]);
    Ok(())
}
