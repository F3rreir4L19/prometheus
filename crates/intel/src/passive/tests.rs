use super::*;

const POLICY: &[u8] = br#"
version: 1
snapshot:
  id: lab-v2
  program_id: lab
  source: manual_reviewed
  valid_from: 10
  expires_at: 20
  rules:
    - { id: host-deny, effect: deny, kind: domain, target: private.example.com, actions: [passive] }
    - { id: wildcard, effect: allow, kind: wildcard, target: '*.example.com', actions: [passive] }
    - { id: idna, effect: allow, kind: domain, target: xn--mnchen-3ya.example, actions: [passive] }
    - { id: http-only, effect: allow, kind: domain, target: http.example.org, actions: [http] }
"#;

#[test]
fn inventory_canonicalizes_deduplicates_and_blocks_untrusted_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let engine = ScopeEngine::from_yaml(POLICY)?;
    let mut input = "# notes\n\r\nWWW.Example.com.\nwww.example.com\nmünchen.example\n\
                 private.example.com\nhttp.example.org\nexample.com\nspill.example.net\n\
                 http://www.example.com/?token=synthetic\n*.example.com\n\
                 ::ffff:192.0.2.1\nwww.example.com;cmd\n"
        .as_bytes()
        .to_vec();
    input.extend_from_slice(b"\xff.example.com\n");
    let result = filter_inventory(&input, &engine, engine.snapshot_id(), 12)?;
    assert_eq!(
        result.domains,
        ["www.example.com", "xn--mnchen-3ya.example"]
    );
    assert_eq!(
        result.counts,
        SelectionCounts {
            allowed: 2,
            denied: 1,
            unknown: 3,
            duplicates: 1,
            malformed: 5,
        }
    );
    assert!(!serde_json::to_string(&result.counts)?.contains("example"));
    Ok(())
}

#[test]
fn discovery_metadata_and_nonliteral_targets_never_create_candidates(
) -> Result<(), Box<dyn std::error::Error>> {
    let engine = ScopeEngine::from_yaml(POLICY)?;
    let index = br#"[{"handle":"lab-index", "targets": {
      "in_scope": [
        {"asset_type":"URL", "asset_identifier":"api.example.com", "instruction":"debug.example.com"},
        {"asset_type":"DOMAIN", "asset_identifier":"private.example.com"},
        {"asset_type":"DOMAIN", "asset_identifier":"elsewhere.invalid"},
        {"asset_type":"DOMAIN", "asset_identifier":"test.example.com\nwww.example.com"},
        {"asset_type":"URL", "asset_identifier":"https://vault.example.com/?x=y"},
        {"asset_type":"WILDCARD", "asset_identifier":"*.example.com"}
      ],
      "out_of_scope": [{"asset_type":"URL", "asset_identifier":"skipped.example.com"}]
    }}]"#;
    let result = filter_discovery_index(index, &engine, engine.snapshot_id(), 12)?;
    assert_eq!(result.candidates(), ["api.example.com"]);
    assert_eq!(result.counts.denied, 1);
    assert_eq!(result.counts.unknown, 1);
    assert_eq!(result.counts.malformed, 2);

    let result = filter_discovery_index(
        b"api.example.com\nelsewhere.invalid\n",
        &engine,
        engine.snapshot_id(),
        12,
    )?;
    assert_eq!(result.candidates(), ["api.example.com"]);
    Ok(())
}

#[test]
fn limits_and_snapshot_mismatch_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let engine = ScopeEngine::from_yaml(POLICY)?;
    assert!(matches!(
        filter_inventory(b"", &engine, &ScopeSnapshotId("lab-v1".into()), 12),
        Err(PassiveInputError::InactiveSnapshot)
    ));
    assert!(matches!(
        filter_discovery_index(b"api.example.com", &engine, engine.snapshot_id(), 20),
        Err(PassiveInputError::InactiveSnapshot)
    ));
    assert!(matches!(
        filter_inventory(
            &vec![b' '; MAX_INVENTORY_BYTES + 1],
            &engine,
            engine.snapshot_id(),
            12
        ),
        Err(PassiveInputError::ByteLimit)
    ));
    assert!(matches!(
        filter_inventory(
            &b"api.example.com\n".repeat(MAX_INVENTORY_RECORDS + 1),
            &engine,
            engine.snapshot_id(),
            12
        ),
        Err(PassiveInputError::RecordLimit)
    ));
    assert!(matches!(
        filter_discovery_index(b"[{", &engine, engine.snapshot_id(), 12),
        Err(PassiveInputError::InvalidIndex)
    ));
    Ok(())
}

#[test]
fn crtsh_uses_canonical_san_names_and_checks_every_candidate(
) -> Result<(), Box<dyn std::error::Error>> {
    let engine = ScopeEngine::from_yaml(POLICY)?;
    let input = r#"[
        {"name_value":"*.WWW.example.com\nwww.example.com.\nmünchen.example", "common_name":"ignored.example.com"},
        {"name_value":"private.example.com\nexample.com\nhttp.example.org\nwww.example.com;malicious"},
        {"name_value":13},
        {"common_name":"malicious.example.com"}
    ]"#;
    let batch = parse_crtsh(input.as_bytes())?;
    let result = filter_live_candidates(
        &batch.candidates,
        batch.malformed,
        &engine,
        engine.snapshot_id(),
        12,
    )?;
    assert_eq!(
        result.domains,
        ["www.example.com", "xn--mnchen-3ya.example"]
    );
    assert_eq!(
        result.counts,
        SelectionCounts {
            allowed: 2,
            denied: 1,
            unknown: 2,
            duplicates: 1,
            malformed: 3,
        }
    );
    assert!(matches!(
        parse_crtsh(br#"[{"name_value":"example.com"}"#),
        Err(PassiveInputError::InvalidProvider)
    ));
    assert!(matches!(
        parse_crtsh(b"[] []"),
        Err(PassiveInputError::InvalidProvider)
    ));
    Ok(())
}

#[test]
fn subfinder_rejects_oversized_records_and_treats_json_fields_as_data(
) -> Result<(), Box<dyn std::error::Error>> {
    let engine = ScopeEngine::from_yaml(POLICY)?;
    let mut input = br#"{"host":"wide.example.com","metadata":""#.to_vec();
    input.extend(std::iter::repeat_n(b'x', 10_000));
    input.extend_from_slice(b"\"}\n\xff\n");
    input.extend_from_slice(
        br#"{"host":"www.example.com","command":"private.example.com"}
{"host":"$(printf should-not-be-run)"}
{"host":"www.example.com\nprivate.example.com"}
{"host":"outside.invalid"}
{"host":"private.example.com"}
{"host":"*.wild.example.com"}
{"source":"unexpected.example.com"}"#,
    );
    let batch = parse_subfinder(&input)?;
    let result = filter_live_candidates(
        &batch.candidates,
        batch.malformed,
        &engine,
        engine.snapshot_id(),
        12,
    )?;
    assert_eq!(result.domains, ["www.example.com"]);
    assert_eq!(
        result.counts,
        SelectionCounts {
            allowed: 1,
            denied: 1,
            unknown: 1,
            duplicates: 0,
            malformed: 6,
        }
    );
    assert!(matches!(
        filter_live_candidates(
            &batch.candidates,
            batch.malformed,
            &engine,
            engine.snapshot_id(),
            20
        ),
        Err(PassiveInputError::InactiveSnapshot)
    ));
    Ok(())
}
