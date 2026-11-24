use domain::{Action, Decision, ScopeSnapshotId};
use proptest::prelude::*;

use crate::{canonicalize_domain, canonicalize_target, Reason, ScopeEngine};

const LAB: &[u8] = include_bytes!("../../../examples/lab-scope.yaml");
const RULE_ALLOW: &str =
    "    - { id: allow, effect: allow, kind: wildcard, target: '*.example.com', actions: [http] }";
const RULE_DENY: &str =
    "    - { id: deny, effect: deny, kind: wildcard, target: '*.example.com', actions: [http] }";

fn engine() -> ScopeEngine {
    ScopeEngine::from_yaml(LAB).expect("reviewed fixture")
}

#[test]
fn fixture_decisions() {
    let engine = engine();
    let cases = [
        ("api.example.com", Decision::Allow),
        ("payments.example.com", Decision::Deny),
        ("https://payments.example.com/", Decision::Deny),
        ("example.com", Decision::Unknown),
        ("badexample.com", Decision::Unknown),
        ("api.example.com.evil.example", Decision::Unknown),
        ("192.0.2.0/25", Decision::Deny),
        ("192.0.2.0/24", Decision::Deny),
        ("192.0.2.64/26", Decision::Allow),
        ("192.0.2.128/25", Decision::Unknown),
        ("192.0.2.128", Decision::Unknown),
        ("192.0.2.1", Decision::Deny),
        ("::ffff:192.0.2.1", Decision::Deny),
        ("http://[::ffff:192.0.2.1]/", Decision::Deny),
        ("::ffff:192.0.2.64/122", Decision::Allow),
        ("münchen.example", Decision::Allow),
        ("xn--mnchen-3ya.example", Decision::Allow),
        ("https://MÜNCHEN.example./", Decision::Allow),
        (
            "https://example.org:443/docs/page?q=opaque",
            Decision::Allow,
        ),
        ("https://example.org:444/docs/page", Decision::Unknown),
        ("http://example.org/docs", Decision::Unknown),
        ("https://example.org/docsets", Decision::Unknown),
        ("https://api.example.com/a/../private", Decision::Unknown),
        ("https://api.example.com/%2Fprivate", Decision::Unknown),
        ("https://user@api.example.com/", Decision::Unknown),
        ("https://api.example.com:0/", Decision::Unknown),
        ("https://api.example.com:/", Decision::Unknown),
        ("https://api.example.com//private", Decision::Unknown),
        ("http://0xc0000201/", Decision::Unknown),
        ("192.0.2.3/24", Decision::Unknown),
        ("::/0", Decision::Unknown),
    ];
    for (target, expected) in cases {
        let verdict = engine.evaluate(engine.snapshot_id(), 1, Action::Http, target);
        assert_eq!(verdict.decision, expected, "target {target}");
        assert_eq!(verdict.is_allowed(), expected == Decision::Allow);
    }
    assert!(!engine
        .evaluate(engine.snapshot_id(), 1, Action::Dns, "api.example.com")
        .is_allowed());
}

#[test]
fn passive_inventory_requires_a_domain_and_passive_authority() {
    let bytes = include_bytes!("../../../examples/lab-passive-scope.yaml");
    let engine = ScopeEngine::from_yaml(bytes).expect("reviewed passive fixture");
    let snapshot = engine.snapshot_id();
    let allowed = canonicalize_domain("MÜNCHEN.Example.").expect("IDNA domain");
    assert_eq!(allowed, "xn--mnchen-3ya.example");
    assert!(engine
        .evaluate(snapshot, 1, Action::Passive, &allowed)
        .is_allowed());
    assert_eq!(
        engine
            .evaluate(snapshot, 1, Action::Passive, "payments.example.com")
            .decision,
        Decision::Deny
    );
    assert_eq!(
        engine
            .evaluate(snapshot, 1, Action::Passive, "192.0.2.64")
            .decision,
        Decision::Unknown
    );
    for input in [
        "https://api.example.com/",
        "::ffff:192.0.2.64",
        "192.0.2.0/25",
    ] {
        assert!(canonicalize_domain(input).is_none());
    }
}

#[test]
fn importer_rejects_unreviewed_sources_and_bad_documents() {
    let fixture = std::str::from_utf8(LAB).expect("UTF-8 fixture");
    for (from, to) in [
        ("manual_reviewed", "discovery_feed"),
        ("version: 1", "version: 2"),
        ("*.example.com", "example.com"),
        ("192.0.2.0/25", "192.0.2.1/25"),
        (
            "https://example.org/docs",
            "https://example.org/docs?token=secret",
        ),
        ("id: lab-ip-deny", "id: lab-network"),
        ("expires_at: 4102444800", "expires_at: 0"),
    ] {
        let invalid = fixture.replace(from, to);
        assert!(ScopeEngine::from_yaml(invalid.as_bytes()).is_err(), "{to}");
    }
}

#[test]
fn inactive_revision_fails_closed() {
    let engine = engine();
    let stale = ScopeSnapshotId("lab-v0".into());
    for (id, time) in [(&stale, 1), (engine.snapshot_id(), 4102444800)] {
        let verdict = engine.evaluate(id, time, Action::Http, "api.example.com");
        assert_eq!(verdict.reason, Reason::InactiveSnapshot);
        assert!(!verdict.is_allowed());
    }
}

#[test]
fn redirect_requires_independent_absolute_url_permission() {
    let engine = engine();
    let id = engine.snapshot_id();
    assert!(engine
        .evaluate(id, 1, Action::Http, "https://api.example.com/")
        .is_allowed());
    for (location, expected) in [
        ("https://elsewhere.example.org/", Decision::Unknown),
        ("https://payments.example.com/", Decision::Deny),
        ("https://www.example.com/", Decision::Allow),
        ("//api.example.com/path", Decision::Unknown),
        ("/path", Decision::Unknown),
    ] {
        assert_eq!(
            engine
                .evaluate_redirect_hop(id, 1, Action::Http, location)
                .decision,
            expected
        );
    }
}

proptest! {
    #[test]
    fn deny_wins_independent_of_order(label in "[a-z]{1,16}", reverse in any::<bool>()) {
        let rules = if reverse { [RULE_DENY, RULE_ALLOW] } else { [RULE_ALLOW, RULE_DENY] };
        let yaml = format!(
            "version: 1\nsnapshot:\n  id: current\n  program_id: lab\n  source: manual_reviewed\n  valid_from: 0\n  expires_at: 99\n  rules:\n{}\n",
            rules.join("\n")
        );
        let engine = ScopeEngine::from_yaml(yaml.as_bytes()).expect("valid lab rules");
        let verdict = engine.evaluate(engine.snapshot_id(), 1, Action::Http, &format!("{label}.example.com"));
        prop_assert_eq!(verdict.decision, Decision::Deny);
    }

    #[test]
    fn unknown_never_admits(label in "[a-z]{1,16}", invalid in any::<bool>()) {
        let engine = engine();
        let target = if invalid { format!("https://{label}.example.com/../x") } else { format!("{label}.example.org") };
        let verdict = engine.evaluate(engine.snapshot_id(), 1, Action::Http, &target);
        prop_assert_eq!(verdict.decision, Decision::Unknown);
        prop_assert!(!verdict.is_allowed());
    }

    #[test]
    fn canonicalization_is_idempotent(label in "[a-zA-Z]{1,16}", octet in any::<u8>()) {
        for raw in [
            format!("{label}.Example.COM."),
            format!("HTTPS://{label}.Example.COM.:443/docs/{octet}?q=1"),
            format!("https://[::ffff:192.0.2.{octet}]:443/docs"),
            format!("::ffff:192.0.2.{octet}"),
            format!("192.0.2.{octet}/32"),
            "https://münchen.example./".into(),
        ] {
            let canonical = canonicalize_target(&raw).expect("valid target");
            let round_trip = canonicalize_target(&canonical);
            prop_assert_eq!(round_trip.as_deref(), Some(canonical.as_str()));
        }
    }

    #[test]
    fn mapped_ip_has_the_same_policy(octet in any::<u8>()) {
        let engine = engine();
        let id = engine.snapshot_id();
        let plain = engine.evaluate(id, 1, Action::Http, &format!("192.0.2.{octet}"));
        let mapped = engine.evaluate(id, 1, Action::Http, &format!("::ffff:192.0.2.{octet}"));
        prop_assert_eq!(plain, mapped);
    }
}
