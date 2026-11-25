use std::{cell::RefCell, time::Duration};

use domain::PassiveSource;
use scope_engine::{ScopeEngine, ScopeError};

use crate::{CollectionError, CollectionGate, PassiveRequest};

pub(crate) fn reviewed_scope(program: &str, rates: [u32; 4]) -> Result<ScopeEngine, ScopeError> {
    let [program_rate, action, host, provider] = rates;
    ScopeEngine::from_yaml(format!(r#"
version: 1
snapshot:
  id: v1-{program}
  program_id: {program}
  source: manual_reviewed
  valid_from: 10
  expires_at: 20
  passive_live:
    program_per_minute: {program_rate}
    action_per_minute: {action}
    host_per_minute: {host}
    provider_per_minute: {provider}
  rules:
    - {{ id: root, effect: allow, kind: domain, target: example.test, actions: [passive] }}
    - {{ id: second-root, effect: allow, kind: domain, target: other.example, actions: [passive] }}
    - {{ id: wildcard, effect: allow, kind: wildcard, target: '*.example.test', actions: [passive] }}
"#).as_bytes())
}

#[derive(Default)]
pub(crate) struct TestGate {
    pub(crate) blocked: bool,
    pub(crate) checks: RefCell<Vec<PassiveSource>>,
    pub(crate) deferred: RefCell<Vec<(PassiveSource, Duration)>>,
}

impl CollectionGate for TestGate {
    async fn check(
        &self,
        _: &PassiveRequest<'_>,
        source: PassiveSource,
    ) -> Result<(), CollectionError> {
        self.checks.borrow_mut().push(source);
        if self.blocked {
            return Err(CollectionError::PolicyHold);
        }
        Ok(())
    }

    async fn defer_provider(
        &self,
        _: &PassiveRequest<'_>,
        source: PassiveSource,
        delay: Duration,
    ) -> Result<(), CollectionError> {
        self.deferred.borrow_mut().push((source, delay));
        Ok(())
    }
}
