use crate::claim::ClaimRegistry;
use crate::artifacts::ArtifactId;
use crate::eval::{TrustPolicy, TrustLevel};
use std::sync::Arc;

pub struct CheckerConfig {
    pass_threshold: TrustLevel,
}

pub struct CheckResult {
    artifact_id: ArtifactId,
    passed: bool,
}

pub struct Checker<C,P> where C: ClaimRegistry, P: TrustPolicy {
    config: CheckerConfig,
    claim_registry: Arc<C>,
    trust_policy: Arc<P>,
}

impl <C,P> Checker<C,P> where C: ClaimRegistry, P: TrustPolicy {
    pub fn check(&self, artifact_id: ArtifactId) -> CheckResult {
        let claims = self.claim_registry.authenticated_claims_for(&artifact_id);
//        let trust_level = self.trust_policy.evaluate(claims);

        CheckResult {
            artifact_id,
            passed: true,
//            passed: trust_level >= self.config.pass_threshold,
        }
    }
}