//! Policy integrity: a SHA-256 hash over the canonical (normalized)
//! policy JSON. The adapter records the hash of the last applied policy
//! and refuses to apply a document whose content differs from a previously
//! approved hash unless the operator explicitly re-approves it.
//!
//! Note: this is a tamper-*evidence* hash, not a signature. Signed
//! policies (M2) add an asymmetric signature over this hash.

use crate::policy::Policy;
use sha2::{Digest, Sha256};

/// Canonical hash of a normalized policy. Deterministic: the same policy
/// document always yields the same hash.
pub fn policy_hash(policy: &Policy) -> String {
    let json = serde_json::to_string(policy).expect("policy must serialize");
    let digest = Sha256::digest(json.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn hash_is_stable_and_sensitive() {
        let a = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"x","priority":10,"action":"allow","protocol":"tcp","dst_port":443}]}"#,
        )
        .unwrap();
        let b = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"x","priority":10,"action":"allow","protocol":"tcp","dst_port":443}]}"#,
        )
        .unwrap();
        assert_eq!(policy_hash(&a), policy_hash(&b));
        let c = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"x","priority":10,"action":"deny","protocol":"tcp","dst_port":443}]}"#,
        )
        .unwrap();
        assert_ne!(policy_hash(&a), policy_hash(&c));
    }
}
