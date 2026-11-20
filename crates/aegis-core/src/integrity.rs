//! Policy integrity: a SHA-256 hash over the canonical (normalized)
//! policy JSON. The adapter records the hash of the last applied policy
//! (tamper evidence: the hash lets an operator detect that a stored
//! policy changed) and the Linux adapter verifies the stored rollback
//! script's hash before applying it.
//!
//! Note: this is a tamper-*evidence* hash, not a signature, and NOT a
//! re-approval gate — the adapter does not refuse a policy whose
//! content differs from a previously recorded hash. (Review Nov 14,
//! 2026: an earlier version of this docstring claimed such a gate.)
//! Signed policies (M2) add an asymmetric signature over this hash.

use crate::policy::Policy;
use sha2::{Digest, Sha256};

/// SHA-256 hex of arbitrary bytes (used for the stored nft script in
/// the Linux adapter's state dir, so rollback can verify the script
/// it is about to apply). Same tamper-evidence note as `policy_hash`:
/// a hash, not a signature.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Canonical hash of a normalized policy. Deterministic: the same policy
/// document always yields the same hash.
pub fn policy_hash(policy: &Policy) -> String {
    let json = serde_json::to_string(policy).expect("policy must serialize");
    sha256_hex(json.as_bytes())
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
