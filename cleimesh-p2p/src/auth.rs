use crate::{Result, AgentIdentity};
use libp2p::identity::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

/// Domain separation for capability signatures. Bump the version whenever the
/// signed layout changes, so old signatures cannot be reinterpreted.
const CAPABILITY_SIGNING_DOMAIN: &[u8] = b"cleimesh-cap-v2\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    pub issuer: AgentIdentity,
    pub subject: AgentIdentity,
    pub resource: String,
    pub actions: Vec<String>,
    pub constraints: Constraints,
    /// PeerId of the node that may honor this capability. A node refuses a
    /// capability addressed to another node, so a token sent to node X
    /// cannot be replayed against node Y.
    #[serde(default)]
    pub audience: Option<String>,
    pub proof: CapabilityProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Constraints {
    pub max_calls: Option<u64>,
    pub max_duration_ms: Option<u64>,
    pub allowed_args: Option<Vec<serde_json::Value>>,
    pub rate_limit: Option<RateLimit>,
    pub expiration: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimit {
    pub calls_per_window: u64,
    pub window_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityProof {
    pub signature: Vec<u8>,
    pub signed_at: u64,
    pub nonce: [u8; 32],
}

impl Capability {
    pub fn new(
        issuer: AgentIdentity,
        subject: AgentIdentity,
        resource: impl Into<String>,
        actions: Vec<String>,
        constraints: Constraints,
    ) -> Self {
        let nonce = rand::random();
        let signed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            issuer,
            subject,
            resource: resource.into(),
            actions,
            constraints,
            audience: None,
            proof: CapabilityProof {
                signature: Vec::new(),
                signed_at,
                nonce,
            },
        }
    }

    /// Issues a capability signed with `keypair` and addressed to its own
    /// PeerId: the node holding that key is the one that will honor it. Needs
    /// only the key, not a running node, so the CLI can issue offline.
    pub fn issue(
        keypair: &Keypair,
        subject: &PeerId,
        resource: impl Into<String>,
        actions: Vec<String>,
        constraints: Constraints,
    ) -> Result<Self> {
        let node = keypair.public().to_peer_id();
        let issuer = AgentIdentity::from_keypair(keypair.public().encode_protobuf(), node.to_string());
        let mut cap = Self::new(issuer, AgentIdentity::from_peer_id(subject.to_string()), resource, actions, constraints)
            .with_audience(&node);
        cap.sign(keypair)?;
        Ok(cap)
    }

    /// Addresses the capability to the node with this PeerId. Set it before
    /// signing: the audience is covered by the signature.
    pub fn with_audience(mut self, node: &PeerId) -> Self {
        self.audience = Some(node.to_string());
        self
    }

    pub fn sign(&mut self, keypair: &Keypair) -> Result<()> {
        let message = self.signing_message();
        self.proof.signature = keypair.sign(&message)
            .map_err(|e| anyhow::anyhow!("Signing failed: {:?}", e))?;
        Ok(())
    }

    pub fn verify(&self, issuer_public_key: &[u8]) -> Result<bool> {
        let message = self.signing_message();
        let public_key = PublicKey::try_decode_protobuf(issuer_public_key)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {:?}", e))?;
        let valid = public_key.verify(&message, &self.proof.signature);
        Ok(valid)
    }

    /// Bytes covered by the signature: a domain prefix followed by canonical
    /// JSON of every field except the signature itself. Object keys come out
    /// sorted because serde_json's `Value` uses a BTreeMap (the
    /// `preserve_order` feature must stay off; a test guards this).
    fn signing_message(&self) -> Vec<u8> {
        let unsigned = serde_json::json!({
            "issuer": self.issuer,
            "subject": self.subject,
            "resource": self.resource,
            "actions": self.actions,
            "constraints": self.constraints,
            "audience": self.audience,
            "signed_at": self.proof.signed_at,
            "nonce": self.proof.nonce,
        });
        let mut msg = CAPABILITY_SIGNING_DOMAIN.to_vec();
        msg.extend(serde_json::to_vec(&unsigned).expect("capability fields always serialize to JSON"));
        msg
    }

    pub fn can_execute(&self, action: &str, args: &serde_json::Value) -> bool {
        if !self.actions.contains(&action.to_string()) && !self.actions.contains(&"*".to_string()) {
            return false;
        }

        if let Some(exp) = self.constraints.expiration {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > exp {
                return false;
            }
        }

        if let Some(allowed) = &self.constraints.allowed_args {
            if !allowed.contains(args) {
                return false;
            }
        }

        true
    }

    /// Everything `node` checks before running `action` on `resource` for
    /// `requester` under this capability. Until delegation chains exist (S4),
    /// the only trusted issuer is the node itself. The error says which check
    /// failed, without echoing the capability.
    pub fn check_request(
        &self,
        node: &PeerId,
        requester: &PeerId,
        resource: &str,
        action: &str,
        args: &serde_json::Value,
    ) -> std::result::Result<(), String> {
        if self.resource != resource {
            return Err(format!("capability is for {}, not {}", self.resource, resource));
        }
        // The requester is the PeerId that Noise authenticated, so a token
        // copied from its subject is useless to anyone else.
        if self.subject.peer_id != requester.to_string() {
            return Err("capability subject is not the requesting peer".to_string());
        }
        if self.audience.as_deref() != Some(node.to_string().as_str()) {
            return Err("capability audience is not this node".to_string());
        }
        if self.issuer.peer_id != node.to_string() {
            return Err("capability issuer is not trusted by this node".to_string());
        }
        // The issuer's key must be the one behind its PeerId; otherwise
        // anyone could sign with their own key under the node's name.
        let issuer_key = PublicKey::try_decode_protobuf(&self.issuer.public_key)
            .map_err(|_| "capability issuer key is invalid".to_string())?;
        if issuer_key.to_peer_id().to_string() != self.issuer.peer_id {
            return Err("capability issuer key does not match its PeerId".to_string());
        }
        if !issuer_key.verify(&self.signing_message(), &self.proof.signature) {
            return Err("capability signature is invalid".to_string());
        }
        if let Some(exp) = self.constraints.expiration {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > exp {
                return Err(format!("capability expired at {}", exp));
            }
        }
        if !self.actions.iter().any(|a| a == action || a == "*") {
            return Err(format!("action {} is not granted", action));
        }
        if let Some(allowed) = &self.constraints.allowed_args {
            if !allowed.contains(args) {
                return Err("arguments are not in allowed_args".to_string());
            }
        }
        Ok(())
    }

    pub fn attenuate(
        &self,
        new_subject: AgentIdentity,
        resource: Option<String>,
        actions: Option<Vec<String>>,
        additional_constraints: Constraints,
    ) -> Result<Capability> {
        if let Some(ref new_resource) = resource {
            if *new_resource != self.resource {
                return Err(anyhow::anyhow!(
                    "Cannot attenuate: resource '{}' differs from original '{}'",
                    new_resource, self.resource
                ).into());
            }
        }

        if !self.actions.contains(&"*".to_string()) {
            if let Some(ref new_actions) = actions {
                for action in new_actions {
                    if !self.actions.contains(action) {
                        return Err(anyhow::anyhow!("Cannot attenuate: action '{}' not in original capability", action).into());
                    }
                }
            }
        }

        let mut constraints = self.constraints.clone();
        
        if let Some(max_calls) = additional_constraints.max_calls {
            constraints.max_calls = Some(
                constraints.max_calls.map(|c| c.min(max_calls)).unwrap_or(max_calls)
            );
        }
        if let Some(max_duration) = additional_constraints.max_duration_ms {
            constraints.max_duration_ms = Some(
                constraints.max_duration_ms.map(|c| c.min(max_duration)).unwrap_or(max_duration)
            );
        }
        // Narrowing args is an intersection: the delegate may only keep
        // argument sets the original already allowed.
        if let Some(allowed_args) = additional_constraints.allowed_args {
            let narrowed: Vec<serde_json::Value> = match constraints.allowed_args {
                Some(existing) => allowed_args.into_iter().filter(|a| existing.contains(a)).collect(),
                None => allowed_args,
            };
            if narrowed.is_empty() {
                return Err(anyhow::anyhow!("Cannot attenuate: no allowed_args left after narrowing").into());
            }
            constraints.allowed_args = Some(narrowed);
        }
        if let Some(rate_limit) = additional_constraints.rate_limit {
            constraints.rate_limit = Some(
                constraints.rate_limit.map(|existing| RateLimit {
                    calls_per_window: existing.calls_per_window.min(rate_limit.calls_per_window),
                    window_ms: existing.window_ms.max(rate_limit.window_ms),
                }).unwrap_or(rate_limit)
            );
        }
        if let Some(exp) = additional_constraints.expiration {
            constraints.expiration = Some(
                constraints.expiration.map(|c| c.min(exp)).unwrap_or(exp)
            );
        }

        let mut cap = Capability::new(
            self.issuer.clone(),
            new_subject,
            resource.unwrap_or_else(|| self.resource.clone()),
            actions.unwrap_or_else(|| self.actions.clone()),
            constraints,
        );
        cap.audience = self.audience.clone();

        Ok(cap)
    }

    pub fn delegate(
        &self,
        keypair: &Keypair,
        new_subject: AgentIdentity,
        resource: Option<String>,
        actions: Option<Vec<String>>,
        constraints: Constraints,
    ) -> Result<Capability> {
        let mut cap = self.attenuate(new_subject, resource, actions, constraints)?;
        cap.sign(keypair)?;
        Ok(cap)
    }
}

#[derive(Debug, Default)]
pub struct CapabilityStore {
    capabilities: HashMap<String, Vec<Capability>>,
    /// Keyed by the capability's nonce, which the signature covers.
    usage_tracker: HashMap<[u8; 32], UsageRecord>,
    /// Nonces of revoked capabilities, so a revoked token is refused even
    /// when the client presents it again with a request.
    revoked: HashSet<[u8; 32]>,
}

#[derive(Debug, Clone)]
struct UsageRecord {
    calls: u64,
    window_start: u64,
    last_call: u64,
}

impl CapabilityStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, capability: Capability) {
        let key = capability.resource.clone();
        self.capabilities.entry(key).or_default().push(capability);
    }

    pub fn get(&self, resource: &str, subject: &AgentIdentity, action: &str) -> Option<&Capability> {
        self.capabilities.get(resource)?
            .iter()
            .find(|c| c.subject == *subject && c.can_execute(action, &serde_json::json!({})))
    }

    pub fn get_mut(&mut self, resource: &str, subject: &AgentIdentity, action: &str) -> Option<&mut Capability> {
        self.capabilities.get_mut(resource)?
            .iter_mut()
            .find(|c| c.subject == *subject && c.can_execute(action, &serde_json::json!({})))
    }

    /// Every stored capability for `resource`, valid or not.
    pub fn for_resource(&self, resource: &str) -> &[Capability] {
        self.capabilities.get(resource).map_or(&[], |v| v.as_slice())
    }

    pub fn is_revoked(&self, capability: &Capability) -> bool {
        self.revoked.contains(&capability.proof.nonce)
    }

    /// Revokes this exact capability, stored or not.
    pub fn revoke_capability(&mut self, capability: &Capability) {
        self.revoked.insert(capability.proof.nonce);
        if let Some(caps) = self.capabilities.get_mut(&capability.resource) {
            caps.retain(|c| c.proof.nonce != capability.proof.nonce);
        }
    }

    pub fn has_capabilities_for_resource(&self, resource: &str) -> bool {
        self.capabilities.get(resource).map_or(false, |v| !v.is_empty())
    }

    /// Get all capabilities across all resources
    pub fn all_capabilities(&self) -> Vec<Capability> {
        self.capabilities.values().flatten().cloned().collect()
    }

    pub fn record_usage(&mut self, capability: &Capability) -> Result<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let record = self.usage_tracker.entry(capability.proof.nonce).or_insert(UsageRecord {
            calls: 0,
            window_start: now,
            last_call: 0,
        });

        if let Some(max_calls) = capability.constraints.max_calls {
            if record.calls >= max_calls {
                return Err(anyhow::anyhow!("Max calls exceeded").into());
            }
        }

        if let Some(rate_limit) = &capability.constraints.rate_limit {
            if now - record.window_start > rate_limit.window_ms / 1000 {
                record.calls = 0;
                record.window_start = now;
            }
            if record.calls >= rate_limit.calls_per_window {
                return Err(anyhow::anyhow!("Rate limit exceeded").into());
            }
        }

        record.calls += 1;
        record.last_call = now;

        if let Some(exp) = capability.constraints.expiration {
            if now > exp {
                return Err(anyhow::anyhow!("Capability expired").into());
            }
        }

        Ok(true)
    }

    pub fn revoke(&mut self, resource: &str, subject: &AgentIdentity) {
        if let Some(caps) = self.capabilities.get_mut(resource) {
            let revoked = &mut self.revoked;
            caps.retain(|c| {
                let keep = c.subject != *subject;
                if !keep {
                    revoked.insert(c.proof.nonce);
                }
                keep
            });
        }
    }

    pub fn cleanup_expired(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for caps in self.capabilities.values_mut() {
            caps.retain(|c| {
                c.constraints.expiration.map_or(true, |exp| exp > now)
            });
        }

        self.usage_tracker.retain(|_, record| {
            now - record.last_call < 3600
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn test_capability_creation_and_verification() {
        let keypair = Keypair::generate_ed25519();
        let public_key_bytes = keypair.public().encode_protobuf();
        let issuer = AgentIdentity::from_keypair(public_key_bytes.clone(), keypair.public().to_peer_id().to_string());
        let subject = AgentIdentity::new("subject");

        let mut cap = Capability::new(
            issuer.clone(),
            subject.clone(),
            "tool:echo",
            vec!["execute".to_string()],
            Constraints {
                max_calls: Some(10),
                expiration: Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() + 3600
                ),
                ..Default::default()
            },
        );
        cap.sign(&keypair).unwrap();
        assert!(cap.verify(&public_key_bytes).unwrap());
    }

    #[test]
    fn test_capability_attenuation() {
        let keypair = Keypair::generate_ed25519();
        let public_key_bytes = keypair.public().encode_protobuf();
        let issuer = AgentIdentity::from_keypair(public_key_bytes.clone(), keypair.public().to_peer_id().to_string());
        let subject = AgentIdentity::new("subject");

        let mut cap = Capability::new(
            issuer.clone(),
            subject.clone(),
            "tool:echo",
            vec!["execute".to_string(), "read".to_string()],
            Constraints {
                max_calls: Some(100),
                ..Default::default()
            },
        );
        cap.sign(&keypair).unwrap();

        let new_subject = AgentIdentity::new("delegate");
        let attenuated = cap.attenuate(
            new_subject.clone(),
            Some("tool:echo".to_string()),
            Some(vec!["execute".to_string()]),
            Constraints {
                max_calls: Some(10),
                ..Default::default()
            },
        ).unwrap();

        assert_eq!(attenuated.subject, new_subject);
        assert_eq!(attenuated.actions, vec!["execute".to_string()]);
        assert_eq!(attenuated.constraints.max_calls, Some(10));
    }

    #[test]
    fn test_capability_store() {
        let mut store = CapabilityStore::new();
        let keypair = Keypair::generate_ed25519();
        let public_key_bytes = keypair.public().encode_protobuf();
        let issuer = AgentIdentity::from_keypair(public_key_bytes.clone(), keypair.public().to_peer_id().to_string());
        let subject = AgentIdentity::new("subject");

        let mut cap = Capability::new(
            issuer,
            subject.clone(),
            "tool:echo",
            vec!["execute".to_string()],
            Constraints {
                max_calls: Some(5),
                ..Default::default()
            },
        );
        cap.sign(&keypair).unwrap();

        store.add(cap);

        for _ in 0..5 {
            let cap = store.get("tool:echo", &subject, "execute").unwrap().clone();
            store.record_usage(&cap).unwrap();
        }

        // Get the cap again for the final check
        let cap = store.get("tool:echo", &subject, "execute").unwrap().clone();
        assert!(store.record_usage(&cap).is_err());
    }
}