//! Fetch, verify, and persist remote juror votes from the key-addressed DHT.

use std::collections::HashSet;
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hal_settings::NetworkTrustPolicy;
use hal_storage::{
    jury_rosters::{list_assignments_for_generation, read_latest_roster},
    jury_votes::{insert_vote_if_missing, read_vote, JuryVoteRow},
};
use tokio::sync::Mutex;

use crate::{
    dht::{
        jury_dkg_commitment::JURY_PARTICIPANTS,
        lookup::{Lookup, LookupConfig},
        mux_transport::MuxDhtTransport,
        routing::RoutingTable,
        NodeId,
    },
    jury_vote::{node_id_from_public_key, verify_vote, vote_dht_key, JuryVote, JURY_VOTE_TTL_SECS},
    pinning::KnownHosts,
    runtime_context::RuntimeContext,
};

pub struct JuryVoteFetcher {
    local_id: NodeId,
    signing_key: SigningKey,
    hosts: Arc<StdMutex<KnownHosts>>,
    routing: Arc<Mutex<RoutingTable>>,
    trust_policy: NetworkTrustPolicy,
}

impl JuryVoteFetcher {
    pub fn new(
        local_id: NodeId,
        signing_key: SigningKey,
        hosts: Arc<StdMutex<KnownHosts>>,
        routing: Arc<Mutex<RoutingTable>>,
        trust_policy: NetworkTrustPolicy,
    ) -> Self {
        Self {
            local_id,
            signing_key,
            hosts,
            routing,
            trust_policy,
        }
    }

    pub async fn fetch_remote_votes(
        &self,
        ctx: &Arc<RuntimeContext>,
        complaint_id: &[u8; 32],
        evidence_hash: &[u8; 32],
        now: u64,
    ) -> Result<Vec<JuryVote>> {
        let storage_arc = ctx
            .storage
            .as_ref()
            .context("storage required to fetch jury votes")?;
        let assignments = {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            let Some(roster) = read_latest_roster(storage.connection(), complaint_id)? else {
                return Ok(Vec::new());
            };
            let assignments = list_assignments_for_generation(
                storage.connection(),
                complaint_id,
                roster.roster_generation,
            )?;
            if assignments.len() != JURY_PARTICIPANTS as usize {
                return Err(anyhow!(
                    "expected {JURY_PARTICIPANTS} roster assignments, found {}",
                    assignments.len()
                ));
            }
            assignments
        };

        let transport = MuxDhtTransport::new(
            self.signing_key.clone(),
            Arc::clone(&self.hosts),
            self.trust_policy.clone(),
        );
        let local_id = *self.local_id.as_bytes();
        let mut seen_candidates = HashSet::with_capacity(assignments.len());
        let mut fetched = Vec::new();
        for assignment in assignments {
            let candidate = assignment.candidate_node_id;
            if candidate == local_id || !seen_candidates.insert(candidate) {
                continue;
            }
            let key = vote_dht_key(complaint_id, evidence_hash, &candidate);
            let result = {
                let mut routing = self.routing.lock().await;
                let mut lookup = Lookup::new(
                    self.local_id,
                    NodeId::from_bytes(key),
                    LookupConfig::default(),
                    &transport,
                    &mut routing,
                );
                lookup.find_value(key).await
            };
            let result = match result {
                Ok(result) => result,
                Err(error) => {
                    log::warn!(
                        "DHT lookup failed for jury vote from {}: {error}",
                        hex::encode(candidate)
                    );
                    continue;
                }
            };
            let Some(value) = result.value else {
                continue;
            };
            if value.key != key || value.expires_at <= now {
                continue;
            }
            let vote: JuryVote = match serde_json::from_slice(&value.value) {
                Ok(vote) => vote,
                Err(error) => {
                    log::warn!(
                        "invalid DHT jury vote from {}: {error}",
                        hex::encode(candidate)
                    );
                    continue;
                }
            };
            if validate_fetched_vote(
                &vote,
                &value.signature,
                value.expires_at,
                now,
                complaint_id,
                evidence_hash,
                &candidate,
            )
            .is_err()
            {
                log::warn!("rejected DHT jury vote from {}", hex::encode(candidate));
                continue;
            }
            let row = vote_row(&vote);
            let persisted = {
                let storage = storage_arc
                    .lock()
                    .map_err(|_| anyhow!("storage lock poisoned"))?;
                let conn = storage.connection();
                if insert_vote_if_missing(conn, &row)? {
                    Some(row.clone())
                } else {
                    read_vote(conn, complaint_id, evidence_hash, &candidate)?
                }
            };
            if let Some(persisted) = persisted {
                if persisted == row {
                    fetched.push(vote);
                }
            }
        }
        Ok(fetched)
    }
}

fn validate_fetched_vote(
    vote: &JuryVote,
    dht_signature: &[u8],
    expires_at: u64,
    now: u64,
    complaint_id: &[u8; 32],
    evidence_hash: &[u8; 32],
    roster_juror_node_id: &[u8; 32],
) -> Result<()> {
    if vote.complaint_id != *complaint_id
        || vote.evidence_hash != *evidence_hash
        || vote.juror_node_id != *roster_juror_node_id
        || vote.issued_at > now
        || vote.issued_at.checked_add(JURY_VOTE_TTL_SECS) != Some(expires_at)
        || expires_at <= now
        || dht_signature != vote.signature
    {
        return Err(anyhow!("jury vote binding or expiry is invalid"));
    }
    let public_key =
        VerifyingKey::from_bytes(&vote.juror_public_key).context("decode jury vote public key")?;
    if node_id_from_public_key(&public_key) != vote.juror_node_id {
        return Err(anyhow!("jury vote node ID does not match public key"));
    }
    verify_vote(&public_key, vote).context("verify fetched jury vote")?;
    Ok(())
}

fn vote_row(vote: &JuryVote) -> JuryVoteRow {
    JuryVoteRow {
        complaint_id: vote.complaint_id,
        evidence_hash: vote.evidence_hash,
        juror_node_id: vote.juror_node_id,
        juror_public_key: vote.juror_public_key,
        decision: vote.decision.as_u8(),
        issued_at: vote.issued_at,
        signature: vote.signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jury_vote::{sign_vote, JuryDecision};

    fn signed_vote() -> JuryVote {
        let key = SigningKey::from_bytes(&[21; 32]);
        let mut vote = JuryVote {
            complaint_id: [1; 32],
            evidence_hash: [2; 32],
            juror_node_id: node_id_from_public_key(&key.verifying_key()),
            juror_public_key: [0; 32],
            decision: JuryDecision::Guilty,
            issued_at: 100,
            signature: [0; 64],
        };
        sign_vote(&key, &mut vote).expect("sign vote");
        vote
    }

    #[test]
    fn valid_remote_vote_is_accepted_for_roster_entry() {
        let vote = signed_vote();
        assert!(validate_fetched_vote(
            &vote,
            &vote.signature,
            100 + JURY_VOTE_TTL_SECS,
            101,
            &vote.complaint_id,
            &vote.evidence_hash,
            &vote.juror_node_id,
        )
        .is_ok());
    }

    #[test]
    fn fetched_vote_rejects_mismatch_and_expiry() {
        let vote = signed_vote();
        assert!(validate_fetched_vote(
            &vote,
            &vote.signature,
            100 + JURY_VOTE_TTL_SECS,
            101,
            &vote.complaint_id,
            &vote.evidence_hash,
            &[9; 32],
        )
        .is_err());
        assert!(validate_fetched_vote(
            &vote,
            &vote.signature,
            100 + JURY_VOTE_TTL_SECS,
            100 + JURY_VOTE_TTL_SECS,
            &vote.complaint_id,
            &vote.evidence_hash,
            &vote.juror_node_id,
        )
        .is_err());
    }
}
