//! Fetch, verify, and persist remote jury partial decryptions.

use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{anyhow, Context, Result};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hal_crypto::{
    threshold_encrypt::{verify_partial_decryption, DleqProof, Encryption, PartialDecryption},
    vss::{combine_commitments_to_public_key, FeldmanCommitments},
};
use hal_settings::NetworkTrustPolicy;
use hal_storage::{
    jury_commitments::list_jury_commitments_for_complaint,
    jury_evidence_responses::list_evidence_responses,
    jury_partial_decryptions::{insert_partial_decryption_if_missing, PartialDecryptionRow},
    jury_rosters::{list_assignments_for_generation, read_latest_roster},
};
use tokio::sync::Mutex;

use crate::{
    dht::{
        jury_dkg_commitment::{
            partial_dht_key, verify_commitment, JuryDkgCommitmentRecord, JURY_PARTIAL_TTL_SECS,
            JURY_PARTICIPANTS, JURY_THRESHOLD,
        },
        lookup::{Lookup, LookupConfig},
        mux_transport::MuxDhtTransport,
        routing::RoutingTable,
        NodeId,
    },
    jury_evidence::{verify_partial_decryption_signature, JuryPartialDecryption},
    pinning::KnownHosts,
    runtime_context::RuntimeContext,
};

pub struct JuryPartialFetcher {
    local_id: NodeId,
    signing_key: SigningKey,
    hosts: Arc<StdMutex<KnownHosts>>,
    routing: Arc<Mutex<RoutingTable>>,
    trust_policy: NetworkTrustPolicy,
}

impl JuryPartialFetcher {
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

    pub async fn fetch_remote_partials(
        &self,
        ctx: &Arc<RuntimeContext>,
        complaint_id: &[u8; 32],
        evidence_hash: &[u8; 32],
        now: u64,
    ) -> Result<Vec<JuryPartialDecryption>> {
        let storage_arc = ctx
            .storage
            .as_ref()
            .context("storage required to fetch jury partials")?;
        let local_id = *NodeId::from_hex(&ctx.identity_id)
            .context("parse local identity for jury partial fetch")?
            .as_bytes();
        let (assignments, encryption, commitments) = {
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
            let response = list_evidence_responses(storage.connection(), complaint_id)?
                .into_iter()
                .find(|response| &response.evidence_hash == evidence_hash);
            let Some(response) = response else {
                return Ok(Vec::new());
            };
            let records = list_jury_commitments_for_complaint(storage.connection(), complaint_id)?;
            let commitments = aggregate_commitments(records)?;
            let expected_public_key = combine_commitments_to_public_key(&[commitments.clone()])
                .context("combine aggregated jury commitments")?;
            if response.jury_pubkey != *expected_public_key.as_bytes() {
                return Err(anyhow!(
                    "stored evidence response jury public key does not match DKG commitments"
                ));
            }
            let encryption = Encryption {
                encapsulation: CompressedRistretto(response.encapsulation),
                nonce: response.nonce,
                ciphertext: response.ciphertext,
            };
            (assignments, encryption, commitments)
        };

        let transport = MuxDhtTransport::new(
            self.signing_key.clone(),
            Arc::clone(&self.hosts),
            self.trust_policy.clone(),
        );
        let mut fetched = Vec::new();
        for assignment in assignments {
            let candidate = assignment.candidate_node_id;
            if candidate == local_id {
                continue;
            }
            let key = partial_dht_key(complaint_id, evidence_hash, &candidate);
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
                        "DHT lookup failed for jury partial from {}: {error}",
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
            let partial: JuryPartialDecryption = match serde_json::from_slice(&value.value) {
                Ok(partial) => partial,
                Err(error) => {
                    log::warn!(
                        "invalid DHT jury partial from {}: {error}",
                        hex::encode(candidate)
                    );
                    continue;
                }
            };
            let checked = verify_fetched_partial(
                &partial,
                &value.signature,
                value.expires_at,
                now,
                complaint_id,
                evidence_hash,
                &candidate,
                assignment.share_index,
                &encryption,
                &commitments,
            );
            if let Err(error) = checked {
                log::warn!(
                    "rejected DHT jury partial from {}: {error}",
                    hex::encode(candidate)
                );
                continue;
            }
            let row = partial_row(&partial);
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            insert_partial_decryption_if_missing(storage.connection(), &row)
                .context("persist fetched jury partial")?;
            fetched.push(partial);
        }
        Ok(fetched)
    }
}

pub(crate) fn aggregate_commitments(
    records: Vec<hal_storage::jury_commitments::JuryCommitmentRecord>,
) -> Result<FeldmanCommitments> {
    if records.len() != JURY_PARTICIPANTS as usize {
        return Err(anyhow!(
            "expected {JURY_PARTICIPANTS} jury commitments, found {}",
            records.len()
        ));
    }
    let mut dealer_commitments = Vec::with_capacity(records.len());
    for record in records {
        let signed = JuryDkgCommitmentRecord {
            complaint_id: record.complaint_id,
            dealer_node_id: record.dealer_node_id,
            dealer_public_key: record.dealer_public_key,
            commitments: record.commitments,
            threshold: record.threshold,
            participant_count: record.participant_count,
            published_at: record.published_at,
            signature: record.signature,
        };
        verify_commitment(&signed).context("verify stored jury DKG commitment")?;
        dealer_commitments.push(FeldmanCommitments {
            commitments: signed
                .commitments
                .into_iter()
                .map(CompressedRistretto)
                .collect(),
            threshold: signed.threshold,
            participant_count: signed.participant_count,
        });
    }
    let first = dealer_commitments
        .first()
        .context("jury DKG commitments are empty")?;
    if first.threshold != JURY_THRESHOLD
        || first.participant_count != JURY_PARTICIPANTS
        || first.commitments.len() != JURY_THRESHOLD as usize
        || dealer_commitments.iter().any(|commitments| {
            commitments.threshold != first.threshold
                || commitments.participant_count != first.participant_count
                || commitments.commitments.len() != first.commitments.len()
        })
    {
        return Err(anyhow!("jury DKG commitment metadata mismatch"));
    }
    let combined = (0..first.commitments.len())
        .map(|coefficient| {
            dealer_commitments
                .iter()
                .try_fold(RistrettoPoint::default(), |sum, dealer| {
                    dealer.commitments[coefficient]
                        .decompress()
                        .map(|point| sum + point)
                        .ok_or_else(|| anyhow!("invalid compressed Feldman commitment"))
                })
                .map(|point| point.compress())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(FeldmanCommitments {
        commitments: combined,
        threshold: first.threshold,
        participant_count: first.participant_count,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_fetched_partial(
    partial: &JuryPartialDecryption,
    dht_signature: &[u8],
    expires_at: u64,
    now: u64,
    complaint_id: &[u8; 32],
    evidence_hash: &[u8; 32],
    roster_node_id: &[u8; 32],
    roster_share_index: u32,
    encryption: &Encryption,
    commitments: &FeldmanCommitments,
) -> Result<()> {
    if expires_at <= now {
        return Err(anyhow!("DHT jury partial expired"));
    }
    let public_key =
        VerifyingKey::from_bytes(&partial.juror_public_key).context("decode juror public key")?;
    verify_partial_decryption_signature(&public_key, partial)
        .context("verify jury partial signature")?;
    if NodeId::from_public_key(&public_key).as_bytes() != &partial.juror_node_id {
        return Err(anyhow!("juror public key does not match juror node ID"));
    }
    if &partial.complaint_id != complaint_id
        || &partial.juror_node_id != roster_node_id
        || partial.juror_share_index != roster_share_index
    {
        return Err(anyhow!("jury partial does not match complaint roster"));
    }
    if dht_signature != partial.signature {
        return Err(anyhow!(
            "DHT signature does not match jury partial signature"
        ));
    }
    if partial.issued_at > now
        || partial.issued_at.checked_add(JURY_PARTIAL_TTL_SECS) != Some(expires_at)
    {
        return Err(anyhow!("jury partial expiry does not match its TTL"));
    }
    verify_partial_decryption(encryption, commitments, &partial.partial)
        .context("verify jury partial DLEQ proof")?;
    if &partial.evidence_hash != evidence_hash {
        return Err(anyhow!("jury partial does not match evidence hash"));
    }
    Ok(())
}

fn partial_row(partial: &JuryPartialDecryption) -> PartialDecryptionRow {
    PartialDecryptionRow {
        complaint_id: partial.complaint_id,
        juror_node_id: partial.juror_node_id,
        juror_public_key: partial.juror_public_key,
        evidence_hash: partial.evidence_hash,
        juror_share_index: partial.juror_share_index,
        partial_share_index: partial.partial.share_index,
        partial_threshold: partial.partial.threshold,
        partial_participant_count: partial.partial.participant_count,
        partial_point: *partial.partial.partial.as_bytes(),
        proof_challenge: partial.partial.proof.challenge.to_bytes(),
        proof_response: partial.partial.proof.response.to_bytes(),
        proof_share_public: *partial.partial.proof.share_public.as_bytes(),
        signature: partial.signature,
        issued_at: partial.issued_at,
    }
}

pub(crate) fn partial_decryption_from_row(
    row: &PartialDecryptionRow,
) -> Result<JuryPartialDecryption> {
    let challenge = Option::<Scalar>::from(Scalar::from_canonical_bytes(row.proof_challenge))
        .context("jury partial proof challenge is not canonical")?;
    let response = Option::<Scalar>::from(Scalar::from_canonical_bytes(row.proof_response))
        .context("jury partial proof response is not canonical")?;
    Ok(JuryPartialDecryption {
        complaint_id: row.complaint_id,
        juror_node_id: row.juror_node_id,
        juror_public_key: row.juror_public_key,
        juror_share_index: row.juror_share_index,
        evidence_hash: row.evidence_hash,
        partial: PartialDecryption {
            share_index: row.partial_share_index,
            threshold: row.partial_threshold,
            participant_count: row.partial_participant_count,
            partial: CompressedRistretto(row.partial_point),
            proof: DleqProof {
                challenge,
                response,
                share_public: CompressedRistretto(row.proof_share_public),
            },
        },
        signature: row.signature,
        issued_at: row.issued_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jury_evidence::sign_partial_decryption;
    use curve25519_dalek::scalar::Scalar;
    use hal_crypto::{
        threshold_encrypt::{encrypt, partial_decrypt},
        vss::{combine_commitments_to_public_key, feldman_split},
    };
    use rand::rngs::OsRng;

    fn verified_fixture() -> (
        JuryPartialDecryption,
        Encryption,
        FeldmanCommitments,
        SigningKey,
    ) {
        let key = SigningKey::from_bytes(&[61; 32]);
        let mut rng = OsRng;
        let split = feldman_split(&mut rng, &Scalar::from(17u64), 5, 7).expect("split");
        let public_key =
            combine_commitments_to_public_key(&[split.commitments.clone()]).expect("public key");
        let encryption = encrypt(&mut rng, &public_key, b"jury evidence").expect("encrypt");
        let share = split.shares.first().expect("first share");
        let partial_decryption =
            partial_decrypt(&mut rng, share, &encryption).expect("partial decrypt");
        let mut partial = JuryPartialDecryption {
            complaint_id: [1; 32],
            juror_node_id: *NodeId::from_public_key(&key.verifying_key()).as_bytes(),
            juror_public_key: [0; 32],
            juror_share_index: share.index,
            evidence_hash: [2; 32],
            partial: partial_decryption,
            signature: [0; 64],
            issued_at: 100,
        };
        sign_partial_decryption(&key, &mut partial).expect("sign partial");
        (partial, encryption, split.commitments, key)
    }

    #[test]
    fn fetcher_accepts_valid_signed_partial_and_dleq() {
        let (partial, encryption, commitments, _) = verified_fixture();
        let candidate = partial.juror_node_id;
        verify_fetched_partial(
            &partial,
            &partial.signature,
            100 + JURY_PARTIAL_TTL_SECS,
            101,
            &partial.complaint_id,
            &partial.evidence_hash,
            &candidate,
            partial.juror_share_index,
            &encryption,
            &commitments,
        )
        .expect("valid remote partial");
    }

    #[test]
    fn fetcher_rejects_expired_partial() {
        let (partial, encryption, commitments, _) = verified_fixture();
        assert!(verify_fetched_partial(
            &partial,
            &partial.signature,
            100,
            101,
            &partial.complaint_id,
            &partial.evidence_hash,
            &partial.juror_node_id,
            partial.juror_share_index,
            &encryption,
            &commitments,
        )
        .is_err());
    }

    #[test]
    fn fetcher_rejects_invalid_dleq_proof() {
        let (mut partial, encryption, commitments, key) = verified_fixture();
        partial.partial.proof.response += Scalar::ONE;
        sign_partial_decryption(&key, &mut partial).expect("resign tampered partial");
        let error = verify_fetched_partial(
            &partial,
            &partial.signature,
            100 + JURY_PARTIAL_TTL_SECS,
            101,
            &partial.complaint_id,
            &partial.evidence_hash,
            &partial.juror_node_id,
            partial.juror_share_index,
            &encryption,
            &commitments,
        )
        .expect_err("invalid DLEQ must be rejected");
        assert!(error.to_string().contains("DLEQ"));
    }
}
