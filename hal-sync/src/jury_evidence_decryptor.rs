use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::VerifyingKey;
use hal_crypto::threshold_encrypt::{
    combine_partial_decryptions, decrypt_with_combined_key, verify_partial_decryption, Encryption,
    PartialDecryption,
};
use hal_storage::{
    jury_commitments::list_jury_commitments_for_complaint,
    jury_evidence_responses::list_evidence_responses,
    jury_partial_decryptions::list_partial_decryptions,
    jury_rosters::{list_assignments_for_generation, read_latest_roster},
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    dht::{jury_dkg_commitment::JURY_PARTICIPANTS, NodeId},
    jury_evidence::{compute_evidence_hash, verify_partial_decryption_signature},
    jury_partial_fetcher::{aggregate_commitments, partial_decryption_from_row},
    runtime_context::RuntimeContext,
};

pub async fn try_decrypt_evidence(
    ctx: &Arc<RuntimeContext>,
    complaint_id: &[u8; 32],
    evidence_hash: &[u8; 32],
    now: u64,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    if let Some(plaintext) = ctx
        .jury_plaintext_cache
        .get(complaint_id, evidence_hash)
        .context("read jury plaintext cache")?
    {
        return Ok(Some(plaintext));
    }

    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage required to decrypt jury evidence")?;
    NodeId::from_hex(&ctx.identity_id)
        .context("parse local identity for jury evidence decryption")?;

    let (response, assignments, commitment_records, partial_rows) = {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        let responses = list_evidence_responses(storage.connection(), complaint_id)?
            .into_iter()
            .filter(|response| &response.evidence_hash == evidence_hash)
            .collect::<Vec<_>>();
        let response = match responses.as_slice() {
            [] => return Ok(None),
            [response] => response.clone(),
            _ => {
                return Err(anyhow!(
                    "multiple evidence responses share the same evidence hash"
                ))
            }
        };
        let Some(roster) = read_latest_roster(storage.connection(), complaint_id)? else {
            return Ok(None);
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
        let commitment_records =
            list_jury_commitments_for_complaint(storage.connection(), complaint_id)?;
        let partial_rows =
            list_partial_decryptions(storage.connection(), complaint_id, evidence_hash)?;
        (response, assignments, commitment_records, partial_rows)
    };

    let commitments = aggregate_commitments(commitment_records)?;
    let expected_public_key =
        hal_crypto::vss::combine_commitments_to_public_key(&[commitments.clone()])
            .context("combine aggregated jury public key")?;
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
    let roster = assignments
        .into_iter()
        .map(|assignment| (assignment.candidate_node_id, assignment.share_index))
        .collect::<HashMap<_, _>>();
    let mut valid = Vec::new();
    for row in partial_rows {
        if row.complaint_id != *complaint_id
            || row.evidence_hash != *evidence_hash
            || row.issued_at > now
        {
            log::warn!(
                "discarding jury partial with invalid complaint, evidence, or issue time for {}",
                hex::encode(row.juror_node_id)
            );
            continue;
        }
        let Some(expected_share_index) = roster.get(&row.juror_node_id) else {
            log::warn!(
                "discarding jury partial from non-roster juror {}",
                hex::encode(row.juror_node_id)
            );
            continue;
        };
        let partial = match partial_decryption_from_row(&row) {
            Ok(partial) => partial,
            Err(error) => {
                log::warn!(
                    "discarding malformed jury partial from {}: {error}",
                    hex::encode(row.juror_node_id)
                );
                continue;
            }
        };
        if partial.juror_share_index != *expected_share_index
            || partial.partial.share_index != *expected_share_index
        {
            log::warn!(
                "discarding jury partial with mismatched roster share index from {}",
                hex::encode(row.juror_node_id)
            );
            continue;
        }
        let public_key = match VerifyingKey::from_bytes(&partial.juror_public_key) {
            Ok(public_key) => public_key,
            Err(error) => {
                log::warn!(
                    "discarding jury partial with invalid public key from {}: {error}",
                    hex::encode(row.juror_node_id)
                );
                continue;
            }
        };
        if verify_partial_decryption_signature(&public_key, &partial).is_err()
            || verify_partial_decryption(&encryption, &commitments, &partial.partial).is_err()
        {
            log::warn!(
                "discarding jury partial that failed signature or DLEQ verification from {}",
                hex::encode(row.juror_node_id)
            );
            continue;
        }
        valid.push((partial.issued_at, partial.juror_node_id, partial.partial));
    }

    let selected = select_distinct_partials(valid, commitments.threshold as usize);

    if selected.len() < commitments.threshold as usize {
        return Ok(None);
    }
    if !ctx
        .jury_plaintext_cache
        .mark_attempted(*complaint_id, *evidence_hash)
        .context("mark jury evidence decryption attempt")?
    {
        return ctx
            .jury_plaintext_cache
            .get(complaint_id, evidence_hash)
            .context("read jury plaintext cache after duplicate attempt");
    }

    let combined_key = combine_partial_decryptions(&encryption, &commitments, &selected)
        .context("combine verified jury partial decryptions")?;
    let plaintext_bytes = Zeroizing::new(
        decrypt_with_combined_key(&encryption, &combined_key).context("decrypt jury evidence")?,
    );
    let mut parsed: serde_json::Value =
        serde_json::from_slice(&plaintext_bytes).context("parse decrypted jury evidence JSON")?;
    let recomputed = compute_evidence_hash(complaint_id, &parsed);
    zeroize_json_value(&mut parsed);
    let recomputed = recomputed.context("recompute jury evidence hash")?;
    if recomputed != *evidence_hash {
        log::warn!(
            "decrypted jury evidence hash mismatch for complaint {}",
            hex::encode(complaint_id)
        );
        return Ok(None);
    }

    ctx.jury_plaintext_cache
        .insert(*complaint_id, *evidence_hash, plaintext_bytes)
        .context("cache decrypted jury evidence")?;
    ctx.jury_plaintext_cache
        .get(complaint_id, evidence_hash)
        .context("read cached jury evidence after insertion")
}

fn zeroize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(string) => string.zeroize(),
        serde_json::Value::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        serde_json::Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                zeroize_json_value(&mut value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn select_distinct_partials(
    mut candidates: Vec<(u64, [u8; 32], PartialDecryption)>,
    limit: usize,
) -> Vec<PartialDecryption> {
    candidates.sort_by_key(|(issued_at, juror_node_id, _)| (*issued_at, *juror_node_id));
    let mut seen_jurors = HashSet::with_capacity(candidates.len());
    let mut seen_share_indices = HashSet::with_capacity(candidates.len());
    candidates
        .into_iter()
        .filter_map(|(_, juror_node_id, partial)| {
            if !seen_jurors.insert(juror_node_id) || !seen_share_indices.insert(partial.share_index)
            {
                return None;
            }
            Some(partial)
        })
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use ed25519_dalek::SigningKey;
    use hal_crypto::{
        threshold_encrypt::{encrypt, partial_decrypt},
        vss::{combine_commitments_to_public_key, feldman_split},
    };
    use hal_settings::NetworkTrustPolicy;
    use hal_storage::{
        jury_assembly_state::{upsert_juror_state, JurorPhase, JurorState},
        jury_commitments::{
            list_jury_commitments_for_complaint, persist_jury_commitment, JuryCommitmentRecord,
        },
        jury_evidence_responses::{upsert_evidence_response, EvidenceResponseRow},
        jury_partial_decryptions::{upsert_partial_decryption, PartialDecryptionRow},
        jury_rosters::{insert_roster, insert_roster_assignment, RosterAssignmentRow, RosterRow},
        ClientStorage,
    };
    use rand::rngs::OsRng;
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;
    use zeroize::Zeroizing;

    struct Fixture {
        _db_file: NamedTempFile,
        ctx: Arc<RuntimeContext>,
        complaint_id: [u8; 32],
        evidence_hash: [u8; 32],
        plaintext: Vec<u8>,
        partials: Vec<PartialDecryptionRow>,
        local_signing_key: SigningKey,
    }

    fn fixture(partial_count: usize, tamper_hash: bool) -> Fixture {
        let db_file = NamedTempFile::new().expect("create test database");
        let storage = ClientStorage::open(db_file.path(), &[33; 32]).expect("open storage");
        let complaint_id = [34; 32];
        let juror_keys = (1..=7u8)
            .map(|index| SigningKey::from_bytes(&[index; 32]))
            .collect::<Vec<_>>();
        let juror_ids = juror_keys
            .iter()
            .map(|key| *NodeId::from_public_key(&key.verifying_key()).as_bytes())
            .collect::<Vec<_>>();
        let local_id = juror_ids[0];
        let local_identity = NodeId::from_bytes(local_id).to_hex();
        let storage_arc = Arc::new(Mutex::new(storage));
        let ctx = crate::runtime_context::tests::test_runtime_context_with_storage(
            Some(Arc::clone(&storage_arc)),
            local_identity,
        );

        let mut rng = OsRng;
        let mut total_shares = vec![Scalar::ZERO; JURY_PARTICIPANTS as usize];
        let mut dealer_commitments = Vec::new();
        {
            let mut storage = storage_arc.lock().expect("storage lock");
            for dealer_index in 0..JURY_PARTICIPANTS as u8 {
                let dealer_key = SigningKey::from_bytes(&[100 + dealer_index; 32]);
                let split = feldman_split(
                    &mut rng,
                    &Scalar::from(900 + u64::from(dealer_index)),
                    5,
                    JURY_PARTICIPANTS,
                )
                .expect("split dealer secret");
                for share in &split.shares {
                    total_shares[(share.index - 1) as usize] += *share.value;
                }
                let signed = crate::dht::jury_dkg_commitment::sign_commitment(
                    &dealer_key,
                    complaint_id,
                    split
                        .commitments
                        .commitments
                        .iter()
                        .map(|commitment| *commitment.as_bytes())
                        .collect(),
                    90,
                )
                .expect("sign DKG commitments");
                dealer_commitments.push(split.commitments);
                persist_jury_commitment(
                    &mut storage,
                    &JuryCommitmentRecord {
                        complaint_id,
                        dealer_node_id: signed.dealer_node_id,
                        dealer_public_key: signed.dealer_public_key,
                        commitments: signed.commitments,
                        threshold: signed.threshold,
                        participant_count: signed.participant_count,
                        published_at: signed.published_at,
                        signature: signed.signature,
                        expires_at: 10_000,
                    },
                )
                .expect("persist DKG commitments");
            }

            insert_roster(
                storage.connection(),
                &RosterRow {
                    complaint_id,
                    roster_generation: 1,
                    roster_hash: [35; 32],
                    roster_blob: Vec::new(),
                    created_at: 90,
                },
            )
            .expect("insert roster");
            for (index, node_id) in juror_ids.iter().enumerate() {
                insert_roster_assignment(
                    storage.connection(),
                    &RosterAssignmentRow {
                        complaint_id,
                        roster_generation: 1,
                        share_index: index as u32 + 1,
                        candidate_node_id: *node_id,
                        invitation_id: [index as u8 + 40; 32],
                        invited_at: 90,
                        response: None,
                    },
                )
                .expect("insert roster assignment");
            }
        }

        let public_key =
            combine_commitments_to_public_key(&dealer_commitments).expect("combine public key");
        let plaintext = br#"{"message":"jury evidence"}"#.to_vec();
        let parsed: serde_json::Value =
            serde_json::from_slice(&plaintext).expect("parse fixture JSON");
        let correct_hash = compute_evidence_hash(&complaint_id, &parsed).expect("evidence hash");
        let evidence_hash = if tamper_hash { [99; 32] } else { correct_hash };
        let encryption = encrypt(&mut rng, &public_key, &plaintext).expect("encrypt evidence");
        let respondent_key = SigningKey::from_bytes(&[77; 32]);
        let response = EvidenceResponseRow {
            complaint_id,
            respondent_node_id: *NodeId::from_public_key(&respondent_key.verifying_key())
                .as_bytes(),
            jury_pubkey: *public_key.as_bytes(),
            evidence_hash,
            encapsulation: *encryption.encapsulation.as_bytes(),
            nonce: encryption.nonce,
            ciphertext: encryption.ciphertext.clone(),
            signature: [78; 64],
            issued_at: 100,
        };
        {
            let storage = storage_arc.lock().expect("storage lock");
            upsert_evidence_response(storage.connection(), &response)
                .expect("persist evidence response");
        }

        assert_eq!(
            list_jury_commitments_for_complaint(
                storage_arc.lock().expect("storage lock").connection(),
                &complaint_id
            )
            .expect("read DKG commitments")
            .len(),
            JURY_PARTICIPANTS as usize
        );
        let mut partials = Vec::new();
        for (index, key) in juror_keys.iter().take(partial_count).enumerate() {
            let share = hal_crypto::vss::Share {
                index: index as u32 + 1,
                value: Zeroizing::new(total_shares[index]),
                threshold: 5,
                participant_count: JURY_PARTICIPANTS,
            };
            let partial =
                partial_decrypt(&mut rng, &share, &encryption).expect("create juror partial");
            let mut signed = crate::jury_evidence::JuryPartialDecryption {
                complaint_id,
                juror_node_id: juror_ids[index],
                juror_public_key: [0; 32],
                juror_share_index: share.index,
                evidence_hash,
                partial,
                signature: [0; 64],
                issued_at: 101,
            };
            crate::jury_evidence::sign_partial_decryption(key, &mut signed)
                .expect("sign juror partial");
            let row = PartialDecryptionRow {
                complaint_id,
                juror_node_id: signed.juror_node_id,
                juror_public_key: signed.juror_public_key,
                evidence_hash,
                juror_share_index: signed.juror_share_index,
                partial_share_index: signed.partial.share_index,
                partial_threshold: signed.partial.threshold,
                partial_participant_count: signed.partial.participant_count,
                partial_point: *signed.partial.partial.as_bytes(),
                proof_challenge: signed.partial.proof.challenge.to_bytes(),
                proof_response: signed.partial.proof.response.to_bytes(),
                proof_share_public: *signed.partial.proof.share_public.as_bytes(),
                signature: signed.signature,
                issued_at: signed.issued_at,
            };
            {
                let storage = storage_arc.lock().expect("storage lock");
                upsert_partial_decryption(storage.connection(), &row)
                    .expect("persist juror partial");
            }
            partials.push(row);
        }
        Fixture {
            _db_file: db_file,
            ctx,
            complaint_id,
            evidence_hash,
            plaintext,
            partials,
            local_signing_key: juror_keys[0].clone(),
        }
    }

    #[tokio::test]
    async fn decrypt_returns_none_with_fewer_than_five_partials() {
        let fixture = fixture(4, false);
        assert!(try_decrypt_evidence(
            &fixture.ctx,
            &fixture.complaint_id,
            &fixture.evidence_hash,
            200,
        )
        .await
        .expect("try decrypt")
        .is_none());
    }

    #[tokio::test]
    async fn decrypt_succeeds_with_exactly_five_valid_partials() {
        let fixture = fixture(5, false);
        let plaintext = try_decrypt_evidence(
            &fixture.ctx,
            &fixture.complaint_id,
            &fixture.evidence_hash,
            200,
        )
        .await
        .expect("try decrypt")
        .expect("decrypted plaintext");
        assert_eq!(&*plaintext, &fixture.plaintext);
    }

    #[tokio::test]
    async fn decrypt_rejects_when_recomputed_hash_mismatches() {
        let fixture = fixture(5, true);
        assert!(try_decrypt_evidence(
            &fixture.ctx,
            &fixture.complaint_id,
            &fixture.evidence_hash,
            200,
        )
        .await
        .expect("try decrypt")
        .is_none());
        assert!(fixture
            .ctx
            .jury_plaintext_cache
            .get(&fixture.complaint_id, &fixture.evidence_hash)
            .expect("read cache")
            .is_none());
    }

    #[tokio::test]
    async fn decrypt_uses_local_plus_four_remote() {
        let fixture = fixture(5, false);
        let local_id = *NodeId::from_hex(&fixture.ctx.identity_id)
            .expect("local identity")
            .as_bytes();
        assert_eq!(fixture.partials[0].juror_node_id, local_id);
        let plaintext = try_decrypt_evidence(
            &fixture.ctx,
            &fixture.complaint_id,
            &fixture.evidence_hash,
            200,
        )
        .await
        .expect("try decrypt")
        .expect("decrypted plaintext");
        assert_eq!(&*plaintext, &fixture.plaintext);
    }

    #[tokio::test]
    async fn decrypt_dedupes_partials_by_juror_node_id() {
        let fixture = fixture(2, false);
        let first = partial_decryption_from_row(&fixture.partials[0])
            .expect("first partial")
            .partial;
        let second = partial_decryption_from_row(&fixture.partials[1])
            .expect("second partial")
            .partial;
        let selected = select_distinct_partials(
            vec![
                (101, fixture.partials[0].juror_node_id, first.clone()),
                (102, fixture.partials[0].juror_node_id, first),
                (103, fixture.partials[1].juror_node_id, second),
            ],
            5,
        );
        assert_eq!(selected.len(), 2);
        assert_ne!(selected[0].share_index, selected[1].share_index);
    }

    #[tokio::test]
    async fn tick_recovers_plaintext_from_persisted_partials_after_restart() {
        let fixture = fixture(5, false);
        let local_node_id =
            *NodeId::from_public_key(&fixture.local_signing_key.verifying_key()).as_bytes();
        {
            let storage = fixture
                .ctx
                .storage
                .as_ref()
                .expect("storage")
                .lock()
                .expect("storage lock");
            upsert_juror_state(
                storage.connection(),
                &JurorState {
                    complaint_id: fixture.complaint_id,
                    juror_node_id: local_node_id,
                    phase: JurorPhase::AwaitingVotes,
                    updated_at: 150,
                },
            )
            .expect("persist awaiting-votes state");
        }
        let local_node = NodeId::from_bytes(local_node_id);
        let orchestrator = crate::juror_orchestrator::JurorOrchestratorTask::new(
            Arc::clone(&fixture.ctx),
            fixture.local_signing_key.clone(),
            local_node,
            Arc::new(std::sync::Mutex::new(crate::pinning::KnownHosts::new())),
            Arc::new(tokio::sync::Mutex::new(
                crate::dht::routing::RoutingTable::new(local_node),
            )),
            NetworkTrustPolicy::default(),
        );

        orchestrator
            .tick_at(200)
            .await
            .expect("recover jury plaintext on orchestrator tick");

        let recovered = fixture
            .ctx
            .jury_plaintext_cache
            .get(&fixture.complaint_id, &fixture.evidence_hash)
            .expect("read recovered plaintext")
            .expect("plaintext recovered from persisted partials");
        assert_eq!(&*recovered, &fixture.plaintext);
    }

    #[tokio::test]
    async fn decrypt_returns_cached_plaintext_on_second_call() {
        let fixture = fixture(5, false);
        let first = try_decrypt_evidence(
            &fixture.ctx,
            &fixture.complaint_id,
            &fixture.evidence_hash,
            200,
        )
        .await
        .expect("first decrypt")
        .expect("first plaintext");
        {
            let storage = fixture
                .ctx
                .storage
                .as_ref()
                .expect("storage")
                .lock()
                .expect("storage lock");
            storage
                .connection()
                .execute(
                    "DELETE FROM jury_partial_decryptions WHERE complaint_id = ?1",
                    [fixture.complaint_id.as_slice()],
                )
                .expect("delete partials");
        }
        let second = try_decrypt_evidence(
            &fixture.ctx,
            &fixture.complaint_id,
            &fixture.evidence_hash,
            200,
        )
        .await
        .expect("cached decrypt")
        .expect("cached plaintext");
        assert_eq!(&*first, &*second);
    }
}
