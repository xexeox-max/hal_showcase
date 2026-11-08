//! Ingest signed evidence responses and persist the local juror's partial.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hal_crypto::{
    threshold_encrypt::{partial_decrypt, Encryption},
    vss::{combine_commitments_to_public_key, FeldmanCommitments, Share},
};
use hal_storage::{
    complaints::read_complaint,
    jury_aggregated_shares::read_aggregated_share,
    jury_assembly_state::{read_juror_state, JurorPhase},
    jury_commitments::list_jury_commitments_for_complaint,
    jury_evidence_responses::{
        read_evidence_response, upsert_evidence_response, EvidenceResponseRow,
    },
    jury_partial_decryptions::{
        insert_partial_decryption_if_missing, read_partial_decryption, PartialDecryptionRow,
    },
    ClientStorage,
};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{
    dht::{
        jury_dkg_commitment::{verify_commitment, JuryDkgCommitmentRecord},
        NodeId,
    },
    journal::{JuryEvidenceDeliveryPayload, SyncEvent},
    jury_assembly::EVIDENCE_RESPONSE_WINDOW_SECS,
    jury_evidence::{sign_partial_decryption, verify_evidence_response, JuryEvidenceResponse},
    runtime_context::RuntimeContext,
};

pub async fn handle_jury_evidence_delivery(
    ctx: &Arc<RuntimeContext>,
    event: &SyncEvent,
    sender_node_id: &[u8; 32],
    sender_key: &VerifyingKey,
    now: u64,
) -> Result<()> {
    let payload: JuryEvidenceDeliveryPayload =
        serde_json::from_str(&event.data).context("parse JuryEvidenceDelivery payload")?;
    let local_node_id = *NodeId::from_hex(&ctx.identity_id)
        .context("parse local identity for evidence delivery")?
        .as_bytes();
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage required for jury evidence delivery")?;
    let storage = storage_arc
        .lock()
        .map_err(|_| anyhow!("storage lock poisoned"))?;
    process_evidence_response(
        &storage,
        &payload,
        sender_node_id,
        sender_key,
        &local_node_id,
        ctx.identity_signing_key
            .as_deref()
            .context("local signing key required for jury partial decryption")?,
        now,
        &mut OsRng,
    )?;
    Ok(())
}

fn process_evidence_response<R: RngCore + CryptoRng>(
    storage: &ClientStorage,
    payload: &JuryEvidenceDeliveryPayload,
    sender_node_id: &[u8; 32],
    sender_key: &VerifyingKey,
    local_node_id: &[u8; 32],
    signing_key: &SigningKey,
    now: u64,
    rng: &mut R,
) -> Result<()> {
    if payload.respondent_node_id != *sender_node_id {
        return Err(anyhow!("evidence sender does not match respondent"));
    }
    let response = response_from_payload(payload);
    verify_evidence_response(sender_key, &response).context("verify evidence response")?;

    let complaint = match read_complaint(storage.connection(), &payload.complaint_id)? {
        Some(complaint) => complaint,
        None => return Ok(()),
    };
    if payload.respondent_node_id != complaint.complainant_node_id
        && payload.respondent_node_id != complaint.subject_node_id
    {
        return Ok(());
    }

    let state = match read_juror_state(storage.connection(), &payload.complaint_id, local_node_id)?
    {
        Some(state) if state.phase == JurorPhase::ReadyForDecryption => state,
        _ => return Ok(()),
    };
    let deadline = state
        .updated_at
        .checked_add(EVIDENCE_RESPONSE_WINDOW_SECS)
        .context("evidence response deadline overflow")?;
    if now < state.updated_at || now > deadline || payload.issued_at > now {
        return Ok(());
    }

    let commitments = jury_commitments_for_decryption(storage, &payload.complaint_id)?;
    let expected_public_key = combine_commitments_to_public_key(&commitments)
        .context("combine jury commitments into public key")?;
    if payload.jury_pubkey != *expected_public_key.as_bytes() {
        return Err(anyhow!(
            "evidence response jury public key does not match complaint commitments"
        ));
    }

    let response_row = evidence_response_row(&response);
    match read_evidence_response(
        storage.connection(),
        &payload.complaint_id,
        &payload.respondent_node_id,
    )? {
        Some(existing) if existing == response_row => {}
        Some(_) => return Err(anyhow!("conflicting evidence response already stored")),
        None => upsert_evidence_response(storage.connection(), &response_row)?,
    }

    if read_partial_decryption(
        storage.connection(),
        &payload.complaint_id,
        local_node_id,
        &payload.evidence_hash,
    )?
    .is_some()
    {
        return Ok(());
    }

    let aggregate =
        read_aggregated_share(storage.connection(), &payload.complaint_id, local_node_id)?
            .context("aggregated juror share is required for partial decryption")?;
    if aggregate.threshold != 5 || aggregate.participant_count != 7 {
        return Err(anyhow!("aggregated juror share must be 5-of-7"));
    }
    let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(aggregate.aggregated_value))
        .context("aggregated juror share is not a canonical scalar")?;
    let share = Share {
        index: aggregate.share_index,
        value: Zeroizing::new(scalar),
        threshold: aggregate.threshold,
        participant_count: aggregate.participant_count,
    };
    let encryption = Encryption {
        encapsulation: CompressedRistretto(payload.encapsulation),
        nonce: payload.nonce,
        ciphertext: payload.ciphertext.clone(),
    };
    let partial =
        partial_decrypt(rng, &share, &encryption).context("generate jury partial decryption")?;
    let mut signed_partial = crate::jury_evidence::JuryPartialDecryption {
        complaint_id: payload.complaint_id,
        juror_node_id: *local_node_id,
        juror_public_key: [0; 32],
        juror_share_index: aggregate.share_index,
        evidence_hash: payload.evidence_hash,
        partial,
        signature: [0; 64],
        issued_at: now,
    };
    sign_partial_decryption(signing_key, &mut signed_partial)
        .context("sign jury partial decryption")?;
    insert_partial_decryption_if_missing(
        storage.connection(),
        &partial_decryption_row(&signed_partial),
    )?;
    Ok(())
}

fn response_from_payload(payload: &JuryEvidenceDeliveryPayload) -> JuryEvidenceResponse {
    JuryEvidenceResponse {
        complaint_id: payload.complaint_id,
        respondent_node_id: payload.respondent_node_id,
        jury_pubkey: CompressedRistretto(payload.jury_pubkey),
        evidence_hash: payload.evidence_hash,
        encapsulation: CompressedRistretto(payload.encapsulation),
        nonce: payload.nonce,
        ciphertext: payload.ciphertext.clone(),
        signature: payload.signature,
        issued_at: payload.issued_at,
    }
}

fn evidence_response_row(response: &JuryEvidenceResponse) -> EvidenceResponseRow {
    EvidenceResponseRow {
        complaint_id: response.complaint_id,
        respondent_node_id: response.respondent_node_id,
        jury_pubkey: *response.jury_pubkey.as_bytes(),
        evidence_hash: response.evidence_hash,
        encapsulation: *response.encapsulation.as_bytes(),
        nonce: response.nonce,
        ciphertext: response.ciphertext.clone(),
        signature: response.signature,
        issued_at: response.issued_at,
    }
}

fn jury_commitments_for_decryption(
    storage: &ClientStorage,
    complaint_id: &[u8; 32],
) -> Result<Vec<FeldmanCommitments>> {
    let records = list_jury_commitments_for_complaint(storage.connection(), complaint_id)?;
    if records.len() != 7 {
        return Err(anyhow!(
            "expected seven jury DKG commitments, found {}",
            records.len()
        ));
    }
    records
        .into_iter()
        .map(|record| {
            let signed_record = JuryDkgCommitmentRecord {
                complaint_id: record.complaint_id,
                dealer_node_id: record.dealer_node_id,
                dealer_public_key: record.dealer_public_key,
                commitments: record.commitments,
                threshold: record.threshold,
                participant_count: record.participant_count,
                published_at: record.published_at,
                signature: record.signature,
            };
            verify_commitment(&signed_record).context("verify stored jury commitment")?;
            Ok(FeldmanCommitments {
                commitments: signed_record
                    .commitments
                    .into_iter()
                    .map(CompressedRistretto)
                    .collect(),
                threshold: signed_record.threshold,
                participant_count: signed_record.participant_count,
            })
        })
        .collect()
}

fn partial_decryption_row(
    partial: &crate::jury_evidence::JuryPartialDecryption,
) -> PartialDecryptionRow {
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

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
    use ed25519_dalek::SigningKey;
    use hal_crypto::vss::feldman_split;
    use hal_storage::{
        complaints::{insert_complaint, ComplaintRow},
        jury_aggregated_shares::{upsert_aggregated_share, AggregatedShareRow},
        jury_assembly_state::{upsert_juror_state, JurorState},
        jury_commitments::{persist_jury_commitment, JuryCommitmentRecord},
    };
    use rand::rngs::OsRng;
    use tempfile::NamedTempFile;

    struct Fixture {
        _db_file: NamedTempFile,
        storage: ClientStorage,
        local_key: SigningKey,
        respondent_key: SigningKey,
        local_node_id: [u8; 32],
        respondent_node_id: [u8; 32],
        payload: JuryEvidenceDeliveryPayload,
    }

    fn node_id(key: &SigningKey) -> [u8; 32] {
        *NodeId::from_public_key(&key.verifying_key()).as_bytes()
    }

    fn fixture() -> Fixture {
        let db_file = NamedTempFile::new().expect("create test database file");
        let mut storage = ClientStorage::open(db_file.path(), &[7; 32]).expect("open test storage");
        let complaint_id = [19; 32];
        let local_key = SigningKey::from_bytes(&[11; 32]);
        let respondent_key = SigningKey::from_bytes(&[41; 32]);
        let local_node_id = node_id(&local_key);
        let respondent_node_id = node_id(&respondent_key);
        let other_party_key = SigningKey::from_bytes(&[42; 32]);
        let mut rng = OsRng;
        let mut aggregate = Scalar::ZERO;
        let mut all_commitments = Vec::with_capacity(7);

        insert_complaint(
            storage.connection(),
            &ComplaintRow {
                complaint_id,
                complainant_node_id: respondent_node_id,
                subject_node_id: node_id(&other_party_key),
                kind_tag: 1,
                period_start: 1,
                period_end: 2,
                submitted_at: 1,
                record_blob: vec![1],
            },
            100_000,
        )
        .expect("insert complaint");
        upsert_juror_state(
            storage.connection(),
            &JurorState {
                complaint_id,
                juror_node_id: local_node_id,
                phase: JurorPhase::ReadyForDecryption,
                updated_at: 100,
            },
        )
        .expect("insert juror state");

        for dealer_index in 0..7u8 {
            let dealer_key = SigningKey::from_bytes(&[11 + dealer_index; 32]);
            let split = feldman_split(&mut rng, &Scalar::from(100 + u64::from(dealer_index)), 5, 7)
                .expect("split dealer secret");
            let share = split
                .shares
                .iter()
                .find(|share| share.index == 1)
                .expect("share index 1");
            aggregate += *share.value;
            let commitment_bytes = split
                .commitments
                .commitments
                .iter()
                .map(|commitment| *commitment.as_bytes())
                .collect::<Vec<_>>();
            let signed = crate::dht::jury_dkg_commitment::sign_commitment(
                &dealer_key,
                complaint_id,
                commitment_bytes,
                90,
            )
            .expect("sign DKG commitments");
            all_commitments.push(split.commitments.clone());
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
                    expires_at: 100_000,
                },
            )
            .expect("persist DKG commitment");
        }

        upsert_aggregated_share(
            storage.connection(),
            &AggregatedShareRow {
                complaint_id,
                juror_node_id: local_node_id,
                share_index: 1,
                aggregated_value: aggregate.to_bytes(),
                threshold: 5,
                participant_count: 7,
                computed_at: 100,
            },
        )
        .expect("persist aggregate");

        let jury_pubkey =
            combine_commitments_to_public_key(&all_commitments).expect("combine DKG public key");
        let mut response = JuryEvidenceResponse {
            complaint_id,
            respondent_node_id,
            jury_pubkey,
            evidence_hash: [23; 32],
            encapsulation: RISTRETTO_BASEPOINT_COMPRESSED,
            nonce: [24; 12],
            ciphertext: vec![25, 26],
            signature: [0; 64],
            issued_at: 101,
        };
        crate::jury_evidence::sign_evidence_response(&respondent_key, &mut response)
            .expect("sign evidence response");
        Fixture {
            _db_file: db_file,
            storage,
            local_key,
            respondent_key,
            local_node_id,
            respondent_node_id,
            payload: JuryEvidenceDeliveryPayload {
                complaint_id,
                respondent_node_id,
                jury_pubkey: *response.jury_pubkey.as_bytes(),
                evidence_hash: response.evidence_hash,
                encapsulation: *response.encapsulation.as_bytes(),
                nonce: response.nonce,
                ciphertext: response.ciphertext,
                signature: response.signature,
                issued_at: response.issued_at,
            },
        }
    }

    fn process(fixture: &Fixture, now: u64) -> Result<()> {
        process_evidence_response(
            &fixture.storage,
            &fixture.payload,
            &fixture.respondent_node_id,
            &fixture.respondent_key.verifying_key(),
            &fixture.local_node_id,
            &fixture.local_key,
            now,
            &mut OsRng,
        )
    }

    #[test]
    fn valid_response_is_stored_with_signed_partial() {
        let fixture = fixture();
        process(&fixture, 200).expect("process valid response");
        assert!(read_evidence_response(
            fixture.storage.connection(),
            &fixture.payload.complaint_id,
            &fixture.respondent_node_id
        )
        .expect("read evidence")
        .is_some());
        assert!(read_partial_decryption(
            fixture.storage.connection(),
            &fixture.payload.complaint_id,
            &fixture.local_node_id,
            &fixture.payload.evidence_hash
        )
        .expect("read partial")
        .is_some());
    }

    #[test]
    fn non_party_response_is_dropped_without_persistence() {
        let fixture = fixture();
        let stranger = SigningKey::from_bytes(&[51; 32]);
        let mut payload = fixture.payload.clone();
        payload.respondent_node_id = node_id(&stranger);
        let mut response = response_from_payload(&payload);
        crate::jury_evidence::sign_evidence_response(&stranger, &mut response)
            .expect("sign stranger response");
        payload.signature = response.signature;
        process_evidence_response(
            &fixture.storage,
            &payload,
            &node_id(&stranger),
            &stranger.verifying_key(),
            &fixture.local_node_id,
            &fixture.local_key,
            200,
            &mut OsRng,
        )
        .expect("drop non-party response");
        assert!(read_evidence_response(
            fixture.storage.connection(),
            &payload.complaint_id,
            &payload.respondent_node_id
        )
        .expect("read evidence")
        .is_none());
    }

    #[test]
    fn response_is_dropped_before_ready_phase() {
        let fixture = fixture();
        upsert_juror_state(
            fixture.storage.connection(),
            &JurorState {
                complaint_id: fixture.payload.complaint_id,
                juror_node_id: fixture.local_node_id,
                phase: JurorPhase::AwaitingShares,
                updated_at: 100,
            },
        )
        .expect("set phase");
        process(&fixture, 200).expect("drop response before ready");
        assert!(read_evidence_response(
            fixture.storage.connection(),
            &fixture.payload.complaint_id,
            &fixture.respondent_node_id
        )
        .expect("read evidence")
        .is_none());
    }

    #[test]
    fn response_after_local_deadline_is_dropped() {
        let fixture = fixture();
        let now = 100 + EVIDENCE_RESPONSE_WINDOW_SECS + 1;
        process(&fixture, now).expect("drop late response");
        assert!(read_evidence_response(
            fixture.storage.connection(),
            &fixture.payload.complaint_id,
            &fixture.respondent_node_id
        )
        .expect("read evidence")
        .is_none());
    }

    #[test]
    fn future_issued_at_is_dropped() {
        let fixture = fixture();
        let mut payload = fixture.payload.clone();
        payload.issued_at = 201;
        let mut response = response_from_payload(&payload);
        crate::jury_evidence::sign_evidence_response(&fixture.respondent_key, &mut response)
            .expect("resign response");
        payload.signature = response.signature;
        process_evidence_response(
            &fixture.storage,
            &payload,
            &fixture.respondent_node_id,
            &fixture.respondent_key.verifying_key(),
            &fixture.local_node_id,
            &fixture.local_key,
            200,
            &mut OsRng,
        )
        .expect("drop future response");
        assert!(read_evidence_response(
            fixture.storage.connection(),
            &payload.complaint_id,
            &fixture.respondent_node_id
        )
        .expect("read evidence")
        .is_none());
    }

    #[test]
    fn sender_identity_mismatch_is_rejected() {
        let fixture = fixture();
        assert!(process_evidence_response(
            &fixture.storage,
            &fixture.payload,
            &[99; 32],
            &fixture.respondent_key.verifying_key(),
            &fixture.local_node_id,
            &fixture.local_key,
            200,
            &mut OsRng,
        )
        .is_err());
    }

    #[test]
    fn invalid_response_signature_is_rejected() {
        let fixture = fixture();
        let mut payload = fixture.payload.clone();
        payload.signature[0] ^= 1;
        assert!(process_evidence_response(
            &fixture.storage,
            &payload,
            &fixture.respondent_node_id,
            &fixture.respondent_key.verifying_key(),
            &fixture.local_node_id,
            &fixture.local_key,
            200,
            &mut OsRng,
        )
        .is_err());
    }

    #[test]
    fn mismatched_jury_public_key_is_rejected() {
        let fixture = fixture();
        let mut payload = fixture.payload.clone();
        payload.jury_pubkey = *RISTRETTO_BASEPOINT_COMPRESSED.as_bytes();
        let mut response = response_from_payload(&payload);
        crate::jury_evidence::sign_evidence_response(&fixture.respondent_key, &mut response)
            .expect("resign response");
        payload.signature = response.signature;
        assert!(process_evidence_response(
            &fixture.storage,
            &payload,
            &fixture.respondent_node_id,
            &fixture.respondent_key.verifying_key(),
            &fixture.local_node_id,
            &fixture.local_key,
            200,
            &mut OsRng,
        )
        .is_err());
    }

    #[test]
    fn duplicate_response_does_not_replace_existing_partial() {
        let fixture = fixture();
        process(&fixture, 200).expect("process first response");
        let before = read_partial_decryption(
            fixture.storage.connection(),
            &fixture.payload.complaint_id,
            &fixture.local_node_id,
            &fixture.payload.evidence_hash,
        )
        .expect("read initial partial")
        .expect("initial partial");
        process(&fixture, 201).expect("process duplicate response");
        let after = read_partial_decryption(
            fixture.storage.connection(),
            &fixture.payload.complaint_id,
            &fixture.local_node_id,
            &fixture.payload.evidence_hash,
        )
        .expect("read duplicate partial")
        .expect("stored partial");
        assert_eq!(before, after);
    }

    #[test]
    fn evidence_delivery_payload_roundtrips_fixed_width_fields() {
        let payload = JuryEvidenceDeliveryPayload {
            complaint_id: [1; 32],
            respondent_node_id: [2; 32],
            jury_pubkey: [3; 32],
            evidence_hash: [4; 32],
            encapsulation: [5; 32],
            nonce: [6; 12],
            ciphertext: vec![7, 8, 9],
            signature: [10; 64],
            issued_at: 11,
        };
        let encoded = serde_json::to_string(&payload).expect("serialize delivery payload");
        let decoded: JuryEvidenceDeliveryPayload =
            serde_json::from_str(&encoded).expect("deserialize delivery payload");
        assert_eq!(decoded, payload);
    }
}
