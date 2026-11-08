use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct AbuseMetrics {
    pub incoming_stigma_rejected_total: AtomicU64,
    pub incoming_cold_exceeded_total: AtomicU64,
    pub auto_badge_queued_total: AtomicU64,
    pub auto_badge_published_total: AtomicU64,
    pub auto_badge_publish_failed_total: AtomicU64,
    pub auto_badge_skipped_reply_total: AtomicU64,
    pub auto_badge_skipped_no_storage_total: AtomicU64,
    pub auto_badge_skipped_vouch_total: AtomicU64,
    pub auto_badge_skipped_no_evidence_total: AtomicU64,
    pub quic_identity_verified_total: AtomicU64,
    pub quic_identity_rejected_total: AtomicU64,
    pub quic_identity_tofu_total: AtomicU64,
    pub relay_inner_verify_failed_total: AtomicU64,
    pub relay_inner_verify_ok_total: AtomicU64,
    pub relay_consent_verified_total: AtomicU64,
    pub relay_consent_missing_total: AtomicU64,
    pub relay_consent_signature_failed_total: AtomicU64,
    pub relay_consent_target_mismatch_total: AtomicU64,
    pub relay_consent_expired_total: AtomicU64,
    pub relay_consent_replay_total: AtomicU64,
    pub relay_consent_content_mismatch_total: AtomicU64,
    pub envelope_size_exceeded_total: AtomicU64,
    pub envelope_send_size_exceeded_total: AtomicU64,
    pub envelope_transport_identity_verified_total: AtomicU64,
    pub envelope_transport_identity_mismatch_total: AtomicU64,
    pub cold_tracker_evicted_total: AtomicU64,
    pub inbound_observation_dropped_total: AtomicU64,
    pub stigma_refresh_rounds_total: AtomicU64,
    pub transport_stigma_rejected_total: AtomicU64,
    pub invite_rejected_fanout_total: AtomicU64,
    pub invite_rejected_chain_depth_total: AtomicU64,
    pub invite_rejected_cooldown_total: AtomicU64,
    pub degraded_unknown_rejected_total: AtomicU64,
    pub degraded_known_accepted_total: AtomicU64,
    pub degraded_cleared_total: AtomicU64,
    pub degraded_entered_total: AtomicU64,
    pub proof_of_live_cold_rejected_total: AtomicU64,
    pub proof_of_live_invite_rejected_total: AtomicU64,
    pub proof_of_live_dht_rejected_total: AtomicU64,
    pub rate_tier_throttled_total: AtomicU64,
    pub rate_tier_warning_total: AtomicU64,
    pub rate_tier_blocked_total: AtomicU64,
    pub trust_gate_blocked_total: AtomicU64,
    pub rate_blocked_total: AtomicU64,
    pub rate_limiter_worker_failed_total: AtomicU64,
    pub rate_throttled_by_warning_total: AtomicU64,
    pub rate_throttled_by_watching_total: AtomicU64,
    pub biometric_verified_total: AtomicU64,
    pub biometric_rejected_total: AtomicU64,
    pub biometric_unavailable_total: AtomicU64,
    pub messages_encrypted_total: AtomicU64,
    pub messages_decrypted_total: AtomicU64,
    pub messages_decrypt_failed_total: AtomicU64,
    pub replay_precheck_total: AtomicU64,
    pub ratchet_encrypt_total: AtomicU64,
    pub ratchet_encrypt_failed_total: AtomicU64,
    pub ratchet_commit_failed_total: AtomicU64,
    pub ratchet_decrypt_total: AtomicU64,
    pub ratchet_decrypt_failed_total: AtomicU64,
    pub ratchet_replay_total: AtomicU64,
    pub ratchet_out_of_order_total: AtomicU64,
    pub ratchet_out_of_order_accepted_total: AtomicU64,
    pub ratchet_skipped_keys_current: AtomicU64,
    pub ratchet_skipped_keys_inserted_total: AtomicU64,
    pub ratchet_skipped_keys_expired_total: AtomicU64,
    pub ratchet_skipped_keys_evicted_total: AtomicU64,
    pub ratchet_persist_failed_total: AtomicU64,
    pub session_persist_failed_total: AtomicU64,
    pub ratchet_needs_resync_total: AtomicU64,
    pub ratchet_no_session_total: AtomicU64,
    pub ratchet_needs_resync_received_total: AtomicU64,
    pub ratchet_session_replaced_total: AtomicU64,
    pub ratchet_resync_triggered_total: AtomicU64,
    pub ratchet_send_blocked_resync_total: AtomicU64,
    pub ratchet_gap_too_large_total: AtomicU64,
    pub ratchet_parse_failed_total: AtomicU64,
    pub ratchet_unexpected_v2_total: AtomicU64,
    pub ratchet_unexpected_v1_total: AtomicU64,
    pub ratchet_recipient_mismatch_total: AtomicU64,
    pub ratchet_sender_mismatch_total: AtomicU64,
    pub ratchet_counter_overflow_total: AtomicU64,
    pub ratchet_commit_mismatch_total: AtomicU64,
    pub ecies_fallback_total: AtomicU64,
    pub messages_sent_plaintext_total: AtomicU64,
    pub prekey_bundle_published_total: AtomicU64,
    pub prekey_bundle_stored_total: AtomicU64,
    pub prekey_bundle_fetched_total: AtomicU64,
    pub prekey_bundle_fetch_ok_total: AtomicU64,
    pub prekey_bundle_fetch_failed_total: AtomicU64,
    pub prekey_bundle_verify_failed_total: AtomicU64,
    pub prekey_rotation_total: AtomicU64,
    pub prekey_opk_refill_total: AtomicU64,
    pub prekey_opk_generated_total: AtomicU64,
    pub prekey_rotation_failed_total: AtomicU64,
    pub prekey_publish_from_rotation_total: AtomicU64,
    pub prekey_opk_consumed_total: AtomicU64,
    pub prekey_opk_consume_replay_total: AtomicU64,
    pub prekey_opk_consume_not_found_total: AtomicU64,
    pub x3dh_session_established_total: AtomicU64,
    pub x3dh_session_accepted_total: AtomicU64,
    pub x3dh_session_failed_total: AtomicU64,
    pub x3dh_bundle_fetch_failed_total: AtomicU64,
    pub x3dh_bundle_verify_failed_total: AtomicU64,
    pub capability_negotiation_mutual_v4_total: AtomicU64,
    pub capability_negotiation_v3_legacy_total: AtomicU64,
    pub capability_negotiation_v3_declined_total: AtomicU64,
    pub dh_ratchet_initiations_total: AtomicU64,
    pub dh_ratchet_transitions_initiator_total: AtomicU64,
    pub dh_ratchet_transitions_responder_total: AtomicU64,
    pub dh_ratchet_failures_total: AtomicU64,
    pub dh_ratchet_collisions_case1_total: AtomicU64,
    pub dh_ratchet_collisions_case3_larger_total: AtomicU64,
    pub dh_ratchet_collisions_case3_smaller_total: AtomicU64,
    pub v4_messages_sent_total: AtomicU64,
    pub v4_messages_received_total: AtomicU64,
    pub v4_future_chain_rejected_total: AtomicU64,
    pub v4_no_session_total: AtomicU64,
    pub v4_chain_id_overflow_total: AtomicU64,
    pub v4_duplicate_advertise_total: AtomicU64,
    pub v4_missing_chain_total: AtomicU64,
}

impl AbuseMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> AbuseMetricsSnapshot {
        AbuseMetricsSnapshot {
            incoming_stigma_rejected_total: self
                .incoming_stigma_rejected_total
                .load(Ordering::Relaxed),
            incoming_cold_exceeded_total: self.incoming_cold_exceeded_total.load(Ordering::Relaxed),
            auto_badge_queued_total: self.auto_badge_queued_total.load(Ordering::Relaxed),
            auto_badge_published_total: self.auto_badge_published_total.load(Ordering::Relaxed),
            auto_badge_publish_failed_total: self
                .auto_badge_publish_failed_total
                .load(Ordering::Relaxed),
            auto_badge_skipped_reply_total: self
                .auto_badge_skipped_reply_total
                .load(Ordering::Relaxed),
            auto_badge_skipped_no_storage_total: self
                .auto_badge_skipped_no_storage_total
                .load(Ordering::Relaxed),
            auto_badge_skipped_vouch_total: self
                .auto_badge_skipped_vouch_total
                .load(Ordering::Relaxed),
            auto_badge_skipped_no_evidence_total: self
                .auto_badge_skipped_no_evidence_total
                .load(Ordering::Relaxed),
            quic_identity_verified_total: self.quic_identity_verified_total.load(Ordering::Relaxed),
            quic_identity_rejected_total: self.quic_identity_rejected_total.load(Ordering::Relaxed),
            quic_identity_tofu_total: self.quic_identity_tofu_total.load(Ordering::Relaxed),
            relay_inner_verify_failed_total: self
                .relay_inner_verify_failed_total
                .load(Ordering::Relaxed),
            relay_inner_verify_ok_total: self.relay_inner_verify_ok_total.load(Ordering::Relaxed),
            relay_consent_verified_total: self.relay_consent_verified_total.load(Ordering::Relaxed),
            relay_consent_missing_total: self.relay_consent_missing_total.load(Ordering::Relaxed),
            relay_consent_signature_failed_total: self
                .relay_consent_signature_failed_total
                .load(Ordering::Relaxed),
            relay_consent_target_mismatch_total: self
                .relay_consent_target_mismatch_total
                .load(Ordering::Relaxed),
            relay_consent_expired_total: self.relay_consent_expired_total.load(Ordering::Relaxed),
            relay_consent_replay_total: self.relay_consent_replay_total.load(Ordering::Relaxed),
            relay_consent_content_mismatch_total: self
                .relay_consent_content_mismatch_total
                .load(Ordering::Relaxed),
            envelope_size_exceeded_total: self.envelope_size_exceeded_total.load(Ordering::Relaxed),
            envelope_send_size_exceeded_total: self
                .envelope_send_size_exceeded_total
                .load(Ordering::Relaxed),
            envelope_transport_identity_verified_total: self
                .envelope_transport_identity_verified_total
                .load(Ordering::Relaxed),
            envelope_transport_identity_mismatch_total: self
                .envelope_transport_identity_mismatch_total
                .load(Ordering::Relaxed),
            cold_tracker_evicted_total: self.cold_tracker_evicted_total.load(Ordering::Relaxed),
            inbound_observation_dropped_total: self
                .inbound_observation_dropped_total
                .load(Ordering::Relaxed),
            stigma_refresh_rounds_total: self.stigma_refresh_rounds_total.load(Ordering::Relaxed),
            transport_stigma_rejected_total: self
                .transport_stigma_rejected_total
                .load(Ordering::Relaxed),
            invite_rejected_fanout_total: self.invite_rejected_fanout_total.load(Ordering::Relaxed),
            invite_rejected_chain_depth_total: self
                .invite_rejected_chain_depth_total
                .load(Ordering::Relaxed),
            invite_rejected_cooldown_total: self
                .invite_rejected_cooldown_total
                .load(Ordering::Relaxed),
            degraded_unknown_rejected_total: self
                .degraded_unknown_rejected_total
                .load(Ordering::Relaxed),
            degraded_known_accepted_total: self
                .degraded_known_accepted_total
                .load(Ordering::Relaxed),
            degraded_cleared_total: self.degraded_cleared_total.load(Ordering::Relaxed),
            degraded_entered_total: self.degraded_entered_total.load(Ordering::Relaxed),
            proof_of_live_cold_rejected_total: self
                .proof_of_live_cold_rejected_total
                .load(Ordering::Relaxed),
            proof_of_live_invite_rejected_total: self
                .proof_of_live_invite_rejected_total
                .load(Ordering::Relaxed),
            proof_of_live_dht_rejected_total: self
                .proof_of_live_dht_rejected_total
                .load(Ordering::Relaxed),
            rate_tier_throttled_total: self.rate_tier_throttled_total.load(Ordering::Relaxed),
            rate_tier_warning_total: self.rate_tier_warning_total.load(Ordering::Relaxed),
            rate_tier_blocked_total: self.rate_tier_blocked_total.load(Ordering::Relaxed),
            trust_gate_blocked_total: self.trust_gate_blocked_total.load(Ordering::Relaxed),
            rate_blocked_total: self.rate_blocked_total.load(Ordering::Relaxed),
            rate_limiter_worker_failed_total: self
                .rate_limiter_worker_failed_total
                .load(Ordering::Relaxed),
            rate_throttled_by_warning_total: self
                .rate_throttled_by_warning_total
                .load(Ordering::Relaxed),
            rate_throttled_by_watching_total: self
                .rate_throttled_by_watching_total
                .load(Ordering::Relaxed),
            biometric_verified_total: self.biometric_verified_total.load(Ordering::Relaxed),
            biometric_rejected_total: self.biometric_rejected_total.load(Ordering::Relaxed),
            biometric_unavailable_total: self.biometric_unavailable_total.load(Ordering::Relaxed),
            messages_encrypted_total: self.messages_encrypted_total.load(Ordering::Relaxed),
            messages_decrypted_total: self.messages_decrypted_total.load(Ordering::Relaxed),
            messages_decrypt_failed_total: self
                .messages_decrypt_failed_total
                .load(Ordering::Relaxed),
            replay_precheck_total: self.replay_precheck_total.load(Ordering::Relaxed),
            ratchet_encrypt_total: self.ratchet_encrypt_total.load(Ordering::Relaxed),
            ratchet_encrypt_failed_total: self.ratchet_encrypt_failed_total.load(Ordering::Relaxed),
            ratchet_commit_failed_total: self.ratchet_commit_failed_total.load(Ordering::Relaxed),
            ratchet_decrypt_total: self.ratchet_decrypt_total.load(Ordering::Relaxed),
            ratchet_decrypt_failed_total: self.ratchet_decrypt_failed_total.load(Ordering::Relaxed),
            ratchet_replay_total: self.ratchet_replay_total.load(Ordering::Relaxed),
            ratchet_out_of_order_total: self.ratchet_out_of_order_total.load(Ordering::Relaxed),
            ratchet_out_of_order_accepted_total: self
                .ratchet_out_of_order_accepted_total
                .load(Ordering::Relaxed),
            ratchet_skipped_keys_current: self.ratchet_skipped_keys_current.load(Ordering::Relaxed),
            ratchet_skipped_keys_inserted_total: self
                .ratchet_skipped_keys_inserted_total
                .load(Ordering::Relaxed),
            ratchet_skipped_keys_expired_total: self
                .ratchet_skipped_keys_expired_total
                .load(Ordering::Relaxed),
            ratchet_skipped_keys_evicted_total: self
                .ratchet_skipped_keys_evicted_total
                .load(Ordering::Relaxed),
            ratchet_persist_failed_total: self.ratchet_persist_failed_total.load(Ordering::Relaxed),
            session_persist_failed_total: self.session_persist_failed_total.load(Ordering::Relaxed),
            ratchet_needs_resync_total: self.ratchet_needs_resync_total.load(Ordering::Relaxed),
            ratchet_no_session_total: self.ratchet_no_session_total.load(Ordering::Relaxed),
            ratchet_needs_resync_received_total: self
                .ratchet_needs_resync_received_total
                .load(Ordering::Relaxed),
            ratchet_session_replaced_total: self
                .ratchet_session_replaced_total
                .load(Ordering::Relaxed),
            ratchet_resync_triggered_total: self
                .ratchet_resync_triggered_total
                .load(Ordering::Relaxed),
            ratchet_send_blocked_resync_total: self
                .ratchet_send_blocked_resync_total
                .load(Ordering::Relaxed),
            ratchet_gap_too_large_total: self.ratchet_gap_too_large_total.load(Ordering::Relaxed),
            ratchet_parse_failed_total: self.ratchet_parse_failed_total.load(Ordering::Relaxed),
            ratchet_unexpected_v2_total: self.ratchet_unexpected_v2_total.load(Ordering::Relaxed),
            ratchet_unexpected_v1_total: self.ratchet_unexpected_v1_total.load(Ordering::Relaxed),
            ratchet_recipient_mismatch_total: self
                .ratchet_recipient_mismatch_total
                .load(Ordering::Relaxed),
            ratchet_sender_mismatch_total: self
                .ratchet_sender_mismatch_total
                .load(Ordering::Relaxed),
            ratchet_counter_overflow_total: self
                .ratchet_counter_overflow_total
                .load(Ordering::Relaxed),
            ratchet_commit_mismatch_total: self
                .ratchet_commit_mismatch_total
                .load(Ordering::Relaxed),
            ecies_fallback_total: self.ecies_fallback_total.load(Ordering::Relaxed),
            messages_sent_plaintext_total: self
                .messages_sent_plaintext_total
                .load(Ordering::Relaxed),
            prekey_bundle_published_total: self
                .prekey_bundle_published_total
                .load(Ordering::Relaxed),
            prekey_bundle_stored_total: self.prekey_bundle_stored_total.load(Ordering::Relaxed),
            prekey_bundle_fetched_total: self.prekey_bundle_fetched_total.load(Ordering::Relaxed),
            prekey_bundle_fetch_ok_total: self.prekey_bundle_fetch_ok_total.load(Ordering::Relaxed),
            prekey_bundle_fetch_failed_total: self
                .prekey_bundle_fetch_failed_total
                .load(Ordering::Relaxed),
            prekey_bundle_verify_failed_total: self
                .prekey_bundle_verify_failed_total
                .load(Ordering::Relaxed),
            prekey_rotation_total: self.prekey_rotation_total.load(Ordering::Relaxed),
            prekey_opk_refill_total: self.prekey_opk_refill_total.load(Ordering::Relaxed),
            prekey_opk_generated_total: self.prekey_opk_generated_total.load(Ordering::Relaxed),
            prekey_rotation_failed_total: self.prekey_rotation_failed_total.load(Ordering::Relaxed),
            prekey_publish_from_rotation_total: self
                .prekey_publish_from_rotation_total
                .load(Ordering::Relaxed),
            prekey_opk_consumed_total: self.prekey_opk_consumed_total.load(Ordering::Relaxed),
            prekey_opk_consume_replay_total: self
                .prekey_opk_consume_replay_total
                .load(Ordering::Relaxed),
            prekey_opk_consume_not_found_total: self
                .prekey_opk_consume_not_found_total
                .load(Ordering::Relaxed),
            x3dh_session_established_total: self
                .x3dh_session_established_total
                .load(Ordering::Relaxed),
            x3dh_session_accepted_total: self.x3dh_session_accepted_total.load(Ordering::Relaxed),
            x3dh_session_failed_total: self.x3dh_session_failed_total.load(Ordering::Relaxed),
            x3dh_bundle_fetch_failed_total: self
                .x3dh_bundle_fetch_failed_total
                .load(Ordering::Relaxed),
            x3dh_bundle_verify_failed_total: self
                .x3dh_bundle_verify_failed_total
                .load(Ordering::Relaxed),
            capability_negotiation_mutual_v4_total: self
                .capability_negotiation_mutual_v4_total
                .load(Ordering::Relaxed),
            capability_negotiation_v3_legacy_total: self
                .capability_negotiation_v3_legacy_total
                .load(Ordering::Relaxed),
            capability_negotiation_v3_declined_total: self
                .capability_negotiation_v3_declined_total
                .load(Ordering::Relaxed),
            dh_ratchet_initiations_total: self.dh_ratchet_initiations_total.load(Ordering::Relaxed),
            dh_ratchet_transitions_initiator_total: self
                .dh_ratchet_transitions_initiator_total
                .load(Ordering::Relaxed),
            dh_ratchet_transitions_responder_total: self
                .dh_ratchet_transitions_responder_total
                .load(Ordering::Relaxed),
            dh_ratchet_failures_total: self.dh_ratchet_failures_total.load(Ordering::Relaxed),
            dh_ratchet_collisions_case1_total: self
                .dh_ratchet_collisions_case1_total
                .load(Ordering::Relaxed),
            dh_ratchet_collisions_case3_larger_total: self
                .dh_ratchet_collisions_case3_larger_total
                .load(Ordering::Relaxed),
            dh_ratchet_collisions_case3_smaller_total: self
                .dh_ratchet_collisions_case3_smaller_total
                .load(Ordering::Relaxed),
            v4_messages_sent_total: self.v4_messages_sent_total.load(Ordering::Relaxed),
            v4_messages_received_total: self.v4_messages_received_total.load(Ordering::Relaxed),
            v4_future_chain_rejected_total: self
                .v4_future_chain_rejected_total
                .load(Ordering::Relaxed),
            v4_no_session_total: self.v4_no_session_total.load(Ordering::Relaxed),
            v4_chain_id_overflow_total: self.v4_chain_id_overflow_total.load(Ordering::Relaxed),
            v4_duplicate_advertise_total: self.v4_duplicate_advertise_total.load(Ordering::Relaxed),
            v4_missing_chain_total: self.v4_missing_chain_total.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbuseMetricsSnapshot {
    pub incoming_stigma_rejected_total: u64,
    pub incoming_cold_exceeded_total: u64,
    pub auto_badge_queued_total: u64,
    pub auto_badge_published_total: u64,
    pub auto_badge_publish_failed_total: u64,
    pub auto_badge_skipped_reply_total: u64,
    pub auto_badge_skipped_no_storage_total: u64,
    pub auto_badge_skipped_vouch_total: u64,
    pub auto_badge_skipped_no_evidence_total: u64,
    pub quic_identity_verified_total: u64,
    pub quic_identity_rejected_total: u64,
    pub quic_identity_tofu_total: u64,
    pub relay_inner_verify_failed_total: u64,
    pub relay_inner_verify_ok_total: u64,
    pub relay_consent_verified_total: u64,
    pub relay_consent_missing_total: u64,
    pub relay_consent_signature_failed_total: u64,
    pub relay_consent_target_mismatch_total: u64,
    pub relay_consent_expired_total: u64,
    pub relay_consent_replay_total: u64,
    pub relay_consent_content_mismatch_total: u64,
    pub envelope_size_exceeded_total: u64,
    pub envelope_send_size_exceeded_total: u64,
    pub envelope_transport_identity_verified_total: u64,
    pub envelope_transport_identity_mismatch_total: u64,
    pub cold_tracker_evicted_total: u64,
    pub inbound_observation_dropped_total: u64,
    pub stigma_refresh_rounds_total: u64,
    pub transport_stigma_rejected_total: u64,
    pub invite_rejected_fanout_total: u64,
    pub invite_rejected_chain_depth_total: u64,
    pub invite_rejected_cooldown_total: u64,
    pub degraded_unknown_rejected_total: u64,
    pub degraded_known_accepted_total: u64,
    pub degraded_cleared_total: u64,
    pub degraded_entered_total: u64,
    pub proof_of_live_cold_rejected_total: u64,
    pub proof_of_live_invite_rejected_total: u64,
    pub proof_of_live_dht_rejected_total: u64,
    #[serde(default)]
    pub rate_tier_throttled_total: u64,
    #[serde(default)]
    pub rate_tier_warning_total: u64,
    #[serde(default)]
    pub rate_tier_blocked_total: u64,
    #[serde(default)]
    pub trust_gate_blocked_total: u64,
    #[serde(default)]
    pub rate_blocked_total: u64,
    #[serde(default)]
    pub rate_limiter_worker_failed_total: u64,
    #[serde(default)]
    pub rate_throttled_by_warning_total: u64,
    #[serde(default)]
    pub rate_throttled_by_watching_total: u64,
    #[serde(default)]
    pub biometric_verified_total: u64,
    #[serde(default)]
    pub biometric_rejected_total: u64,
    #[serde(default)]
    pub biometric_unavailable_total: u64,
    #[serde(default)]
    pub messages_encrypted_total: u64,
    #[serde(default)]
    pub messages_decrypted_total: u64,
    #[serde(default)]
    pub messages_decrypt_failed_total: u64,
    #[serde(default)]
    pub replay_precheck_total: u64,
    #[serde(default)]
    pub ratchet_encrypt_total: u64,
    #[serde(default)]
    pub ratchet_encrypt_failed_total: u64,
    pub ratchet_commit_failed_total: u64,
    pub ratchet_decrypt_total: u64,
    #[serde(default)]
    pub ratchet_decrypt_failed_total: u64,
    #[serde(default)]
    pub ratchet_replay_total: u64,
    #[serde(default)]
    pub ratchet_out_of_order_total: u64,
    #[serde(default)]
    pub ratchet_out_of_order_accepted_total: u64,
    #[serde(default)]
    pub ratchet_skipped_keys_current: u64,
    #[serde(default)]
    pub ratchet_skipped_keys_inserted_total: u64,
    #[serde(default)]
    pub ratchet_skipped_keys_expired_total: u64,
    #[serde(default)]
    pub ratchet_skipped_keys_evicted_total: u64,
    #[serde(default)]
    pub ratchet_persist_failed_total: u64,
    #[serde(default)]
    pub session_persist_failed_total: u64,
    #[serde(default)]
    pub ratchet_needs_resync_total: u64,
    #[serde(default)]
    pub ratchet_no_session_total: u64,
    #[serde(default)]
    pub ratchet_needs_resync_received_total: u64,
    #[serde(default)]
    pub ratchet_session_replaced_total: u64,
    #[serde(default)]
    pub ratchet_resync_triggered_total: u64,
    #[serde(default)]
    pub ratchet_send_blocked_resync_total: u64,
    #[serde(default)]
    pub ratchet_gap_too_large_total: u64,
    #[serde(default)]
    pub ratchet_parse_failed_total: u64,
    #[serde(default)]
    pub ratchet_unexpected_v2_total: u64,
    #[serde(default)]
    pub ratchet_unexpected_v1_total: u64,
    #[serde(default)]
    pub ratchet_recipient_mismatch_total: u64,
    #[serde(default)]
    pub ratchet_sender_mismatch_total: u64,
    #[serde(default)]
    pub ratchet_counter_overflow_total: u64,
    #[serde(default)]
    pub ratchet_commit_mismatch_total: u64,
    #[serde(default)]
    pub ecies_fallback_total: u64,
    #[serde(default)]
    pub messages_sent_plaintext_total: u64,
    #[serde(default)]
    pub prekey_bundle_published_total: u64,
    #[serde(default)]
    pub prekey_bundle_stored_total: u64,
    #[serde(default)]
    pub prekey_bundle_fetched_total: u64,
    #[serde(default)]
    pub prekey_bundle_fetch_ok_total: u64,
    #[serde(default)]
    pub prekey_bundle_fetch_failed_total: u64,
    #[serde(default)]
    pub prekey_bundle_verify_failed_total: u64,
    #[serde(default)]
    pub prekey_rotation_total: u64,
    #[serde(default)]
    pub prekey_opk_refill_total: u64,
    #[serde(default)]
    pub prekey_opk_generated_total: u64,
    #[serde(default)]
    pub prekey_rotation_failed_total: u64,
    #[serde(default)]
    pub prekey_publish_from_rotation_total: u64,
    #[serde(default)]
    pub prekey_opk_consumed_total: u64,
    #[serde(default)]
    pub prekey_opk_consume_replay_total: u64,
    #[serde(default)]
    pub prekey_opk_consume_not_found_total: u64,
    #[serde(default)]
    pub x3dh_session_established_total: u64,
    #[serde(default)]
    pub x3dh_session_accepted_total: u64,
    #[serde(default)]
    pub x3dh_session_failed_total: u64,
    #[serde(default)]
    pub x3dh_bundle_fetch_failed_total: u64,
    #[serde(default)]
    pub x3dh_bundle_verify_failed_total: u64,
    #[serde(default)]
    pub capability_negotiation_mutual_v4_total: u64,
    #[serde(default)]
    pub capability_negotiation_v3_legacy_total: u64,
    #[serde(default)]
    pub capability_negotiation_v3_declined_total: u64,
    #[serde(default)]
    pub dh_ratchet_initiations_total: u64,
    #[serde(default)]
    pub dh_ratchet_transitions_initiator_total: u64,
    #[serde(default)]
    pub dh_ratchet_transitions_responder_total: u64,
    #[serde(default)]
    pub dh_ratchet_failures_total: u64,
    #[serde(default)]
    pub dh_ratchet_collisions_case1_total: u64,
    #[serde(default)]
    pub dh_ratchet_collisions_case3_larger_total: u64,
    #[serde(default)]
    pub dh_ratchet_collisions_case3_smaller_total: u64,
    #[serde(default)]
    pub v4_messages_sent_total: u64,
    #[serde(default)]
    pub v4_messages_received_total: u64,
    #[serde(default)]
    pub v4_future_chain_rejected_total: u64,
    #[serde(default)]
    pub v4_no_session_total: u64,
    #[serde(default)]
    pub v4_chain_id_overflow_total: u64,
    #[serde(default)]
    pub v4_duplicate_advertise_total: u64,
    #[serde(default)]
    pub v4_missing_chain_total: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_tier_counters_are_in_snapshot() {
        let metrics = AbuseMetrics::new();
        assert_eq!(metrics.snapshot().rate_tier_throttled_total, 0);
        assert_eq!(metrics.snapshot().rate_tier_warning_total, 0);
        assert_eq!(metrics.snapshot().rate_tier_blocked_total, 0);

        metrics
            .rate_tier_throttled_total
            .store(2, Ordering::Relaxed);
        metrics.rate_tier_warning_total.store(3, Ordering::Relaxed);
        metrics.rate_tier_blocked_total.store(4, Ordering::Relaxed);
        metrics
            .rate_limiter_worker_failed_total
            .store(5, Ordering::Relaxed);
        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.rate_tier_throttled_total, 2);
        assert_eq!(snapshot.rate_tier_warning_total, 3);
        assert_eq!(snapshot.rate_tier_blocked_total, 4);
        assert_eq!(snapshot.rate_limiter_worker_failed_total, 5);
        assert_eq!(snapshot.rate_blocked_total, 0);
        assert_eq!(snapshot.rate_throttled_by_warning_total, 0);
        assert_eq!(snapshot.rate_throttled_by_watching_total, 0);
        assert_eq!(snapshot.messages_encrypted_total, 0);
        assert_eq!(snapshot.messages_decrypted_total, 0);
        assert_eq!(snapshot.messages_decrypt_failed_total, 0);
        assert_eq!(snapshot.ratchet_encrypt_total, 0);
        assert_eq!(snapshot.ratchet_encrypt_failed_total, 0);
        assert_eq!(snapshot.ratchet_commit_failed_total, 0);
        assert_eq!(snapshot.ratchet_decrypt_total, 0);
        assert_eq!(snapshot.ratchet_decrypt_failed_total, 0);
        assert_eq!(snapshot.ecies_fallback_total, 0);
        assert_eq!(snapshot.messages_sent_plaintext_total, 0);
    }

    #[test]
    fn trust_gate_blocked_total_increments_on_block() {
        let metrics = AbuseMetrics::new();
        assert_eq!(metrics.snapshot().trust_gate_blocked_total, 0);

        metrics
            .trust_gate_blocked_total
            .fetch_add(1, Ordering::Relaxed);

        assert_eq!(metrics.snapshot().trust_gate_blocked_total, 1);
    }

    #[test]
    fn ratchet_counters_are_in_snapshot() {
        let metrics = AbuseMetrics::new();
        metrics.ratchet_encrypt_total.store(1, Ordering::Relaxed);
        metrics
            .ratchet_encrypt_failed_total
            .store(5, Ordering::Relaxed);
        metrics
            .ratchet_commit_failed_total
            .store(6, Ordering::Relaxed);
        metrics.ratchet_decrypt_total.store(2, Ordering::Relaxed);
        metrics
            .ratchet_decrypt_failed_total
            .store(3, Ordering::Relaxed);
        metrics
            .ratchet_out_of_order_accepted_total
            .store(7, Ordering::Relaxed);
        metrics
            .ratchet_skipped_keys_current
            .store(8, Ordering::Relaxed);
        metrics
            .ratchet_skipped_keys_inserted_total
            .store(9, Ordering::Relaxed);
        metrics
            .ratchet_skipped_keys_expired_total
            .store(10, Ordering::Relaxed);
        metrics
            .ratchet_skipped_keys_evicted_total
            .store(11, Ordering::Relaxed);
        metrics.ecies_fallback_total.store(4, Ordering::Relaxed);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.ratchet_encrypt_total, 1);
        assert_eq!(snapshot.ratchet_encrypt_failed_total, 5);
        assert_eq!(snapshot.ratchet_commit_failed_total, 6);
        assert_eq!(snapshot.ratchet_decrypt_total, 2);
        assert_eq!(snapshot.ratchet_decrypt_failed_total, 3);
        assert_eq!(snapshot.ratchet_out_of_order_accepted_total, 7);
        assert_eq!(snapshot.ratchet_skipped_keys_current, 8);
        assert_eq!(snapshot.ratchet_skipped_keys_inserted_total, 9);
        assert_eq!(snapshot.ratchet_skipped_keys_expired_total, 10);
        assert_eq!(snapshot.ratchet_skipped_keys_evicted_total, 11);
        assert_eq!(snapshot.ecies_fallback_total, 4);
    }

    #[test]
    fn prekey_rotation_counters_are_in_snapshot() {
        let metrics = AbuseMetrics::new();
        metrics.prekey_rotation_total.store(2, Ordering::Relaxed);
        metrics.prekey_opk_refill_total.store(3, Ordering::Relaxed);
        metrics
            .prekey_opk_generated_total
            .store(180, Ordering::Relaxed);
        metrics
            .prekey_rotation_failed_total
            .store(4, Ordering::Relaxed);
        metrics
            .prekey_publish_from_rotation_total
            .store(5, Ordering::Relaxed);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.prekey_rotation_total, 2);
        assert_eq!(snapshot.prekey_opk_refill_total, 3);
        assert_eq!(snapshot.prekey_opk_generated_total, 180);
        assert_eq!(snapshot.prekey_rotation_failed_total, 4);
        assert_eq!(snapshot.prekey_publish_from_rotation_total, 5);
    }

    #[test]
    fn prekey_consumption_counters_are_in_snapshot() {
        let metrics = AbuseMetrics::new();
        metrics
            .prekey_opk_consumed_total
            .store(6, Ordering::Relaxed);
        metrics
            .prekey_opk_consume_replay_total
            .store(7, Ordering::Relaxed);
        metrics
            .prekey_opk_consume_not_found_total
            .store(8, Ordering::Relaxed);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.prekey_opk_consumed_total, 6);
        assert_eq!(snapshot.prekey_opk_consume_replay_total, 7);
        assert_eq!(snapshot.prekey_opk_consume_not_found_total, 8);
    }

    #[test]
    fn x3dh_session_counters_are_in_snapshot() {
        let metrics = AbuseMetrics::new();
        metrics
            .x3dh_session_established_total
            .store(1, Ordering::Relaxed);
        metrics
            .x3dh_session_accepted_total
            .store(2, Ordering::Relaxed);
        metrics
            .x3dh_session_failed_total
            .store(3, Ordering::Relaxed);
        metrics
            .x3dh_bundle_fetch_failed_total
            .store(4, Ordering::Relaxed);
        metrics
            .x3dh_bundle_verify_failed_total
            .store(5, Ordering::Relaxed);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.x3dh_session_established_total, 1);
        assert_eq!(snapshot.x3dh_session_accepted_total, 2);
        assert_eq!(snapshot.x3dh_session_failed_total, 3);
        assert_eq!(snapshot.x3dh_bundle_fetch_failed_total, 4);
        assert_eq!(snapshot.x3dh_bundle_verify_failed_total, 5);
    }
}
