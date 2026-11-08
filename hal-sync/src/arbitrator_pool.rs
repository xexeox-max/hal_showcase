//! Arbitrator pool — selection of trusted arbitrators for a jury.
//!
//! The pool is built automatically from network state; no one appoints
//! candidates directly.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

use crate::dht::NodeId;
use crate::runtime_context::RuntimeContext;

pub const MIN_POL_FULL_AGE_SECS: u64 = 6 * 30 * 24 * 3600;
pub const MIN_ARBITRATOR_SCORE: u8 = 60;
pub const MIN_GOVERNANCE_VOTES_90D: u32 = 5;
pub const GOVERNANCE_WINDOW_SECS: u64 = 90 * 24 * 3600;

pub trait JuryVerdictProvider: Send + Sync {
    fn has_active_guilty(&self, node_id: &NodeId, now: u64) -> bool;
}

pub struct NoVerdictsProvider;

impl JuryVerdictProvider for NoVerdictsProvider {
    fn has_active_guilty(&self, _: &NodeId, _: u64) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArbitratorCriteria {
    pub pol_full_ok: bool,
    pub score_ok: bool,
    pub no_active_guilty: bool,
    pub governance_ok: bool,
    pub phone_verified: bool,
}

impl ArbitratorCriteria {
    pub fn meets_required(&self) -> bool {
        self.pol_full_ok && self.score_ok && self.no_active_guilty
    }

    pub fn meets_all(&self, governance_gate_active: bool) -> bool {
        self.meets_required() && (!governance_gate_active || self.governance_ok)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionWeight {
    VerifiedWeight(u8),
    NonVerifiedWeight,
}

impl SelectionWeight {
    pub fn from_criteria(criteria: &ArbitratorCriteria) -> Self {
        if criteria.phone_verified {
            Self::VerifiedWeight(3)
        } else {
            Self::NonVerifiedWeight
        }
    }

    pub fn weight(&self) -> u32 {
        match self {
            Self::VerifiedWeight(weight) => *weight as u32,
            Self::NonVerifiedWeight => 1,
        }
    }
}

/// Selection seed v2.
/// Uses submitted_at and roster_generation as stable per-attempt inputs.
/// Schema: docs/EVIDENCE_AND_JURY.md §4.4.
pub fn selection_seed(
    complaint_id: &[u8; 32],
    submitted_at: u64,
    roster_generation: u32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"HAL-JURY-SELECTION-v2\0");
    hasher.update(complaint_id);
    hasher.update(submitted_at.to_be_bytes());
    hasher.update(roster_generation.to_be_bytes());
    hasher.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub node_id: NodeId,
    pub weight: u32,
    pub criteria: ArbitratorCriteria,
    pub tie_breaker: [u8; 32],
}

impl Candidate {
    pub fn new(node_id: NodeId, criteria: ArbitratorCriteria, seed: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(node_id.as_bytes());
        let tie_breaker: [u8; 32] = hasher.finalize().into();
        let weight = SelectionWeight::from_criteria(&criteria).weight();
        Self {
            node_id,
            weight,
            criteria,
            tie_breaker,
        }
    }
}

pub fn sort_candidates(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    candidates.sort_by(|a, b| {
        b.weight
            .cmp(&a.weight)
            .then_with(|| a.tie_breaker.cmp(&b.tie_breaker))
    });
    candidates
}

pub async fn evaluate_criteria(
    ctx: &RuntimeContext,
    verdicts: &dyn JuryVerdictProvider,
    node_id: &NodeId,
    now: u64,
    phone_verified: bool,
) -> ArbitratorCriteria {
    let pol_full_status = match ctx.proof_of_live.as_ref() {
        Some(pol) => pol.status(node_id, now).await.is_full(),
        None => false,
    };
    let old_enough = match ctx.age_tracker.as_ref() {
        Some(age_tracker) => {
            let tracker = age_tracker.lock().await;
            matches!(
                tracker.first_seen(node_id),
                Ok(Some(first_seen)) if now.saturating_sub(first_seen) >= MIN_POL_FULL_AGE_SECS
            )
        }
        None => false,
    };
    let pol_full_ok = pol_full_status && old_enough;

    let score_ok = match ctx.scores.lock() {
        Ok(scores) => scores.score_of(node_id) >= MIN_ARBITRATOR_SCORE,
        Err(_) => false,
    };
    let no_active_guilty = !verdicts.has_active_guilty(node_id, now);

    ArbitratorCriteria {
        pol_full_ok,
        score_ok,
        no_active_guilty,
        governance_ok: true,
        phone_verified,
    }
}

pub async fn build_candidate_list(
    ctx: &RuntimeContext,
    verdicts: &dyn JuryVerdictProvider,
    complaint_id: &[u8; 32],
    submitted_at: u64,
    roster_generation: u32,
    now: u64,
    governance_gate_active: bool,
    phone_verified_set: &HashSet<NodeId>,
) -> Vec<Candidate> {
    let seed = selection_seed(complaint_id, submitted_at, roster_generation);
    let known_hosts = match ctx.hosts.lock() {
        Ok(hosts) => hosts.all_identity_ids(),
        Err(_) => return Vec::new(),
    };
    let mut candidates = Vec::new();
    for identity_id in known_hosts {
        let Ok(node_id) = NodeId::from_hex(&identity_id) else {
            continue;
        };
        let phone_verified = phone_verified_set.contains(&node_id);
        let criteria = evaluate_criteria(ctx, verdicts, &node_id, now, phone_verified).await;
        if criteria.meets_all(governance_gate_active) {
            candidates.push(Candidate::new(node_id, criteria, &seed));
        }
    }
    sort_candidates(candidates)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        selection_seed, sort_candidates, ArbitratorCriteria, Candidate, JuryVerdictProvider,
        NoVerdictsProvider, SelectionWeight,
    };
    use crate::dht::NodeId;

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    fn criteria(
        pol_full_ok: bool,
        score_ok: bool,
        no_active_guilty: bool,
        governance_ok: bool,
        phone_verified: bool,
    ) -> ArbitratorCriteria {
        ArbitratorCriteria {
            pol_full_ok,
            score_ok,
            no_active_guilty,
            governance_ok,
            phone_verified,
        }
    }

    struct StubVerdicts {
        guilty: HashSet<NodeId>,
    }

    impl JuryVerdictProvider for StubVerdicts {
        fn has_active_guilty(&self, node_id: &NodeId, _: u64) -> bool {
            self.guilty.contains(node_id)
        }
    }

    #[test]
    fn criteria_meets_required_all_true() {
        assert!(criteria(true, true, true, true, false).meets_required());
    }

    #[test]
    fn criteria_meets_required_fails_on_pol() {
        assert!(!criteria(false, true, true, true, false).meets_required());
    }

    #[test]
    fn criteria_meets_required_fails_on_score() {
        assert!(!criteria(true, false, true, true, false).meets_required());
    }

    #[test]
    fn criteria_meets_required_fails_on_guilty() {
        assert!(!criteria(true, true, false, true, false).meets_required());
    }

    #[test]
    fn criteria_governance_gate_off_ignores_governance() {
        assert!(criteria(true, true, true, false, false).meets_all(false));
    }

    #[test]
    fn criteria_governance_gate_on_requires_governance() {
        assert!(!criteria(true, true, true, false, false).meets_all(true));
        assert!(criteria(true, true, true, true, false).meets_all(true));
    }

    #[test]
    fn selection_seed_differs_by_complaint_id() {
        assert_ne!(
            selection_seed(&[7; 32], 1_700_000_000, 0),
            selection_seed(&[8; 32], 1_700_000_000, 0)
        );
    }

    #[test]
    fn selection_seed_v2_deterministic() {
        let seed_a = selection_seed(&[1; 32], 1_700_000_000, 0);
        let seed_b = selection_seed(&[1; 32], 1_700_000_000, 0);
        assert_eq!(seed_a, seed_b);
    }

    #[test]
    fn selection_seed_v2_differs_by_generation() {
        let seed_0 = selection_seed(&[1; 32], 1_700_000_000, 0);
        let seed_1 = selection_seed(&[1; 32], 1_700_000_000, 1);
        assert_ne!(seed_0, seed_1);
    }

    #[test]
    fn selection_seed_v2_differs_by_submitted_at() {
        let seed_a = selection_seed(&[1; 32], 1_700_000_000, 0);
        let seed_b = selection_seed(&[1; 32], 1_700_000_001, 0);
        assert_ne!(seed_a, seed_b);
    }

    #[test]
    fn candidate_weight_verified_is_3() {
        let c = criteria(true, true, true, true, true);
        assert_eq!(SelectionWeight::from_criteria(&c).weight(), 3);
    }

    #[test]
    fn candidate_weight_non_verified_is_1() {
        let c = criteria(true, true, true, true, false);
        assert_eq!(SelectionWeight::from_criteria(&c).weight(), 1);
    }

    #[test]
    fn sort_candidates_weight_desc_then_tie_asc() {
        let low_tie = Candidate {
            node_id: node(1),
            weight: 3,
            criteria: criteria(true, true, true, true, true),
            tie_breaker: [1; 32],
        };
        let high_tie = Candidate {
            node_id: node(2),
            weight: 3,
            criteria: criteria(true, true, true, true, true),
            tie_breaker: [2; 32],
        };
        let lower_weight = Candidate {
            node_id: node(3),
            weight: 1,
            criteria: criteria(true, true, true, true, false),
            tie_breaker: [0; 32],
        };

        let sorted = sort_candidates(vec![high_tie, lower_weight, low_tie]);
        assert_eq!(sorted[0].tie_breaker, [1; 32]);
        assert_eq!(sorted[1].tie_breaker, [2; 32]);
        assert_eq!(sorted[2].weight, 1);
    }

    #[test]
    fn candidate_new_stable_tie_breaker() {
        let c = criteria(true, true, true, true, false);
        let first = Candidate::new(node(1), c, &[9; 32]);
        let second = Candidate::new(node(1), c, &[9; 32]);
        assert_eq!(first.tie_breaker, second.tie_breaker);
    }

    #[test]
    fn no_verdicts_provider_never_guilty() {
        assert!(!NoVerdictsProvider.has_active_guilty(&node(1), 100));
    }

    #[test]
    fn stub_verdicts_detects_guilty() {
        let guilty_node = node(1);
        let provider = StubVerdicts {
            guilty: HashSet::from([guilty_node]),
        };
        assert!(provider.has_active_guilty(&guilty_node, 100));
        assert!(!provider.has_active_guilty(&node(2), 100));
    }
}
