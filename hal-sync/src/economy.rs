use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Stable identifier for a future settlement operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SettlementId(pub String);

impl SettlementId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

/// A payment or entitlement request. It carries no blockchain assumptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementIntent {
    pub id: SettlementId,
    pub payer: String,
    pub payee: String,
    pub asset: String,
    pub amount: u64,
    pub purpose: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementStatus {
    Pending,
    Accepted,
    Completed,
    Rejected,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub settlement_id: SettlementId,
    pub status: SettlementStatus,
    pub provider: String,
    pub reference: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaidResourceKind {
    CreatorSupport,
    PremiumChannel,
    PublisherTools,
    UpdateDistribution,
    RelayService,
    StorageService,
    EnterpriseSupport,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceOffer {
    pub offer_id: String,
    pub kind: PaidResourceKind,
    pub owner: String,
    pub title: String,
    pub description: String,
    pub asset: String,
    pub amount: u64,
    pub duration_seconds: Option<u64>,
    pub active: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceCatalog {
    pub offers: Vec<ResourceOffer>,
}

impl ResourceCatalog {
    pub fn publish(&mut self, offer: ResourceOffer) -> Result<()> {
        if offer.offer_id.trim().is_empty() || offer.owner.trim().is_empty() || offer.amount == 0 {
            return Err(anyhow!("invalid resource offer"));
        }
        self.offers
            .retain(|existing| existing.offer_id != offer.offer_id);
        self.offers.push(offer);
        Ok(())
    }

    pub fn get(&self, offer_id: &str) -> Option<&ResourceOffer> {
        self.offers
            .iter()
            .find(|offer| offer.offer_id == offer_id && offer.active)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutRequest {
    pub checkout_id: SettlementId,
    pub offer_id: String,
    pub payer: String,
    pub return_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutSession {
    pub checkout_id: SettlementId,
    pub provider: String,
    pub payment_url: Option<String>,
    pub status: SettlementStatus,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    pub entitlement_id: String,
    pub offer_id: String,
    pub subject: String,
    pub issuer: String,
    pub granted_at: u64,
    pub expires_at: Option<u64>,
    pub settlement_id: SettlementId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutRequest {
    pub payout_id: SettlementId,
    pub beneficiary: String,
    pub asset: String,
    pub amount: u64,
    pub settlement_ids: Vec<SettlementId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutReceipt {
    pub payout_id: SettlementId,
    pub provider: String,
    pub status: SettlementStatus,
    pub external_reference: Option<String>,
    pub timestamp: u64,
}

/// Gateway for charging users. The core only handles intent and entitlement state.
pub trait PaymentGateway: Send + Sync {
    fn provider_id(&self) -> &str;
    fn create_checkout(
        &self,
        request: &CheckoutRequest,
        offer: &ResourceOffer,
    ) -> Result<CheckoutSession>;
    fn verify_checkout(&self, checkout_id: &SettlementId) -> Result<SettlementReceipt>;
}

/// Separate payout rail: receiving money and withdrawing money need not use the same provider.
pub trait PayoutGateway: Send + Sync {
    fn provider_id(&self) -> &str;
    fn request_payout(&self, request: &PayoutRequest) -> Result<PayoutReceipt>;
    fn payout_status(&self, payout_id: &SettlementId) -> Result<PayoutReceipt>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailablePaymentGateway;

impl PaymentGateway for UnavailablePaymentGateway {
    fn provider_id(&self) -> &str {
        "unavailable"
    }

    fn create_checkout(
        &self,
        _request: &CheckoutRequest,
        _offer: &ResourceOffer,
    ) -> Result<CheckoutSession> {
        Err(anyhow!("no payment gateway configured"))
    }

    fn verify_checkout(&self, _checkout_id: &SettlementId) -> Result<SettlementReceipt> {
        Err(anyhow!("no payment gateway configured"))
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailablePayoutGateway;

impl PayoutGateway for UnavailablePayoutGateway {
    fn provider_id(&self) -> &str {
        "unavailable"
    }

    fn request_payout(&self, _request: &PayoutRequest) -> Result<PayoutReceipt> {
        Err(anyhow!("no payout gateway configured"))
    }

    fn payout_status(&self, _payout_id: &SettlementId) -> Result<PayoutReceipt> {
        Err(anyhow!("no payout gateway configured"))
    }
}

/// Optional monetization adapter. Core messaging never requires it.
pub trait SettlementAdapter: Send + Sync {
    fn provider_id(&self) -> &str;
    fn submit(&self, intent: &SettlementIntent) -> Result<SettlementReceipt>;
    fn status(&self, settlement_id: &SettlementId) -> Result<SettlementReceipt>;
    fn cancel(&self, settlement_id: &SettlementId) -> Result<SettlementReceipt>;
}

/// Explicit default: monetization is unavailable until a provider is installed.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableSettlement;

impl SettlementAdapter for UnavailableSettlement {
    fn provider_id(&self) -> &str {
        "unavailable"
    }

    fn submit(&self, _intent: &SettlementIntent) -> Result<SettlementReceipt> {
        Err(anyhow!("no settlement provider configured"))
    }

    fn status(&self, _settlement_id: &SettlementId) -> Result<SettlementReceipt> {
        Err(anyhow!("no settlement provider configured"))
    }

    fn cancel(&self, _settlement_id: &SettlementId) -> Result<SettlementReceipt> {
        Err(anyhow!("no settlement provider configured"))
    }
}

/// Reference to an immutable anchor created by an optional ledger adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorReceipt {
    pub batch_id: String,
    pub root_hash: String,
    pub provider: String,
    pub external_reference: Option<String>,
    pub timestamp: u64,
}

/// Optional adapter for anchoring signed event batches. It is not used for chat.
pub trait LedgerAnchor: Send + Sync {
    fn provider_id(&self) -> &str;
    fn anchor_batch(&self, batch_id: &str, root_hash: &str) -> Result<AnchorReceipt>;
    fn verify_anchor(&self, receipt: &AnchorReceipt) -> Result<bool>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableLedger;

impl LedgerAnchor for UnavailableLedger {
    fn provider_id(&self) -> &str {
        "unavailable"
    }

    fn anchor_batch(&self, _batch_id: &str, _root_hash: &str) -> Result<AnchorReceipt> {
        Err(anyhow!("no ledger anchor configured"))
    }

    fn verify_anchor(&self, _receipt: &AnchorReceipt) -> Result<bool> {
        Err(anyhow!("no ledger anchor configured"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_does_not_require_a_monetization_provider() {
        let provider = UnavailableSettlement;
        let result = provider.submit(&SettlementIntent {
            id: SettlementId::new(),
            payer: "payer".into(),
            payee: "payee".into(),
            asset: "credits".into(),
            amount: 1,
            purpose: "creator-support".into(),
            created_at: 1,
            expires_at: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn anchoring_is_optional_and_separate_from_messages() {
        let ledger = UnavailableLedger;
        assert!(ledger.anchor_batch("batch-1", "root-hash").is_err());
    }

    #[test]
    fn resource_catalog_is_extensible_without_payment_provider() {
        let mut catalog = ResourceCatalog::default();
        catalog
            .publish(ResourceOffer {
                offer_id: "creator-support-1".into(),
                kind: PaidResourceKind::CreatorSupport,
                owner: "creator".into(),
                title: "Support creator".into(),
                description: "Optional support".into(),
                asset: "credits".into(),
                amount: 10,
                duration_seconds: None,
                active: true,
            })
            .expect("offer");

        assert!(catalog.get("creator-support-1").is_some());
        assert!(UnavailablePaymentGateway
            .create_checkout(
                &CheckoutRequest {
                    checkout_id: SettlementId::new(),
                    offer_id: "creator-support-1".into(),
                    payer: "supporter".into(),
                    return_hint: None
                },
                catalog.get("creator-support-1").unwrap(),
            )
            .is_err());
    }

    #[test]
    fn payout_is_a_separate_optional_rail() {
        let gateway = UnavailablePayoutGateway;
        assert!(gateway
            .request_payout(&PayoutRequest {
                payout_id: SettlementId::new(),
                beneficiary: "creator".into(),
                asset: "credits".into(),
                amount: 10,
                settlement_ids: vec![],
            })
            .is_err());
    }
}
