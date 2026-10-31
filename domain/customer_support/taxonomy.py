from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from core.memory.authority import AuthorityTier, MemoryClass


@dataclass
class DomainMemoryItem:
    memory_id: str
    memory_class: MemoryClass
    authority_tier: AuthorityTier
    title: str
    content: str
    criticality_score: float  # 0.0 - 1.0
    dependencies: List[str] = field(default_factory=list)


CUSTOMER_SUPPORT_KNOWLEDGE_BASE: List[DomainMemoryItem] = [
    # --- Tier 1: Policies (Critical) ---
    DomainMemoryItem(
        memory_id="POLICY-REFUND-001",
        memory_class=MemoryClass.POLICY,
        authority_tier=AuthorityTier.TIER_1_CRITICAL,
        title="Enterprise Customer Refund Policy",
        content="Standard refund window is 30 calendar days from delivery with original receipt. Items must be undamaged.",
        criticality_score=1.0,
        dependencies=["FAQ-REFUND-001", "TEMPLATE-REFUND-RESPONSE", "SOP-REFUND-PROCESSING"],
    ),
    DomainMemoryItem(
        memory_id="POLICY-WARRANTY-001",
        memory_class=MemoryClass.POLICY,
        authority_tier=AuthorityTier.TIER_1_CRITICAL,
        title="Hardware Limited Warranty",
        content="Standard limited hardware warranty covers manufacturer defects for 12 months from purchase date.",
        criticality_score=0.9,
        dependencies=["FAQ-WARRANTY-001", "TEMPLATE-WARRANTY-RESPONSE"],
    ),
    DomainMemoryItem(
        memory_id="POLICY-SHIPPING-SLA",
        memory_class=MemoryClass.POLICY,
        authority_tier=AuthorityTier.TIER_1_CRITICAL,
        title="Enterprise Shipping SLA",
        content="Standard ground shipping delivery SLA is 3 to 5 business days. Expedited delivery SLA is 1 to 2 business days.",
        criticality_score=0.85,
        dependencies=["FAQ-SHIPPING-001", "TEMPLATE-SHIPPING-RESPONSE"],
    ),
    DomainMemoryItem(
        memory_id="POLICY-RETURN-COND",
        memory_class=MemoryClass.POLICY,
        authority_tier=AuthorityTier.TIER_1_CRITICAL,
        title="Return Condition Standards",
        content="Returned products must be in original packaging with serial number intact and factory seals verified.",
        criticality_score=0.9,
        dependencies=["TEMPLATE-RETURN-INSPECTION"],
    ),

    # --- Tier 1: Pricing & Promotions (Critical) ---
    DomainMemoryItem(
        memory_id="PRICING-TIER-ANNUAL",
        memory_class=MemoryClass.PRICING_PROMOTIONS,
        authority_tier=AuthorityTier.TIER_1_CRITICAL,
        title="Annual Enterprise Discount Rule",
        content="Enterprise volume discount is 15% off standard seat pricing for annual upfront billing on 50 or more seats.",
        criticality_score=0.95,
        dependencies=["TEMPLATE-PRICE-QUOTE", "CALC-SEAT-DISCOUNT"],
    ),
    DomainMemoryItem(
        memory_id="PRICING-PROMO-WELCOME",
        memory_class=MemoryClass.PRICING_PROMOTIONS,
        authority_tier=AuthorityTier.TIER_1_CRITICAL,
        title="Welcome New Customer Promotion",
        content="Promotional code WELCOME20 grants 20% discount on first monthly invoice for newly registered accounts.",
        criticality_score=0.85,
        dependencies=["TEMPLATE-PROMO-QUOTE"],
    ),

    # --- Tier 1: Escalation & Security (Critical) ---
    DomainMemoryItem(
        memory_id="ESCALATION-AUTH-MFA",
        memory_class=MemoryClass.ESCALATION_PROCEDURES,
        authority_tier=AuthorityTier.TIER_1_CRITICAL,
        title="Identity Verification & Re-authentication Rule",
        content="Mandatory identity verification via registered SMS or email MFA code is required before password or PIN change.",
        criticality_score=1.0,
        dependencies=["SOP-PASSWORD-RESET", "TEMPLATE-MFA-CHALLENGE"],
    ),
    DomainMemoryItem(
        memory_id="ESCALATION-FRAUD-TIER3",
        memory_class=MemoryClass.ESCALATION_PROCEDURES,
        authority_tier=AuthorityTier.TIER_1_CRITICAL,
        title="High-Value Transaction Fraud Escalation",
        content="Transactions or refund requests exceeding $10,000 must be escalated immediately to Tier 3 fraud investigation.",
        criticality_score=0.95,
        dependencies=["SOP-FRAUD-ROUTING"],
    ),

    # --- Tier 2: FAQs & Product Knowledge (High) ---
    DomainMemoryItem(
        memory_id="FAQ-REFUND-001",
        memory_class=MemoryClass.PRODUCT_FAQ,
        authority_tier=AuthorityTier.TIER_2_HIGH,
        title="FAQ: How to request a refund",
        content="Submit refund requests through the billing portal with invoice number and proof of purchase within 30 days.",
        criticality_score=0.7,
        dependencies=["TEMPLATE-REFUND-RESPONSE"],
    ),
    DomainMemoryItem(
        memory_id="FAQ-WARRANTY-001",
        memory_class=MemoryClass.PRODUCT_FAQ,
        authority_tier=AuthorityTier.TIER_2_HIGH,
        title="FAQ: Warranty coverage scope",
        content="Warranty covers hardware failure under normal use for 12 months; excludes accidental physical damage and water immersion.",
        criticality_score=0.65,
        dependencies=["TEMPLATE-WARRANTY-RESPONSE"],
    ),
    DomainMemoryItem(
        memory_id="FAQ-SHIPPING-001",
        memory_class=MemoryClass.PRODUCT_FAQ,
        authority_tier=AuthorityTier.TIER_2_HIGH,
        title="FAQ: Tracking and transit times",
        content="Ground transit takes 3 to 5 business days. Tracking number is emailed within 24 hours of dispatch.",
        criticality_score=0.6,
        dependencies=[],
    ),
    DomainMemoryItem(
        memory_id="FAQ-SSO-SETUP",
        memory_class=MemoryClass.PRODUCT_FAQ,
        authority_tier=AuthorityTier.TIER_2_HIGH,
        title="FAQ: Single Sign-On (SSO) configuration",
        content="Enterprise SSO integration requires SAML 2.0 metadata XML from customer Okta, Azure AD, or Google Workspace.",
        criticality_score=0.7,
        dependencies=["TEMPLATE-SSO-GUIDE"],
    ),
    DomainMemoryItem(
        memory_id="FAQ-COMPATIBILITY-001",
        memory_class=MemoryClass.PRODUCT_FAQ,
        authority_tier=AuthorityTier.TIER_2_HIGH,
        title="FAQ: Client OS Compatibility",
        content="Supported client platforms: Windows 11 64-bit, macOS 14 Sonoma or higher, and Ubuntu 22.04 LTS.",
        criticality_score=0.6,
        dependencies=[],
    ),
]


def get_domain_dependency_graph() -> Dict[str, List[str]]:
    """
    Returns the customer support dependency graph: parent_memory_id -> [downstream_dependent_ids]
    """
    graph: Dict[str, List[str]] = {}
    for item in CUSTOMER_SUPPORT_KNOWLEDGE_BASE:
        graph[item.memory_id] = list(item.dependencies)
    return graph


def compute_impact_weight(item: DomainMemoryItem) -> float:
    """
    Calculates TCRP impact weight based on domain criticality and downstream graph blast radius:
    Impact = Criticality * (1 + 0.5 * Number of Dependents)
    """
    num_dependents = len(item.dependencies)
    return round(item.criticality_score * (1.0 + 0.5 * num_dependents), 3)
