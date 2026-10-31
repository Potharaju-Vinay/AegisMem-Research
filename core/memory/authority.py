from enum import Enum
from typing import Any, Dict, Optional


class AuthorityTier(str, Enum):
    TIER_1_CRITICAL = "tier_1_critical"       # Policy, Pricing, Promotions, Escalation (Signed staff only)
    TIER_2_HIGH = "tier_2_high"               # Product FAQs, Setup Guides (Signed editors)
    TIER_3_MEDIUM = "tier_3_medium"           # Customer Profile, Ticket History (System with provenance)
    TIER_4_LOW = "tier_4_low"                 # Conversation-derived notes (Lowest authority)


class MemoryClass(str, Enum):
    POLICY = "policy"
    PRICING_PROMOTIONS = "pricing_promotions"
    ESCALATION_PROCEDURES = "escalation_procedures"
    PRODUCT_FAQ = "product_faq"
    CUSTOMER_PROFILE = "customer_profile"
    CONVERSATION_NOTE = "conversation_note"


# Mapping from MemoryClass to AuthorityTier and verification requirements
MEMORY_CLASS_POLICY: Dict[MemoryClass, Dict[str, Any]] = {
    MemoryClass.POLICY: {
        "tier": AuthorityTier.TIER_1_CRITICAL,
        "requires_owner_signature": True,
        "verify_on_read": True,
        "allow_conversation_override": False,
        "description": "Company policies (refunds, warranty, legal terms)",
    },
    MemoryClass.PRICING_PROMOTIONS: {
        "tier": AuthorityTier.TIER_1_CRITICAL,
        "requires_owner_signature": True,
        "verify_on_read": True,
        "allow_conversation_override": False,
        "description": "Pricing, promotions, discounts, SLA guarantees",
    },
    MemoryClass.ESCALATION_PROCEDURES: {
        "tier": AuthorityTier.TIER_1_CRITICAL,
        "requires_owner_signature": True,
        "verify_on_read": True,
        "allow_conversation_override": False,
        "description": "Account verification and security escalation procedures",
    },
    MemoryClass.PRODUCT_FAQ: {
        "tier": AuthorityTier.TIER_2_HIGH,
        "requires_owner_signature": False,
        "requires_editor_signature": True,
        "verify_on_read": True,
        "allow_conversation_override": False,
        "description": "Product documentation, compatibility, and FAQs",
    },
    MemoryClass.CUSTOMER_PROFILE: {
        "tier": AuthorityTier.TIER_3_MEDIUM,
        "requires_owner_signature": False,
        "requires_provenance": True,
        "verify_on_read": False,
        "allow_conversation_override": False,
        "description": "Customer account details and verified order history",
    },
    MemoryClass.CONVERSATION_NOTE: {
        "tier": AuthorityTier.TIER_4_LOW,
        "requires_owner_signature": False,
        "verify_on_read": False,
        "allow_conversation_override": False,  # Strict: conversation claims can NEVER override higher tiers
        "description": "Unauthenticated conversational notes and customer claims",
    },
}


def classify_memory(memory_id: str, metadata: Optional[Dict[str, Any]] = None) -> MemoryClass:
    """
    Determines the MemoryClass for a given memory_id and metadata.
    """
    if metadata and "memory_class" in metadata:
        val = metadata["memory_class"].lower()
        for mc in MemoryClass:
            if mc.value == val:
                return mc

    mid = memory_id.upper()
    if "NOTE" in mid or "CHAT" in mid or "CONV" in mid or "CLAIM" in mid:
        return MemoryClass.CONVERSATION_NOTE
    if "POLICY" in mid or "RETURN" in mid or "REFUND" in mid or "WARRANTY" in mid or "SLA" in mid:
        return MemoryClass.POLICY
    if "PRICING" in mid or "PROMO" in mid or "DISCOUNT" in mid:
        return MemoryClass.PRICING_PROMOTIONS
    if "ESCALAT" in mid or "AUTH" in mid or "IDENTITY" in mid:
        return MemoryClass.ESCALATION_PROCEDURES
    if "FAQ" in mid or "PRODUCT" in mid or "GUIDE" in mid or "MANUAL" in mid:
        return MemoryClass.PRODUCT_FAQ
    if "CUSTOMER" in mid or "USER" in mid or "PROFILE" in mid or "ACCOUNT" in mid:
        return MemoryClass.CUSTOMER_PROFILE

    # Default to policy for enterprise memories
    return MemoryClass.POLICY


def is_conversation_override_permitted(target_class: MemoryClass, source_class: MemoryClass) -> bool:
    """
    Central design rule (Part B1): An attacker chatting with the bot must never
    be able to write something the agent treats as company policy.
    Conversation-derived notes can NEVER override or merge into signed classes.
    """
    if source_class == MemoryClass.CONVERSATION_NOTE:
        return False
    return True
