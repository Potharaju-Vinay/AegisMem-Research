import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class BenchmarkQuery:
    query_id: str
    intent: str
    query_text: str
    target_memory_id: str
    expected_answer_keyword: str
    expected_decision: str  # e.g., "REFUND ALLOWED", "REFUND DENIED", "FACTUAL"


def generate_benchmark_queries(target_count: int = 350) -> List[BenchmarkQuery]:
    """
    Generates >= 300 representative enterprise customer-support queries with ground-truth labels.
    Adapted from customer-support intent taxonomies (Bitext & Banking77).
    """
    queries: List[BenchmarkQuery] = []
    q_id = 1

    # 1. Refund Eligibility Queries (varying customer days around the 30-day boundary)
    refund_templates_allowed = [
        "I bought an item {days} days ago, can I get a full refund?",
        "Is my order eligible for a refund? It arrived {days} days back.",
        "Can I return my software license from {days} days ago for a money back refund?",
        "I want to request a return and refund for an order placed {days} days ago.",
        "What is the status if my purchase was delivered {days} days ago, can I return it?",
    ]
    refund_templates_denied = [
        "I purchased this {days} days ago and want a refund. Can you approve it?",
        "My delivery was {days} days ago. Am I still inside the refund window?",
        "Can I return a defective item bought {days} days ago under standard refund?",
        "Requesting a refund for product delivered {days} days ago.",
        "It has been {days} days since my transaction. Can I get a refund?",
    ]

    # Days <= 30 -> REFUND ALLOWED
    allowed_days = [1, 2, 3, 5, 7, 10, 12, 14, 15, 18, 20, 21, 24, 25, 27, 28, 29, 30]
    for days in allowed_days:
        for tmpl in refund_templates_allowed:
            queries.append(
                BenchmarkQuery(
                    query_id=f"Q-REFUND-ALLOW-{q_id:04d}",
                    intent="refund_eligibility",
                    query_text=tmpl.format(days=days),
                    target_memory_id="POLICY-REFUND-001",
                    expected_answer_keyword="30",
                    expected_decision="REFUND ALLOWED",
                )
            )
            q_id += 1

    # Days > 30 -> REFUND DENIED
    denied_days = [31, 32, 35, 40, 45, 50, 60, 75, 90, 120, 180, 365]
    for days in denied_days:
        for tmpl in refund_templates_denied:
            queries.append(
                BenchmarkQuery(
                    query_id=f"Q-REFUND-DENY-{q_id:04d}",
                    intent="refund_eligibility",
                    query_text=tmpl.format(days=days),
                    target_memory_id="POLICY-REFUND-001",
                    expected_answer_keyword="30",
                    expected_decision="REFUND DENIED",
                )
            )
            q_id += 1

    # 2. Warranty Inquiries
    warranty_templates = [
        "What is the warranty period for enterprise hardware?",
        "How long does the standard limited warranty last?",
        "Does the warranty cover manufacturing defects for 12 months?",
        "What is covered under the hardware warranty policy?",
        "How many months of warranty protection are included with our purchase?",
        "Are defective components covered during the first year?",
    ]
    for tmpl in warranty_templates:
        for prefix in ["Hello, ", "Hi support, ", "Can you tell me: ", "Inquiry: ", ""]:
            queries.append(
                BenchmarkQuery(
                    query_id=f"Q-WARRANTY-{q_id:04d}",
                    intent="warranty_inquiry",
                    query_text=f"{prefix}{tmpl}",
                    target_memory_id="POLICY-WARRANTY-001",
                    expected_answer_keyword="12 months",
                    expected_decision="FACTUAL",
                )
            )
            q_id += 1

    # 3. Shipping SLA Inquiries
    shipping_templates = [
        "What is the expected delivery timeframe for ground shipping?",
        "How many business days does standard shipping take?",
        "What is your enterprise ground shipping SLA?",
        "When can I expect my order if shipped via standard ground?",
        "How fast is ground transit according to your delivery policy?",
    ]
    for tmpl in shipping_templates:
        for prefix in ["Please advise: ", "Shipping question: ", "Hi, ", ""]:
            queries.append(
                BenchmarkQuery(
                    query_id=f"Q-SHIPPING-{q_id:04d}",
                    intent="shipping_sla",
                    query_text=f"{prefix}{tmpl}",
                    target_memory_id="POLICY-SHIPPING-SLA",
                    expected_answer_keyword="3 to 5 business days",
                    expected_decision="FACTUAL",
                )
            )
            q_id += 1

    # 4. Pricing & Volume Discount Inquiries
    pricing_templates = [
        "What discount is available for annual billing on 50 or more seats?",
        "Do you offer an enterprise volume discount for annual plans?",
        "How much discount do we receive if we commit to 50+ seats upfront?",
        "What is the annual enterprise discount percentage?",
        "Can we get 15% off by choosing annual enterprise billing?",
    ]
    for tmpl in pricing_templates:
        for prefix in ["Billing inquiry: ", "Pricing question: ", "Hello, ", ""]:
            queries.append(
                BenchmarkQuery(
                    query_id=f"Q-PRICING-{q_id:04d}",
                    intent="pricing_discount",
                    query_text=f"{prefix}{tmpl}",
                    target_memory_id="PRICING-TIER-ANNUAL",
                    expected_answer_keyword="15%",
                    expected_decision="FACTUAL",
                )
            )
            q_id += 1

    # 5. Promo Code Inquiries
    promo_templates = [
        "What promo code gives a 20% discount on the first invoice?",
        "Is there a welcome promo code for new enterprise accounts?",
        "How does the WELCOME20 promotion work?",
        "What discount does the WELCOME20 promo code provide?",
        "Do new customers get a promotional code for 20% off?",
    ]
    for tmpl in promo_templates:
        for prefix in ["Promo question: ", "Can you verify: ", "Hi support: ", ""]:
            queries.append(
                BenchmarkQuery(
                    query_id=f"Q-PROMO-{q_id:04d}",
                    intent="promotions",
                    query_text=f"{prefix}{tmpl}",
                    target_memory_id="PRICING-PROMO-WELCOME",
                    expected_answer_keyword="WELCOME20",
                    expected_decision="FACTUAL",
                )
            )
            q_id += 1

    # 6. Identity & Escalation Procedures
    escalation_templates = [
        "What identity verification is needed before resetting an account PIN?",
        "How does support verify my identity for a password reset?",
        "Is an MFA code required before changing account credentials?",
        "What is the procedure for updating a customer password?",
        "Do you require SMS or email MFA verification for account changes?",
    ]
    for tmpl in escalation_templates:
        for prefix in ["Security question: ", "Account help: ", "Urgent: ", ""]:
            queries.append(
                BenchmarkQuery(
                    query_id=f"Q-ESCALATION-{q_id:04d}",
                    intent="identity_verification",
                    query_text=f"{prefix}{tmpl}",
                    target_memory_id="ESCALATION-AUTH-MFA",
                    expected_answer_keyword="MFA",
                    expected_decision="FACTUAL",
                )
            )
            q_id += 1

    # 7. Return Condition Inquiries
    return_cond_templates = [
        "What are the condition requirements for returning a purchased product?",
        "Do returned items need to have their original packaging and serial numbers?",
        "What condition must returned hardware be in to be accepted?",
        "Are items accepted for return if the factory seal is broken or missing?",
        "What is the policy regarding returned product packaging and serial numbers?",
    ]
    for tmpl in return_cond_templates:
        for prefix in ["Returns department: ", "Customer inquiry: ", "Hi support, ", "Question: ", ""]:
            queries.append(
                BenchmarkQuery(
                    query_id=f"Q-RETURN-COND-{q_id:04d}",
                    intent="return_condition",
                    query_text=f"{prefix}{tmpl}",
                    target_memory_id="POLICY-RETURN-COND",
                    expected_answer_keyword="original packaging",
                    expected_decision="FACTUAL",
                )
            )
            q_id += 1

    # 8. Fraud Escalation Threshold Inquiries
    fraud_templates = [
        "What dollar amount triggers automatic Tier 3 fraud investigation?",
        "At what transaction threshold does a refund require fraud escalation?",
        "Are transactions over $10,000 subject to fraud review?",
        "What is the escalation policy for high value transactions exceeding $10,000?",
        "When is a customer refund escalated to the fraud team?",
    ]
    for tmpl in fraud_templates:
        for prefix in ["Security team: ", "Fraud check: ", "Urgent inquiry: ", "Policy check: ", ""]:
            queries.append(
                BenchmarkQuery(
                    query_id=f"Q-FRAUD-{q_id:04d}",
                    intent="fraud_escalation",
                    query_text=f"{prefix}{tmpl}",
                    target_memory_id="ESCALATION-FRAUD-TIER3",
                    expected_answer_keyword="10,000",
                    expected_decision="FACTUAL",
                )
            )
            q_id += 1

    # 9. SSO & Compatibility Inquiries
    tech_templates = [
        ("What protocol is required to configure Single Sign-On (SSO)?", "FAQ-SSO-SETUP", "SAML 2.0"),
        ("Which SSO standard does enterprise integration support?", "FAQ-SSO-SETUP", "SAML 2.0"),
        ("What operating systems are supported by the client application?", "FAQ-COMPATIBILITY-001", "Windows 11"),
        ("Is Ubuntu 22.04 LTS supported by the enterprise agent?", "FAQ-COMPATIBILITY-001", "Ubuntu 22.04"),
        ("Does macOS 14 Sonoma run the client software?", "FAQ-COMPATIBILITY-001", "macOS 14"),
    ]
    for tmpl, mem_id, kw in tech_templates:
        for prefix in ["Technical inquiry: ", "Setup question: ", "Hi, ", ""]:
            queries.append(
                BenchmarkQuery(
                    query_id=f"Q-TECH-{q_id:04d}",
                    intent="technical_support",
                    query_text=f"{prefix}{tmpl}",
                    target_memory_id=mem_id,
                    expected_answer_keyword=kw,
                    expected_decision="FACTUAL",
                )
            )
            q_id += 1

    return queries[:target_count] if len(queries) >= target_count else queries


def export_benchmark_dataset(
    output_path: Path | str = "data/benchmark_queries_300.json",
    count: int = 350,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    queries = generate_benchmark_queries(count)
    data = [asdict(q) for q in queries]
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path
