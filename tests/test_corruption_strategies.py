from types import SimpleNamespace

from attack_lab.generator import CorruptionGenerator


def test_numerical_mutation():

    memory = SimpleNamespace(
        memory_id="POLICY-001",
        content="Refunds are permitted within 30 days."
    )

    case = CorruptionGenerator().numerical_mutation(
        memory,
        "30",
        "180"
    )

    assert case.modified_content == (
        "Refunds are permitted within 180 days."
    )
    assert case.corruption_type == "numerical_mutation"
    assert case.original_hash != case.modified_hash


def test_negation_mutation():

    memory = SimpleNamespace(
        memory_id="POLICY-002",
        content="Privileged access requires MFA."
    )

    case = CorruptionGenerator().negation_mutation(
        memory,
        "requires MFA",
        "does not require MFA"
    )

    assert case.modified_content == (
        "Privileged access does not require MFA."
    )
    assert case.corruption_type == "negation_mutation"


def test_permission_mutation():

    memory = SimpleNamespace(
        memory_id="POLICY-003",
        content="Access requires administrator approval."
    )

    case = CorruptionGenerator().permission_mutation(
        memory,
        "requires administrator approval",
        "does not require administrator approval"
    )

    assert case.corruption_type == "permission_mutation"


def test_obligation_mutation():

    memory = SimpleNamespace(
        memory_id="SOP-004",
        content="Security incidents must be escalated."
    )

    case = CorruptionGenerator().obligation_mutation(
        memory,
        "must be escalated",
        "may be handled locally"
    )

    assert case.modified_content == (
        "Security incidents may be handled locally."
    )
    assert case.corruption_type == "obligation_mutation"
