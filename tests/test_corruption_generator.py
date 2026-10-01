from types import SimpleNamespace

from attack_lab.generator import CorruptionGenerator


def test_corruption_generator():

    memory = SimpleNamespace(
        memory_id="POLICY-001",
        content="Customer refunds are permitted within 30 days."
    )

    generator = CorruptionGenerator()

    case = generator.generate(
        memory=memory,
        modified_content="Customer refunds are permitted within 180 days.",
        corruption_type="numerical_mutation"
    )

    assert case.memory_id == "POLICY-001"
    assert case.original_content == (
        "Customer refunds are permitted within 30 days."
    )
    assert case.modified_content == (
        "Customer refunds are permitted within 180 days."
    )
    assert case.corruption_type == "numerical_mutation"
    assert case.original_hash != case.modified_hash
    assert case.attack_id.startswith("ATT-")


def test_corruption_generator_rejects_identical_content():

    memory = SimpleNamespace(
        memory_id="POLICY-001",
        content="Customer refunds are permitted within 30 days."
    )

    generator = CorruptionGenerator()

    try:
        generator.generate(
            memory=memory,
            modified_content=memory.content
        )
        assert False
    except ValueError:
        assert True
