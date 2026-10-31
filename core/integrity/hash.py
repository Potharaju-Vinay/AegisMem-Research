import hashlib


def calculate_content_hash(content: str) -> str:
    return hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()


def calculate_version_hash(
    content: str,
    previous_hash: str | None
) -> str:

    payload = content

    if previous_hash:
        payload = previous_hash + content

    return hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()