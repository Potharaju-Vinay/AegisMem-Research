# AegisMem Owner Digital-Signature Protocol

## 1. Purpose

This protocol defines how an owner authorizes a persistent memory write and how the API authenticates sensitive HTTP requests.

## 2. Algorithms and encoding

- Signature algorithm: Ed25519.
- Text encoding: UTF-8.
- Signature representation: hexadecimal.
- JSON canonicalization: sorted keys, compact separators, and `ensure_ascii=False`.
- Content digest: SHA-256 over the UTF-8 encoded memory content.

## 3. Owner approval payload

The owner approval payload contains these fields:

- `protocol`: `aegismem-owner-approval-v1`
- `operation`: `memory.write`
- `memory_id`: target memory identifier
- `content_sha256`: SHA-256 digest of the exact UTF-8 content
- `expected_parent_revision_id`: expected parent revision identifier, or JSON null
- `authorization_id`: authorization identifier
- `nonce`: unique authorization nonce

Serialize the object using the equivalent of:

`json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`

Sign those exact bytes using the owner's Ed25519 private key. Send the resulting signature as a hexadecimal string in `authorization_signature`.

The server verifies the signature against the public key configured for owner approval.

## 4. HTTP request signature

The HTTP request signature covers five newline-separated fields, in this order:

1. HTTP method in uppercase
2. Request URL path
3. Unix timestamp in integer seconds, represented as text
4. Request nonce
5. Exact raw request body decoded as UTF-8

The resulting string is encoded as UTF-8 and signed with Ed25519. Send the signature in hexadecimal using the `X-Owner-Signature` header, with `X-Owner-Timestamp` and `X-Owner-Nonce`. The request must also include the configured bearer token.

The server rejects timestamps outside its configured clock-skew window, which is currently 300 seconds, and rejects nonces that cannot be registered.

## 5. Security requirements

- Keep private keys under owner control; do not expose them in source control, logs, or API responses.
- Never substitute a signature from a different memory, content, parent revision, authorization ID, or nonce.
- Generate a fresh nonce for each authorization and HTTP request.
- Preserve the exact request body and path used to calculate the HTTP request signature.
- Reject missing, malformed, invalid, stale, or replayed signatures.
- Use separate key pairs for owner approvals and HTTP request authentication in production.
- Store public keys securely and define a controlled key-rotation process.
- A valid signature proves possession of the corresponding private key; it does not independently prove that the requested business action is safe.

## 6. Implementation note

This document describes the current server-side canonicalization rules. An owner-side client must reproduce them exactly. Verify compatibility with test keys before using a real owner key.
