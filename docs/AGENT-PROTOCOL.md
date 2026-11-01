# Agents elsewhere: the relay protocol

An AI agent on another computer than the owner's 2Secret (a cloud agent, a
build server, a second machine) cannot reach the desktop app's local socket.
Since 2Secret 1.12 it talks to the owner's apps through the sync server
instead. The server relays sealed envelopes it cannot open: it learns which
agent asked when and how large the question was, never what was asked, which
item, or what the answer is. This document is the wire format; the code is
`crates/core/src/agent_remote.rs` (cryptography and formats),
`crates/server/src/agents.rs` (routes), `crates/agent/src/remote.rs` (the
agent) and `crates/app/src/remote_agents.rs` (the owner's apps).

All constants carry a `2secret/v1/…` context; the protocol version is 1.

## Roles and keys

| Who | Keys | Where |
|---|---|---|
| The account (owner) | X25519 and ML-KEM-768 public keys, as for sharing; the account key (symmetric) | every device of the account |
| The agent | X25519, ML-KEM-768 and Ed25519, all derived (HKDF-SHA256) from one random 32-byte root: `2secret/v1/agent/x25519`, `2secret/v1/agent/ml-kem` (the seed of `PqPrivateKey::derive`), `2secret/v1/agent/ed25519` | `remote-<name>.json` on the agent's computer |

The agent id is the fingerprint of its Ed25519 key, like a local agent's.
The agent's *fingerprint* shown to people covers all three public keys:
`fingerprint(SHA-256(x25519 ‖ ml_kem ‖ ed25519))`.

Envelopes to the account are `HybridSealedBox`es (X25519 + ML-KEM-768, see
SECURITY.md, *Quantum-resistant sharing*). Answers are symmetric
(XChaCha20-Poly1305) with a key the agent put inside its request.

## 1. Pairing code

The owner's app makes a code and shows it (as text and as a QR code of the
link). The person pastes it where the agent runs.

```
2A-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXX     typable
2secret-agent:v1?server=https%3A%2F%2Fsync.2secret.app&code=2A-…      link
```

The text is 32 bytes in the Secret Key alphabet (`23456789ABCDEFGHJKLMNPQRSTUVWXYZ`,
5 bits per character, 52 characters) plus a check character
(`SK_ALPHABET[SHA-256("2secret-agent-code-check:" ‖ body)[0] mod 32]`):

| Bytes | Meaning |
|---|---|
| 0–15 | `seed`, random |
| 16–31 | `key_hash` = `SHA-256("2secret/v1/agent-pair/keys" ‖ x25519 ‖ ml_kem)[0..16]` of the account's public keys |

From the seed follow two values:

- `token` = base64url(`SHA-256("2secret/v1/agent-pair/token" ‖ seed)`): what
  the agent shows the server. The server stores only `token_hash` =
  base64url(`SHA-256(token)`).
- `secret` = `SHA-256("2secret/v1/agent-pair/secret" ‖ seed)`: what the agent
  proves to the owner's app. The server never sees it.

A code is valid for 10 minutes and works once. The app registers it:

```
POST /api/v1/agents/pairings            (signed in)
{ "token_hash": "…" }
→ 201 { "expires_at": 1730000600 }
```

At most 5 codes per account are open at a time.

## 2. Pairing

The agent (`2secret agent pair <code>`) makes fresh keys, asks the server for
the account's public keys and checks them against `key_hash` in the code, so
a server cannot hand it other keys:

```
GET /api/v1/agent/pairing/{token}       (no sign-in; 20 per 15 minutes per address)
→ 200 { "x25519": "…", "ml_kem": "…", "expires_at": … }
→ 404 pairing_invalid
```

It then seals a proof to the account and pairs:

```
POST /api/v1/agent/pair                 (X-2Secret-Agent header, see §4)
{
  "token": "…",
  "keys": { "x25519": "…", "ml_kem": "…", "ed25519": "…" },
  "proof": HybridSealedBox
}
→ 201 { "agent_id": "3F9A-77C1-0B2E-91D4", "expires_at": … }
```

`proof` = `seal_hybrid(account keys, JSON { secret (base64), keys, name,
version, device }, AD = "2secret/v1/agent-pair/<token_hash>")`. The server
checks that the header's signature matches `keys.ed25519`, deletes the code,
stores the agent as *pending* with its public keys and the proof, and counts
it against the account's limit (default 20 agents). An agent id already
paired with another account is refused (409); the same agent pairing again
(after a revocation) starts over.

## 3. Confirming

Every signed-in device lists the account's agents:

```
GET /api/v1/agents
→ 200 [ { "id", "keys", "token_hash"?, "proof"?, "record"?, "created_at", "expires_at"?, "last_seen_at"? } ]
```

The device that made the code recognises its `token_hash`, opens `proof`
with the account's keys and checks that

- the `secret` in the proof is the code's secret (constant time), and
- the `keys` in the proof are the keys the server lists for the agent.

It shows the agent's name, device and fingerprint, and on *Confirm* writes
the record every device can open:

```
PUT /api/v1/agents/{id}
{ "record": EncString }
→ 204
```

`record` = `encrypt(account key, JSON { name, version, keys, fingerprint,
paired_at, device, paired_on }, AD = "2secret/v1/agent-record/<account id>/<agent id>")`.
Opening a record checks that its keys are the keys the server lists; a
mismatch means the server swapped keys and the agent is ignored. Until the
record exists the agent cannot ask (403 `agent_not_confirmed`); a pending
agent is deleted when its code's time runs out.

`DELETE /api/v1/agents/{id}` revokes an agent: its open requests are
deleted and its calls answer 403 `agent_revoked` for a week, then it is
forgotten. The agent's grants and log entries on each device are removed by
the app.

## 4. The agent's header

Every call of an agent carries

```
X-2Secret-Agent: <agent id>.<unix seconds>.<nonce>.<signature>
```

with `nonce` 16 random bytes (base64url) and `signature` (base64url) the
Ed25519 signature over

```
"2secret/v1/agent-http" ‖ "\n" ‖ METHOD ‖ "\n" ‖ path-and-query ‖ "\n" ‖ hex(SHA-256(body)) ‖ "\n" ‖ seconds ‖ "\n" ‖ nonce
```

The server verifies it with the agent's stored Ed25519 key (for `/agent/pair`
with the key in the body), refuses a time more than 300 s off and a nonce it
saw within that window (401 `agent_signature`), counts the call against the
agent's limit (60 per 15 minutes, 429) and updates `last_seen_at`. The header
is for routing and limits; the secrecy and integrity of the content rest on
the envelopes below, so a malicious server gains nothing from forging it.

## 5. Requests

```
POST /api/v1/agent/requests
{ "id": "<22 characters base64url, chosen by the agent>", "request": HybridSealedBox }
→ 201 { "expires_at": … }
→ 403 (more than 20 open requests), 409 (id in use)
```

The envelope is sealed to the account with AD `"2secret/v1/agent-request/<id>"`.
Its plaintext is a 64-byte Ed25519 signature followed by the JSON payload:

```
{ "agent_id": "…", "ts": 1730000000, "method": "read", "params": { … }, "reply_key": "<32 bytes base64url>" }
```

The signature is over `"2secret/v1/agent-request" ‖ "\n" ‖ id ‖ "\n" ‖ payload bytes`,
so the owner's app verifies it against the Ed25519 key pinned in the record:
not even the server can forge or alter a request. `method` and `params` are
those of the local agent protocol (`search`, `item`, `read`, `read_many`,
`otp`, `generate`, `create_item`, `update_item`, `fill`; see
`twosecret_core::agent::Request`). A request expires after 10 minutes.

The owner's apps fetch open requests while unlocked:

```
GET /api/v1/agents/requests?wait=25     (signed in; long-poll up to 25 s)
→ 200 [ { "id", "agent_id", "request", "created_at", "expires_at" } ]
```

Every unlocked device shows the question; the first answer counts:

```
POST /api/v1/agents/requests/{id}/answer   { "answer": EncString }   → 204, 409 when already answered
POST /api/v1/agents/requests/{id}/deny                                → 204, 409
```

`answer` = `encrypt(reply_key, JSON { "result": … } or { "error": { "code", "message" } },
AD = "2secret/v1/agent-answer/<id>")`. Only whoever opened the request knows
the reply key, so the server cannot forge an answer either. A denial without
an envelope is what the server reports when the owner refused, the app was
locked, or the request could not be opened.

The agent waits for the outcome:

```
GET /api/v1/agent/requests/{id}?wait=25
→ 200 { "status": "open" | "answered" | "denied" | "expired", "answer"?: EncString }
→ 404 once the request is gone
```

An answer is handed out once and then deleted, as is a denied or expired
request.

A `fill` request is answered with the login itself (the `FillCommand`:
user name, password, current one-time code, the fill rules of the item),
because the browser to fill is on the agent's computer. `2secret mcp
--remote --cdp …` fills it there through the browser's debugging port
(`crates/agent/src/cdp.rs`) and the model only hears the outcome.

## What the server sees

Agent ids and public keys, which account an agent belongs to, when it paired
and was last seen, the sizes and times of requests and answers, and the
pairing tokens' hashes. Never a method, an item, a field, a name or a value.
The database tables are `agent_pairings`, `agents` and `agent_requests`.

## Limits and errors

| | Default | Server flag |
|---|---|---|
| Agents per account | 20 | `--max-agents` / `TWOSECRET_MAX_AGENTS` |
| Open requests per agent | 20 | `--max-agent-requests` / `TWOSECRET_MAX_AGENT_REQUESTS` |
| Calls per agent | 60 per 15 minutes | – |
| Pairing lookups and attempts per address | 20 per 15 minutes | – |
| Pairing code, pending agent | 10 minutes | – |
| Request | 10 minutes | – |
| Envelope | 256 KiB | – |

Error codes in the JSON body (`{ "error", "message" }`): `pairing_invalid`
(404), `agent_signature` (401), `agent_not_confirmed` (403), `agent_revoked`
(403), `rate_limited` (429), `conflict` (409). Inside an answer the error
codes are those of the local agent protocol, plus `-32009` *not confirmed*.
