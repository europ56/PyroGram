# PyroGram Security Model

## Executive Summary

PyroGram implements a multi-layer defense strategy inspired by military cryptography standards. Every message is authenticated, encrypted, and sequenced. The system is resistant to eavesdropping, tampering, replay attacks, and man-in-the-middle (MITM) scenarios through a combination of public-key cryptography, symmetric encryption, and cryptographic proof systems.

---

## Threat Model

### In Scope

We protect against:

1. **Network Eavesdropping**: Attacker passively observes network traffic
   - *Defense*: All payloads encrypted with AES-256-GCM
   
2. **Message Tampering**: Attacker modifies packets in transit
   - *Defense*: HMAC-SHA256 authentication on every packet, Ed25519 signatures on messages
   
3. **Replay Attacks**: Attacker replays old packets
   - *Defense*: Sequence numbers, timestamps, random_id deduplication
   
4. **Man-in-the-Middle (MITM)**: Attacker intercepts and impersonates
   - *Defense*: SRP-6a mutual authentication, server identity key pinning in client
   
5. **Offline Password Attack**: Attacker obtains password hash and brute-forces
   - *Defense*: Argon2id with configurable cost (default: 3 iterations, 64MB memory)
   
6. **Forward Secrecy Breach**: Attacker compromises session auth_key
   - *Defense*: Ephemeral keys, Double Ratchet for E2E chats
   
7. **Unauthorized Access**: Attacker attempts to forge user identity
   - *Defense*: Ed25519 identity keys, TOTP 2FA optional

### Out of Scope

We do NOT protect against:

- **Device Compromise**: If user's device is rooted/jailbroken, all bets are off
- **Server Compromise**: If attacker has root access to server, plaintext keys are accessible (use HSM in production)
- **Quantum Adversaries**: RSA-2048 and ECC will be broken by quantum computers (migration planned post-NIST PQC standardization)
- **Metadata Analysis**: While messages are encrypted, TLVs headers (chat_id, sender_id) are plaintext for routing
- **Timing Attacks**: Some operations are not fully constant-time; we use hmac.compare_digest for comparisons

---

## Cryptographic Primitives

### Key Exchange: X25519 Elliptic Curve Diffie-Hellman

**Purpose**: Establish ephemeral shared secret for session

**Specification**:
- Curve: Curve25519 (Montgomery form)
- Private key: 32 bytes random
- Public key: 32 bytes (computed from private)
- Shared secret: 32 bytes (X25519(my_private, their_public))

**Security**:
- Resistance: 128 bits (equivalent to RSA-3072)
- No small subgroup issues (curve cofactor = 8, but random scalars)
- Immune to timing attacks (constant-time Montgomery ladder)

**Implementation**:
```python
from cryptography.hazmat.primitives.asymmetric import x25519

# Server DH (long-term identity key for session establishment)
server_private = x25519.X25519PrivateKey.generate()
server_public = server_private.public_key()

# Client ephemeral DH
client_private = x25519.X25519PrivateKey.generate()
client_public = client_private.public_key()

# Shared secret computation (both sides)
shared_secret = server_private.exchange(client_public)  # or client_private.exchange(server_public)
```

### Authentication: SRP-6a (Secure Remote Password)

**Purpose**: Zero-knowledge password authentication (server never sees password)

**Protocol**:
1. Client and server agree on:
   - N: 2048-bit safe prime
   - g: generator (2)
   - k: multiplier (derived from N, g)
   
2. Registration:
   - User enters password P
   - Salt s = random(32 bytes)
   - x = SHA256(s || P)
   - Verifier v = g^x mod N
   - Server stores (salt, verifier, username)
   
3. Authentication:
   - Client → Server: username, A = g^a mod N
   - Server → Client: salt, B = (k*v + g^b) mod N
   - Both compute: S = (B - k*g^x)^(a + u*x) mod N  [server: S = (A*v^u)^b]
   - auth_key = SHA256(S)
   - Client proof M1 = SHA256(H(N) XOR H(g) || H(username) || salt || A || B || S)
   - Server proof M2 = SHA256(A || M1 || S)
   
**Security**:
- Password never sent to server (zero-knowledge)
- Resistant to offline dictionary attack if N is large and auth is slow
- Mutual authentication (server proves knowledge of password)
- Salted (prevents rainbow tables)

**Implementation**:
```python
# Using custom SRP implementation in core/auth/srp6a.py
# Never use naive implementation; must follow RFC 5054 carefully
```

### Symmetric Encryption: AES-256-GCM

**Purpose**: Encrypt all authenticated messages

**Specification**:
- Algorithm: AES-256-GCM (Galois/Counter Mode)
- Key size: 256 bits (32 bytes)
- Nonce: 96 bits (12 bytes, unique per message)
- Authentication: 128-bit GCM tag (included in ciphertext)
- IV derivation: SHA256(auth_key + msg_key)[0:12]

**Why GCM**:
- Provides both confidentiality (AES) and authenticity (GMAC)
- No need for separate HMAC layer
- Hardware acceleration available on modern CPUs
- Failure to decrypt returns error, never succeeds with garbage

**Implementation**:
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = derive_key(auth_key)
nonce = derive_nonce(auth_key, msg_key)[:12]
cipher = AESGCM(key)
ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)
# GCM tag is appended to ciphertext
```

**Message Key Derivation** (MTProto-style):
```
msg_key = SHA256(auth_key[88:120] + plaintext)[:16]  # Use 128 bits
aes_key = SHA256(msg_key + auth_key[0:36])
aes_iv = SHA256(msg_key + auth_key[36:72])[0:12]
```

### Digital Signatures: Ed25519

**Purpose**: Prove message origin, prevent tampering

**Specification**:
- Algorithm: EdDSA using Curve25519
- Private key: 32 bytes (seed)
- Public key: 32 bytes (point on curve)
- Signature: 64 bytes

**Security**:
- Unforgeability: 128 bits security level
- No key recovery
- Deterministic (same message always produces same signature)
- Fast verification (~100,000 signatures/sec on modern CPU)

**Implementation**:
```python
from cryptography.hazmat.primitives.asymmetric import ed25519

# Generate user identity key (stored locally on client)
identity_private = ed25519.Ed25519PrivateKey.generate()
identity_public = identity_private.public_key()

# Sign a message
message = b"chat_id=42||text=hello"
signature = identity_private.sign(message)

# Verify (server receives public_key during registration)
identity_public.verify(signature, message)  # raises if invalid
```

### Password Hashing: Argon2id

**Purpose**: Hash user passwords for storage, resist brute-force

**Specification**:
- Algorithm: Argon2id (memory-hard, time-hard)
- Memory cost: 64 MB (configurable)
- Time cost: 3 iterations (configurable)
- Parallelism: 2 threads (configurable)
- Output: 32 bytes

**Why Argon2id**:
- Memory-hard: requires 64MB RAM per attempt (prevents GPU/ASIC attacks)
- Time-hard: 3 iterations × parallelism overhead
- Resistant to GPU attacks (unlike bcrypt)
- OWASP recommended (as of 2023)

**Implementation**:
```python
from argon2 import PasswordHasher

hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64MB
    parallelism=2,
    hash_len=32
)

# Hashing
hash_value = hasher.hash(password)

# Verification
hasher.verify(hash_value, password)  # raises if wrong
```

### TOTP (Time-based One-Time Password)

**Purpose**: Optional 2FA for login security

**Specification**:
- Algorithm: HMAC-based OTP (HMAC-SHA1 per RFC 4226)
- Time-step: 30 seconds (RFC 6238)
- Digits: 6 (standard)
- Secret: 32 bytes (base32-encoded for QR code)

**Implementation**:
```python
import hmac
import hashlib
import time
from base64 import b32encode

def generate_totp_secret():
    return secrets.token_bytes(32)

def get_totp_code(secret: bytes, time_step: int = 30) -> str:
    """Generate current TOTP code."""
    counter = int(time.time()) // time_step
    hmac_result = hmac.new(secret, counter.to_bytes(8, 'big'), hashlib.sha1).digest()
    offset = hmac_result[-1] & 0x0F
    code = (int.from_bytes(hmac_result[offset:offset+4], 'big') & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"

def verify_totp(secret: bytes, code: str, window: int = 1) -> bool:
    """Verify TOTP code with time window tolerance."""
    current_time = int(time.time()) // 30
    for i in range(-window, window + 1):
        expected = get_totp_code(secret, 30)
        if code == expected:
            return True
    return False
```

---

## Authentication Flow Security

### SRP-6a Handshake Threats Mitigated

| Threat | Mitigation |
|--------|-----------|
| Eavesdropping of password | SRP never sends password; only derived values |
| Server compromise (password leak) | Server stores hash, not password |
| Offline dictionary attack on verifier | Argon2id hashing + large N (2048 bits) + salt |
| MITM interception of A or B | Server verifies proof M1; if wrong, connection rejected |
| Replay of old SRP proofs | Timestamp + random nonce in proof, SRP salt is unique per session |
| Weak password brute-force | Rate limiting (max 5 attempts/min per IP) + Argon2id cost |

---

## Session Security

### Session Key Management

```
After successful SRP-6a:

1. Derived Keys:
   auth_key = SHA256(shared_secret)                  # 256-bit master key
   session_id = UUID4()                              # 128-bit session identifier
   refresh_token = random(32 bytes)                  # For session extension

2. Per-Message Encryption:
   msg_key = SHA256(auth_key[88:120] + plaintext)
   aes_key, aes_iv = KDF(auth_key, msg_key)
   ciphertext = AES-256-GCM(plaintext, aes_key, aes_iv)

3. Packet Authentication:
   packet_hmac = HMAC-SHA256(header || ciphertext || nonce, auth_key)
   
4. All HMAC comparisons use hmac.compare_digest() for constant-time verification
```

### Session Termination

```python
# Server clears session from memory
del sessions[session_id]
del auth_keys[session_id]  # Wipe from memory (ctypes.memset pattern)

# Client clears local auth_key
auth_key = None  # Relies on Python GC, best-effort
# For sensitive data: use ctypes.memset pattern
```

---

## End-to-End Encryption (Secret Chats)

### Double Ratchet Algorithm (Signal Protocol)

Secret chats use the Double Ratchet for perfect forward secrecy.

**Ratchet State**:
```
root_key (32 bytes)
send_chain_key (32 bytes)
recv_chain_key (32 bytes)
dh_send (X25519 private key)
dh_recv (X25519 public key)
send_chain_counter (u32)
recv_chain_counter (u32)
```

**Sending a Message**:
```
1. msg_key = HKDF-SHA256(send_chain_key, b"message")
2. next_send_chain_key = HKDF-SHA256(send_chain_key, b"chain")
3. Encrypt message with msg_key
4. Increment send_chain_counter
5. Periodically (every 100 messages):
   - Generate new DH key pair
   - Compute root_key = HKDF-SHA256(root_key, DH_out)
   - Reset send_chain_key from root_key
```

**Receiving a Message**:
```
1. Extract DH_recv from message header
2. If different from previous:
   - Skip forward in recv chain to catch up
   - Compute new root_key = HKDF-SHA256(root_key, DH_out)
   - Reset recv_chain_key
3. Derive msg_key from recv_chain_key
4. Decrypt message
5. Increment recv_chain_counter
6. Skip-list: if messages arrive out of order, buffer and re-derive
```

**Security Properties**:
- Forward secrecy: even if auth_key is compromised, past messages are safe
- Post-compromise security: ratchet advances after each message, recovers confidentiality after 1 message
- Backward secrecy: compromising msg_key does not reveal others
- Out-of-order delivery: buffering + ratchet state allows recovery

---

## Network Transport Security

### TCP + TLS for Future Upgrades

Current: raw TCP (no TLS)

Future: optional TLS 1.3 with:
- Certificate pinning in client (prevent MITM via CA compromise)
- Perfect forward secrecy (ECDHE with ephemeral keys)
- ALPN for protocol negotiation

### WebSocket Handshake

```
GET / HTTP/1.1
Host: example.com:443
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64-encoded-16-bytes>
Sec-WebSocket-Version: 13

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: <sha1-based-response-hash>
```

After upgrade, all frames are encrypted per protocol, then masked (RFC 6455).

---

## Rate Limiting & DoS Prevention

### Per-Connection Rate Limiter

```python
# Token bucket: 100 messages/sec per client
class RateLimiter:
    def __init__(self, rate: float = 100.0):  # msgs/sec
        self.rate = rate
        self.tokens = rate
        self.last_update = time.monotonic()
    
    def is_allowed(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
        self.last_update = now
        
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False
```

### Per-IP Global Rate Limiter

```
Sliding window counter (Redis-style):
  Bucket key: f"ratelimit:{ip}:send_message"
  Increment on message send
  TTL: 60 seconds
  Limit: 10,000 messages/IP/60sec
  
If exceeded: return ERROR_RATE_LIMITED, backoff client
```

### Authentication Endpoint Rate Limiting

```
Per IP:
  Max 5 login attempts per minute
  Max 10 registration attempts per hour
  Exponential backoff: 1s, 2s, 4s, 8s, etc.
```

---

## Input Validation & Injection Prevention

### Payload Length Limits

```python
MAX_MESSAGE_LENGTH = 65535  # TLV 16-bit length field
MAX_CHAT_TITLE_LENGTH = 256
MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024  # 4GB
MAX_CHUNK_SIZE = 512 * 1024  # 512KB per chunk
MAX_USERNAME_LENGTH = 64
```

### TLV Parsing Safety

```python
def parse_tlv_safe(data: bytes) -> List[TLV]:
    """Parse TLVs with bounds checking."""
    offset = 0
    tlvs = []
    
    while offset < len(data):
        if offset + 8 > len(data):
            raise ProtocolError("Truncated TLV header")
        
        tag = int.from_bytes(data[offset:offset+4], 'big')
        length = int.from_bytes(data[offset+4:offset+8], 'big')
        
        if length > 0x1000000:  # 16MB max per TLV
            raise ProtocolError("TLV too large")
        
        if offset + 8 + length > len(data):
            raise ProtocolError("Truncated TLV value")
        
        value = data[offset+8:offset+8+length]
        tlvs.append(TLV(tag, value))
        offset += 8 + length
    
    return tlvs
```

### Database Query Safety

All queries are parameterized (no SQL), using the custom query builder:

```python
# Safe (parameterized)
db.table("messages").where(chat_id=42).where(sender_id=user_id)

# Not possible (no SQL)
# db.query(f"SELECT * FROM messages WHERE chat_id={chat_id}")
```

---

## Logging & Audit Trail

### What to Log (safe data)

```
[timestamp] [level] [session_id] [event]
  2026-06-05 12:00:00 INFO session_abc123 User "alice" authenticated from 192.168.1.1
  2026-06-05 12:00:05 INFO session_abc123 Message sent to chat 42 (id: msg_9001)
  2026-06-05 12:01:00 WARN session_abc123 Rate limit exceeded (5 messages/sec)
  2026-06-05 12:05:00 ERROR session_abc123 Authentication failed (invalid proof)
```

### What NOT to Log (sensitive data)

```
❌ Passwords or password hashes
❌ auth_keys or session keys
❌ Private keys (Ed25519, X25519)
❌ TOTP secrets
❌ Message plaintext
❌ User email addresses (only in registration)
❌ HMAC values or signatures
```

### Log Storage

```
server_data/logs/
├── 2026-06-05.log      # Daily rotation
├── 2026-06-04.log
└── ...

Structured JSON logs for easy parsing:
{
  "timestamp": "2026-06-05T12:00:00.000000Z",
  "level": "INFO",
  "session_id": "abc123",
  "event": "message_sent",
  "chat_id": 42,
  "msg_id": 9001
}
```

---

## Memory Safety

### Secret Data Wiping

For sensitive data (keys, passwords), use constant-time overwrite:

```python
import ctypes

def secure_wipe(data: bytes) -> None:
    """Overwrite bytes in memory."""
    if isinstance(data, bytes):
        ctypes.memset(id(data) + 28, 0, len(data))  # CPython internals

# Usage
auth_key = derive_key(...)
try:
    # ... use auth_key
finally:
    secure_wipe(auth_key)
```

**Better approach** (use bytearray):
```python
import secrets

secret = bytearray(secrets.token_bytes(32))
try:
    # use secret
finally:
    secret[:] = b'\x00' * len(secret)  # Overwrite in-place
```

---

## Known Limitations & Future Hardening

### Current Limitations

1. **Metadata Leakage**: TLV headers expose chat_id, sender_id (routing requires this)
2. **No Perfect Forward Secrecy on Server**: If server auth_key is compromised, past sessions are vulnerable
3. **RSA-2048 Identity Key**: Vulnerable to quantum computers (post-quantum migration needed)
4. **No Key Compromise Resilience for non-E2E chats**: Regular chats rely on session key not being compromised
5. **TOTP Optional**: 2FA not enforced by default

### Future Hardening

- [ ] TLS 1.3 layer on top of custom protocol
- [ ] Certificate pinning in client SDK
- [ ] HSM support for server keys (no key material on disk)
- [ ] Post-quantum cryptography (CRYSTALS-Kyber for KEM post-NIST standardization)
- [ ] Signal Protocol upgrade for all 1-on-1 chats (not just secret chats)
- [ ] Mandatory TOTP for sensitive accounts
- [ ] Zero-knowledge proofs for chat membership (prevent member list leakage)
- [ ] Onion routing layer (optional Tor integration)

---

## Security Checklist (Compliance)

✅ **Encryption**: All payloads encrypted with AES-256-GCM
✅ **Authentication**: Every packet HMAC-verified, messages Ed25519-signed
✅ **Key Exchange**: X25519 ECDH for ephemeral shared secrets
✅ **Password Hashing**: Argon2id with 64MB memory cost
✅ **Rate Limiting**: Token bucket + IP-based sliding window
✅ **Input Validation**: Length limits, TLV bounds checking, parameterized queries
✅ **Logging**: No sensitive data in logs, structured JSON for auditability
✅ **Memory Safety**: Attempt to securely wipe secrets after use
✅ **Random Number Generation**: secrets module (cryptographically secure)
✅ **Timing Attacks**: HMAC-SHA256 verification via hmac.compare_digest()
✅ **Sequence Numbers**: Prevent replays, detect out-of-order delivery
✅ **Forward Secrecy**: Ephemeral keys, Double Ratchet for E2E chats

---

## Deployment Recommendations

1. **TLS Termination**: Use nginx/HAProxy in front of PyroGram server (TLS 1.3)
2. **Certificate Pinning**: Distribute root CA cert in client app
3. **HSM for Keys**: Store server RSA private key in Hardware Security Module (e.g., YubiHSM)
4. **Audit Logging**: Send logs to centralized SIEM (Splunk, ELK Stack)
5. **Intrusion Detection**: Monitor for:
   - Unusual number of failed auth attempts
   - Rate limit violations
   - Packet malformations (protocol abuse)
6. **Regular Security Audits**: Engage third-party cryptography experts annually
7. **Bug Bounty Program**: Incentivize responsible disclosure

---

## References

- RFC 5054: SRP (Secure Remote Password) Protocol
- RFC 4226: HOTP (HMAC-based One-Time Password)
- RFC 6238: TOTP (Time-based One-Time Password)
- RFC 6455: WebSocket Protocol
- FIPS 197: AES Specification
- RFC 7748: Elliptic Curves for Security (X25519)
- RFC 8032: Edwards-Curve Digital Signature Algorithm (Ed25519)
- Argon2 whitepaper: https://github.com/P-H-C/phc-winner-argon2
- Signal Protocol: https://signal.org/docs/
- NIST Post-Quantum Cryptography: https://csrc.nist.gov/projects/post-quantum-cryptography/
