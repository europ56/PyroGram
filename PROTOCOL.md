# PyroGram Protocol Specification

## Overview

PyroGram uses a custom binary protocol designed for low-latency, high-throughput messaging. The protocol is inspired by Telegram's MTProto but implemented from scratch. Every message is encrypted, authenticated, and sequenced.

---

## Protocol Version

Current: **1.0**

Version negotiation occurs during the handshake phase. Servers support a range of versions; clients must upgrade if disconnected with `VERSION_NOT_SUPPORTED`.

---

## Packet Format

### Header (56 bytes fixed)

```
 0- 3    Magic Number         [0xDE, 0xAD, 0xF0, 0x0D]  (4 bytes)
 4- 5    Protocol Version     Big-endian u16             (2 bytes)
 6- 6    Message Type         u8 enum                    (1 byte)
 7- 7    Flags                u8 bitfield                (1 byte)
 8-11    Payload Length       Big-endian u32             (4 bytes)
12-19    Sequence Number      Big-endian u64             (8 bytes)
20-27    Timestamp            Big-endian u64 (μs)        (8 bytes)
28-31    Reserved             All zeros                  (4 bytes)
32-55    Per-packet Nonce     Random 24 bytes            (24 bytes)

TOTAL HEADER: 56 bytes
```

### Payload

```
Variable-length TLV (Type-Length-Value) encoded data
Minimum: 1 byte, Maximum: 2^32 - 1 bytes
```

### Authentication Tag

```
32-byte HMAC-SHA256 of (header || payload || nonce_used)
Computed using session auth_key
```

### Complete Packet

```
[Header (56 bytes)] [Payload (1 to 2^32-1 bytes)] [HMAC (32 bytes)]
```

---

## Flags (1 byte bitfield)

```
Bit 0: ENCRYPTED         (1 = payload is encrypted, 0 = plaintext)
Bit 1: COMPRESSED        (1 = payload is gzip-compressed)
Bit 2: FRAGMENTED        (1 = more fragments follow)
Bit 3: RESPONSE_NEEDED   (1 = client expects ACK)
Bit 4: RELIABLE          (1 = server must ACK or retry)
Bit 5: PRIORITY          (1 = high priority, process first)
Bit 6: RESERVED
Bit 7: RESERVED

Example flags:
  ENCRYPTED | RESPONSE_NEEDED  = 0b00001001 = 0x09
  ENCRYPTED | RELIABLE         = 0b00010001 = 0x11
```

---

## Message Types (u8 enum)

| Value | Name | Direction | Description |
|-------|------|-----------|-------------|
| 0x01 | AUTH_INIT | C→S | Initiate SRP-6a handshake |
| 0x02 | AUTH_CHALLENGE | S→C | Server challenge (salt, public) |
| 0x03 | AUTH_PROOF | C→S | Client proof (M1) |
| 0x04 | AUTH_SUCCESS | S→C | Authentication succeeded |
| 0x05 | AUTH_FAIL | S→C | Authentication failed |
| 0x10 | SEND_MESSAGE | C→S | User sends a message |
| 0x11 | MESSAGE_ACK | S→C | Server acknowledges message |
| 0x12 | RECEIVE_MESSAGE | S→C | New message for client (push) |
| 0x20 | GET_UPDATES | C→S | Fetch updates (long-poll) |
| 0x21 | UPDATES | S→C | Batch of updates |
| 0x22 | UPDATE_ACK | C→S | Acknowledge received updates |
| 0x30 | FILE_CHUNK_UPLOAD | C→S | Upload file chunk |
| 0x31 | FILE_CHUNK_ACK | S→C | Chunk received, request next |
| 0x32 | FILE_CHUNK_DOWNLOAD | C→S | Request file chunk |
| 0x33 | FILE_CHUNK_DATA | S→C | File chunk data |
| 0x40 | PING | C→S or S→C | Keep-alive |
| 0x41 | PONG | S→C or C→S | Keep-alive response |
| 0x50 | ERROR | S→C | Error response |
| 0x51 | DISCONNECT | C→S or S→C | Clean disconnect |
| 0x60 | CREATE_CHAT | C→S | Create group chat |
| 0x61 | CHAT_CREATED | S→C | Chat created confirmation |
| 0x62 | JOIN_CHAT | C→S | Join existing chat |
| 0x63 | MEMBER_JOINED | S→C | Update: member joined |
| 0x64 | LEAVE_CHAT | C→S | Leave chat |
| 0x65 | MEMBER_LEFT | S→C | Update: member left |
| 0x70 | TYPING_INDICATOR | C→S | User is typing |
| 0x71 | TYPING_UPDATE | S→C | Update: user typing in chat |
| 0x80 | READ_RECEIPT | C→S | Mark messages as read |
| 0x81 | READ_UPDATE | S→C | Update: messages read by user |
| 0x90 | SECRET_CHAT_INIT | C→S | Initiate secret (E2E) chat |
| 0x91 | SECRET_CHAT_KEY | S→C | Secret chat keys (DH) |
| 0x92 | SECRET_CHAT_READY | C→S | Client confirms E2E ready |
| 0x93 | SECRET_CHAT_MESSAGE | C→S | Encrypted message (Double Ratchet) |

---

## TLV (Type-Length-Value) Encoding

Payloads use TLV encoding for extensibility and forward compatibility.

### Format

```
 0-3    Type              Big-endian u32 (tag ID)        (4 bytes)
 4-7    Length            Big-endian u32 (value length)  (4 bytes)
 8-N    Value             Raw bytes                      (Length bytes)

Total for one TLV: 8 + Length bytes
```

Multiple TLV fields are concatenated in a single payload.

### Common TLV Types

| Tag ID | Name | Value Type | Length |
|--------|------|-----------|--------|
| 0x001 | USERNAME | UTF-8 string | 1-64 bytes |
| 0x002 | USER_ID | u64 big-endian | 8 bytes |
| 0x003 | AUTH_KEY | binary | 32 bytes (unused in plaintext) |
| 0x004 | SRP_SALT | binary | 32 bytes |
| 0x005 | SRP_PUBLIC_A | binary | 256 bytes |
| 0x006 | SRP_PUBLIC_B | binary | 256 bytes |
| 0x007 | SRP_PROOF_M1 | binary | 64 bytes |
| 0x008 | SRP_PROOF_M2 | binary | 64 bytes |
| 0x009 | SESSION_ID | UUID (binary) | 16 bytes |
| 0x00A | DEVICE_INFO | JSON string | variable |
| 0x010 | MESSAGE_ID | u64 | 8 bytes |
| 0x011 | CHAT_ID | u64 | 8 bytes |
| 0x012 | SENDER_ID | u64 | 8 bytes |
| 0x013 | MESSAGE_TEXT | UTF-8 string | 1-65535 bytes |
| 0x014 | MESSAGE_TYPE | u8 enum | 1 byte |
| 0x015 | TIMESTAMP | u64 (μs) | 8 bytes |
| 0x016 | RANDOM_ID | binary (dedup) | 16 bytes |
| 0x017 | PREV_MESSAGE_ID | u64 (replies) | 8 bytes |
| 0x020 | CHAT_TITLE | UTF-8 string | 1-256 bytes |
| 0x021 | CHAT_TYPE | u8 enum (private/group/channel) | 1 byte |
| 0x022 | MEMBER_IDS | array of u64 | 8*N bytes |
| 0x030 | FILE_ID | u64 | 8 bytes |
| 0x031 | FILE_NAME | UTF-8 string | 1-256 bytes |
| 0x032 | FILE_SIZE | u64 | 8 bytes |
| 0x033 | FILE_MIME_TYPE | ASCII string | 1-128 bytes |
| 0x034 | CHUNK_INDEX | u32 | 4 bytes |
| 0x035 | CHUNK_DATA | binary | 1-524288 bytes |
| 0x036 | FILE_HASH_SHA256 | binary | 32 bytes |
| 0x050 | UPDATE_ID | u64 (monotonic per user) | 8 bytes |
| 0x051 | UPDATE_TYPE | u8 enum | 1 byte |
| 0x052 | UPDATE_DATA | JSON or nested TLV | variable |
| 0x060 | ERROR_CODE | u32 enum | 4 bytes |
| 0x061 | ERROR_TEXT | UTF-8 string | 1-1024 bytes |
| 0x070 | SIGNATURE_ED25519 | binary | 64 bytes |
| 0x071 | PUBKEY_ED25519 | binary | 32 bytes |
| 0x080 | ENCRYPTION_KEY | binary | 32 bytes (for E2E key negotiation) |
| 0x081 | RATCHET_KEY | binary | 32 bytes (Double Ratchet state) |

---

## Handshake Flow (SRP-6a Authentication)

### Phase 1: Client Initiates

**Client → Server: AUTH_INIT**

```
Flags: ENCRYPTED=0 (plaintext for handshake)
Payload TLVs:
  0x001 (USERNAME) = "alice"
  0x005 (SRP_PUBLIC_A) = <256 bytes of A>
  0x00A (DEVICE_INFO) = '{"os":"linux","app":"pyrogram-cli","version":"1.0"}'
```

### Phase 2: Server Responds

**Server → Client: AUTH_CHALLENGE**

```
Flags: ENCRYPTED=0
Payload TLVs:
  0x004 (SRP_SALT) = <32 random bytes>
  0x006 (SRP_PUBLIC_B) = <256 bytes of B>
  (Timestamp included in packet header)
```

### Phase 3: Client Proves Knowledge

**Client → Server: AUTH_PROOF**

```
Flags: ENCRYPTED=0
Payload TLVs:
  0x007 (SRP_PROOF_M1) = SHA256(H(N) XOR H(g) || H(username) || salt || A || B || S)
  0x001 (USERNAME) = "alice" (repeat for verification)
```

### Phase 4: Server Validates and Issues Session

**Server → Client: AUTH_SUCCESS or AUTH_FAIL**

On success:
```
Flags: ENCRYPTED=0
Payload TLVs:
  0x008 (SRP_PROOF_M2) = SHA256(A || M1 || S)  [mutual auth]
  0x009 (SESSION_ID) = <16 bytes UUID>
  0x002 (USER_ID) = <8 bytes>
  [Session auth_key is derived from S, not transmitted]
```

On failure:
```
Flags: ENCRYPTED=0
Payload TLVs:
  0x060 (ERROR_CODE) = 0x0001
  0x061 (ERROR_TEXT) = "Invalid proof"
```

After successful AUTH_SUCCESS, all subsequent packets are encrypted with the session auth_key.

---

## Message Send Flow (Authenticated)

### Client → Server: SEND_MESSAGE

```
Flags: ENCRYPTED=1 | RESPONSE_NEEDED=1 = 0x09
Sequence: incremented by 1 each message
Payload TLVs (encrypted):
  0x011 (CHAT_ID) = 42
  0x013 (MESSAGE_TEXT) = "hello alice!"
  0x015 (TIMESTAMP) = 1717628400000000 (Unix microseconds)
  0x016 (RANDOM_ID) = <16 bytes random, for deduplication>
  0x070 (SIGNATURE_ED25519) = <sign sender_id || chat_id || timestamp || text with Ed25519 key>
```

### Server → Client: MESSAGE_ACK

```
Flags: ENCRYPTED=1
Sequence: same as request (for correlation)
Payload TLVs (encrypted):
  0x010 (MESSAGE_ID) = 9001
  0x015 (TIMESTAMP) = server_timestamp
  [Verifies: client's seq was received]
```

### Server → All Group Members: RECEIVE_MESSAGE (push)

Each member connected to the server receives:
```
Flags: ENCRYPTED=1 | PRIORITY=1 = 0x21
Payload TLVs (encrypted for each member with their auth_key):
  0x010 (MESSAGE_ID) = 9001
  0x011 (CHAT_ID) = 42
  0x012 (SENDER_ID) = alice_id
  0x013 (MESSAGE_TEXT) = "hello alice!"
  0x015 (TIMESTAMP) = 1717628400000000
  0x070 (SIGNATURE_ED25519) = <signature>
```

---

## Update Queue & Long-Poll

### Client → Server: GET_UPDATES

```
Flags: ENCRYPTED=1
Payload TLVs:
  0x050 (UPDATE_ID) = offset (0 to fetch all)
  0x015 (TIMESTAMP) = timeout in seconds (e.g., 30)
  (Server holds connection open up to `timeout` if no updates)
```

### Server → Client: UPDATES

```
Flags: ENCRYPTED=1
Payload TLVs (repeated for each update):
  0x050 (UPDATE_ID) = 1000
  0x051 (UPDATE_TYPE) = 0x01 (NEW_MESSAGE)
  0x052 (UPDATE_DATA) = '{"msg_id":9001,"sender_id":2,"text":"hello"}'

  0x050 (UPDATE_ID) = 1001
  0x051 (UPDATE_TYPE) = 0x02 (MESSAGE_EDITED)
  0x052 (UPDATE_DATA) = '{"msg_id":9001,"new_text":"hello world"}'
```

### Client → Server: UPDATE_ACK

```
Flags: ENCRYPTED=1
Payload TLVs:
  0x050 (UPDATE_ID) = 1001  (acknowledges all updates up to this ID)
```

---

## File Transfer Protocol

### Step 1: Upload Chunk

**Client → Server: FILE_CHUNK_UPLOAD**

```
Flags: ENCRYPTED=1 | RELIABLE=1 = 0x11
Payload TLVs:
  0x030 (FILE_ID) = 0 (0 = new file, else resuming)
  0x031 (FILE_NAME) = "photo.jpg"
  0x032 (FILE_SIZE) = 5242880
  0x033 (FILE_MIME_TYPE) = "image/jpeg"
  0x034 (CHUNK_INDEX) = 0
  0x035 (CHUNK_DATA) = <up to 512KB of encrypted file bytes>
  0x036 (FILE_HASH_SHA256) = SHA256(file[0:512KB])
```

### Step 2: Server Acknowledges

**Server → Client: FILE_CHUNK_ACK**

```
Flags: ENCRYPTED=1
Payload TLVs:
  0x030 (FILE_ID) = 123 (assigned by server)
  0x034 (CHUNK_INDEX) = 0
  (If successful, client uploads next chunk with FILE_ID=123, CHUNK_INDEX=1)
```

### Complete File Upload

After all chunks uploaded and acknowledged:
- Server computes SHA256(entire file)
- Stores file in server_data/files/{file_id}
- Returns FILE_ID to client for later download or share

### Download

**Client → Server: FILE_CHUNK_DOWNLOAD**

```
Flags: ENCRYPTED=1
Payload TLVs:
  0x030 (FILE_ID) = 123
  0x034 (CHUNK_INDEX) = 0
```

**Server → Client: FILE_CHUNK_DATA**

```
Flags: ENCRYPTED=1
Payload TLVs:
  0x030 (FILE_ID) = 123
  0x034 (CHUNK_INDEX) = 0
  0x035 (CHUNK_DATA) = <512KB encrypted file bytes>
```

---

## Secret Chat (End-to-End Encrypted)

For private 1-on-1 chats with E2E encryption using Double Ratchet.

### Initialization

**User A → User B: SECRET_CHAT_INIT**

```
Flags: ENCRYPTED=1
Payload TLVs:
  0x011 (CHAT_ID) = new_secret_chat_id
  0x012 (SENDER_ID) = user_a_id
  0x071 (PUBKEY_ED25519) = user_a_identity_public_key (32 bytes)
  0x080 (ENCRYPTION_KEY) = user_a_ephemeral_public (X25519, 32 bytes)
```

**User B → User A: SECRET_CHAT_KEY**

```
Flags: ENCRYPTED=1
Payload TLVs:
  0x011 (CHAT_ID) = secret_chat_id
  0x071 (PUBKEY_ED25519) = user_b_identity_public_key
  0x080 (ENCRYPTION_KEY) = user_b_ephemeral_public (X25519)
```

Both sides compute shared secret via X25519 ECDH, derive root key via HKDF-SHA256, initialize Double Ratchet state.

**User B → User A: SECRET_CHAT_READY**

```
Flags: ENCRYPTED=1 (now encrypted with ratchet)
Payload TLVs:
  0x011 (CHAT_ID) = secret_chat_id
```

### Message Exchange

**User A → User B: SECRET_CHAT_MESSAGE**

```
Flags: ENCRYPTED=1
Payload TLVs:
  0x011 (CHAT_ID) = secret_chat_id
  0x013 (MESSAGE_TEXT) = "encrypted hello"
  0x081 (RATCHET_KEY) = current_dh_public (32 bytes)
  0x010 (MESSAGE_ID) = msg_id
  0x016 (RANDOM_ID) = random_for_dedup
  (Message body encrypted with current send chain key)
  0x070 (SIGNATURE_ED25519) = sign(msg_id || text || timestamp with User A's identity key)
```

Each message advances the send chain. Recipient extracts ratchet_key, advances receive chain, decrypts, verifies signature.

---

## Error Handling

### Error Response

**Server → Client: ERROR**

```
Flags: ENCRYPTED=1 (if session exists) or ENCRYPTED=0 (auth errors)
Payload TLVs:
  0x060 (ERROR_CODE) = error_code
  0x061 (ERROR_TEXT) = human-readable message
```

### Error Codes

| Code | Name | Meaning |
|------|------|---------|
| 0x0001 | INVALID_AUTH | Authentication failed |
| 0x0002 | SESSION_EXPIRED | Session TTL exceeded |
| 0x0003 | INVALID_SIGNATURE | Message signature verification failed |
| 0x0004 | INVALID_HMAC | Packet HMAC mismatch |
| 0x0005 | RATE_LIMITED | Too many requests |
| 0x0006 | NOT_FOUND | Resource not found (chat, file, etc.) |
| 0x0007 | PERMISSION_DENIED | User lacks permission for action |
| 0x0008 | INVALID_CHAT_ID | Chat does not exist or user not member |
| 0x0009 | INVALID_MESSAGE_ID | Message not found |
| 0x000A | FILE_NOT_FOUND | File does not exist |
| 0x000B | CHUNK_MISMATCH | File chunk hash verification failed |
| 0x000C | VERSION_NOT_SUPPORTED | Protocol version not supported |
| 0x000D | INTERNAL_SERVER_ERROR | Server error (retry later) |

---

## Keep-Alive (Ping-Pong)

Every 30 seconds (configurable), client may send PING:

**Client → Server: PING**

```
Flags: ENCRYPTED=1
Sequence: incremented
Payload TLVs: (empty)
```

**Server → Client: PONG**

```
Flags: ENCRYPTED=1
Sequence: same as request
Payload TLVs: (empty)
```

Server responds immediately. If server receives no data (ping or message) for 5 minutes, closes connection.

---

## Encryption Details

All encrypted payloads use:
1. **Derivation**: msg_key = SHA256(auth_key[88:120] + plaintext)
2. **Key & IV derivation**: 
   - Key1 = SHA256(auth_key, msg_key + [0:16])
   - IV1 = SHA256(auth_key, msg_key + [16:32])
3. **Cipher**: AES-256-GCM with IV1 as nonce (96-bit), Key1 as key
4. **Auth tag**: included in GCM
5. **Packet HMAC**: computed *after* encryption as per packet format

---

## Fragmentation

For payloads > 512KB, use FRAGMENTED flag:

**Fragment 1:**
```
Flags: ENCRYPTED=1 | FRAGMENTED=1 = 0x05
Sequence: N
Fragment Index: 0
Total Fragments: 10
Payload Length: 512KB
```

**Fragment 2-9:**
```
Flags: ENCRYPTED=1 | FRAGMENTED=1 = 0x05
Sequence: N
Fragment Index: 1-8
Total Fragments: 10
Payload Length: 512KB
```

**Fragment 10 (final):**
```
Flags: ENCRYPTED=1  (FRAGMENTED=0, signals completion)
Sequence: N
Fragment Index: 9
Total Fragments: 10
Payload Length: remaining bytes
```

Receiver reassembles, verifies SHA256 of complete reconstructed payload.

---

## Compression

If COMPRESSED flag is set, payload is gzip-compressed before encryption. Decompressed by receiver after decryption.

```
plaintext → gzip compress → AES-256-GCM encrypt → transmit
receive → AES-256-GCM decrypt → gzip decompress → plaintext
```

---

## Sequence Number Semantics

- Sequence numbers are per-session, starting at 1 after successful AUTH_SUCCESS
- Incremented by sender for each message sent
- Allows receiver to detect:
  - Packet loss (gap in sequence)
  - Out-of-order delivery (reorder buffer keeps last 100 packets)
  - Retransmissions (duplicate seq = ACK retry, ignore)

---

## Performance Notes

- Packet parsing: zero-copy for payload, streaming TLV parser
- Serialization: struct module for header, custom buffer for payload
- HMAC computation: done on-the-fly during serialization
- Encryption: hardware-accelerated via cryptography library
- No padding except to page boundaries in storage
