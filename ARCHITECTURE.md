# PyroGram Architecture

A production-grade messenger application with a fully custom stack, inspired by Telegram's architecture but built from scratch in pure Python.

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    PyroGram Messenger System                     │
└─────────────────────────────────────────────────────────────────┘

                         ┌──────────────────────┐
                         │   CLI Client SDK     │
                         │  (MessengerClient)   │
                         └──────┬───────────────┘
                                │
                 ┌──────────────┴──────────────┐
                 │                             │
        ┌────────▼────────┐        ┌───────────▼────────┐
        │  TCP Transport  │        │ WebSocket Transport│
        │  (length-prefix)│        │  (RFC 6455 impl)   │
        └────────┬────────┘        └───────────┬────────┘
                 │                             │
                 └──────────────┬──────────────┘
                                │
                      ┌─────────▼────────┐
                      │  Connection Mgr  │ ◄─ tracks all active sessions
                      └─────────┬────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
    ┌───▼─────┐         ┌──────▼─────┐         ┌──────▼──────┐
    │Dispatcher│         │Auth Module │         │Rate Limiter │
    │(handlers)│         │  (SRP-6a)  │         │(token bucket)│
    └───┬─────┘         └──────┬─────┘         └──────┬──────┘
        │                      │                      │
        ├──────────────────────┼──────────────────────┤
        │                      │                      │
    ┌───▼─────────┐  ┌────────▼──────┐  ┌────────────▼──┐
    │CryptoManager │  │Database Engine│  │FileManager    │
    │ (E2E, AES,  │  │(custom BTree, │  │ (chunked,    │
    │  Ed25519)   │  │ WAL, paging)  │  │  encrypted)  │
    └─────────────┘  └───────┬───────┘  └──────────────┘
                              │
                      ┌───────▼────────┐
                      │  Update Queue  │
                      │  (per-user DB) │
                      └────────────────┘


CORE MODULES:
=============

┌─ core/
│  ├─ protocol/       TLV-encoded binary protocol (custom MTProto-style)
│  ├─ crypto/         X25519 ECDH, AES-256-GCM, Ed25519, Argon2id, TOTP
│  ├─ database/       B-Tree storage engine with WAL, page cache
│  ├─ network/        TCP + WebSocket dual-transport layer
│  ├─ auth/           SRP-6a authentication, session management
│  └─ dispatcher/     Message routing, update fanout, event bus
│
├─ server/
│  ├─ app.py         Main asyncio server loop
│  ├─ handlers/      Request handlers per message type
│  └─ middleware/    Auth, rate limiting, validation pipeline
│
├─ client/
│  ├─ cli_client.py  Terminal UI client
│  └─ sdk/
│     └─ messenger.py Client SDK (reusable for Android/Web)
│
└─ tests/
   ├─ unit/         Protocol, crypto, database tests
   ├─ integration/  Full message flow tests
   └─ benchmarks/   Performance tests


## Data Flow: "User Sends a Message"

┌──────────────────────────────────────────────────────────────┐
│ 1. CLIENT SIDE                                               │
├──────────────────────────────────────────────────────────────┤
│ User types: /msg alice hello world                           │
│                                                              │
│ MessengerClient.send_message(chat_id=42, text="hello world") │
│ ↓                                                            │
│ Generate msg_key = SHA256(auth_key_substr + plaintext)       │
│ ↓                                                            │
│ Derive: aes_key, aes_iv = KDF(auth_key, msg_key)             │
│ ↓                                                            │
│ plaintext_msg = TLV(type=MSG, chat_id=42, text="hello...", │
│                     timestamp=now(), random_id=random128)    │
│ ↓                                                            │
│ ciphertext = AES-256-GCM(plaintext_msg, aes_key, aes_iv)     │
│ ↓                                                            │
│ packet = Packet(                                             │
│   magic=0xDEADF00D,                                          │
│   version=1,                                                 │
│   type=SEND_MESSAGE,                                         │
│   seq=1234,                                                  │
│   timestamp=now_us,                                          │
│   payload=ciphertext,                                        │
│   hmac=HMAC-SHA256(entire_packet, auth_key)                  │
│ )                                                            │
│ ↓                                                            │
│ Serialize: bytes = struct.pack(...) + ciphertext + hmac      │
│ ↓                                                            │
│ Send over TCP or WebSocket                                   │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ 2. NETWORK                                                   │
├──────────────────────────────────────────────────────────────┤
│ TCP Transport: send_frame(length || bytes)                   │
│ WebSocket Transport: apply RFC 6455 framing, masking         │
│                                                              │
│ Backpressure: pause reading if send buffer > threshold       │
│ Rate limiting: token bucket check (messages/sec per client)  │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ 3. SERVER SIDE                                               │
├──────────────────────────────────────────────────────────────┤
│ ConnectionManager.handle_data(session_id, bytes)             │
│ ↓                                                            │
│ ProtocolParser.parse(bytes) → Packet                         │
│ ↓                                                            │
│ Verify HMAC-SHA256(packet, auth_key_from_session)            │
│ ↓                                                            │
│ Dispatcher.route(packet.type, packet) → handler              │
│ ↓                                                            │
│ AuthMiddleware: verify session is not expired                │
│ ↓                                                            │
│ RateLimitMiddleware: check tokens available                  │
│ ↓                                                            │
│ ValidationMiddleware: check chat_id belongs to user          │
│ ↓                                                            │
│ HandlerSendMessage(packet):                                  │
│   - Decrypt ciphertext with auth_key                         │
│   - Parse TLV payload                                        │
│   - Validate message length, encoding                        │
│   - Check sender has permission in chat                      │
│   - Database.insert_message(                                 │
│       chat_id=42,                                            │
│       sender_id=alice_id,                                    │
│       body_encrypted=ciphertext,                             │
│       timestamp=msg_ts,                                      │
│       random_id=msg.random_id  ← dedup key                   │
│     )                                                        │
│   - Return ACK(seq=1234) to client                           │
│ ↓                                                            │
│ MESSAGE FANOUT:                                              │
│ For each member in chat_42:                                  │
│   - Create Update(                                           │
│       update_id=next_update_id(user),                        │
│       type=NEW_MESSAGE,                                      │
│       data={msg_id, sender_id, timestamp}                    │
│     )                                                        │
│   - Database.insert_update(user_id, update)                  │
│   - If user is connected:                                    │
│       ConnectionManager.push_to_user(user_id, update)        │
│   - Else: update sits in queue for long-poll                 │
│                                                              │
│ Database.insert_update() uses WAL + batch commit             │
└─────────────────���────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ 4. RECEIVING CLIENT (bob)                                    │
├──────────────────────────────────────────────────────────────┤
│ Two paths depending on connection state:                     │
│                                                              │
│ PATH A: Bob connected (persistent TCP/WS)                    │
│   Server pushes: UPDATE_FRAME(update_id=999, ...)            │
│   ↓                                                          │
│   MessengerClient receives via on("update", callback)        │
│   ↓                                                          │
│   Bob's UI renders: "alice: hello world"                     │
│   ↓                                                          │
│   Bob sends: ACK(update_id=999)                              │
│   ↓                                                          │
│   Server marks update as delivered                           │
│                                                              │
│ PATH B: Bob offline (no connection)                          │
│   Updates accumulate in DB update queue                      │
│   ↓                                                          │
│   When Bob reconnects:                                       │
│   MessengerClient.get_updates(offset=last_update_id) calls   │
│   Server query: SELECT * FROM updates WHERE                  │
│     user_id=bob AND update_id > last_offset LIMIT 100        │
│   ↓                                                          │
│   Server returns batch: [Update1, Update2, ...]              │
│   ↓                                                          │
│   Client renders all, sends: ACK(update_id=latest)           │
│   ↓                                                          │
│   Server deletes acknowledged updates from DB                │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ 5. GROUP MESSAGES (fanout to 1000s of members)               │
├──────────────────────────────────────────────────────────────┤
│ HandlerSendMessage in group chat:                            │
│                                                              │
│ 1. Insert message into DB (fast)                             │
│ 2. Get all members: SELECT user_id FROM members              │
│                      WHERE chat_id=42 (bulk from index)      │
│ 3. Batch insert updates: INSERT INTO updates (bulk operation │
│                         with ~1000 rows)                     │
│ 4. For connected members: async push via ConnectionManager   │
│ 5. For offline members: updates persist in DB, fetched on    │
│    reconnect via long-poll or on-connect getUpdates          │
│                                                              │
│ Optimization: Use asyncio.gather(*push_tasks) for concurrency│
└──────────────────────────────────────────────────────────────┘


## Component Responsibilities

### protocol/
- ProtocolParser: parse() and serialize() for custom binary format
- MessageType enum: all packet types (AUTH, MSG, ACK, PING, etc.)
- TLVCodec: encode/decode Type-Length-Value fields
- PacketFragmentation: handle packets > MTU

### crypto/
- CryptoManager: facade for all crypto operations
- X25519KeyExchange: ephemeral ECDH handshake
- AES256GCM: per-message symmetric encryption
- DoubleRatchet: Signal Protocol-style E2E for secret chats
- Ed25519: message signing and identity verification
- Argon2id: password hashing
- SRP6A: zero-knowledge authentication
- TOTP: RFC 6238 two-factor authentication

### database/
- StorageEngine: BTree-based embedded DB
- PageManager: 4KB page allocation and caching
- WAL: Write-Ahead Log for crash recovery
- QueryBuilder: WHERE, ORDER BY, LIMIT, OFFSET
- TransactionManager: ACID transactions with row locking
- Tables: Users, Sessions, Chats, Messages, Members, Files, Updates

### network/
- TransportBase: abstract transport interface
- TCPTransport: asyncio TCP with length-prefix framing
- WebSocketTransport: RFC 6455 frame parser and composer
- ConnectionManager: session tracking, multiplexing
- Multiplexer: virtual channels with flow control
- RateLimiter: token bucket and sliding window

### auth/
- Authenticator: SRP-6a login/registration flow
- SessionManager: session creation, refresh, TTL
- MultiDeviceManager: track all sessions per user
- TOTPManager: TOTP setup and verification
- KeyVerification: safety number / emoji sequence

### dispatcher/
- MessageDispatcher: route by message type
- Middleware: auth, rate limit, validation pipeline
- HandlerRegistry: @handler decorators
- UpdateQueue: per-user update list
- LongPoller: getUpdates(offset, timeout) implementation
- FanoutQueue: async task queue for group message delivery

### file_transfer/
- FileManager: chunk upload/download
- ChunkProcessor: encrypt, verify SHA-256
- ContentAddressable: deduplication by file hash
- StreamingDownload: serve without loading to RAM
- PauseResumeManager: state tracking for incomplete transfers


## Session Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│ 1. CLIENT CONNECTS                                          │
├─────────────────────────────────────────────────────────────┤
│ TCP/WebSocket connection established                        │
│ ↓                                                           │
│ Client sends: AUTH_REQUEST(username, client_public_A)       │
│ ↓                                                           │
│ Server responds: AUTH_CHALLENGE(salt, server_public_B)      │
│                                                             │
│ 2. SRP-6a KEY AGREEMENT                                     │
├─────────────────────────────────────────────────────────────┤
│ Both compute: S = (B ^ (k*g^x))^(a + u*x) mod N              │
│ Derive: auth_key = SHA256(S)                                │
│                                                             │
│ 3. MUTUAL AUTHENTICATION                                    │
├─────────────────────────────────────────────────────────────┤
│ Client → Server: PROOF_M1                                    │
│ Server → Client: PROOF_M2                                    │
│ Both verify SRP proofs                                       │
│                                                             │
│ 4. SESSION CREATION                                         │
├─────────────────────────────────────────────────────────────┤
│ If proofs match:                                            │
│ session_id = UUID4()                                        │
│ Server stores: Session {                                    │
│   session_id,                                               │
│   user_id,                                                  │
│   auth_key,                                                 │
│   device_info,                                              │
│   created_at,                                               │
│   expires_at = now + 30 days                                │
│ }                                                           │
│                                                             │
│ Server → Client: SUCCESS(session_id, auth_key_encrypted)    │
│                                                             │
│ 5. MESSAGE EXCHANGE (authenticated)                         │
├─────────────────────────────────────────────────────────────┤
│ All subsequent packets are encrypted with auth_key          │
│ Each packet has: seq, timestamp, type, payload, HMAC        │
│                                                             │
│ 6. SESSION REFRESH                                          │
├─────────────────────────────────────────────────────────────┤
│ Client sends: REFRESH_TOKEN(session_id, refresh_token)      │
│ Server: extends expires_at, returns new refresh token       │
│                                                             │
│ 7. DISCONNECTION                                            │
├─────────────────────────────────────────────────────────────┤
│ Connection closed (clean or timeout)                        │
│ Updates accumulate in DB until next reconnect               │
│ Session persists for grace period (5 minutes)               │
│ Reconnect with same session_id = automatic recovery         │
│                                                             │
│ 8. LOGOUT                                                   │
├─────────────────────────────────────────────────────────────┤
│ Client sends: LOGOUT(session_id)                            │
│ Server: removes session from active pool, flags as logged   │
│ Next connection attempt must re-authenticate                │
└─────────────────────────────────────────────────────────────┘
```


## Concurrency Model

- **asyncio everywhere**: no threads except for blocking I/O where necessary
- **Connections**: each active client connection runs in its own asyncio task
- **Database**: async context manager for transactions, row-level locks via asyncio.Lock
- **Fanout**: asyncio.gather() for concurrent update delivery to group members
- **File I/O**: aiofiles for async disk operations
- **No GIL issues**: all CPU-bound work (crypto, serialization) is performed on main event loop


## Storage Layout

```
server_data/
├── messenger.db          # Main database file (pages)
├── messenger.db-wal      # Write-Ahead Log for crash recovery
├── messenger.db-cache    # Optional page cache dump for fast startup
└── files/
    ├── {file_id_1}       # Raw file bytes (content-addressable)
    ├── {file_id_2}
    └── ...
```

## Error Handling Strategy

- **Protocol errors**: malformed packets trigger connection close (cannot trust stream)
- **Auth errors**: return specific error code (invalid proof, session expired)
- **Database errors**: transactional rollback, retry logic for deadlocks
- **Crypto errors**: never log sensitive data, return generic "decryption failed"
- **All exceptions**: typed exceptions, no bare except, structured logging


## Performance Targets & Trade-offs

| Metric | Target | Strategy |
|--------|--------|----------|
| Concurrent connections | 10,000/server | TCP_NODELAY, SO_KEEPALIVE, connection pooling |
| Message latency | <50ms | Local delivery without extra hops, pipelined fanout |
| DB throughput | >50k inserts/sec | Batch writes, WAL buffering, B-Tree index |
| Protocol overhead | <8% | TLV encoding, no padding except alignment |
| Crypto throughput | >1M packets/sec | Hardware AES (via cryptography lib), Ed25519 (fast) |

## Security Principles

1. **Zero Trust**: every packet verified (HMAC, signature)
2. **Forward Secrecy**: ephemeral keys, ratcheting in E2E chats
3. **Defense in Depth**: auth layers, rate limiting, input validation
4. **No Plaintext**: sensitive data wiped from memory, never logged
5. **Constant Time**: HMAC comparisons, signature verification
