"""
PyroGram Protocol Module

Custom binary protocol implementation with TLV encoding, packet serialization,
and message type registry. Inspired by MTProto but built from scratch.
"""

import struct
import hmac
import hashlib
import secrets
from enum import IntEnum
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from io import BytesIO


# ============================================================================
# Constants
# ============================================================================

MAGIC_HEADER = 0xDEADF00D
PROTOCOL_VERSION = 1
HEADER_SIZE = 56  # Bytes (fixed header before payload)
HMAC_SIZE = 32    # SHA-256 output
NONCE_SIZE = 24   # Per-packet nonce
MAX_PAYLOAD_SIZE = 0xFFFFFFFF  # 4GB max (u32)
MAX_TLV_VALUE_SIZE = 0x1000000  # 16MB per TLV


# ============================================================================
# Message Types Enum
# ============================================================================

class MessageType(IntEnum):
    """Protocol message type identifiers."""
    # Authentication
    AUTH_INIT = 0x01
    AUTH_CHALLENGE = 0x02
    AUTH_PROOF = 0x03
    AUTH_SUCCESS = 0x04
    AUTH_FAIL = 0x05
    
    # Messaging
    SEND_MESSAGE = 0x10
    MESSAGE_ACK = 0x11
    RECEIVE_MESSAGE = 0x12
    
    # Updates
    GET_UPDATES = 0x20
    UPDATES = 0x21
    UPDATE_ACK = 0x22
    
    # File Transfer
    FILE_CHUNK_UPLOAD = 0x30
    FILE_CHUNK_ACK = 0x31
    FILE_CHUNK_DOWNLOAD = 0x32
    FILE_CHUNK_DATA = 0x33
    
    # Keep-alive
    PING = 0x40
    PONG = 0x41
    
    # Errors
    ERROR = 0x50
    DISCONNECT = 0x51
    
    # Chat Management
    CREATE_CHAT = 0x60
    CHAT_CREATED = 0x61
    JOIN_CHAT = 0x62
    MEMBER_JOINED = 0x63
    LEAVE_CHAT = 0x64
    MEMBER_LEFT = 0x65
    
    # Typing & Read Receipts
    TYPING_INDICATOR = 0x70
    TYPING_UPDATE = 0x71
    READ_RECEIPT = 0x80
    READ_UPDATE = 0x81
    
    # Secret Chats (E2E)
    SECRET_CHAT_INIT = 0x90
    SECRET_CHAT_KEY = 0x91
    SECRET_CHAT_READY = 0x92
    SECRET_CHAT_MESSAGE = 0x93


# ============================================================================
# Flags Bitfield (1 byte)
# ============================================================================

class PacketFlags:
    """Packet flag bit positions."""
    ENCRYPTED = 1 << 0        # Bit 0: payload is encrypted
    COMPRESSED = 1 << 1       # Bit 1: payload is gzip-compressed
    FRAGMENTED = 1 << 2       # Bit 2: more fragments follow
    RESPONSE_NEEDED = 1 << 3   # Bit 3: client expects ACK
    RELIABLE = 1 << 4         # Bit 4: server must ACK or retry
    PRIORITY = 1 << 5         # Bit 5: high priority, process first


# ============================================================================
# TLV (Type-Length-Value) Tags
# ============================================================================

class TLVTag(IntEnum):
    """TLV tag identifiers."""
    # Authentication
    USERNAME = 0x001
    USER_ID = 0x002
    AUTH_KEY = 0x003
    SRP_SALT = 0x004
    SRP_PUBLIC_A = 0x005
    SRP_PUBLIC_B = 0x006
    SRP_PROOF_M1 = 0x007
    SRP_PROOF_M2 = 0x008
    SESSION_ID = 0x009
    DEVICE_INFO = 0x00A
    
    # Messaging
    MESSAGE_ID = 0x010
    CHAT_ID = 0x011
    SENDER_ID = 0x012
    MESSAGE_TEXT = 0x013
    MESSAGE_TYPE = 0x014
    TIMESTAMP = 0x015
    RANDOM_ID = 0x016
    PREV_MESSAGE_ID = 0x017
    
    # Chat
    CHAT_TITLE = 0x020
    CHAT_TYPE = 0x021
    MEMBER_IDS = 0x022
    
    # Files
    FILE_ID = 0x030
    FILE_NAME = 0x031
    FILE_SIZE = 0x032
    FILE_MIME_TYPE = 0x033
    CHUNK_INDEX = 0x034
    CHUNK_DATA = 0x035
    FILE_HASH_SHA256 = 0x036
    
    # Updates
    UPDATE_ID = 0x050
    UPDATE_TYPE = 0x051
    UPDATE_DATA = 0x052
    
    # Errors
    ERROR_CODE = 0x060
    ERROR_TEXT = 0x061
    
    # Cryptography
    SIGNATURE_ED25519 = 0x070
    PUBKEY_ED25519 = 0x071
    ENCRYPTION_KEY = 0x080
    RATCHET_KEY = 0x081


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class TLV:
    """Type-Length-Value field."""
    tag: int
    value: bytes
    
    def serialize(self) -> bytes:
        """Serialize TLV to bytes: [tag(4)] [length(4)] [value(N)]."""
        tag_bytes = struct.pack('>I', self.tag)
        length_bytes = struct.pack('>I', len(self.value))
        return tag_bytes + length_bytes + self.value
    
    @staticmethod
    def deserialize(data: bytes, offset: int = 0) -> Tuple['TLV', int]:
        """Deserialize single TLV from bytes. Returns (TLV, new_offset)."""
        if offset + 8 > len(data):
            raise ProtocolError("Truncated TLV header")
        
        tag = struct.unpack('>I', data[offset:offset+4])[0]
        length = struct.unpack('>I', data[offset+4:offset+8])[0]
        
        if length > MAX_TLV_VALUE_SIZE:
            raise ProtocolError(f"TLV value too large: {length} > {MAX_TLV_VALUE_SIZE}")
        
        if offset + 8 + length > len(data):
            raise ProtocolError("Truncated TLV value")
        
        value = data[offset+8:offset+8+length]
        return TLV(tag, value), offset + 8 + length


@dataclass
class Packet:
    """PyroGram protocol packet."""
    magic: int
    version: int
    msg_type: MessageType
    flags: int
    seq_num: int
    timestamp_us: int
    nonce: bytes
    payload: bytes
    hmac: bytes
    
    def get_flag(self, flag: int) -> bool:
        """Check if flag is set."""
        return bool(self.flags & flag)
    
    def set_flag(self, flag: int, enabled: bool = True) -> None:
        """Set or clear a flag."""
        if enabled:
            self.flags |= flag
        else:
            self.flags &= ~flag
    
    @property
    def is_encrypted(self) -> bool:
        return self.get_flag(PacketFlags.ENCRYPTED)
    
    @property
    def is_compressed(self) -> bool:
        return self.get_flag(PacketFlags.COMPRESSED)
    
    @property
    def is_fragmented(self) -> bool:
        return self.get_flag(PacketFlags.FRAGMENTED)
    
    @property
    def needs_response(self) -> bool:
        return self.get_flag(PacketFlags.RESPONSE_NEEDED)


# ============================================================================
# Exceptions
# ============================================================================

class ProtocolError(Exception):
    """Protocol-level error (corrupted packet, etc.)."""
    pass


# ============================================================================
# TLV Codec
# ============================================================================

class TLVCodec:
    """Encode/decode Type-Length-Value payloads."""
    
    @staticmethod
    def encode(tlvs: List[TLV]) -> bytes:
        """Encode list of TLVs into bytes."""
        buffer = BytesIO()
        for tlv in tlvs:
            buffer.write(tlv.serialize())
        return buffer.getvalue()
    
    @staticmethod
    def decode(data: bytes) -> List[TLV]:
        """Decode bytes into list of TLVs."""
        tlvs = []
        offset = 0
        
        while offset < len(data):
            tlv, offset = TLV.deserialize(data, offset)
            tlvs.append(tlv)
        
        return tlvs
    
    @staticmethod
    def encode_u64(value: int) -> bytes:
        """Encode 64-bit unsigned integer."""
        return struct.pack('>Q', value)
    
    @staticmethod
    def encode_u32(value: int) -> bytes:
        """Encode 32-bit unsigned integer."""
        return struct.pack('>I', value)
    
    @staticmethod
    def encode_u8(value: int) -> bytes:
        """Encode 8-bit unsigned integer."""
        return struct.pack('>B', value)
    
    @staticmethod
    def encode_string(value: str) -> bytes:
        """Encode UTF-8 string."""
        return value.encode('utf-8')
    
    @staticmethod
    def decode_u64(data: bytes) -> int:
        """Decode 64-bit unsigned integer."""
        if len(data) < 8:
            raise ProtocolError("Not enough bytes for u64")
        return struct.unpack('>Q', data[:8])[0]
    
    @staticmethod
    def decode_u32(data: bytes) -> int:
        """Decode 32-bit unsigned integer."""
        if len(data) < 4:
            raise ProtocolError("Not enough bytes for u32")
        return struct.unpack('>I', data[:4])[0]
    
    @staticmethod
    def decode_u8(data: bytes) -> int:
        """Decode 8-bit unsigned integer."""
        if len(data) < 1:
            raise ProtocolError("Not enough bytes for u8")
        return struct.unpack('>B', data[:1])[0]
    
    @staticmethod
    def decode_string(data: bytes) -> str:
        """Decode UTF-8 string."""
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError as e:
            raise ProtocolError(f"Invalid UTF-8 string: {e}")


# ============================================================================
# Packet Serialization & Parsing
# ============================================================================

class ProtocolParser:
    """Serialize and deserialize PyroGram packets."""
    
    @staticmethod
    def serialize(packet: Packet, auth_key: Optional[bytes] = None) -> bytes:
        """
        Serialize packet to bytes.
        
        If auth_key is provided, compute HMAC over entire packet.
        """
        # Build header (56 bytes)
        header = struct.pack(
            '>I HB B I Q Q 4s 24s',
            packet.magic,
            packet.version,
            packet.msg_type,
            packet.flags,
            len(packet.payload),
            packet.seq_num,
            packet.timestamp_us,
            b'\x00' * 4,  # reserved
            packet.nonce
        )
        
        # Compute HMAC if auth_key provided
        if auth_key:
            hmac_input = header + packet.payload
            computed_hmac = hmac.new(auth_key, hmac_input, hashlib.sha256).digest()
        else:
            computed_hmac = packet.hmac
        
        return header + packet.payload + computed_hmac
    
    @staticmethod
    def parse(data: bytes, auth_key: Optional[bytes] = None) -> Packet:
        """
        Parse bytes into Packet object.
        
        If auth_key is provided, verify HMAC.
        Raises ProtocolError if packet is malformed.
        """
        if len(data) < HEADER_SIZE + HMAC_SIZE:
            raise ProtocolError(
                f"Packet too short: {len(data)} < {HEADER_SIZE + HMAC_SIZE}"
            )
        
        # Parse header
        try:
            (magic, version, msg_type, flags, payload_len, seq_num,
             timestamp_us, reserved, nonce) = struct.unpack(
                '>I HB B I Q Q 4s 24s',
                data[:HEADER_SIZE]
            )
        except struct.error as e:
            raise ProtocolError(f"Failed to parse header: {e}")
        
        # Validate magic
        if magic != MAGIC_HEADER:
            raise ProtocolError(f"Invalid magic header: 0x{magic:08X}")
        
        # Validate version
        if version != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {version}")
        
        # Validate message type
        try:
            msg_type = MessageType(msg_type)
        except ValueError:
            raise ProtocolError(f"Unknown message type: {msg_type}")
        
        # Extract payload
        if len(data) < HEADER_SIZE + payload_len + HMAC_SIZE:
            raise ProtocolError(
                f"Packet truncated: expected {HEADER_SIZE + payload_len + HMAC_SIZE}, "
                f"got {len(data)}"
            )
        
        payload = data[HEADER_SIZE:HEADER_SIZE + payload_len]
        packet_hmac = data[HEADER_SIZE + payload_len:HEADER_SIZE + payload_len + HMAC_SIZE]
        
        # Verify HMAC if auth_key provided
        if auth_key:
            expected_hmac = hmac.new(
                auth_key,
                data[:HEADER_SIZE + payload_len],
                hashlib.sha256
            ).digest()
            
            # Constant-time comparison
            if not hmac.compare_digest(packet_hmac, expected_hmac):
                raise ProtocolError("HMAC verification failed")
        
        packet = Packet(
            magic=magic,
            version=version,
            msg_type=msg_type,
            flags=flags,
            seq_num=seq_num,
            timestamp_us=timestamp_us,
            nonce=nonce,
            payload=payload,
            hmac=packet_hmac
        )
        
        return packet
    
    @staticmethod
    def create_packet(
        msg_type: MessageType,
        seq_num: int,
        payload: Optional[bytes] = None,
        flags: int = 0,
        auth_key: Optional[bytes] = None,
        timestamp_us: Optional[int] = None
    ) -> Packet:
        """
        Create a new packet with given parameters.
        
        Args:
            msg_type: Message type
            seq_num: Sequence number
            payload: Optional payload bytes (default: empty)
            flags: Optional flag bits (default: 0)
            auth_key: Optional auth key for HMAC computation
            timestamp_us: Optional Unix timestamp in microseconds (default: now)
        """
        import time
        
        if payload is None:
            payload = b''
        
        if timestamp_us is None:
            timestamp_us = int(time.time() * 1_000_000)
        
        nonce = secrets.token_bytes(NONCE_SIZE)
        
        packet = Packet(
            magic=MAGIC_HEADER,
            version=PROTOCOL_VERSION,
            msg_type=msg_type,
            flags=flags,
            seq_num=seq_num,
            timestamp_us=timestamp_us,
            nonce=nonce,
            payload=payload,
            hmac=b'\x00' * HMAC_SIZE
        )
        
        # Compute HMAC if key provided
        if auth_key:
            serialized = ProtocolParser.serialize(packet)
            packet.hmac = hmac.new(
                auth_key,
                serialized[:-HMAC_SIZE],
                hashlib.sha256
            ).digest()
        
        return packet


# ============================================================================
# Fragmentation Support
# ============================================================================

class FragmentHandler:
    """Handle packet fragmentation for large payloads."""
    
    FRAGMENT_SIZE = 512 * 1024  # 512KB per fragment
    
    @staticmethod
    def fragment(
        packet: Packet,
        fragment_size: int = FRAGMENT_SIZE
    ) -> List[Packet]:
        """
        Fragment a large packet into multiple smaller packets.
        
        Returns list of packets with FRAGMENTED flag set (except last).
        """
        if len(packet.payload) <= fragment_size:
            return [packet]
        
        fragments = []
        payload = packet.payload
        fragment_index = 0
        total_fragments = (len(payload) + fragment_size - 1) // fragment_size
        
        for offset in range(0, len(payload), fragment_size):
            chunk = payload[offset:offset + fragment_size]
            
            frag_packet = Packet(
                magic=packet.magic,
                version=packet.version,
                msg_type=packet.msg_type,
                flags=packet.flags,
                seq_num=packet.seq_num + fragment_index,
                timestamp_us=packet.timestamp_us,
                nonce=secrets.token_bytes(NONCE_SIZE),
                payload=chunk,
                hmac=b''
            )
            
            # Set fragmentation flag for all but last
            if fragment_index < total_fragments - 1:
                frag_packet.set_flag(PacketFlags.FRAGMENTED)
            
            # Encode fragment metadata into payload header
            # (In real implementation, would prepend fragment info to payload)
            fragments.append(frag_packet)
            fragment_index += 1
        
        return fragments
    
    @staticmethod
    def reassemble(fragments: List[Packet]) -> bytes:
        """Reassemble fragmented payload from list of packets."""
        return b''.join(frag.payload for frag in fragments)


# ============================================================================
# Version Negotiation
# ============================================================================

class VersionNegotiation:
    """Handle protocol version negotiation."""
    
    SUPPORTED_VERSIONS = [1]  # Add new versions here
    MIN_VERSION = 1
    MAX_VERSION = 1
    
    @staticmethod
    def is_supported(version: int) -> bool:
        """Check if protocol version is supported."""
        return version in VersionNegotiation.SUPPORTED_VERSIONS
    
    @staticmethod
    def get_best_version(client_versions: List[int]) -> Optional[int]:
        """Return highest mutually supported version, or None if incompatible."""
        supported = set(VersionNegotiation.SUPPORTED_VERSIONS)
        client_supported = set(client_versions)
        
        common = supported & client_supported
        if not common:
            return None
        
        return max(common)


# ============================================================================
# Message Registry (for extensibility)
# ============================================================================

class MessageRegistry:
    """
    Registry for message type handlers.
    
    Allows handlers to be registered per message type,
    enabling clean dispatch logic.
    """
    
    def __init__(self):
        self._handlers: Dict[MessageType, callable] = {}
    
    def register(self, msg_type: MessageType):
        """Decorator to register handler for message type."""
        def decorator(func: callable):
            self._handlers[msg_type] = func
            return func
        return decorator
    
    def get_handler(self, msg_type: MessageType) -> Optional[callable]:
        """Get handler for message type."""
        return self._handlers.get(msg_type)
    
    def handle(self, packet: Packet, *args, **kwargs):
        """Dispatch packet to registered handler."""
        handler = self.get_handler(packet.msg_type)
        if handler:
            return handler(packet, *args, **kwargs)
        else:
            raise ProtocolError(f"No handler for message type: {packet.msg_type}")


if __name__ == '__main__':
    # Example: Create and serialize a ping packet
    ping_packet = ProtocolParser.create_packet(
        msg_type=MessageType.PING,
        seq_num=1,
        flags=PacketFlags.ENCRYPTED
    )
    
    serialized = ProtocolParser.serialize(ping_packet)
    print(f"Ping packet: {len(serialized)} bytes")
    
    # Parse it back
    parsed = ProtocolParser.parse(serialized)
    print(f"Parsed: type={parsed.msg_type}, seq={parsed.seq_num}")
    
    # TLV example
    tlvs = [
        TLV(TLVTag.USERNAME, TLVCodec.encode_string("alice")),
        TLV(TLVTag.USER_ID, TLVCodec.encode_u64(42))
    ]
    encoded = TLVCodec.encode(tlvs)
    decoded = TLVCodec.decode(encoded)
    print(f"TLV roundtrip: {len(decoded)} fields")
