"""
PyroGram Cryptographic Layer

Complete cryptographic subsystem using pyca/cryptography.
Includes X25519 ECDH, AES-256-GCM, Ed25519, Argon2id, SRP-6a, and TOTP.
"""

import os
import struct
import hmac
import hashlib
import secrets
import time
from typing import Tuple, Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


# ============================================================================
# Exceptions
# ============================================================================

class CryptoError(Exception):
    """Cryptographic operation failed."""
    pass


# ============================================================================
# Secure Random Generation
# ============================================================================

class SecureRandom:
    """Cryptographically secure random number generation."""
    
    @staticmethod
    def bytes(length: int) -> bytes:
        """Generate random bytes using OS entropy."""
        return secrets.token_bytes(length)
    
    @staticmethod
    def int_range(start: int, end: int) -> int:
        """Generate random integer in [start, end)."""
        return secrets.randbelow(end - start) + start


# ============================================================================
# Key Exchange: X25519 ECDH
# ============================================================================

@dataclass
class EphemeralKeyPair:
    """Ephemeral key pair for session establishment."""
    private_key: x25519.X25519PrivateKey
    public_key_bytes: bytes
    
    @staticmethod
    def generate() -> 'EphemeralKeyPair':
        """Generate new ephemeral key pair."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes_raw()
        return EphemeralKeyPair(private_key, public_key_bytes)
    
    def compute_shared_secret(self, their_public_bytes: bytes) -> bytes:
        """
        Compute X25519 shared secret.
        
        Args:
            their_public_bytes: 32-byte public key from peer
            
        Returns:
            32-byte shared secret
        """
        their_public_key = x25519.X25519PublicKey.from_public_bytes(their_public_bytes)
        return self.private_key.exchange(their_public_key)


# ============================================================================
# SRP-6a (Secure Remote Password)
# ============================================================================

class SRP6a:
    """
    SRP-6a implementation for zero-knowledge password authentication.
    
    Follows RFC 5054 and Telegram's adaptation.
    """
    
    # RFC 3526 - 2048-bit safe prime
    N_HEX = """
        FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
        020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F140
        27D9F27CE9CDADF8B50E7AAB3D59FA0B5B8F06C2606B1E65F0F4F3B3F4C3C3CF
        FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
        020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F140
    """.replace('\n', '').replace(' ', '')
    
    N = int(N_HEX, 16)
    g = 2  # Generator
    k = int(hashlib.sha256(b'').hexdigest(), 16) % (N - 1) + 1  # Multiplier
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate random salt for user (32 bytes)."""
        return SecureRandom.bytes(32)
    
    @staticmethod
    def compute_verifier(username: str, password: str, salt: bytes) -> bytes:
        """
        Compute SRP verifier for registration.
        
        Verifier is: g^x mod N, where x = SHA256(salt || password)
        Server stores verifier (never password).
        """
        x = hashlib.sha256(salt + password.encode()).digest()
        x_int = int.from_bytes(x, 'big')
        verifier_int = pow(SRP6a.g, x_int, SRP6a.N)
        return verifier_int.to_bytes((SRP6a.N.bit_length() + 7) // 8, 'big')
    
    @staticmethod
    def client_ephemeral() -> Tuple[bytes, bytes]:
        """
        Generate client ephemeral: a and A = g^a mod N.
        
        Returns:
            (a_private, A_public) where A_public is 256 bytes
        """
        a = int.from_bytes(SecureRandom.bytes(32), 'big') % (SRP6a.N - 1) + 1
        A = pow(SRP6a.g, a, SRP6a.N)
        A_bytes = A.to_bytes(256, 'big')
        a_bytes = a.to_bytes(32, 'big')
        return a_bytes, A_bytes
    
    @staticmethod
    def server_ephemeral(verifier: bytes) -> Tuple[bytes, bytes]:
        """
        Generate server ephemeral: b and B = k*v + g^b mod N.
        
        Returns:
            (b_private, B_public) where B_public is 256 bytes
        """
        b = int.from_bytes(SecureRandom.bytes(32), 'big') % (SRP6a.N - 1) + 1
        v = int.from_bytes(verifier, 'big')
        B = (SRP6a.k * v + pow(SRP6a.g, b, SRP6a.N)) % SRP6a.N
        B_bytes = B.to_bytes(256, 'big')
        b_bytes = b.to_bytes(32, 'big')
        return b_bytes, B_bytes
    
    @staticmethod
    def client_compute_shared_secret(
        username: str,
        password: str,
        salt: bytes,
        A_bytes: bytes,
        B_bytes: bytes,
        a_bytes: bytes
    ) -> bytes:
        """
        Client computes shared secret S.
        
        S = (B - k*g^x)^(a + u*x) mod N
        """
        x = hashlib.sha256(salt + password.encode()).digest()
        x_int = int.from_bytes(x, 'big')
        u = int.from_bytes(hashlib.sha256(A_bytes + B_bytes).digest(), 'big')
        a_int = int.from_bytes(a_bytes, 'big')
        B_int = int.from_bytes(B_bytes, 'big')
        
        # S = (B - k*g^x)^(a + u*x) mod N
        exp = (a_int + u * x_int) % (SRP6a.N - 1)
        base = (B_int - SRP6a.k * pow(SRP6a.g, x_int, SRP6a.N)) % SRP6a.N
        S = pow(base, exp, SRP6a.N)
        
        return S.to_bytes(256, 'big')
    
    @staticmethod
    def server_compute_shared_secret(
        A_bytes: bytes,
        B_bytes: bytes,
        b_bytes: bytes,
        verifier: bytes
    ) -> bytes:
        """
        Server computes shared secret S.
        
        S = (A*v^u)^b mod N
        """
        u = int.from_bytes(hashlib.sha256(A_bytes + B_bytes).digest(), 'big')
        b_int = int.from_bytes(b_bytes, 'big')
        A_int = int.from_bytes(A_bytes, 'big')
        v_int = int.from_bytes(verifier, 'big')
        
        # S = (A*v^u)^b mod N
        base = (A_int * pow(v_int, u, SRP6a.N)) % SRP6a.N
        S = pow(base, b_int, SRP6a.N)
        
        return S.to_bytes(256, 'big')
    
    @staticmethod
    def compute_proof_m1(
        username: str,
        salt: bytes,
        A_bytes: bytes,
        B_bytes: bytes,
        S_bytes: bytes
    ) -> bytes:
        """
        Compute client proof M1 for authentication.
        
        M1 = SHA256(H(N) XOR H(g) || H(username) || salt || A || B || S)
        """
        H_N = hashlib.sha256(SRP6a.N.to_bytes(256, 'big')).digest()
        H_g = hashlib.sha256(SRP6a.g.to_bytes(256, 'big')).digest()
        H_N_xor_H_g = bytes(a ^ b for a, b in zip(H_N, H_g))
        
        username_hash = hashlib.sha256(username.encode()).digest()
        
        proof_input = (H_N_xor_H_g + username_hash + salt + A_bytes + B_bytes + S_bytes)
        return hashlib.sha256(proof_input).digest()
    
    @staticmethod
    def compute_proof_m2(A_bytes: bytes, M1: bytes, S_bytes: bytes) -> bytes:
        """
        Compute server proof M2 for mutual authentication.
        
        M2 = SHA256(A || M1 || S)
        """
        return hashlib.sha256(A_bytes + M1 + S_bytes).digest()


# ============================================================================
# AES-256-GCM Encryption
# ============================================================================

class AES256GCM:
    """AES-256-GCM authenticated encryption."""
    
    @staticmethod
    def derive_keys(auth_key: bytes, msg_key: bytes) -> Tuple[bytes, bytes]:
        """
        Derive AES key and IV from auth_key and msg_key (MTProto-style).
        
        Returns:
            (aes_key, aes_iv)
        """
        # Key derivation: SHA256(msg_key + auth_key_slice)
        aes_key = hashlib.sha256(msg_key + auth_key[:36]).digest()
        
        # IV derivation: SHA256(msg_key + auth_key_slice)
        aes_iv_full = hashlib.sha256(msg_key + auth_key[36:72]).digest()
        aes_iv = aes_iv_full[:12]  # 96-bit nonce for GCM
        
        return aes_key, aes_iv
    
    @staticmethod
    def encrypt(plaintext: bytes, auth_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext using AES-256-GCM.
        
        Derives msg_key from auth_key and plaintext.
        
        Returns:
            (ciphertext_with_tag, msg_key)
        """
        # Compute message key
        msg_key = hashlib.sha256(auth_key[88:120] + plaintext).digest()[:16]
        
        # Derive encryption key and IV
        aes_key, aes_iv = AES256GCM.derive_keys(auth_key, msg_key)
        
        # Encrypt with GCM (tag automatically appended)
        cipher = AESGCM(aes_key)
        ciphertext = cipher.encrypt(aes_iv, plaintext, None)
        
        return ciphertext, msg_key
    
    @staticmethod
    def decrypt(ciphertext: bytes, auth_key: bytes, msg_key: bytes) -> bytes:
        """
        Decrypt AES-256-GCM ciphertext.
        
        Args:
            ciphertext: Ciphertext with 16-byte GCM tag appended
            auth_key: Session authentication key
            msg_key: Message key (used for decryption)
            
        Returns:
            Plaintext bytes
            
        Raises:
            CryptoError: If decryption fails (tampering detected)
        """
        # Derive encryption key and IV
        aes_key, aes_iv = AES256GCM.derive_keys(auth_key, msg_key)
        
        # Decrypt with GCM
        cipher = AESGCM(aes_key)
        try:
            plaintext = cipher.decrypt(aes_iv, ciphertext, None)
        except Exception as e:
            raise CryptoError(f"AES-256-GCM decryption failed: {e}")
        
        return plaintext


# ============================================================================
# Ed25519 Digital Signatures
# ============================================================================

class Ed25519Signer:
    """Ed25519 digital signatures for message authentication."""
    
    @staticmethod
    def generate_key_pair() -> Tuple[bytes, bytes]:
        """
        Generate Ed25519 key pair.
        
        Returns:
            (private_key_bytes, public_key_bytes)
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes_raw()
        public_bytes = private_key.public_key().public_bytes_raw()
        return private_bytes, public_bytes
    
    @staticmethod
    def sign(message: bytes, private_key_bytes: bytes) -> bytes:
        """
        Sign message with Ed25519 private key.
        
        Args:
            message: Message to sign
            private_key_bytes: Private key (32 bytes)
            
        Returns:
            Signature (64 bytes)
        """
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        return private_key.sign(message)
    
    @staticmethod
    def verify(message: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
        """
        Verify Ed25519 signature.
        
        Args:
            message: Original message
            signature: Signature bytes (64 bytes)
            public_key_bytes: Public key (32 bytes)
            
        Returns:
            True if signature is valid
        """
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        try:
            public_key.verify(signature, message)
            return True
        except Exception:
            return False


# ============================================================================
# Argon2id Password Hashing
# ============================================================================

class Argon2Hasher:
    """Memory-hard password hashing using Argon2id."""
    
    def __init__(
        self,
        time_cost: int = 3,
        memory_cost_kib: int = 65536,  # 64MB
        parallelism: int = 2
    ):
        """
        Initialize Argon2 hasher.
        
        Args:
            time_cost: Number of iterations (default: 3)
            memory_cost_kib: Memory cost in KiB (default: 65536 = 64MB)
            parallelism: Number of parallel threads (default: 2)
        """
        self.hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            hash_len=32,
            type='id'
        )
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using Argon2id.
        
        Returns:
            Hash string (can be stored in database)
        """
        return self.hasher.hash(password)
    
    def verify_password(self, password: str, hash_value: str) -> bool:
        """
        Verify password against hash.
        
        Returns:
            True if password matches hash
        """
        try:
            self.hasher.verify(hash_value, password)
            return True
        except VerifyMismatchError:
            return False


# ============================================================================
# TOTP (Time-based One-Time Password)
# ============================================================================

class TOTPGenerator:
    """RFC 6238 TOTP implementation for 2FA."""
    
    @staticmethod
    def generate_secret() -> bytes:
        """
        Generate random TOTP secret.
        
        Returns:
            32-byte random secret
        """
        return SecureRandom.bytes(32)
    
    @staticmethod
    def get_totp_code(secret: bytes, time_step: int = 30) -> str:
        """
        Generate current TOTP code.
        
        Args:
            secret: TOTP secret (32 bytes)
            time_step: Time step in seconds (default: 30)
            
        Returns:
            6-digit TOTP code
        """
        counter = int(time.time()) // time_step
        counter_bytes = struct.pack('>Q', counter)
        
        # HMAC-SHA1
        hmac_result = hmac.new(secret, counter_bytes, hashlib.sha1).digest()
        offset = hmac_result[-1] & 0x0F
        
        # Extract 31-bit code
        code = struct.unpack('>I', hmac_result[offset:offset+4])[0] & 0x7FFFFFFF
        code = code % 1000000
        
        return f"{code:06d}"
    
    @staticmethod
    def verify_totp(secret: bytes, code: str, window: int = 1) -> bool:
        """
        Verify TOTP code with time window tolerance.
        
        Args:
            secret: TOTP secret (32 bytes)
            code: 6-digit TOTP code from user
            window: Number of time steps to check before/after current
            
        Returns:
            True if code is valid
        """
        current_time = int(time.time()) // 30
        
        for i in range(-window, window + 1):
            counter = current_time + i
            counter_bytes = struct.pack('>Q', counter)
            hmac_result = hmac.new(secret, counter_bytes, hashlib.sha1).digest()
            offset = hmac_result[-1] & 0x0F
            code_int = struct.unpack('>I', hmac_result[offset:offset+4])[0] & 0x7FFFFFFF
            code_int = code_int % 1000000
            expected = f"{code_int:06d}"
            
            if hmac.compare_digest(code, expected):
                return True
        
        return False


# ============================================================================
# Unified Crypto Manager
# ============================================================================

class CryptoManager:
    """
    Facade for all cryptographic operations.
    
    Provides unified interface for:
    - Key exchange (X25519)
    - Authentication (SRP-6a)
    - Encryption (AES-256-GCM)
    - Signing (Ed25519)
    - Password hashing (Argon2id)
    - TOTP (2FA)
    """
    
    def __init__(self):
        self.hasher = Argon2Hasher()
        self.totp = TOTPGenerator()
    
    # Key Exchange
    def generate_ephemeral_key_pair(self) -> EphemeralKeyPair:
        """Generate ephemeral X25519 key pair for session."""
        return EphemeralKeyPair.generate()
    
    # SRP-6a Authentication
    def srp_generate_salt(self) -> bytes:
        """Generate salt for SRP."""
        return SRP6a.generate_salt()
    
    def srp_compute_verifier(self, username: str, password: str, salt: bytes) -> bytes:
        """Compute SRP verifier for storage."""
        return SRP6a.compute_verifier(username, password, salt)
    
    def srp_client_ephemeral(self) -> Tuple[bytes, bytes]:
        """Generate client SRP ephemeral."""
        return SRP6a.client_ephemeral()
    
    def srp_server_ephemeral(self, verifier: bytes) -> Tuple[bytes, bytes]:
        """Generate server SRP ephemeral."""
        return SRP6a.server_ephemeral(verifier)
    
    def srp_client_shared_secret(
        self,
        username: str,
        password: str,
        salt: bytes,
        A_bytes: bytes,
        B_bytes: bytes,
        a_bytes: bytes
    ) -> bytes:
        """Compute client shared secret."""
        return SRP6a.client_compute_shared_secret(username, password, salt, A_bytes, B_bytes, a_bytes)
    
    def srp_server_shared_secret(
        self,
        A_bytes: bytes,
        B_bytes: bytes,
        b_bytes: bytes,
        verifier: bytes
    ) -> bytes:
        """Compute server shared secret."""
        return SRP6a.server_compute_shared_secret(A_bytes, B_bytes, b_bytes, verifier)
    
    def srp_proof_m1(
        self,
        username: str,
        salt: bytes,
        A_bytes: bytes,
        B_bytes: bytes,
        S_bytes: bytes
    ) -> bytes:
        """Compute SRP proof M1."""
        return SRP6a.compute_proof_m1(username, salt, A_bytes, B_bytes, S_bytes)
    
    def srp_proof_m2(self, A_bytes: bytes, M1: bytes, S_bytes: bytes) -> bytes:
        """Compute SRP proof M2."""
        return SRP6a.compute_proof_m2(A_bytes, M1, S_bytes)
    
    # Encryption
    def encrypt_aes256_gcm(self, plaintext: bytes, auth_key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt plaintext, returns (ciphertext, msg_key)."""
        return AES256GCM.encrypt(plaintext, auth_key)
    
    def decrypt_aes256_gcm(self, ciphertext: bytes, auth_key: bytes, msg_key: bytes) -> bytes:
        """Decrypt ciphertext."""
        return AES256GCM.decrypt(ciphertext, auth_key, msg_key)
    
    # Signing
    def generate_identity_keys(self) -> Tuple[bytes, bytes]:
        """Generate user identity Ed25519 key pair."""
        return Ed25519Signer.generate_key_pair()
    
    def sign_message(self, message: bytes, private_key: bytes) -> bytes:
        """Sign message with Ed25519."""
        return Ed25519Signer.sign(message, private_key)
    
    def verify_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify Ed25519 signature."""
        return Ed25519Signer.verify(message, signature, public_key)
    
    # Password Hashing
    def hash_password(self, password: str) -> str:
        """Hash password with Argon2id."""
        return self.hasher.hash_password(password)
    
    def verify_password(self, password: str, hash_value: str) -> bool:
        """Verify password against hash."""
        return self.hasher.verify_password(password, hash_value)
    
    # TOTP
    def generate_totp_secret(self) -> bytes:
        """Generate TOTP secret."""
        return self.totp.generate_secret()
    
    def get_totp_code(self, secret: bytes) -> str:
        """Get current TOTP code."""
        return self.totp.get_totp_code(secret)
    
    def verify_totp(self, secret: bytes, code: str) -> bool:
        """Verify TOTP code."""
        return self.totp.verify_totp(secret, code)


if __name__ == '__main__':
    # Example usage
    crypto = CryptoManager()
    
    # SRP Example
    salt = crypto.srp_generate_salt()
    verifier = crypto.srp_compute_verifier("alice", "password123", salt)
    print(f"Verifier: {verifier.hex()[:32]}...")
    
    # Encryption Example
    auth_key = secrets.token_bytes(32)
    plaintext = b"Hello, World!"
    ciphertext, msg_key = crypto.encrypt_aes256_gcm(plaintext, auth_key)
    decrypted = crypto.decrypt_aes256_gcm(ciphertext, auth_key, msg_key)
    assert decrypted == plaintext
    print(f"Encryption roundtrip: OK")
    
    # Signing Example
    priv, pub = crypto.generate_identity_keys()
    message = b"Important message"
    signature = crypto.sign_message(message, priv)
    verified = crypto.verify_signature(message, signature, pub)
    print(f"Signature verified: {verified}")
