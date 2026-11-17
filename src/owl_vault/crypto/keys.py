"""Derivação de subchaves com HKDF-SHA256 e separação de domínio (FORMAT §2)."""

from __future__ import annotations

from enum import Enum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from owl_vault.domain.limits import ID_SIZE, KEY_SIZE


class KeyPurpose(bytes, Enum):
    FILE = b"owlvault/v1/file-key\x00"
    MANIFEST = b"owlvault/v1/manifest-key\x00"
    JOURNAL = b"owlvault/v1/journal-key\x00"
    COMPLETE = b"owlvault/v1/complete-key\x00"


def derive_subkey(master_key: bytes, vault_id: bytes, purpose: KeyPurpose, key_id: bytes) -> bytes:
    """``HKDF(ikm=master_key, salt=vault_id, info=rótulo ‖ id, L=32)``."""
    if len(master_key) != KEY_SIZE:
        raise ValueError("master_key deve ter 32 bytes")
    if len(vault_id) != ID_SIZE or len(key_id) != ID_SIZE:
        raise ValueError("vault_id e key_id devem ter 16 bytes")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=vault_id,
        info=purpose.value + key_id,
    )
    return hkdf.derive(master_key)


def file_key(master_key: bytes, vault_id: bytes, file_id: bytes) -> bytes:
    return derive_subkey(master_key, vault_id, KeyPurpose.FILE, file_id)
