"""Cabeçalho do cofre ``vault.owl`` (FORMAT §3): 144 bytes, parâmetros autenticados."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from owl_vault.crypto.kdf import (
    KDF_ALGORITHM_ARGON2ID,
    KDF_VERSION_13,
    SALT_SIZE,
    KdfPolicy,
    derive_kek,
    validate_params,
)
from owl_vault.domain.errors import AuthenticationError, FormatError
from owl_vault.domain.limits import FORMAT_VERSION, ID_SIZE, KEY_SIZE, NONCE_SIZE, TAG_SIZE
from owl_vault.domain.models import KdfParams

MAGIC = b"OWLVAULT"
HEADER_SIZE = 144
AAD_SIZE = 96
WRAP_AES_256_GCM = 1

# magic, versão, header_size, flags, vault_id, kdf_alg, kdf_ver, reservado16,
# m, t, p, salt, wrap_alg, reservado(3), nonce
_CORE = struct.Struct(">8sHHI16sBBHIII32sB3s12s")
assert _CORE.size == AAD_SIZE


@dataclass(frozen=True, slots=True)
class VaultHeader:
    vault_id: bytes
    kdf: KdfParams
    salt: bytes
    wrap_nonce: bytes
    wrapped_master_key: bytes  # 48 bytes = ct(32) ‖ tag(16)

    def core_bytes(self) -> bytes:
        return _CORE.pack(
            MAGIC,
            FORMAT_VERSION,
            HEADER_SIZE,
            0,
            self.vault_id,
            KDF_ALGORITHM_ARGON2ID,
            KDF_VERSION_13,
            0,
            self.kdf.memory_kib,
            self.kdf.iterations,
            self.kdf.parallelism,
            self.salt,
            WRAP_AES_256_GCM,
            b"\x00\x00\x00",
            self.wrap_nonce,
        )

    def pack(self) -> bytes:
        out = self.core_bytes() + self.wrapped_master_key
        assert len(out) == HEADER_SIZE
        return out

    def kdf_key(self) -> tuple[bytes, KdfParams]:
        """Tupla que identifica a derivação (para derivar uma vez por tupla distinta)."""
        return self.salt, self.kdf


def parse_header(data: bytes, policy: KdfPolicy) -> VaultHeader:
    """Validação estrutural e de limites (antes de qualquer derivação)."""
    if len(data) != HEADER_SIZE:
        raise FormatError("cabeçalho do cofre com tamanho inválido")
    (
        magic,
        version,
        header_size,
        flags,
        vault_id,
        kdf_alg,
        kdf_ver,
        reserved16,
        m,
        t,
        p,
        salt,
        wrap_alg,
        reserved3,
        nonce,
    ) = _CORE.unpack_from(data, 0)
    if magic != MAGIC:
        raise FormatError("não é um cabeçalho de cofre do Owl Vault")
    if version != FORMAT_VERSION:
        raise FormatError(f"versão de formato não suportada ({version})")
    if header_size != HEADER_SIZE or flags != 0 or reserved16 != 0 or reserved3 != b"\x00\x00\x00":
        raise FormatError("cabeçalho do cofre com campos reservados inválidos")
    if kdf_alg != KDF_ALGORITHM_ARGON2ID or kdf_ver != KDF_VERSION_13:
        raise FormatError("algoritmo de derivação de chave não suportado")
    if wrap_alg != WRAP_AES_256_GCM:
        raise FormatError("algoritmo de envelope de chave não suportado")
    params = KdfParams(memory_kib=m, iterations=t, parallelism=p)
    validate_params(params, policy)
    return VaultHeader(
        vault_id=vault_id,
        kdf=params,
        salt=salt,
        wrap_nonce=nonce,
        wrapped_master_key=data[AAD_SIZE:],
    )


def build_header(
    master_key: bytes,
    vault_id: bytes,
    password: str,
    params: KdfParams,
    policy: KdfPolicy,
    available_memory: int | None = None,
) -> VaultHeader:
    if len(master_key) != KEY_SIZE or len(vault_id) != ID_SIZE:
        raise ValueError("tamanhos de chave/id inválidos")
    validate_params(params, policy)
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    draft = VaultHeader(vault_id, params, salt, nonce, b"\x00" * (KEY_SIZE + TAG_SIZE))
    kek = derive_kek(password, salt, params, policy, available_memory)
    wrapped = AESGCM(kek).encrypt(nonce, master_key, draft.core_bytes())
    return VaultHeader(vault_id, params, salt, nonce, wrapped)


def unwrap_with_kek(header: VaultHeader, kek: bytes) -> bytes:
    """Desenvolve a master_key; ``AuthenticationError`` se a KEK/cabeçalho não conferem."""
    try:
        master = AESGCM(kek).decrypt(
            header.wrap_nonce, header.wrapped_master_key, header.core_bytes()
        )
    except InvalidTag as exc:
        raise AuthenticationError("senha incorreta ou cabeçalho do cofre corrompido") from exc
    if len(master) != KEY_SIZE:
        raise FormatError("chave mestra com tamanho inválido")
    return master
