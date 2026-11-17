"""Cifragem de blobs em chunks autenticados, estilo STREAM (FORMAT §4).

Este módulo é puro (sem E/S): calcula tamanhos, nonces e AAD e cifra/decifra chunks.
A escolha de ``file_id`` NÃO acontece aqui — ela é feita pela camada de armazenamento
(``storage.blob``), que gera um id novo a cada tentativa.
"""

from __future__ import annotations

import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from owl_vault.domain.errors import IntegrityError, LimitError
from owl_vault.domain.limits import MAX_CHUNK_SIZE, MAX_FILE_SIZE, MIN_CHUNK_SIZE, TAG_SIZE

BLOB_HEADER_SIZE = 64


def validate_chunk_size(chunk_size: int) -> None:
    if (
        isinstance(chunk_size, bool)
        or not isinstance(chunk_size, int)
        or chunk_size < MIN_CHUNK_SIZE
        or chunk_size > MAX_CHUNK_SIZE
        or chunk_size & (chunk_size - 1)
    ):
        raise LimitError("tamanho de chunk inválido")


def validate_plaintext_size(size: int) -> None:
    if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > MAX_FILE_SIZE:
        raise LimitError("tamanho de arquivo fora dos limites (máx. 1 TiB)")


def chunk_count(plaintext_size: int, chunk_size: int) -> int:
    """``n = max(1, ceil(P / c))`` — arquivo vazio tem 1 chunk vazio."""
    validate_plaintext_size(plaintext_size)
    validate_chunk_size(chunk_size)
    return max(1, -(-plaintext_size // chunk_size))


def chunk_plain_len(index: int, plaintext_size: int, chunk_size: int) -> int:
    n = chunk_count(plaintext_size, chunk_size)
    if not 0 <= index < n:
        raise ValueError("índice de chunk fora da faixa")
    if index < n - 1:
        return chunk_size
    return plaintext_size - (n - 1) * chunk_size


def blob_size(plaintext_size: int, chunk_size: int) -> int:
    """Tamanho exato do arquivo de blob: ``64 + P + 16·n``."""
    return BLOB_HEADER_SIZE + plaintext_size + TAG_SIZE * chunk_count(plaintext_size, chunk_size)


def chunk_nonce(index: int, final: bool) -> bytes:
    """``0x000000 ‖ u8(final) ‖ u64(i)``."""
    return b"\x00\x00\x00" + struct.pack(">BQ", 1 if final else 0, index)


def chunk_aad(blob_header: bytes, index: int, final: bool) -> bytes:
    if len(blob_header) != BLOB_HEADER_SIZE:
        raise ValueError("cabeçalho de blob deve ter 64 bytes")
    return blob_header + struct.pack(">QB", index, 1 if final else 0)


class ChunkCipher:
    """Cifra/decifra os chunks de UM blob sob sua chave exclusiva."""

    def __init__(self, file_key: bytes, blob_header: bytes) -> None:
        if len(blob_header) != BLOB_HEADER_SIZE:
            raise ValueError("cabeçalho de blob deve ter 64 bytes")
        self._aead = AESGCM(file_key)
        self._header = bytes(blob_header)

    def encrypt(self, index: int, final: bool, plaintext: bytes) -> bytes:
        return self._aead.encrypt(
            chunk_nonce(index, final), plaintext, chunk_aad(self._header, index, final)
        )

    def decrypt(self, index: int, final: bool, ciphertext: bytes) -> bytes:
        try:
            return self._aead.decrypt(
                chunk_nonce(index, final), ciphertext, chunk_aad(self._header, index, final)
            )
        except InvalidTag as exc:
            raise IntegrityError(
                f"falha de autenticação no bloco {index} (dados corrompidos ou adulterados)"
            ) from exc
