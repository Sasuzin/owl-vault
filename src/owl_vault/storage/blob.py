"""Blobs cifrados (FORMAT §4): cifragem a partir da origem e decifragem verificada.

Regra crítica: ``encrypt_source_to_blob`` GERA o ``file_id`` internamente (não aceita um
id do chamador), cria ``<file_id>.tmp`` com ``CREATE_NEW`` e promove com renomeação sem
substituição. Assim o par (chave, nonce) do AES-GCM nunca se repete.
"""

from __future__ import annotations

import hashlib
import os
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from owl_vault.crypto.keys import file_key
from owl_vault.crypto.stream import (
    BLOB_HEADER_SIZE,
    ChunkCipher,
    blob_size,
    chunk_count,
    validate_chunk_size,
    validate_plaintext_size,
)
from owl_vault.domain.errors import (
    CancelledError,
    FormatError,
    IntegrityError,
    SourceChangedError,
)
from owl_vault.domain.limits import FORMAT_VERSION, ID_SIZE, TAG_SIZE
from owl_vault.domain.models import Fingerprint
from owl_vault.storage import faults, winfs
from owl_vault.storage.layout import VaultLayout

MAGIC = b"OWLVBLOB"
_HDR = struct.Struct(">8sHHI16s16sIQI")
assert _HDR.size == BLOB_HEADER_SIZE


@dataclass(frozen=True, slots=True)
class BlobHeader:
    vault_id: bytes
    file_id: bytes
    chunk_size: int
    plaintext_size: int

    def pack(self) -> bytes:
        return _HDR.pack(
            MAGIC,
            FORMAT_VERSION,
            BLOB_HEADER_SIZE,
            0,
            self.vault_id,
            self.file_id,
            self.chunk_size,
            self.plaintext_size,
            0,
        )


def parse_blob_header(data: bytes) -> BlobHeader:
    if len(data) != BLOB_HEADER_SIZE:
        raise FormatError("cabeçalho de blob truncado")
    magic, version, hsize, flags, vault_id, fid, csize, psize, reserved = _HDR.unpack(data)
    if magic != MAGIC:
        raise FormatError("arquivo não é um blob do Owl Vault")
    if version != FORMAT_VERSION:
        raise FormatError("versão de blob não suportada")
    if hsize != BLOB_HEADER_SIZE or flags != 0 or reserved != 0:
        raise FormatError("cabeçalho de blob com campos reservados inválidos")
    validate_chunk_size(csize)
    validate_plaintext_size(psize)
    return BlobHeader(vault_id, fid, csize, psize)


class _Reader(Protocol):
    def read(self, size: int) -> bytes: ...


Cancel = Callable[[], None]
OnBytes = Callable[[int], None]


@dataclass(frozen=True, slots=True)
class BlobWriteResult:
    file_id: bytes
    sha256: bytes
    size: int
    fingerprint_after: Fingerprint


def encrypt_source_to_blob(
    src: winfs.Win32File,
    before: Fingerprint,
    layout: VaultLayout,
    master_key: bytes,
    vault_id: bytes,
    chunk_size: int,
    check_cancel: Cancel,
    on_bytes: OnBytes,
) -> BlobWriteResult:
    """Cifra o arquivo aberto ``src`` num blob novo. ``before`` vem do mesmo handle."""
    validate_chunk_size(chunk_size)
    size = before.size
    validate_plaintext_size(size)
    file_id = os.urandom(ID_SIZE)  # novo a cada tentativa — nunca reutilizado
    winfs.ensure_own_dir(layout.data_dir)
    winfs.ensure_own_dir(layout.blob_dir(file_id))
    final = layout.blob(file_id)
    if os.path.lexists(final):
        raise FormatError("colisão de identificador de blob (abortado por segurança)")
    out = winfs.Win32File.create_new(layout.blob_tmp(file_id))
    try:
        header = BlobHeader(vault_id, file_id, chunk_size, size).pack()
        faults.checkpoint("blob.write")
        out.write(header)
        cipher = ChunkCipher(file_key(master_key, vault_id, file_id), header)
        sha = hashlib.sha256()
        n = chunk_count(size, chunk_size)
        for i in range(n):
            check_cancel()
            want = chunk_size if i < n - 1 else size - (n - 1) * chunk_size
            pt = src.read_exact(want) if want else b""
            sha.update(pt)
            faults.checkpoint("blob.write")
            out.write(cipher.encrypt(i, i == n - 1, pt))
            on_bytes(len(pt))
        if src.read(1):
            raise SourceChangedError("o arquivo cresceu durante a leitura")
        after = src.info().fingerprint()
        if after != before:
            raise SourceChangedError("o arquivo da origem foi modificado durante a leitura")
        faults.checkpoint("blob.flush")
        out.flush()
        faults.checkpoint("blob.rename")
        out.rename_in_place(f"{file_id.hex()}.owlb")
    except BaseException:
        try:
            out.mark_delete()
        except OSError:
            pass
        raise
    finally:
        out.close()
    return BlobWriteResult(file_id, sha.digest(), size, after)


def decrypt_blob(
    path: str,
    master_key: bytes,
    vault_id: bytes,
    expected_file_id: bytes | None,
    expected_size: int | None,
    sink: Callable[[bytes], None] | None,
    check_cancel: Cancel,
    on_bytes: OnBytes,
    *,
    unbuffered: bool = True,
) -> tuple[bytes, BlobHeader]:
    """Decifra e autentica um blob inteiro; retorna (sha256 do texto claro, cabeçalho).

    Confere tamanho exato do arquivo ANTES de decifrar. ``sink`` recebe o texto claro
    chunk a chunk (já autenticado). Nada é entregue de um chunk que falhou.
    """
    st = os.lstat(path)
    if not winfs.is_plain_file(st):
        raise IntegrityError("blob não é um arquivo regular")
    reader: winfs.UnbufferedReader | winfs.Win32File
    if unbuffered:
        reader = winfs.UnbufferedReader(path)
    else:
        reader = winfs.Win32File.open(
            path,
            winfs.GENERIC_READ,
            winfs.FILE_SHARE_READ,
            winfs.OPEN_EXISTING,
            winfs.FILE_FLAG_SEQUENTIAL_SCAN | winfs.FILE_FLAG_OPEN_REPARSE_POINT,
        )
    try:
        actual_size = reader.info().size
        raw_header = reader.read(BLOB_HEADER_SIZE)
        try:
            header = parse_blob_header(raw_header)
        except FormatError as exc:
            raise IntegrityError(f"cabeçalho do blob inválido: {exc}") from exc
        if header.vault_id != vault_id:
            raise IntegrityError("blob pertence a outro cofre")
        if expected_file_id is not None and header.file_id != expected_file_id:
            raise IntegrityError("blob não corresponde à entrada do manifesto (trocado?)")
        if expected_size is not None and header.plaintext_size != expected_size:
            raise IntegrityError("tamanho do blob não confere com o manifesto")
        if actual_size != blob_size(header.plaintext_size, header.chunk_size):
            raise IntegrityError("blob truncado ou estendido (tamanho exato não confere)")
        cipher = ChunkCipher(file_key(master_key, vault_id, header.file_id), raw_header)
        sha = hashlib.sha256()
        n = chunk_count(header.plaintext_size, header.chunk_size)
        c = header.chunk_size
        for i in range(n):
            check_cancel()
            plain_len = c if i < n - 1 else header.plaintext_size - (n - 1) * c
            ct = reader.read(plain_len + TAG_SIZE)
            if len(ct) != plain_len + TAG_SIZE:
                raise IntegrityError("blob truncado durante a leitura")
            pt = cipher.decrypt(i, i == n - 1, ct)
            sha.update(pt)
            if sink is not None:
                sink(pt)
            on_bytes(len(pt))
        if reader.read(1):
            raise IntegrityError("dados extras após o último bloco do blob")
        return sha.digest(), header
    finally:
        reader.close()


def read_blob_header(path: str) -> BlobHeader:
    if not winfs.is_plain_file_at(path):  # nunca seguir links de um cofre possivelmente hostil
        raise IntegrityError("blob não é um arquivo regular")
    with open(path, "rb") as fh:
        return parse_blob_header(fh.read(BLOB_HEADER_SIZE))


def no_cancel() -> None:
    return None


def no_progress(_: int) -> None:
    return None


def raise_if(cancelled: Callable[[], bool]) -> Cancel:
    def check() -> None:
        if cancelled():
            raise CancelledError("operação cancelada")

    return check
