"""Matemática de chunks e cifragem de fluxo (FORMAT §4).

Cobre: n = max(1, ceil(P/c)), tamanhos de borda (vazio, c-1, c, c+1, múltiplos exatos,
muitos chunks), tamanho exato do blob ``64 + P + 16·n``, layout do nonce
``0x000000 ‖ u8(final) ‖ u64(i)`` e do AAD ``header(64) ‖ u64(i) ‖ u8(final)``, rejeição de
índice/flag final/cabeçalho errados, blobs reais gravados por ``encrypt_source_to_blob`` e
decifrados tanto pelo motor quanto por uma implementação independente escrita a partir do
FORMAT, e adulterações (truncamento, extensão, troca de chunks, campos do cabeçalho do blob).
Somente pastas temporárias com dados sintéticos.
"""

from __future__ import annotations

import hashlib
import inspect
import os
import struct
import types
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from owl_vault.application.vault import open_vault, read_manifest
from owl_vault.crypto.kdf import TESTING_POLICY
from owl_vault.crypto.stream import (
    BLOB_HEADER_SIZE,
    ChunkCipher,
    blob_size,
    chunk_aad,
    chunk_count,
    chunk_nonce,
    chunk_plain_len,
    validate_chunk_size,
    validate_plaintext_size,
)
from owl_vault.domain.errors import FormatError, IntegrityError, LimitError
from owl_vault.domain.limits import (
    DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_SIZE,
    MAX_FILE_SIZE,
    MIN_CHUNK_SIZE,
    TAG_SIZE,
)
from owl_vault.storage import blob as blob_mod
from owl_vault.storage import winfs
from owl_vault.storage.blob import (
    BlobHeader,
    decrypt_blob,
    encrypt_source_to_blob,
    no_cancel,
    no_progress,
    parse_blob_header,
)
from owl_vault.storage.layout import VaultLayout
from tests.conftest import PASSWORD, SMALL_CHUNK, Area, make_vault, write_tree

C = SMALL_CHUNK  # 64 KiB = MIN_CHUNK_SIZE
_BLOB_HDR = struct.Struct(">8sHHI16s16sIQI")
_FILE_KEY_LABEL = b"owlvault/v1/file-key\x00"


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _expected_n(p: int, c: int) -> int:
    """FORMAT §4.2, escrito de forma independente do motor."""
    if p == 0:
        return 1
    return (p + c - 1) // c


def _spec_nonce(i: int, final: bool) -> bytes:
    return b"\x00\x00\x00" + bytes([1 if final else 0]) + i.to_bytes(8, "big")


def _spec_aad(header: bytes, i: int, final: bool) -> bytes:
    return header + i.to_bytes(8, "big") + bytes([1 if final else 0])


def _spec_file_key(master_key: bytes, vault_id: bytes, file_id: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=vault_id, info=_FILE_KEY_LABEL + file_id
    ).derive(master_key)


def _spec_decrypt_blob(blob: bytes, master_key: bytes, vault_id: bytes) -> bytes:
    """Decifrador independente, escrito só a partir do FORMAT §2 e §4."""
    header = blob[:64]
    magic, ver, hsize, flags, vid, fid, c, p, reserved = _BLOB_HDR.unpack(header)
    assert (magic, ver, hsize, flags, reserved) == (b"OWLVBLOB", 1, 64, 0, 0)
    assert vid == vault_id
    n = _expected_n(p, c)
    assert len(blob) == 64 + p + 16 * n
    aead = AESGCM(_spec_file_key(master_key, vault_id, fid))
    out = []
    pos = 64
    for i in range(n):
        final = i == n - 1
        plain_len = c if not final else p - (n - 1) * c
        piece = blob[pos : pos + plain_len + 16]
        out.append(aead.decrypt(_spec_nonce(i, final), piece, _spec_aad(header, i, final)))
        pos += plain_len + 16
    assert pos == len(blob)
    return b"".join(out)


class _Collector:
    def __init__(self) -> None:
        self.parts: list[bytes] = []

    def __call__(self, data: bytes) -> None:
        self.parts.append(bytes(data))

    @property
    def data(self) -> bytes:
        return b"".join(self.parts)


class _Env:
    """Pasta de cofre sintética com chaves aleatórias para testar blobs diretamente."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.vault_dir = root / "cofre"
        self.vault_dir.mkdir()
        self.src_dir = root / "origem"
        self.src_dir.mkdir()
        self.layout = VaultLayout(winfs.to_extended(str(self.vault_dir)))
        self.master_key = os.urandom(32)
        self.vault_id = os.urandom(16)
        self._n = 0

    def encrypt(self, data: bytes, chunk_size: int = C) -> tuple[str, blob_mod.BlobWriteResult]:
        self._n += 1
        src = self.src_dir / f"arquivo-{self._n}.bin"
        src.write_bytes(data)
        f, info = winfs.open_source(winfs.to_extended(str(src)))
        try:
            res = encrypt_source_to_blob(
                f,
                info.fingerprint(),
                self.layout,
                self.master_key,
                self.vault_id,
                chunk_size,
                no_cancel,
                no_progress,
            )
        finally:
            f.close()
        return self.layout.blob(res.file_id), res

    def decrypt(
        self,
        path: str,
        *,
        expected_file_id: bytes | None = None,
        expected_size: int | None = None,
        vault_id: bytes | None = None,
        unbuffered: bool = True,
        sink: _Collector | None = None,
    ) -> tuple[bytes, BlobHeader]:
        return decrypt_blob(
            path,
            self.master_key,
            self.vault_id if vault_id is None else vault_id,
            expected_file_id,
            expected_size,
            sink,
            no_cancel,
            no_progress,
            unbuffered=unbuffered,
        )


@pytest.fixture
def env(tmp_path: Path) -> _Env:
    return _Env(tmp_path)


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _write(path: str, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)


def _flip(data: bytes, offset: int, bit: int = 0) -> bytes:
    b = bytearray(data)
    b[offset] ^= 1 << bit
    return bytes(b)


# --------------------------------------------------------------------------------------
# matemática de chunks (puro)
# --------------------------------------------------------------------------------------

EDGE_SIZES = [0, 1, C - 1, C, C + 1, 2 * C - 1, 2 * C, 2 * C + 1, 3 * C, 3 * C + 17, 10 * C]


@pytest.mark.parametrize("p", EDGE_SIZES)
def test_chunk_count_edge_sizes(p: int) -> None:
    assert chunk_count(p, C) == _expected_n(p, C)


@pytest.mark.parametrize(
    ("p", "c", "n"),
    [
        (0, C, 1),  # arquivo vazio = 1 chunk vazio (só a tag)
        (1, C, 1),
        (C - 1, C, 1),
        (C, C, 1),  # múltiplo exato: n = P / c
        (C + 1, C, 2),
        (2 * C, C, 2),
        (2 * C + 1, C, 3),
        (7 * C, C, 7),
        (0, DEFAULT_CHUNK_SIZE, 1),
        (DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE, 1),
        (DEFAULT_CHUNK_SIZE + 1, DEFAULT_CHUNK_SIZE, 2),
        (MAX_CHUNK_SIZE, MAX_CHUNK_SIZE, 1),
        (MAX_CHUNK_SIZE + 1, MAX_CHUNK_SIZE, 2),
        (MAX_FILE_SIZE, MIN_CHUNK_SIZE, 2**24),
        (MAX_FILE_SIZE, MAX_CHUNK_SIZE, 2**16),
        (MAX_FILE_SIZE - 1, MIN_CHUNK_SIZE, 2**24),
    ],
)
def test_chunk_count_table(p: int, c: int, n: int) -> None:
    assert chunk_count(p, c) == n


@pytest.mark.parametrize("c", [MIN_CHUNK_SIZE, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE])
@pytest.mark.parametrize(
    ("mult", "delta"),
    [(m, d) for m in (0, 1, 2, 3) for d in (-1, 0, 1) if m * MIN_CHUNK_SIZE + d >= 0],
)
def test_chunk_lengths_and_blob_size(c: int, mult: int, delta: int) -> None:
    p = mult * c + delta
    n = chunk_count(p, c)
    assert n == _expected_n(p, c)
    lengths = [chunk_plain_len(i, p, c) for i in range(n)]
    # todos os chunks exceto o último têm c bytes; o último tem P - (n-1)c
    assert all(x == c for x in lengths[:-1])
    assert lengths[-1] == p - (n - 1) * c
    assert sum(lengths) == p
    if p == 0:
        assert lengths == [0]
    elif p % c == 0:
        assert lengths[-1] == c  # múltiplo exato: último chunk cheio, sem chunk vazio extra
    else:
        assert 0 < lengths[-1] < c
    assert blob_size(p, c) == 64 + p + 16 * n


@pytest.mark.parametrize("p", [0, 1, C, C + 1, 3 * C])
def test_chunk_plain_len_rejects_out_of_range_index(p: int) -> None:
    n = chunk_count(p, C)
    with pytest.raises(ValueError):
        chunk_plain_len(n, p, C)
    with pytest.raises(ValueError):
        chunk_plain_len(-1, p, C)


def test_blob_size_known_values() -> None:
    assert blob_size(0, C) == 64 + 16
    assert blob_size(1, C) == 64 + 1 + 16
    assert blob_size(C, C) == 64 + C + 16
    assert blob_size(C + 1, C) == 64 + C + 1 + 32
    assert blob_size(MAX_FILE_SIZE, MIN_CHUNK_SIZE) == 64 + 2**40 + 16 * 2**24


@pytest.mark.parametrize("c", [2**k for k in range(16, 25)])
def test_valid_chunk_sizes_accepted(c: int) -> None:
    validate_chunk_size(c)
    assert chunk_count(c, c) == 1


@pytest.mark.parametrize(
    "c",
    [
        0,
        -1,
        1,
        MIN_CHUNK_SIZE - 1,
        MIN_CHUNK_SIZE // 2,
        MIN_CHUNK_SIZE + 1,
        3 * MIN_CHUNK_SIZE,  # não é potência de 2
        MAX_CHUNK_SIZE + 1,
        MAX_CHUNK_SIZE * 2,
        2**32,
        True,
        float(MIN_CHUNK_SIZE),
        str(MIN_CHUNK_SIZE),
        None,
    ],
)
def test_invalid_chunk_sizes_rejected(c: object) -> None:
    with pytest.raises(LimitError):
        validate_chunk_size(c)  # type: ignore[arg-type]
    with pytest.raises(LimitError):
        chunk_count(0, c)  # type: ignore[arg-type]


@pytest.mark.parametrize("p", [0, 1, MAX_FILE_SIZE - 1, MAX_FILE_SIZE])
def test_valid_plaintext_sizes_accepted(p: int) -> None:
    validate_plaintext_size(p)


@pytest.mark.parametrize("p", [-1, MAX_FILE_SIZE + 1, 2**63, True, False, 1.0, "1", None])
def test_invalid_plaintext_sizes_rejected(p: object) -> None:
    with pytest.raises(LimitError):
        validate_plaintext_size(p)  # type: ignore[arg-type]
    with pytest.raises(LimitError):
        chunk_count(p, C)  # type: ignore[arg-type]
    if isinstance(p, (int, float)):
        with pytest.raises(LimitError):
            blob_size(p, C)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------
# layout de nonce e AAD
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("i", [0, 1, 255, 256, 2**32 - 1, 2**32, 2**63, 2**64 - 1])
@pytest.mark.parametrize("final", [False, True])
def test_nonce_layout(i: int, final: bool) -> None:
    nonce = chunk_nonce(i, final)
    assert len(nonce) == 12
    assert nonce[:3] == b"\x00\x00\x00"
    assert nonce[3] == (1 if final else 0)
    assert nonce[4:] == i.to_bytes(8, "big")
    assert nonce == _spec_nonce(i, final)


def test_nonces_unique_within_a_blob() -> None:
    n = 1000
    nonces = [chunk_nonce(i, i == n - 1) for i in range(n)]
    assert len(set(nonces)) == n
    # o mesmo índice com flag final diferente produz nonce diferente
    for i in (0, 1, n - 1):
        assert chunk_nonce(i, True) != chunk_nonce(i, False)


@pytest.mark.parametrize("i", [0, 1, 2**40 + 3])
@pytest.mark.parametrize("final", [False, True])
def test_aad_layout(i: int, final: bool) -> None:
    header = os.urandom(64)
    aad = chunk_aad(header, i, final)
    assert len(aad) == 64 + 8 + 1
    assert aad[:64] == header
    assert aad[64:72] == i.to_bytes(8, "big")
    assert aad[72] == (1 if final else 0)
    assert aad == _spec_aad(header, i, final)


@pytest.mark.parametrize("size", [0, 63, 65, 128])
def test_aad_and_cipher_require_64_byte_header(size: int) -> None:
    with pytest.raises(ValueError):
        chunk_aad(b"\x00" * size, 0, True)
    with pytest.raises(ValueError):
        ChunkCipher(os.urandom(32), b"\x00" * size)


# --------------------------------------------------------------------------------------
# ChunkCipher
# --------------------------------------------------------------------------------------


def _cipher() -> tuple[bytes, bytes, ChunkCipher]:
    key = os.urandom(32)
    header = BlobHeader(os.urandom(16), os.urandom(16), C, 3 * C).pack()
    return key, header, ChunkCipher(key, header)


@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, C - 1, C])
def test_chunk_cipher_matches_spec_construction(length: int) -> None:
    key, header, cipher = _cipher()
    pt = os.urandom(length)
    for i, final in ((0, False), (0, True), (5, False), (5, True)):
        ct = cipher.encrypt(i, final, pt)
        assert len(ct) == length + TAG_SIZE  # ct ‖ tag; chunk vazio = só a tag
        # mesma saída que AES-256-GCM com nonce/AAD montados conforme o FORMAT
        assert ct == AESGCM(key).encrypt(_spec_nonce(i, final), pt, _spec_aad(header, i, final))
        assert cipher.decrypt(i, final, ct) == pt


def test_chunk_decrypt_rejects_wrong_index() -> None:
    _, _, cipher = _cipher()
    pt = os.urandom(100)
    ct = cipher.encrypt(3, False, pt)
    for wrong in (0, 2, 4, 3 + 2**32, 2**63 + 3):
        with pytest.raises(IntegrityError):
            cipher.decrypt(wrong, False, ct)


def test_chunk_decrypt_rejects_wrong_final_flag() -> None:
    _, _, cipher = _cipher()
    pt = os.urandom(C)
    ct_mid = cipher.encrypt(1, False, pt)
    ct_final = cipher.encrypt(1, True, pt)
    with pytest.raises(IntegrityError):
        cipher.decrypt(1, True, ct_mid)  # chunk intermediário apresentado como final
    with pytest.raises(IntegrityError):
        cipher.decrypt(1, False, ct_final)  # chunk final apresentado como intermediário
    # vazio final (arquivo vazio) não serve como chunk intermediário
    ct_empty = cipher.encrypt(0, True, b"")
    with pytest.raises(IntegrityError):
        cipher.decrypt(0, False, ct_empty)


def test_chunk_decrypt_rejects_any_header_bit_change() -> None:
    key, header, cipher = _cipher()
    pt = os.urandom(64)
    ct = cipher.encrypt(0, True, pt)
    for off in range(BLOB_HEADER_SIZE):
        other = ChunkCipher(key, _flip(header, off, off % 8))
        with pytest.raises(IntegrityError):
            other.decrypt(0, True, ct)
    assert cipher.decrypt(0, True, ct) == pt


def test_chunk_decrypt_rejects_wrong_key() -> None:
    _, header, cipher = _cipher()
    ct = cipher.encrypt(0, True, b"abc")
    with pytest.raises(IntegrityError):
        ChunkCipher(os.urandom(32), header).decrypt(0, True, ct)


def test_chunk_decrypt_rejects_tampered_ciphertext_and_tag() -> None:
    _, _, cipher = _cipher()
    pt = os.urandom(200)
    ct = cipher.encrypt(2, False, pt)
    for off in (0, 1, 100, 199, 200, 207, 215):  # texto cifrado e tag
        with pytest.raises(IntegrityError):
            cipher.decrypt(2, False, _flip(ct, off, 3))
    with pytest.raises(IntegrityError):
        cipher.decrypt(2, False, ct[:-1])
    with pytest.raises(IntegrityError):
        cipher.decrypt(2, False, ct + b"\x00")
    with pytest.raises(IntegrityError):
        cipher.decrypt(2, False, b"")


def test_chunk_decrypt_error_is_domain_error_not_invalid_tag() -> None:
    _, _, cipher = _cipher()
    ct = cipher.encrypt(0, True, b"x")
    with pytest.raises(IntegrityError) as info:
        cipher.decrypt(1, True, ct)
    assert not isinstance(info.value, InvalidTag)


# --------------------------------------------------------------------------------------
# blobs reais (storage.blob) — tamanhos de borda
# --------------------------------------------------------------------------------------

BLOB_SIZES = [0, 1, C - 1, C, C + 1, 2 * C - 1, 2 * C, 2 * C + 1, 3 * C, 3 * C + 17]


@pytest.mark.parametrize("p", BLOB_SIZES)
def test_blob_roundtrip_edge_sizes(env: _Env, p: int) -> None:
    data = os.urandom(p)
    path, res = env.encrypt(data)
    n = _expected_n(p, C)
    raw = _read(path)

    # nome do blob = file_id hex em data/<hh>/; nenhum temporário sobrando
    assert os.path.basename(path) == res.file_id.hex() + ".owlb"
    assert os.path.basename(os.path.dirname(path)) == res.file_id.hex()[:2]
    assert os.listdir(os.path.dirname(path)) == [res.file_id.hex() + ".owlb"]

    # tamanho exato 64 + P + 16·n
    assert len(raw) == 64 + p + 16 * n == blob_size(p, C)

    # cabeçalho do blob (FORMAT §4.1)
    magic, ver, hsize, flags, vid, fid, csize, psize, reserved = _BLOB_HDR.unpack(raw[:64])
    assert magic == b"OWLVBLOB"
    assert (ver, hsize, flags, reserved) == (1, 64, 0, 0)
    assert vid == env.vault_id
    assert fid == res.file_id
    assert csize == C
    assert psize == p

    # resultado da cifragem
    assert res.size == p
    assert res.sha256 == hashlib.sha256(data).digest()

    # decifrador independente (somente FORMAT) concorda com o motor
    assert _spec_decrypt_blob(raw, env.master_key, env.vault_id) == data

    # decifragem do motor, com e sem E/S sem cache
    for unbuffered in (True, False):
        sink = _Collector()
        sha, header = env.decrypt(
            path,
            expected_file_id=res.file_id,
            expected_size=p,
            unbuffered=unbuffered,
            sink=sink,
        )
        assert sha == hashlib.sha256(data).digest()
        assert sink.data == data
        assert len(sink.parts) == n
        assert header == BlobHeader(env.vault_id, res.file_id, C, p)


@pytest.mark.parametrize(
    ("c", "p"),
    [
        (DEFAULT_CHUNK_SIZE, 2 * DEFAULT_CHUNK_SIZE),  # múltiplo exato com chunk padrão
        (DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE + 1),
        (DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE - 1),
        (2 * C, 5 * C),
        (MAX_CHUNK_SIZE, MAX_CHUNK_SIZE + 1),
    ],
)
def test_blob_roundtrip_other_chunk_sizes(env: _Env, c: int, p: int) -> None:
    data = os.urandom(p)
    path, res = env.encrypt(data, chunk_size=c)
    raw = _read(path)
    assert len(raw) == blob_size(p, c) == 64 + p + 16 * _expected_n(p, c)
    assert parse_blob_header(raw[:64]).chunk_size == c
    assert _spec_decrypt_blob(raw, env.master_key, env.vault_id) == data
    sink = _Collector()
    sha, _ = env.decrypt(path, expected_file_id=res.file_id, expected_size=p, sink=sink)
    assert sha == hashlib.sha256(data).digest() and sink.data == data


def test_blob_many_chunks(env: _Env) -> None:
    p = 40 * C + 5
    data = os.urandom(p)
    path, res = env.encrypt(data)
    raw = _read(path)
    n = 41
    assert chunk_count(p, C) == n
    assert len(raw) == 64 + p + 16 * n
    # cada chunk ocupa o lugar exato e o último é o único "final"
    key = _spec_file_key(env.master_key, env.vault_id, res.file_id)
    header = raw[:64]
    pos = 64
    for i in range(n):
        final = i == n - 1
        length = C if not final else 5
        piece = raw[pos : pos + length + 16]
        assert (
            AESGCM(key).decrypt(_spec_nonce(i, final), piece, _spec_aad(header, i, final))
            == (data[i * C : i * C + length])
        )
        if not final:
            with pytest.raises(InvalidTag):
                AESGCM(key).decrypt(_spec_nonce(i, True), piece, _spec_aad(header, i, True))
        pos += length + 16
    assert pos == len(raw)


def test_encrypt_api_generates_fresh_file_id(env: _Env) -> None:
    """FORMAT §4.3: a API gera o file_id internamente; o chamador não pode passá-lo."""
    params = inspect.signature(encrypt_source_to_blob).parameters
    assert not any("file_id" in name or name == "fid" for name in params)
    data = os.urandom(C + 3)
    ids = set()
    cts = set()
    for _ in range(4):
        path, res = env.encrypt(data)
        ids.add(res.file_id)
        cts.add(_read(path)[64:])
    assert len(ids) == 4  # sempre um file_id novo
    assert len(cts) == 4  # chave por arquivo ⇒ texto cifrado diferente para o mesmo conteúdo


class _UrandomProxy(types.ModuleType):
    """Proxy do módulo ``os`` visto por ``storage.blob`` com ``urandom`` determinístico."""

    def __init__(self, fixed: bytes) -> None:
        super().__init__("os_proxy")
        self._fixed = fixed

    def urandom(self, n: int) -> bytes:
        assert n == len(self._fixed)
        return self._fixed

    def __getattr__(self, name: str) -> object:
        return getattr(os, name)


def test_existing_blob_is_never_opened_for_writing(
    env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixed = bytes.fromhex("ab" * 16)
    hh = os.path.join(str(env.vault_dir), "data", "ab")
    os.makedirs(hh)
    final = os.path.join(hh, fixed.hex() + ".owlb")
    sentinel = b"blob existente que nunca pode ser sobrescrito"
    with open(final, "wb") as fh:
        fh.write(sentinel)
    monkeypatch.setattr(blob_mod, "os", _UrandomProxy(fixed))
    with pytest.raises(FormatError):
        env.encrypt(b"conteudo novo")
    monkeypatch.undo()
    assert _read(final) == sentinel
    assert sorted(os.listdir(hh)) == [fixed.hex() + ".owlb"]


def test_existing_tmp_aborts_create_new(env: _Env, monkeypatch: pytest.MonkeyPatch) -> None:
    fixed = bytes.fromhex("cd" * 16)
    hh = os.path.join(str(env.vault_dir), "data", "cd")
    os.makedirs(hh)
    tmp = os.path.join(hh, fixed.hex() + ".tmp")
    sentinel = b"temporario alheio"
    with open(tmp, "wb") as fh:
        fh.write(sentinel)
    monkeypatch.setattr(blob_mod, "os", _UrandomProxy(fixed))
    with pytest.raises(OSError):
        env.encrypt(b"conteudo novo")
    monkeypatch.undo()
    assert _read(tmp) == sentinel
    assert sorted(os.listdir(hh)) == [fixed.hex() + ".tmp"]


# --------------------------------------------------------------------------------------
# blobs reais — adulterações
# --------------------------------------------------------------------------------------


def _three_chunk_blob(env: _Env, extra: int = 17) -> tuple[str, blob_mod.BlobWriteResult, bytes]:
    data = os.urandom(3 * C + extra)
    path, res = env.encrypt(data)
    return path, res, data


def _chunk_offset(i: int) -> int:
    return 64 + i * (C + 16)


@pytest.mark.parametrize("unbuffered", [True, False])
@pytest.mark.parametrize(
    "mutation",
    ["truncate_1", "truncate_tag", "truncate_final_chunk", "extend_1", "extend_fake_chunk"],
)
def test_truncated_or_extended_blob_rejected_before_any_output(
    env: _Env, mutation: str, unbuffered: bool
) -> None:
    path, res, data = _three_chunk_blob(env)
    raw = _read(path)
    if mutation == "truncate_1":
        bad = raw[:-1]
    elif mutation == "truncate_tag":
        bad = raw[:-16]
    elif mutation == "truncate_final_chunk":
        bad = raw[: _chunk_offset(3)]
    elif mutation == "extend_1":
        bad = raw + b"\x00"
    else:
        bad = raw + os.urandom(C + 16)
    _write(path, bad)
    sink = _Collector()
    with pytest.raises(IntegrityError):
        env.decrypt(
            path,
            expected_file_id=res.file_id,
            expected_size=len(data),
            sink=sink,
            unbuffered=unbuffered,
        )
    assert sink.parts == []  # tamanho exato verificado ANTES de decifrar


def test_truncation_with_rewritten_size_is_detected(env: _Env) -> None:
    """Remover o último chunk e ajustar plaintext_size (tamanho coerente) não passa: o
    cabeçalho está no AAD e o chunk 2 não foi cifrado como final."""
    data = os.urandom(3 * C)
    path, _ = env.encrypt(data)
    raw = _read(path)
    header = bytearray(raw[:64])
    header[52:60] = (2 * C).to_bytes(8, "big")
    bad = bytes(header) + raw[64 : _chunk_offset(2)]
    assert len(bad) == blob_size(2 * C, C)
    _write(path, bad)
    sink = _Collector()
    with pytest.raises(IntegrityError):
        env.decrypt(path, sink=sink)
    assert sink.parts == []


def test_dropping_final_chunk_at_boundary_detected_by_final_flag(env: _Env) -> None:
    """Mesmo com a chave e o cabeçalho originais, um prefixo de chunks não é aceito como
    arquivo completo: o último chunk restante não foi cifrado com final=1."""
    data = os.urandom(3 * C)
    path, res = env.encrypt(data)
    raw = _read(path)
    key = _spec_file_key(env.master_key, env.vault_id, res.file_id)
    header = raw[:64]
    chunk1 = raw[_chunk_offset(1) : _chunk_offset(2)]
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(_spec_nonce(1, True), chunk1, _spec_aad(header, 1, True))
    cipher = ChunkCipher(key, header)
    with pytest.raises(IntegrityError):
        cipher.decrypt(1, True, chunk1)


@pytest.mark.parametrize("unbuffered", [True, False])
def test_swapped_chunks_rejected(env: _Env, unbuffered: bool) -> None:
    path, res, data = _three_chunk_blob(env)
    raw = bytearray(_read(path))
    a = raw[_chunk_offset(0) : _chunk_offset(1)]
    b = raw[_chunk_offset(1) : _chunk_offset(2)]
    raw[_chunk_offset(0) : _chunk_offset(1)] = b
    raw[_chunk_offset(1) : _chunk_offset(2)] = a
    _write(path, bytes(raw))
    sink = _Collector()
    with pytest.raises(IntegrityError):
        env.decrypt(
            path,
            expected_file_id=res.file_id,
            expected_size=len(data),
            sink=sink,
            unbuffered=unbuffered,
        )
    assert sink.parts == []


@pytest.mark.parametrize("bad_chunk", [0, 1, 2, 3])
@pytest.mark.parametrize("where", ["ciphertext", "tag"])
def test_corrupted_chunk_stops_output_at_that_chunk(env: _Env, bad_chunk: int, where: str) -> None:
    path, res, data = _three_chunk_blob(env)
    raw = _read(path)
    length = C if bad_chunk < 3 else 17
    off = _chunk_offset(bad_chunk) + (length // 2 if where == "ciphertext" else length + 7)
    _write(path, _flip(raw, off, 5))
    sink = _Collector()
    with pytest.raises(IntegrityError):
        env.decrypt(path, expected_file_id=res.file_id, expected_size=len(data), sink=sink)
    # só chunks anteriores (já autenticados) foram entregues; nada do chunk corrompido
    assert sink.data == data[: bad_chunk * C]
    assert len(sink.parts) == bad_chunk


@pytest.mark.parametrize(
    ("field", "offset"),
    [
        ("magic", 0),
        ("format_version", 9),
        ("header_size", 11),
        ("flags", 15),
        ("vault_id", 16),
        ("file_id", 40),
        ("chunk_size_low", 51),
        ("plaintext_size", 59),
        ("reserved", 63),
    ],
)
@pytest.mark.parametrize("pass_expectations", [True, False])
def test_blob_header_bit_flip_rejected(
    env: _Env, field: str, offset: int, pass_expectations: bool
) -> None:
    path, res, data = _three_chunk_blob(env)
    raw = _read(path)
    _write(path, _flip(raw, offset, 0))
    sink = _Collector()
    with pytest.raises(IntegrityError):
        if pass_expectations:
            env.decrypt(path, expected_file_id=res.file_id, expected_size=len(data), sink=sink)
        else:
            env.decrypt(path, sink=sink)
    assert sink.parts == [], field


def test_blob_chunk_size_changed_to_other_valid_value_rejected(env: _Env) -> None:
    data = os.urandom(4 * C)
    path, res = env.encrypt(data)
    raw = bytearray(_read(path))
    raw[48:52] = (2 * C).to_bytes(4, "big")
    _write(path, bytes(raw))
    with pytest.raises(IntegrityError):
        env.decrypt(path, expected_file_id=res.file_id, expected_size=len(data))


def test_blob_expectations_enforced(env: _Env) -> None:
    data = os.urandom(C + 1)
    path, res = env.encrypt(data)
    with pytest.raises(IntegrityError):
        env.decrypt(path, expected_file_id=os.urandom(16), expected_size=len(data))
    with pytest.raises(IntegrityError):
        env.decrypt(path, expected_file_id=res.file_id, expected_size=len(data) + 1)
    with pytest.raises(IntegrityError):
        env.decrypt(path, expected_file_id=res.file_id, expected_size=len(data) - 1)
    with pytest.raises(IntegrityError):
        env.decrypt(path, vault_id=os.urandom(16))
    # sem adulteração tudo confere
    sha, _ = env.decrypt(path, expected_file_id=res.file_id, expected_size=len(data))
    assert sha == hashlib.sha256(data).digest()


def test_blob_from_another_file_rejected(env: _Env) -> None:
    """Conteúdo de um blob colocado no nome de outro (mesmo tamanho) não autentica."""
    data_a = os.urandom(C + 5)
    data_b = os.urandom(C + 5)
    path_a, res_a = env.encrypt(data_a)
    path_b, _ = env.encrypt(data_b)
    _write(path_a, _read(path_b))
    with pytest.raises(IntegrityError):
        env.decrypt(path_a, expected_file_id=res_a.file_id, expected_size=len(data_a))
    # cabeçalho de A + chunks de B: chave/AAD de A não autenticam os chunks de B
    raw_a_hdr = BlobHeader(env.vault_id, res_a.file_id, C, len(data_a)).pack()
    _write(path_a, raw_a_hdr + _read(path_b)[64:])
    with pytest.raises(IntegrityError):
        env.decrypt(path_a, expected_file_id=res_a.file_id, expected_size=len(data_a))


def test_blob_with_other_master_key_rejected(env: _Env) -> None:
    data = os.urandom(10)
    path, res = env.encrypt(data)
    with pytest.raises(IntegrityError):
        decrypt_blob(
            path, os.urandom(32), env.vault_id, res.file_id, 10, None, no_cancel, no_progress
        )


# --------------------------------------------------------------------------------------
# integração: cofre real criado pelo motor
# --------------------------------------------------------------------------------------


def test_vault_blobs_have_exact_sizes(area: Area) -> None:
    sizes = {
        "vazio.bin": 0,
        "um.bin": 1,
        "c-1.bin": C - 1,
        "c.bin": C,
        "c+1.bin": C + 1,
        "2c.bin": 2 * C,
        "3c+17.bin": 3 * C + 17,
    }
    contents = {name: os.urandom(size) for name, size in sizes.items()}
    write_tree(area.src, {"sub": dict(contents)})
    result = make_vault(area)
    assert result.status == "success", result.divergences

    opened = open_vault(str(area.vault()), PASSWORD, TESTING_POLICY)
    mread = read_manifest(opened)
    assert mread.manifest.chunk_size == C
    by_name = {e.path[-1]: e for e in mread.manifest.files}
    assert set(by_name) == set(sizes)
    for name, entry in by_name.items():
        p = sizes[name]
        blob_path = opened.layout.blob(entry.file_id)
        raw = _read(blob_path)
        assert len(raw) == 64 + p + 16 * _expected_n(p, C), name
        hdr = parse_blob_header(raw[:64])
        assert (hdr.vault_id, hdr.file_id, hdr.chunk_size, hdr.plaintext_size) == (
            opened.vault_id,
            entry.file_id,
            C,
            p,
        )
        assert _spec_decrypt_blob(raw, opened.master_key, opened.vault_id) == contents[name]
        sha, _ = decrypt_blob(
            blob_path,
            opened.master_key,
            opened.vault_id,
            entry.file_id,
            entry.size,
            None,
            no_cancel,
            no_progress,
        )
        assert sha == entry.sha256 == hashlib.sha256(contents[name]).digest()
