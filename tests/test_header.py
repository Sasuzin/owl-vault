"""Cabeçalho do cofre ``vault.owl`` (FORMAT §3) e algoritmo normativo de leitura (§3.1).

Cobre: layout de 144 bytes, validação estrita (magic, versão, tamanhos, flags, cada campo
reservado, algoritmos), limites do Argon2id verificados ANTES da derivação (política de
produção e de testes, parâmetros abusivos), senha errada, NFC, AAD = bytes[0:96], e o
algoritmo de leitura das duas cópias via ``application.vault.open_vault`` em cofres reais
criados com ``make_vault``: fallback ``vault.owl`` ⇄ ``vault.owl.bak``, cópias ausentes, as
duas corrompidas, cabeçalho de OUTRO cofre com a mesma senha, notas sobre a cópia usada,
nunca reescrever cópias. Somente pastas temporárias com dados sintéticos.
"""

from __future__ import annotations

import dataclasses
import inspect
import os
import shutil
import struct
import unicodedata
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from argon2.low_level import Type
from argon2.low_level import hash_secret_raw as real_hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import owl_vault.cli.main as cli_main
import owl_vault.crypto.kdf as kdf_mod
from owl_vault.application.create import create_vault, resume_create
from owl_vault.application.vault import OpenedVault, open_vault, read_manifest
from owl_vault.crypto.kdf import (
    PRODUCTION_POLICY,
    TESTING_PARAMS,
    TESTING_POLICY,
    KdfPolicy,
    derive_kek,
    validate_params,
)
from owl_vault.domain.errors import (
    AuthenticationError,
    FormatError,
    InconsistentVaultError,
    LimitError,
    ResourceError,
)
from owl_vault.domain.limits import GIB, MIB, TIB
from owl_vault.domain.models import KdfParams
from owl_vault.storage import faults, winfs
from owl_vault.storage.header import (
    HEADER_SIZE,
    VaultHeader,
    build_header,
    parse_header,
    unwrap_with_kek,
)
from tests.conftest import (
    PASSWORD,
    Area,
    do_restore,
    do_verify,
    make_vault,
    tree_digest,
    write_tree,
)

OTHER_PASSWORD = "uma senha completamente diferente 987"
WRONG_PASSWORD = "senha errada errada errada"

# Offsets da tabela do FORMAT §3
OFF_MAGIC = 0
OFF_VERSION = 8
OFF_HSIZE = 10
OFF_FLAGS = 12
OFF_VAULT_ID = 16
OFF_KDF_ALG = 32
OFF_KDF_VER = 33
OFF_RES16 = 34
OFF_M = 36
OFF_T = 40
OFF_P = 44
OFF_SALT = 48
OFF_WRAP_ALG = 80
OFF_RES3 = 81
OFF_NONCE = 84
OFF_WRAPPED = 96

# Layout independente do motor (para montar/inspecionar cabeçalhos nos testes)
_SPEC = struct.Struct(">8sHHI16sBBHIII32sB3s12s48s")
assert _SPEC.size == 144

# política de teste com checagem de memória ligada (injeção explícita, só em testes)
CHECKING_TEST_POLICY = dataclasses.replace(TESTING_POLICY, check_available_memory=True)
# política permissiva (só para PARSE em testes de autenticação; nunca usada para derivar)
PERMISSIVE_POLICY = KdfPolicy(0, 2**32 - 1, 0, 2**32 - 1, 0, 2**32 - 1, False)


# --------------------------------------------------------------------------------------
# helpers de bytes
# --------------------------------------------------------------------------------------


def _flip(data: bytes, offset: int, bit: int = 0) -> bytes:
    b = bytearray(data)
    b[offset] ^= 1 << bit
    return bytes(b)


def _set(data: bytes, offset: int, fmt: str, value: Any) -> bytes:
    b = bytearray(data)
    struct.pack_into(fmt, b, offset, value)
    return bytes(b)


def _set_u8(data: bytes, off: int, v: int) -> bytes:
    return _set(data, off, ">B", v)


def _set_u16(data: bytes, off: int, v: int) -> bytes:
    return _set(data, off, ">H", v)


def _set_u32(data: bytes, off: int, v: int) -> bytes:
    return _set(data, off, ">I", v)


def _spec_header(
    *,
    magic: bytes = b"OWLVAULT",
    version: int = 1,
    header_size: int = 144,
    flags: int = 0,
    vault_id: bytes = bytes(range(16)),
    kdf_alg: int = 1,
    kdf_ver: int = 0x13,
    res16: int = 0,
    m: int = TESTING_PARAMS.memory_kib,
    t: int = TESTING_PARAMS.iterations,
    p: int = TESTING_PARAMS.parallelism,
    salt: bytes = bytes(range(100, 132)),
    wrap_alg: int = 1,
    res3: bytes = b"\x00\x00\x00",
    nonce: bytes = bytes(range(200, 212)),
    wrapped: bytes = bytes(range(48)),
) -> bytes:
    return _SPEC.pack(
        magic,
        version,
        header_size,
        flags,
        vault_id,
        kdf_alg,
        kdf_ver,
        res16,
        m,
        t,
        p,
        salt,
        wrap_alg,
        res3,
        nonce,
        wrapped,
    )


def _header_from_raw_unchecked(raw: bytes) -> VaultHeader:
    """Monta um VaultHeader a partir dos bytes SEM validação (para testar o AAD)."""
    (_, _, _, _, vid, _, _, _, m, t, p, salt, _, _, nonce, wrapped) = _SPEC.unpack(raw)
    return VaultHeader(vid, KdfParams(m, t, p), salt, nonce, wrapped)


# --------------------------------------------------------------------------------------
# fixtures de instrumentação do Argon2id
# --------------------------------------------------------------------------------------


@pytest.fixture
def argon_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Registra cada execução real do Argon2id (derivação) feita pelo motor."""
    calls: list[dict[str, Any]] = []

    def spy(*args: Any, **kwargs: Any) -> bytes:
        calls.append(kwargs)
        return real_hash_secret_raw(*args, **kwargs)

    monkeypatch.setattr(kdf_mod, "hash_secret_raw", spy)
    return calls


@pytest.fixture
def no_argon2(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Qualquer derivação Argon2id falha o teste (limites devem ser checados antes)."""
    calls: list[dict[str, Any]] = []

    def forbidden(*args: Any, **kwargs: Any) -> bytes:
        calls.append(kwargs)
        raise AssertionError(f"Argon2id executado com {kwargs.get('memory_cost')} KiB")

    monkeypatch.setattr(kdf_mod, "hash_secret_raw", forbidden)
    return calls


def _fake_memory(monkeypatch: pytest.MonkeyPatch, *, physical: int, commit: int) -> None:
    status = winfs.MemoryStatus(
        total_physical=64 * GIB, available_physical=physical, available_commit=commit
    )
    monkeypatch.setattr(winfs, "memory_status", lambda: status)


# ======================================================================================
# Parte 1 — pack/parse (unidade)
# ======================================================================================


def test_pack_layout_matches_format_table() -> None:
    vid = bytes(range(16))
    salt = bytes(range(100, 132))
    nonce = bytes(range(200, 212))
    wrapped = bytes(range(48))
    params = KdfParams(memory_kib=65_536, iterations=3, parallelism=4)
    raw = VaultHeader(vid, params, salt, nonce, wrapped).pack()
    assert len(raw) == HEADER_SIZE == 144
    assert raw[0:8] == b"OWLVAULT"
    assert raw[8:10] == b"\x00\x01"  # format_version = 1 (big-endian)
    assert raw[10:12] == (144).to_bytes(2, "big")
    assert raw[12:16] == b"\x00" * 4
    assert raw[16:32] == vid
    assert raw[32] == 1  # Argon2id
    assert raw[33] == 0x13
    assert raw[34:36] == b"\x00\x00"
    assert raw[36:40] == (65_536).to_bytes(4, "big")
    assert raw[40:44] == (3).to_bytes(4, "big")
    assert raw[44:48] == (4).to_bytes(4, "big")
    assert raw[48:80] == salt
    assert raw[80] == 1  # AES-256-GCM
    assert raw[81:84] == b"\x00\x00\x00"
    assert raw[84:96] == nonce
    assert raw[96:144] == wrapped
    assert raw == _spec_header(m=65_536, t=3, p=4)


def test_parse_roundtrip() -> None:
    raw = _spec_header()
    h = parse_header(raw, TESTING_POLICY)
    assert h.vault_id == bytes(range(16))
    assert h.kdf == TESTING_PARAMS
    assert h.salt == bytes(range(100, 132))
    assert h.wrap_nonce == bytes(range(200, 212))
    assert h.wrapped_master_key == bytes(range(48))
    assert h.pack() == raw


@pytest.mark.parametrize("value", [b"\x00" * 16, b"\xff" * 16])
def test_random_fields_accept_any_value(value: bytes) -> None:
    """vault_id, salt, nonce e chave envolvida são aleatórios: nenhum valor é recusado."""
    raw = _spec_header(vault_id=value, salt=value * 2, nonce=value[:12], wrapped=value * 3)
    assert parse_header(raw, TESTING_POLICY).pack() == raw


@pytest.mark.parametrize("size", [0, 1, 16, 95, 96, 143, 145, 160, 288, 4096])
def test_parse_rejects_wrong_total_size(size: int) -> None:
    base = _spec_header()
    data = (base * 40)[:size]
    with pytest.raises(FormatError):
        parse_header(data, TESTING_POLICY)


@pytest.mark.parametrize(
    ("label", "raw"),
    [
        ("magic minúsculo", _spec_header(magic=b"owlvault")),
        ("magic de blob", _spec_header(magic=b"OWLVBLOB")),
        ("magic de manifesto", _spec_header(magic=b"OWLVMANI")),
        ("magic zerado", _spec_header(magic=b"\x00" * 8)),
        ("versão 0", _spec_header(version=0)),
        ("versão 2", _spec_header(version=2)),
        ("versão little-endian", _spec_header(version=0x0100)),
        ("versão máxima", _spec_header(version=0xFFFF)),
        ("header_size 0", _spec_header(header_size=0)),
        ("header_size 64", _spec_header(header_size=64)),
        ("header_size 143", _spec_header(header_size=143)),
        ("header_size 145", _spec_header(header_size=145)),
        ("header_size little-endian", _spec_header(header_size=0x9000)),
        ("flags bit 0", _spec_header(flags=1)),
        ("flags bit 31", _spec_header(flags=0x80000000)),
        ("kdf_algorithm 0", _spec_header(kdf_alg=0)),
        ("kdf_algorithm 2 (Argon2i?)", _spec_header(kdf_alg=2)),
        ("kdf_algorithm 255", _spec_header(kdf_alg=255)),
        ("kdf_version 0x10", _spec_header(kdf_ver=0x10)),
        ("kdf_version 0x12", _spec_header(kdf_ver=0x12)),
        ("kdf_version 0x14", _spec_header(kdf_ver=0x14)),
        ("reservado(34) = 1", _spec_header(res16=1)),
        ("reservado(34) = 0x8000", _spec_header(res16=0x8000)),
        ("wrap_algorithm 0", _spec_header(wrap_alg=0)),
        ("wrap_algorithm 2", _spec_header(wrap_alg=2)),
        ("reservado(81) primeiro byte", _spec_header(res3=b"\x01\x00\x00")),
        ("reservado(81) último byte", _spec_header(res3=b"\x00\x00\x80")),
    ],
)
def test_parse_rejects_invalid_fixed_fields(label: str, raw: bytes) -> None:
    with pytest.raises(FormatError):
        parse_header(raw, TESTING_POLICY)


def test_parse_rejects_every_bit_flip_in_fixed_and_reserved_fields() -> None:
    """magic, versão, header_size, flags, kdf_alg, kdf_ver, reservado(34), wrap_alg,
    reservado(81): todos têm valor exato; qualquer bit alterado é recusado."""
    raw = _spec_header()
    offsets = [*range(0, 16), 32, 33, 34, 35, 80, 81, 82, 83]
    accepted = []
    for off in offsets:
        for bit in range(8):
            try:
                parse_header(_flip(raw, off, bit), TESTING_POLICY)
            except FormatError:
                continue
            accepted.append((off, bit))
    assert accepted == []


# --------------------------------------------------------------------------------------
# limites do Argon2id
# --------------------------------------------------------------------------------------

U32 = 2**32 - 1

PRODUCTION_CASES = [
    # (m, t, p, aceito?)
    (65_536, 3, 1, True),
    (1_048_576, 16, 8, True),
    (65_536, 3, 8, True),
    (262_144, 4, 4, True),
    (65_535, 3, 1, False),
    (1_048_577, 3, 1, False),
    (65_536, 2, 1, False),
    (65_536, 17, 1, False),
    (65_536, 3, 0, False),
    (65_536, 3, 9, False),
    (0, 3, 1, False),
    (65_536, 0, 1, False),
    (U32, 3, 1, False),
    (65_536, U32, 1, False),
    (65_536, 3, U32, False),
    (U32, U32, U32, False),
    (8_192, 1, 1, False),  # TESTING_PARAMS: inalcançável pela política de produção
]

TESTING_CASES = [
    (8_192, 1, 1, True),
    (1_048_576, 16, 8, True),
    (65_536, 3, 4, True),
    (8_191, 1, 1, False),
    (1_048_577, 1, 1, False),
    (8_192, 0, 1, False),
    (8_192, 17, 1, False),
    (8_192, 1, 0, False),
    (8_192, 1, 9, False),
    (0, 0, 0, False),
    (U32, 1, 1, False),
    (8_192, U32, 1, False),
    (8_192, 1, U32, False),
]


def _policy_cases() -> list[Any]:
    out = []
    for name, policy, cases in (
        ("producao", PRODUCTION_POLICY, PRODUCTION_CASES),
        ("teste", TESTING_POLICY, TESTING_CASES),
    ):
        for m, t, p, ok in cases:
            out.append(pytest.param(policy, m, t, p, ok, id=f"{name}-m{m}-t{t}-p{p}"))
    return out


@pytest.mark.parametrize(("policy", "m", "t", "p", "ok"), _policy_cases())
def test_kdf_bounds_in_parse(policy: KdfPolicy, m: int, t: int, p: int, ok: bool) -> None:
    raw = _spec_header(m=m, t=t, p=p)
    if ok:
        assert parse_header(raw, policy).kdf == KdfParams(m, t, p)
    else:
        with pytest.raises(LimitError):
            parse_header(raw, policy)


@pytest.mark.parametrize(("policy", "m", "t", "p", "ok"), _policy_cases())
def test_kdf_bounds_checked_before_derivation(
    no_argon2: list[dict[str, Any]], policy: KdfPolicy, m: int, t: int, p: int, ok: bool
) -> None:
    params = KdfParams(m, t, p)
    if ok:
        validate_params(params, policy)
        return
    with pytest.raises(LimitError):
        derive_kek(PASSWORD, os.urandom(32), params, policy)
    with pytest.raises(LimitError):
        build_header(os.urandom(32), os.urandom(16), PASSWORD, params, policy)
    assert no_argon2 == []


def test_production_policy_matches_format() -> None:
    assert PRODUCTION_POLICY.min_memory_kib == 65_536
    assert PRODUCTION_POLICY.max_memory_kib == 1_048_576
    assert (PRODUCTION_POLICY.min_iterations, PRODUCTION_POLICY.max_iterations) == (3, 16)
    assert (PRODUCTION_POLICY.min_parallelism, PRODUCTION_POLICY.max_parallelism) == (1, 8)
    assert PRODUCTION_POLICY.check_available_memory is True
    assert KdfParams(8 * 1024, 1, 1) == TESTING_PARAMS
    assert (TESTING_POLICY.min_memory_kib, TESTING_POLICY.min_iterations) == (8 * 1024, 1)


def test_testing_floor_not_selectable_by_distributed_build() -> None:
    """FORMAT §3: o piso de testes (8 MiB, t=1) não é selecionável por UI/CLI."""
    with pytest.raises(LimitError):
        validate_params(TESTING_PARAMS, PRODUCTION_POLICY)
    assert inspect.signature(create_vault).parameters["kdf_policy"].default is PRODUCTION_POLICY
    assert inspect.signature(resume_create).parameters["kdf_policy"].default is PRODUCTION_POLICY
    cli_source = inspect.getsource(cli_main)
    assert "TESTING_POLICY" not in cli_source
    assert "TESTING_PARAMS" not in cli_source


def test_memory_coherence_rule_m_at_least_8p() -> None:
    lax = dataclasses.replace(TESTING_POLICY, min_memory_kib=1)
    with pytest.raises(LimitError):
        validate_params(KdfParams(63, 1, 8), lax)
    with pytest.raises(LimitError):
        validate_params(KdfParams(7, 1, 1), lax)
    validate_params(KdfParams(64, 1, 8), lax)
    validate_params(KdfParams(8, 1, 1), lax)


@pytest.mark.parametrize("salt_len", [0, 16, 31, 33, 64])
def test_bad_salt_length_rejected_before_derivation(
    no_argon2: list[dict[str, Any]], salt_len: int
) -> None:
    with pytest.raises(LimitError):
        derive_kek(PASSWORD, b"\x00" * salt_len, TESTING_PARAMS, TESTING_POLICY)
    assert no_argon2 == []


def test_insufficient_available_memory_refused_before_derivation(
    no_argon2: list[dict[str, Any]],
) -> None:
    m_bytes = TESTING_PARAMS.memory_kib * 1024
    for avail in (0, m_bytes, m_bytes + 128 * MIB - 1):
        with pytest.raises(ResourceError):
            derive_kek(PASSWORD, os.urandom(32), TESTING_PARAMS, CHECKING_TEST_POLICY, avail)
    big = KdfParams(1_048_576, 3, 4)
    with pytest.raises(ResourceError):
        derive_kek(PASSWORD, os.urandom(32), big, PRODUCTION_POLICY, 1 * GIB)
    assert no_argon2 == []


def test_available_memory_threshold_is_m_plus_256_mib() -> None:
    """FORMAT §3: exige-se memória comprometível ≥ m + 256 MiB (exatamente isso basta)."""
    m_bytes = TESTING_PARAMS.memory_kib * 1024
    kek = derive_kek(
        PASSWORD, os.urandom(32), TESTING_PARAMS, CHECKING_TEST_POLICY, m_bytes + 256 * MIB
    )
    assert len(kek) == 32
    with pytest.raises(ResourceError):
        derive_kek(
            PASSWORD,
            os.urandom(32),
            TESTING_PARAMS,
            CHECKING_TEST_POLICY,
            m_bytes + 256 * MIB - 1,
        )


def test_memory_error_during_derivation_is_handled(monkeypatch: pytest.MonkeyPatch) -> None:
    def oom(*args: Any, **kwargs: Any) -> bytes:
        raise MemoryError

    monkeypatch.setattr(kdf_mod, "hash_secret_raw", oom)
    with pytest.raises(ResourceError):
        derive_kek(PASSWORD, os.urandom(32), TESTING_PARAMS, TESTING_POLICY)


# --------------------------------------------------------------------------------------
# envelope da chave mestra
# --------------------------------------------------------------------------------------


def test_build_and_unwrap_roundtrip_and_wrong_password() -> None:
    mk, vid = os.urandom(32), os.urandom(16)
    h = build_header(mk, vid, PASSWORD, TESTING_PARAMS, TESTING_POLICY)
    raw = h.pack()
    assert raw[OFF_VAULT_ID : OFF_VAULT_ID + 16] == vid
    parsed = parse_header(raw, TESTING_POLICY)
    kek = derive_kek(PASSWORD, parsed.salt, parsed.kdf, TESTING_POLICY)
    assert unwrap_with_kek(parsed, kek) == mk
    bad_kek = derive_kek(WRONG_PASSWORD, parsed.salt, parsed.kdf, TESTING_POLICY)
    with pytest.raises(AuthenticationError):
        unwrap_with_kek(parsed, bad_kek)
    # salt e nonce novos a cada cabeçalho
    h2 = build_header(mk, vid, PASSWORD, TESTING_PARAMS, TESTING_POLICY)
    assert h2.salt != h.salt and h2.wrap_nonce != h.wrap_nonce


def test_wrapped_key_is_aes_gcm_over_first_96_bytes() -> None:
    """Conformidade com o FORMAT usando Argon2id/AES-GCM diretamente (sem o motor)."""
    mk, vid = os.urandom(32), os.urandom(16)
    raw = build_header(mk, vid, PASSWORD, TESTING_PARAMS, TESTING_POLICY).pack()
    m, t, p = struct.unpack(">III", raw[36:48])
    kek = real_hash_secret_raw(
        secret=unicodedata.normalize("NFC", PASSWORD).encode("utf-8"),
        salt=raw[48:80],
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=32,
        type=Type.ID,
        version=0x13,
    )
    assert AESGCM(kek).decrypt(raw[84:96], raw[96:144], raw[0:96]) == mk


def test_every_header_byte_is_authenticated_with_the_same_kek() -> None:
    """AAD = bytes[0:96]: mesmo com a KEK correta, alterar vault_id, m/t/p, salt, nonce ou
    a chave envolvida faz o unwrap falhar (campos fixos já são recusados no parse)."""
    mk, vid = os.urandom(32), os.urandom(16)
    h = build_header(mk, vid, PASSWORD, TESTING_PARAMS, TESTING_POLICY)
    kek = derive_kek(PASSWORD, h.salt, h.kdf, TESTING_POLICY)
    raw = h.pack()
    free = list(range(16, 32)) + list(range(36, 80)) + list(range(84, 144))
    unauthenticated = []
    for off in free:
        for bit in (0, 7):
            mutated = _header_from_raw_unchecked(_flip(raw, off, bit))
            try:
                unwrap_with_kek(mutated, kek)
            except AuthenticationError:
                continue
            unauthenticated.append((off, bit))
    assert unauthenticated == []


def test_password_is_nfc_normalized() -> None:
    nfc = "Coração çãé ü — senha 12345"
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfd != nfc
    mk, vid = os.urandom(32), os.urandom(16)
    h = build_header(mk, vid, nfd, TESTING_PARAMS, TESTING_POLICY)
    assert unwrap_with_kek(h, derive_kek(nfc, h.salt, h.kdf, TESTING_POLICY)) == mk
    assert unwrap_with_kek(h, derive_kek(nfd, h.salt, h.kdf, TESTING_POLICY)) == mk


# ======================================================================================
# Parte 2 — algoritmo normativo de leitura (FORMAT §3.1) em cofres reais
# ======================================================================================


@dataclass(frozen=True)
class Pristine:
    vault: Path
    src: Path
    password: str
    vault_id: bytes
    master_key: bytes
    header: bytes
    core_files: dict[str, bytes]


# Arquivos que o algoritmo do cabeçalho e a leitura do manifesto usam (cópia mínima, rápida)
_CORE_FILES = ("vault.owl", "vault.owl.bak", "manifest.owl", "manifest.owl.bak")


def _new_area(root: Path) -> Area:
    a = Area(
        root=root,
        src=root / "origem",
        vaults=root / "cofres",
        testarea=root / "teste",
        out=root / "saida",
    )
    for p in (a.src, a.vaults, a.testarea, a.out):
        p.mkdir()
    return a


@pytest.fixture(scope="module")
def pristine(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Pristine]:
    """Cofres de referência: A e B com a MESMA senha; C com outra senha."""
    specs: dict[str, tuple[str, dict[str, Any]]] = {
        "A": (PASSWORD, {"a.txt": b"conteudo do cofre A", "sub": {"b.bin": os.urandom(70_000)}}),
        "B": (PASSWORD, {"x.txt": b"conteudo do cofre B"}),
        "C": (OTHER_PASSWORD, {"y.txt": b"conteudo do cofre C"}),
    }
    out: dict[str, Pristine] = {}
    faults.reset()
    for key, (pw, tree) in specs.items():
        a = _new_area(tmp_path_factory.mktemp(f"hdr-{key}"))
        write_tree(a.src, tree)
        res = make_vault(a, password=pw)
        assert res.status == "success"
        header = (a.vault() / "vault.owl").read_bytes()
        assert (a.vault() / "vault.owl.bak").read_bytes() == header  # cópia byte a byte
        opened = open_vault(str(a.vault()), pw, TESTING_POLICY)
        core = {name: (a.vault() / name).read_bytes() for name in _CORE_FILES}
        out[key] = Pristine(a.vault(), a.src, pw, opened.vault_id, opened.master_key, header, core)
    assert len({p.vault_id for p in out.values()}) == 3
    return out


@pytest.fixture
def va(area: Area, pristine: dict[str, Pristine]) -> Iterator[Path]:
    """Cópia mínima descartável do cofre A (cabeçalhos + manifestos) em ``area.vault()``."""
    v = area.vault()
    v.mkdir()
    for name, data in pristine["A"].core_files.items():
        (v / name).write_bytes(data)
    yield v


@pytest.fixture
def va_full(area: Area, pristine: dict[str, Pristine]) -> Iterator[Path]:
    """Cópia completa descartável do cofre A (para Verificar/Restaurar)."""
    shutil.copytree(pristine["A"].vault, area.vault())
    yield area.vault()


def _paths(v: Path) -> tuple[Path, Path]:
    return v / "vault.owl", v / "vault.owl.bak"


def _open(
    v: Path,
    password: str = PASSWORD,
    policy: KdfPolicy = TESTING_POLICY,
    unbuffered: bool = False,
) -> OpenedVault:
    return open_vault(str(v), password, policy, unbuffered=unbuffered)


def _snapshot(v: Path) -> tuple[list[str], dict[str, bytes | None]]:
    """Nomes na raiz do cofre + bytes das duas cópias do cabeçalho (prova de que nenhuma
    cópia é reescrita/recriada e de que nada novo aparece na pasta)."""
    names = sorted(p.name for p in v.iterdir())
    copies: dict[str, bytes | None] = {}
    for name in ("vault.owl", "vault.owl.bak"):
        p = v / name
        copies[name] = p.read_bytes() if p.is_file() else None
    return names, copies


# corrupções de uma cópia: nome → (mutação, tipo). "auth" = estruturalmente válida (chega à
# derivação/unwrap); "struct" = recusada pela validação estrutural/limites.
CORRUPTIONS: dict[str, tuple[Callable[[bytes], bytes], str]] = {
    "vault_id": (lambda d: _flip(d, OFF_VAULT_ID + 7, 3), "auth"),
    "kdf_salt": (lambda d: _flip(d, OFF_SALT + 5, 2), "auth"),
    "wrap_nonce": (lambda d: _flip(d, OFF_NONCE + 3, 7), "auth"),
    "wrapped_key_ct": (lambda d: _flip(d, OFF_WRAPPED + 2, 0), "auth"),
    "wrapped_key_tag": (lambda d: _flip(d, HEADER_SIZE - 1, 4), "auth"),
    "kdf_memory_in_range": (lambda d: _flip(d, OFF_M + 3, 0), "auth"),  # 8192 → 8193
    "kdf_iterations_in_range": (lambda d: _flip(d, OFF_T + 3, 1), "auth"),  # 1 → 3
    "kdf_parallelism_in_range": (lambda d: _flip(d, OFF_P + 3, 1), "auth"),  # 1 → 3
    "magic": (lambda d: _flip(d, OFF_MAGIC + 2, 0), "struct"),
    "format_version": (lambda d: _set_u16(d, OFF_VERSION, 2), "struct"),
    "header_size": (lambda d: _set_u16(d, OFF_HSIZE, 145), "struct"),
    "flags": (lambda d: _flip(d, OFF_FLAGS + 3, 0), "struct"),
    "reserved_34": (lambda d: _flip(d, OFF_RES16 + 1, 0), "struct"),
    "reserved_81": (lambda d: _flip(d, OFF_RES3 + 2, 0), "struct"),
    "kdf_algorithm": (lambda d: _set_u8(d, OFF_KDF_ALG, 2), "struct"),
    "kdf_version": (lambda d: _set_u8(d, OFF_KDF_VER, 0x10), "struct"),
    "wrap_algorithm": (lambda d: _set_u8(d, OFF_WRAP_ALG, 2), "struct"),
    "kdf_memory_bitflip_out_of_range": (lambda d: _flip(d, OFF_M, 7), "struct"),
    "kdf_memory_dos": (lambda d: _set_u32(d, OFF_M, U32), "struct"),
    "kdf_iterations_dos": (lambda d: _set_u32(d, OFF_T, U32), "struct"),
    "kdf_parallelism_dos": (lambda d: _set_u32(d, OFF_P, U32), "struct"),
    "truncated": (lambda d: d[:-1], "struct"),
    "extended": (lambda d: d + b"\x00", "struct"),
    "empty": (lambda d: b"", "struct"),
    "zeroed": (lambda d: b"\x00" * HEADER_SIZE, "struct"),
}

# corrupções que mudam a tupla (salt, m, t, p) ⇒ duas derivações distintas
_NEW_TUPLE = {
    "kdf_salt",
    "kdf_memory_in_range",
    "kdf_iterations_in_range",
    "kdf_parallelism_in_range",
}


# leitura sem cache (Verificar) exercitada num subconjunto representativo
_UNBUFFERED_SUBSET = [
    "kdf_salt",
    "wrapped_key_tag",
    "kdf_memory_in_range",
    "magic",
    "kdf_memory_dos",
    "truncated",
    "extended",
    "empty",
]
_CORRUPTION_CASES = [pytest.param(n, False, id=f"{n}-buffered") for n in CORRUPTIONS] + [
    pytest.param(n, True, id=f"{n}-unbuffered") for n in _UNBUFFERED_SUBSET
]


def _expected_derivations(name: str) -> int:
    return 2 if name in _NEW_TUPLE else 1


def _check_corruption_kind(bad: bytes, kind: str) -> None:
    if kind == "auth":
        parse_header(bad, TESTING_POLICY)  # ainda estruturalmente válido
    else:
        with pytest.raises(FormatError):
            parse_header(bad, TESTING_POLICY)


def _assert_argon_calls_in_bounds(calls: list[dict[str, Any]]) -> None:
    for kw in calls:
        validate_params(
            KdfParams(kw["memory_cost"], kw["time_cost"], kw["parallelism"]), TESTING_POLICY
        )


# --- caso comum ------------------------------------------------------------------------


@pytest.mark.parametrize("unbuffered", [False, True])
def test_pristine_vault_opens_with_one_derivation(
    va: Path, pristine: dict[str, Pristine], argon_calls: list[dict[str, Any]], unbuffered: bool
) -> None:
    opened = _open(va, unbuffered=unbuffered)
    a = pristine["A"]
    assert opened.header_used == "vault.owl"
    assert opened.notes == []
    assert (opened.vault_id, opened.master_key) == (a.vault_id, a.master_key)
    assert len(argon_calls) == 1  # cópias idênticas ⇒ um Argon2id + unwrap


# --- corrupção de UMA cópia: fallback nas duas direções --------------------------------


@pytest.mark.parametrize(("name", "unbuffered"), _CORRUPTION_CASES)
def test_corrupted_primary_opens_via_bak(
    va: Path,
    pristine: dict[str, Pristine],
    argon_calls: list[dict[str, Any]],
    name: str,
    unbuffered: bool,
) -> None:
    mutate, kind = CORRUPTIONS[name]
    primary, _ = _paths(va)
    good = primary.read_bytes()
    bad = mutate(good)
    assert bad != good
    _check_corruption_kind(bad, kind)
    primary.write_bytes(bad)
    before = _snapshot(va)

    opened = _open(va, unbuffered=unbuffered)

    a = pristine["A"]
    assert opened.header_used == "vault.owl.bak"
    assert (opened.vault_id, opened.master_key) == (a.vault_id, a.master_key)
    # informa qual cópia foi usada
    assert any("vault.owl.bak" in n for n in opened.notes), opened.notes
    # uma derivação por tupla distinta (salt, m, t, p); nunca com parâmetros fora da política
    assert len(argon_calls) == _expected_derivations(name)
    _assert_argon_calls_in_bounds(argon_calls)
    # o manifesto autentica com a chave recuperada
    assert read_manifest(opened).manifest.vault_id == a.vault_id
    # nunca reescreve nenhuma cópia
    assert _snapshot(va) == before
    assert before[1] == {"vault.owl": bad, "vault.owl.bak": good}


@pytest.mark.parametrize(("name", "unbuffered"), _CORRUPTION_CASES)
def test_corrupted_bak_keeps_primary(
    va: Path,
    pristine: dict[str, Pristine],
    argon_calls: list[dict[str, Any]],
    name: str,
    unbuffered: bool,
) -> None:
    mutate, kind = CORRUPTIONS[name]
    _, bak = _paths(va)
    good = bak.read_bytes()
    bad = mutate(good)
    _check_corruption_kind(bad, kind)
    bak.write_bytes(bad)
    before = _snapshot(va)

    opened = _open(va, unbuffered=unbuffered)

    a = pristine["A"]
    assert opened.header_used == "vault.owl"
    assert (opened.vault_id, opened.master_key) == (a.vault_id, a.master_key)
    # a divergência / cópia ruim é reportada mesmo com o desbloqueio funcionando
    assert any("vault.owl.bak" in n for n in opened.notes), opened.notes
    assert len(argon_calls) == _expected_derivations(name)
    _assert_argon_calls_in_bounds(argon_calls)
    assert read_manifest(opened).manifest.vault_id == a.vault_id
    assert _snapshot(va) == before
    assert before[1] == {"vault.owl": good, "vault.owl.bak": bad}


@pytest.mark.parametrize("unbuffered", [False, True])
@pytest.mark.parametrize("which", ["vault.owl", "vault.owl.bak"])
def test_copy_replaced_by_directory_falls_back(
    va: Path, pristine: dict[str, Pristine], which: str, unbuffered: bool
) -> None:
    target = va / which
    target.unlink()
    target.mkdir()
    opened = _open(va, unbuffered=unbuffered)
    other = "vault.owl.bak" if which == "vault.owl" else "vault.owl"
    assert opened.header_used == other
    assert opened.master_key == pristine["A"].master_key
    assert any(which in n for n in opened.notes)
    assert target.is_dir()


# --- cópias ausentes -------------------------------------------------------------------


@pytest.mark.parametrize("unbuffered", [False, True])
def test_missing_primary_uses_bak(
    va: Path, pristine: dict[str, Pristine], argon_calls: list[dict[str, Any]], unbuffered: bool
) -> None:
    primary, _ = _paths(va)
    primary.unlink()
    opened = _open(va, unbuffered=unbuffered)
    assert opened.header_used == "vault.owl.bak"
    assert opened.master_key == pristine["A"].master_key
    assert any("vault.owl.bak" in n for n in opened.notes), opened.notes
    assert len(argon_calls) == 1
    assert not primary.exists()  # nunca recriada automaticamente


@pytest.mark.parametrize("unbuffered", [False, True])
def test_missing_bak_uses_primary(
    va: Path, pristine: dict[str, Pristine], argon_calls: list[dict[str, Any]], unbuffered: bool
) -> None:
    _, bak = _paths(va)
    bak.unlink()
    opened = _open(va, unbuffered=unbuffered)
    assert opened.header_used == "vault.owl"
    assert opened.master_key == pristine["A"].master_key
    assert any("vault.owl.bak" in n for n in opened.notes), opened.notes
    assert len(argon_calls) == 1
    assert not bak.exists()


@pytest.mark.parametrize("unbuffered", [False, True])
def test_both_copies_missing(va: Path, no_argon2: list[dict[str, Any]], unbuffered: bool) -> None:
    for p in _paths(va):
        p.unlink()
    with pytest.raises(FormatError):
        _open(va, unbuffered=unbuffered)
    assert no_argon2 == []


@pytest.mark.parametrize(
    ("p_name", "b_name"),
    [
        ("magic", "magic"),
        ("truncated", "extended"),
        ("kdf_memory_dos", "kdf_parallelism_dos"),
        ("zeroed", "empty"),
        ("reserved_81", "format_version"),
    ],
)
def test_both_copies_structurally_invalid(
    va: Path, no_argon2: list[dict[str, Any]], p_name: str, b_name: str
) -> None:
    primary, bak = _paths(va)
    primary.write_bytes(CORRUPTIONS[p_name][0](primary.read_bytes()))
    bak.write_bytes(CORRUPTIONS[b_name][0](bak.read_bytes()))
    with pytest.raises(FormatError):
        _open(va)
    assert no_argon2 == []


# --- as duas cópias corrompidas --------------------------------------------------------


@pytest.mark.parametrize(
    ("p_name", "b_name"),
    [
        ("kdf_salt", "wrapped_key_ct"),
        ("wrap_nonce", "kdf_memory_in_range"),
        ("wrapped_key_tag", "vault_id"),
        ("vault_id", "kdf_salt"),
        ("wrapped_key_ct", "wrapped_key_tag"),
        ("magic", "wrapped_key_ct"),  # uma estruturalmente inválida + outra não autêntica
        ("kdf_iterations_in_range", "truncated"),
    ],
)
def test_both_copies_corrupted_differently(va: Path, p_name: str, b_name: str) -> None:
    primary, bak = _paths(va)
    primary.write_bytes(CORRUPTIONS[p_name][0](primary.read_bytes()))
    bak.write_bytes(CORRUPTIONS[b_name][0](bak.read_bytes()))
    before = _snapshot(va)
    with pytest.raises(AuthenticationError):
        _open(va)
    assert _snapshot(va) == before


@pytest.mark.parametrize("name", [n for n, (_, k) in CORRUPTIONS.items() if k == "auth"])
def test_both_copies_corrupted_identically(
    va: Path, argon_calls: list[dict[str, Any]], name: str
) -> None:
    primary, bak = _paths(va)
    bad = CORRUPTIONS[name][0](primary.read_bytes())
    primary.write_bytes(bad)
    bak.write_bytes(bad)
    with pytest.raises(AuthenticationError):
        _open(va)
    assert len(argon_calls) == 1  # idênticas ⇒ um Argon2id + unwrap


# --- senha errada ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "state", ["identical", "primary_missing", "bak_missing", "primary_corrupt", "bak_corrupt"]
)
@pytest.mark.parametrize("unbuffered", [False, True])
def test_wrong_password(
    va: Path, argon_calls: list[dict[str, Any]], state: str, unbuffered: bool
) -> None:
    primary, bak = _paths(va)
    if state == "primary_missing":
        primary.unlink()
    elif state == "bak_missing":
        bak.unlink()
    elif state == "primary_corrupt":
        primary.write_bytes(CORRUPTIONS["wrapped_key_ct"][0](primary.read_bytes()))
    elif state == "bak_corrupt":
        bak.write_bytes(CORRUPTIONS["wrapped_key_ct"][0](bak.read_bytes()))
    with pytest.raises(AuthenticationError):
        _open(va, password=WRONG_PASSWORD, unbuffered=unbuffered)
    # mesma tupla (salt, m, t, p) nas cópias presentes ⇒ uma única derivação
    assert len(argon_calls) == 1


def test_wrong_password_with_divergent_copies_via_verify_and_restore(
    area: Area, va_full: Path
) -> None:
    primary, _ = _paths(va_full)
    primary.write_bytes(CORRUPTIONS["kdf_salt"][0](primary.read_bytes()))
    with pytest.raises(AuthenticationError):
        do_verify(area, password=WRONG_PASSWORD)
    with pytest.raises(AuthenticationError):
        do_restore(area, password=WRONG_PASSWORD)
    assert not area.dest().exists()


# --- cabeçalho de OUTRO cofre ----------------------------------------------------------

SWAP_CASES = [
    "primary_from_B",
    "bak_from_B",
    "both_from_B",
    "primary_from_B_bak_missing",
    "bak_from_B_primary_missing",
    "primary_from_B_bak_not_authentic",
    "primary_from_B_bak_invalid",
    "bak_from_B_primary_not_authentic",
    "bak_from_B_primary_invalid",
]


def _apply_swap(v: Path, foreign: bytes, case: str) -> None:
    primary, bak = _paths(v)
    corrupt_auth = CORRUPTIONS["wrapped_key_ct"][0]
    corrupt_struct = CORRUPTIONS["truncated"][0]
    if case == "primary_from_B":
        primary.write_bytes(foreign)
    elif case == "bak_from_B":
        bak.write_bytes(foreign)
    elif case == "both_from_B":
        primary.write_bytes(foreign)
        bak.write_bytes(foreign)
    elif case == "primary_from_B_bak_missing":
        primary.write_bytes(foreign)
        bak.unlink()
    elif case == "bak_from_B_primary_missing":
        bak.write_bytes(foreign)
        primary.unlink()
    elif case == "primary_from_B_bak_not_authentic":
        primary.write_bytes(foreign)
        bak.write_bytes(corrupt_auth(bak.read_bytes()))
    elif case == "primary_from_B_bak_invalid":
        primary.write_bytes(foreign)
        bak.write_bytes(corrupt_struct(bak.read_bytes()))
    elif case == "bak_from_B_primary_not_authentic":
        bak.write_bytes(foreign)
        primary.write_bytes(corrupt_auth(primary.read_bytes()))
    elif case == "bak_from_B_primary_invalid":
        bak.write_bytes(foreign)
        primary.write_bytes(corrupt_struct(primary.read_bytes()))
    else:  # pragma: no cover
        raise AssertionError(case)


@pytest.mark.parametrize("unbuffered", [False, True])
@pytest.mark.parametrize("case", SWAP_CASES)
def test_header_from_other_vault_with_same_password_rejected(
    va: Path, pristine: dict[str, Pristine], case: str, unbuffered: bool
) -> None:
    _apply_swap(va, pristine["B"].header, case)
    before = _snapshot(va)
    with pytest.raises((InconsistentVaultError, AuthenticationError)):
        opened = _open(va, unbuffered=unbuffered)
        pytest.fail(f"cabeçalho estranho aceito: usou {opened.header_used}, notas {opened.notes}")
    assert _snapshot(va) == before


@pytest.mark.parametrize("case", ["primary_from_B", "bak_from_B", "both_from_B"])
def test_header_from_other_vault_rejected_by_verify_and_restore(
    area: Area, va_full: Path, pristine: dict[str, Pristine], case: str
) -> None:
    _apply_swap(va_full, pristine["B"].header, case)
    before = _snapshot(va_full)
    with pytest.raises((InconsistentVaultError, AuthenticationError)):
        do_verify(area)
    with pytest.raises((InconsistentVaultError, AuthenticationError)):
        do_restore(area)
    assert not area.dest().exists()
    assert _snapshot(va_full) == before


class _Crash(BaseException):
    """Queda simulada (passa pelo tratamento normal de erros)."""


def test_other_vault_header_rejected_using_journal_hint(
    area: Area, pristine: dict[str, Pristine]
) -> None:
    """Sem manifesto (criação interrompida), o vault_id em claro do diário é a referência."""
    write_tree(area.src, {"a.txt": b"x" * 100, "b.txt": b"y" * 10})
    faults.fail_at("blob.write", 1, _Crash)
    with pytest.raises(_Crash):
        make_vault(area)
    faults.reset()
    v = area.vault()
    assert not (v / "manifest.owl").exists()
    assert (v / "journal").is_dir() and any((v / "journal").iterdir())

    own = _open(v)
    assert own.header_used == "vault.owl"
    own_header = (v / "vault.owl").read_bytes()
    foreign = pristine["B"].header
    for case in ("primary_from_B", "bak_from_B", "both_from_B", "primary_from_B_bak_missing"):
        for p, data in zip(_paths(v), (own_header, own_header), strict=True):
            p.write_bytes(data)
        _apply_swap(v, foreign, case)
        with pytest.raises((InconsistentVaultError, AuthenticationError)):
            opened = _open(v)
            pytest.fail(f"{case}: cabeçalho estranho aceito ({opened.header_used})")


@pytest.mark.parametrize("header_state", ["identical", "primary_corrupt"])
@pytest.mark.parametrize("manifest_copy", ["manifest.owl", "manifest.owl.bak"])
def test_one_manifest_copy_with_corrupted_plain_vault_id_does_not_block_unlock(
    va: Path, pristine: dict[str, Pristine], manifest_copy: str, header_state: str
) -> None:
    """O vault_id em claro do manifesto é só uma DICA (§3.1). Um bit trocado nesse campo de
    UMA cópia do manifesto não pode tornar o cofre inabrível: os cabeçalhos estão íntegros
    e a outra cópia do manifesto também (§5.1: "uma ... não autêntica ⇒ usar a outra")."""
    m = va / manifest_copy
    m.write_bytes(_flip(m.read_bytes(), 16 + 4, 0))  # vault_id do cabeçalho do contêiner
    if header_state == "primary_corrupt":
        primary, _ = _paths(va)
        primary.write_bytes(CORRUPTIONS["wrapped_key_ct"][0](primary.read_bytes()))
    a = pristine["A"]
    opened = _open(va)
    assert (opened.vault_id, opened.master_key) == (a.vault_id, a.master_key)
    mread = read_manifest(opened)
    other = "manifest.owl.bak" if manifest_copy == "manifest.owl" else "manifest.owl"
    assert mread.used == other
    assert mread.notes  # a cópia ruim do manifesto é reportada


def test_header_from_vault_with_other_password_is_not_used(
    va: Path, pristine: dict[str, Pristine]
) -> None:
    primary, _ = _paths(va)
    primary.write_bytes(pristine["C"].header)
    opened = _open(va)  # senha de A
    assert opened.header_used == "vault.owl.bak"
    assert opened.vault_id == pristine["A"].vault_id
    assert opened.master_key == pristine["A"].master_key
    assert any("vault.owl.bak" in n for n in opened.notes)


@pytest.mark.parametrize("case", ["primary_from_B", "bak_from_B", "both_from_B"])
def test_other_vault_header_rejected_even_with_its_own_password(
    va: Path, pristine: dict[str, Pristine], case: str
) -> None:
    """Quem conhece a senha do cofre C não consegue usar o cabeçalho de C na pasta de A."""
    _apply_swap(va, pristine["C"].header, case)
    with pytest.raises((InconsistentVaultError, AuthenticationError)):
        _open(va, password=OTHER_PASSWORD)


@pytest.mark.parametrize("which", ["vault.owl", "vault.owl.bak"])
def test_same_vault_id_but_different_master_key_rejected(
    va: Path, pristine: dict[str, Pristine], which: str
) -> None:
    a = pristine["A"]
    forged = build_header(os.urandom(32), a.vault_id, PASSWORD, TESTING_PARAMS, TESTING_POLICY)
    (va / which).write_bytes(forged.pack())
    with pytest.raises(InconsistentVaultError):
        _open(va)


def test_consistent_rewrap_is_accepted_with_one_derivation_per_tuple(
    va: Path, pristine: dict[str, Pristine], argon_calls: list[dict[str, Any]]
) -> None:
    """Duas cópias diferentes que autenticam com o mesmo vault_id e a mesma master_key não
    são inconsistentes; a KEK é derivada uma vez por tupla (salt, m, t, p) distinta."""
    a = pristine["A"]
    rewrapped = build_header(
        a.master_key, a.vault_id, PASSWORD, KdfParams(8 * 1024, 2, 1), TESTING_POLICY
    ).pack()
    argon_calls.clear()
    primary, _ = _paths(va)
    primary.write_bytes(rewrapped)
    opened = _open(va)
    assert opened.master_key == a.master_key and opened.vault_id == a.vault_id
    assert opened.header_used in ("vault.owl", "vault.owl.bak")
    assert opened.notes  # divergência reportada
    assert len(argon_calls) == 2
    assert primary.read_bytes() == rewrapped


# --- verificar / restaurar com uma cópia ruim ------------------------------------------


@pytest.mark.parametrize("target", ["vault.owl", "vault.owl.bak"])
def test_verify_reports_header_divergence_even_when_unlock_works(
    area: Area, va_full: Path, target: str
) -> None:
    """FORMAT §3.1 passo 5: Verificar autentica as duas cópias e reporta a divergência."""
    path = va_full / target
    bad = CORRUPTIONS["wrapped_key_tag"][0](path.read_bytes())
    path.write_bytes(bad)
    before = _snapshot(va_full)
    report = do_verify(area)
    assert report.ok, report.bad
    assert report.files_ok == 2
    assert any("vault.owl.bak" in n for n in report.redundancy), report.redundancy
    assert not report.fully_ok  # redundância perdida não é "cofre íntegro"
    assert _snapshot(va_full) == before


def test_restore_with_corrupted_primary_uses_bak(
    area: Area, va_full: Path, pristine: dict[str, Pristine]
) -> None:
    primary, _ = _paths(va_full)
    bad = CORRUPTIONS["kdf_salt"][0](primary.read_bytes())
    primary.write_bytes(bad)
    before = _snapshot(va_full)
    report = do_restore(area)
    assert report.ok, (report.failed, report.conflicts)
    assert any("vault.owl.bak" in n for n in report.notes), report.notes
    assert tree_digest(area.dest()) == tree_digest(pristine["A"].src)
    assert _snapshot(va_full) == before


# --- parâmetros abusivos em cofres reais -----------------------------------------------


@pytest.mark.parametrize("policy", [TESTING_POLICY, PRODUCTION_POLICY], ids=["teste", "producao"])
@pytest.mark.parametrize("field_off", [OFF_M, OFF_T, OFF_P], ids=["m", "t", "p"])
def test_dos_params_in_both_copies_rejected_without_derivation(
    va: Path, no_argon2: list[dict[str, Any]], policy: KdfPolicy, field_off: int
) -> None:
    for p in _paths(va):
        p.write_bytes(_set_u32(p.read_bytes(), field_off, U32))
    with pytest.raises(FormatError):
        _open(va, policy=policy)
    assert no_argon2 == []


def test_dos_params_rejected_by_verify_without_derivation(
    area: Area, va_full: Path, no_argon2: list[dict[str, Any]]
) -> None:
    for p in _paths(va_full):
        p.write_bytes(_set_u32(p.read_bytes(), OFF_M, 4 * 1024 * 1024))  # 4 GiB
    with pytest.raises(FormatError):
        do_verify(area)
    assert no_argon2 == []


def test_testing_params_vault_rejected_by_production_policy(
    va: Path, no_argon2: list[dict[str, Any]]
) -> None:
    with pytest.raises(FormatError):
        _open(va, policy=PRODUCTION_POLICY)
    assert no_argon2 == []


# --- memória disponível antes de derivar -----------------------------------------------


def test_insufficient_memory_identical_copies_refused_before_derivation(
    va: Path, monkeypatch: pytest.MonkeyPatch, no_argon2: list[dict[str, Any]]
) -> None:
    _fake_memory(monkeypatch, physical=0, commit=0)
    with pytest.raises(ResourceError):
        _open(va, policy=CHECKING_TEST_POLICY)
    assert no_argon2 == []


@pytest.mark.parametrize("state", ["primary_corrupt", "bak_missing"])
def test_insufficient_memory_reported_as_resource_error_with_one_good_copy(
    va: Path, monkeypatch: pytest.MonkeyPatch, no_argon2: list[dict[str, Any]], state: str
) -> None:
    """Falta de memória não é "senha incorreta/corrupção": com cópias divergentes (ou só
    uma cópia) o usuário deve receber o mesmo ResourceError do caso de cópias idênticas."""
    primary, bak = _paths(va)
    if state == "primary_corrupt":
        primary.write_bytes(CORRUPTIONS["wrapped_key_ct"][0](primary.read_bytes()))
    else:
        bak.unlink()
    _fake_memory(monkeypatch, physical=0, commit=0)
    with pytest.raises(ResourceError):
        _open(va, policy=CHECKING_TEST_POLICY)
    assert no_argon2 == []


def test_memory_check_uses_available_commit_memory(
    va: Path, monkeypatch: pytest.MonkeyPatch, argon_calls: list[dict[str, Any]]
) -> None:
    """FORMAT §3 (revisado): memória COMPROMETÍVEL (RAM + paginação) ≥ m + 256 MiB.

    Pouca RAM física livre com paginação ampla NÃO recusa; pouca memória comprometível
    recusa antes do Argon2id."""
    m_bytes = TESTING_PARAMS.memory_kib * 1024
    _fake_memory(monkeypatch, physical=m_bytes + 64 * MIB, commit=1 * TIB)
    _open(va, policy=CHECKING_TEST_POLICY)  # abre
    argon_calls.clear()
    _fake_memory(monkeypatch, physical=1 * TIB, commit=m_bytes + 64 * MIB)
    with pytest.raises(ResourceError):
        _open(va, policy=CHECKING_TEST_POLICY)
    assert argon_calls == []
