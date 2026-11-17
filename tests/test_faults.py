"""Injeção de falhas (disco cheio / queda) em cada ponto de escrita da criação + retomada.

Cobre ARCHITECTURE §4.2 (retomada) e §5 (consistência, atomicidade e falhas) e as linhas
do TEST_PLAN "Falta de espaço simulada" e "Interrupção/queda em cada ponto de escrita +
retomada".

Depois de CADA falha injetada:
* a origem não mudou (conteúdo, mtime, árvore);
* o cofre não tem ``complete.owl`` (a criação não pode parecer concluída);
* ``resume_create`` termina, o cofre verifica por completo e restaura fielmente;
* nenhum blob existente é aberto para escrita e todo ``file_id`` gerado é inédito.

A "queda" é simulada com uma subclasse de ``BaseException`` (passa pelos tratadores de
erro comuns, como uma interrupção do processo). "Disco cheio" é ``OSError(28)``.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from owl_vault.application import create as create_mod
from owl_vault.application.create import CreateResult, inspect_vault_dir, resume_create
from owl_vault.application.protection import ProtectedPaths
from owl_vault.application.vault import open_vault, read_manifest
from owl_vault.crypto.kdf import TESTING_POLICY
from owl_vault.domain.errors import InsufficientSpaceError, OwlVaultError, StateError
from owl_vault.storage import faults, winfs
from owl_vault.storage.blob import encrypt_source_to_blob
from owl_vault.storage.journal import read_journal
from tests.conftest import (
    PASSWORD,
    SMALL_CHUNK,
    Area,
    do_restore,
    do_verify,
    make_vault,
    tree_digest,
    write_tree,
)

# --------------------------------------------------------------------------------------
# Falhas simuladas


class Crash(BaseException):
    """Queda simulada: não é capturada por ``except Exception``/``except OSError``."""


def disk_full() -> BaseException:
    return OSError(28, "No space left on device")


def crash() -> BaseException:
    return Crash("queda simulada")


MAKERS: dict[str, Callable[[], BaseException]] = {"disk_full": disk_full, "crash": crash}
RAISES: dict[str, Any] = {"disk_full": (OSError, OwlVaultError), "crash": Crash}


@pytest.fixture(autouse=True)
def _deterministic_checkpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sem checkpoint por tempo (5 s): a contagem de segmentos do diário fica determinística."""
    monkeypatch.setattr(create_mod, "_CHECKPOINT_SECONDS", 1e9)


# --------------------------------------------------------------------------------------
# Amostra e utilidades


def _sample(area: Area) -> list[int]:
    """7 arquivos (vazio, 1 chunk, múltiplos chunks, múltiplo exato), 3 pastas (1 vazia)."""
    c = SMALL_CHUNK
    write_tree(
        area.src,
        {
            "vazio.txt": b"",
            "pequeno.txt": b"ola mundo",
            "multi.bin": os.urandom(3 * c + 17),
            "exato.bin": os.urandom(2 * c),
            "pasta vazia": {},
            "sub": {"a.txt": b"A" * 100, "mais": {"b.bin": os.urandom(c + 1)}},
            "Ação 日本語 😀.txt": b"acentos e emoji",
        },
    )
    return [p.stat().st_size for p in area.src.rglob("*") if p.is_file()]


def _chunks(size: int) -> int:
    return max(1, -(-size // SMALL_CHUNK))


def _total(op: str, sizes: list[int]) -> int:
    """Quantas vezes ``op`` passa pelo ponto de falha numa criação completa da amostra."""
    if op == "blob.write":  # cabeçalho + um por chunk
        return sum(1 + _chunks(s) for s in sizes)
    if op == "restore.write":  # um por chunk decifrado no teste de restauração
        return sum(_chunks(s) for s in sizes)
    return len(sizes)  # blob.flush/rename, restore.flush/rename, remove (.chk)


def _nth(op: str, which: int | str, sizes: list[int]) -> int:
    if isinstance(which, int):
        return which
    total = _total(op, sizes)
    return {"first": 1, "middle": (total + 1) // 2, "last": total}[which]


def _vext(area: Area, name: str = "cofre") -> str:
    return winfs.to_extended(str(area.vault(name)))


def _resume(area: Area, name: str = "cofre", **kw: Any) -> CreateResult:
    return resume_create(
        str(area.vault(name)),
        str(area.src),
        PASSWORD,
        kdf_policy=TESTING_POLICY,
        protected=ProtectedPaths.none(),
        **kw,
    )


def _blob_ids(area: Area, name: str = "cofre") -> set[str]:
    data = area.vault(name) / "data"
    return {p.name[:32] for p in data.glob("*/*.owlb")} if data.is_dir() else set()


def _tmp_files(area: Area, name: str = "cofre") -> list[Path]:
    return [p for p in area.vault(name).rglob("*.tmp")]


def _journal_ids(area: Area, name: str = "cofre") -> dict[tuple[str, ...], str]:
    opened = open_vault(_vext(area, name), PASSWORD, TESTING_POLICY)
    st = read_journal(opened.layout, opened.master_key, opened.vault_id)
    return {e.path: e.file_id.hex() for e, _ in st.files.values()}


def _manifest_ids(area: Area, name: str = "cofre") -> dict[tuple[str, ...], str]:
    opened = open_vault(_vext(area, name), PASSWORD, TESTING_POLICY)
    return {f.path: f.file_id.hex() for f in read_manifest(opened).manifest.files}


def _sha(p: Path) -> str | None:
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


_DATA_TMP = re.compile(r"\\data\\([0-9a-f]{2})\\([0-9a-f]{32})\.tmp$", re.IGNORECASE)
_WRITE_MASK = winfs.GENERIC_WRITE | 0x2 | 0x4 | 0x10000000  # WRITE_DATA|APPEND_DATA|GENERIC_ALL


class IoSpy:
    """Registra toda abertura Win32 com acesso de escrita e toda cifragem de blob."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.created: list[str] = []
        self.write_opens: list[tuple[str, int]] = []
        self.encrypted: list[str] = []
        orig_open = winfs.Win32File.__dict__["open"].__func__
        spy = self

        def _open(cls: Any, path: str, access: int, share: int, disp: int, flags: int) -> Any:
            if access & _WRITE_MASK:
                spy.write_opens.append((path, disp))
                if disp == winfs.CREATE_NEW:
                    spy.created.append(path)
            return orig_open(cls, path, access, share, disp, flags)

        monkeypatch.setattr(winfs.Win32File, "open", classmethod(_open))
        orig_enc = encrypt_source_to_blob

        def _enc(*a: Any, **k: Any) -> Any:
            res = orig_enc(*a, **k)
            spy.encrypted.append(res.file_id.hex())
            return res

        monkeypatch.setattr(create_mod, "encrypt_source_to_blob", _enc)

    def reset(self) -> None:
        self.created.clear()
        self.write_opens.clear()
        self.encrypted.clear()

    def new_blob_ids(self) -> list[str]:
        """``file_id`` de cada ``data/<hh>/<id>.tmp`` criado (CREATE_NEW)."""
        out = []
        for p in self.created:
            m = _DATA_TMP.search(p)
            if m:
                assert m.group(2)[:2] == m.group(1).lower()
                out.append(m.group(2).lower())
        return out

    def assert_blob_rules(self, preexisting: set[str]) -> None:
        """FORMAT §4.3: nenhum blob existente aberto para escrita; todo file_id inédito."""
        owlb = [p for p, _ in self.write_opens if p.lower().endswith(".owlb")]
        assert owlb == [], f"blob existente aberto para escrita: {owlb}"
        ids = self.new_blob_ids()
        assert len(ids) == len(set(ids)), "file_id repetido entre tentativas"
        assert not (set(ids) & preexisting), "file_id reutilizado de um blob já existente"


def _assert_interrupted(area: Area, before: dict[str, Any]) -> None:
    assert tree_digest(area.src) == before, "a origem foi alterada"
    assert not (area.vault() / "complete.owl").exists(), "falha deixou complete.owl"
    assert inspect_vault_dir(str(area.vault())).kind == "vault-incomplete"
    # falhas que passam pelo código (exceções) removem o temporário pelo handle
    assert _tmp_files(area) == [], _tmp_files(area)


def _assert_complete_and_faithful(
    area: Area, before: dict[str, Any], result: CreateResult, nfiles: int
) -> None:
    assert result.status == "success", result.divergences
    assert result.files == nfiles
    assert tree_digest(area.src) == before, "a origem foi alterada"
    assert (area.vault() / "complete.owl").is_file()
    assert not (area.vault() / "journal").exists(), "segmentos do diário não foram removidos"
    assert _tmp_files(area) == []
    assert list(area.testarea.iterdir()) == [], "resíduos do teste de restauração"
    rep = do_verify(area)
    assert rep.fully_ok, (rep.bad, rep.anomalies, rep.notes, rep.creation_status)
    assert rep.files_ok == nfiles
    # invariante em COMPLETE: data/ contém exatamente os blobs do manifesto
    assert _blob_ids(area) == set(_manifest_ids(area).values())
    rest = do_restore(area)
    assert rest.ok, (rest.failed, rest.conflicts)
    assert tree_digest(area.dest()) == before


# --------------------------------------------------------------------------------------
# Matriz de pontos de falha

# Ordem numa criação da amostra (com 7 arquivos < 64 e sem checkpoint por tempo):
# journal.write #1 = segmento 0, #2 = checkpoint final da cifragem, #3 = manifest_written,
# #4 = verified, #5 = restore_tested; manifest #1 = manifest.owl, #2 = manifest.owl.bak;
# remove #1..#7 = .chk do teste de restauração.
CRASH_POINTS: list[tuple[str, int | str]] = [
    ("blob.write", "first"),  # cabeçalho do 1º blob
    ("blob.write", "last"),  # último chunk do último arquivo
    ("blob.flush", "last"),
    ("blob.rename", "middle"),
    ("journal.write", 2),  # checkpoint da cifragem: blobs promovidos viram órfãos
    ("journal.rename", 3),  # manifest_written
    ("journal.write", 4),  # verified
    ("journal.flush", 5),  # restore_tested
    ("manifest.write", 1),
    ("manifest.write", 2),  # manifest.owl.bak
    ("restore.write", "middle"),
    ("restore.rename", "first"),
    ("remove", 1),  # .chk fica na pasta de teste
    ("complete.rename", 1),
]

DISK_FULL_POINTS: list[tuple[str, int | str]] = [
    ("blob.write", "middle"),
    ("blob.rename", "last"),
    ("journal.write", 3),
    ("manifest.rename", 2),
    ("restore.write", "first"),
    ("complete.write", 1),
]

_CASES = [pytest.param(op, w, "crash", id=f"crash-{op}-{w}") for op, w in CRASH_POINTS] + [
    pytest.param(op, w, "disk_full", id=f"diskfull-{op}-{w}") for op, w in DISK_FULL_POINTS
]


def _after_encryption(op: str, nth: int) -> bool:
    """Falha depois que todos os blobs foram gravados E registrados no diário."""
    if op.startswith("blob."):
        return False
    return not (op.startswith("journal.") and nth <= 2)


@pytest.mark.parametrize(("op", "which", "kind"), _CASES)
def test_fault_during_create_then_resume(
    area: Area, monkeypatch: pytest.MonkeyPatch, op: str, which: int | str, kind: str
) -> None:
    sizes = _sample(area)
    before = tree_digest(area.src)
    nth = _nth(op, which, sizes)
    spy = IoSpy(monkeypatch)
    faults.fail_at(op, nth, MAKERS[kind])
    with pytest.raises(RAISES[kind]) as excinfo:
        make_vault(area)
    _assert_interrupted(area, before)
    if kind == "disk_full" and op.startswith("blob."):
        # ARCHITECTURE §5: 112/ENOSPC classificado como "disco cheio" (retomável)
        assert isinstance(excinfo.value, InsufficientSpaceError), repr(excinfo.value)
        assert excinfo.value.retryable

    faults.reset()
    blobs_before = _blob_ids(area)
    manifest_before = _sha(area.vault() / "manifest.owl")
    journaled = set(_journal_ids(area).values())
    if op.startswith("blob."):
        # o checkpoint final (no finally da cifragem) registra todo blob já promovido
        assert blobs_before == journaled
    spy.encrypted.clear()

    result = _resume(area)

    _assert_complete_and_faithful(area, before, result, len(sizes))
    spy.assert_blob_rules(preexisting=set())  # todos os file_ids da sessão são únicos
    created_in_resume = set(spy.encrypted)
    assert not (created_in_resume & blobs_before), "file_id reutilizado na retomada"
    final_ids = set(_manifest_ids(area).values())
    # o que já estava registrado e íntegro é mantido (origem não mudou)
    assert journaled <= final_ids
    assert len(spy.encrypted) == len(sizes) - len(journaled)
    if _after_encryption(op, nth):
        # ARCHITECTURE §4.2: nada é cifrado de novo; blobs e manifesto preservados
        assert spy.encrypted == []
        assert _blob_ids(area) == blobs_before
        if manifest_before is not None:
            assert _sha(area.vault() / "manifest.owl") == manifest_before
    assert _sha(area.vault() / "manifest.owl") == _sha(area.vault() / "manifest.owl.bak")


# --------------------------------------------------------------------------------------
# Disco cheio fora da cifragem: deve ser classificado (ARCHITECTURE §5)


@pytest.mark.parametrize(
    ("op", "nth"),
    [
        ("journal.write", 3),
        ("manifest.write", 1),
        ("manifest.write", 2),
        ("restore.write", 1),
        ("complete.write", 1),
    ],
)
def test_disk_full_outside_encryption_is_classified(area: Area, op: str, nth: int) -> None:
    """ENOSPC em qualquer escrita da criação vira "disco cheio" (InsufficientSpaceError).

    ARCHITECTURE §5: "112/ENOSPC 'disco cheio' (retomável se ainda não há espaço)". Um
    ``OSError`` cru escapa do tratamento da CLI (que só captura ``OwlVaultError``).
    """
    _sample(area)
    before = tree_digest(area.src)
    faults.fail_at(op, nth, disk_full)
    with pytest.raises(InsufficientSpaceError):
        make_vault(area)
    _assert_interrupted(area, before)  # a retomada depois é coberta pela matriz acima


def test_disk_full_at_journal_checkpoint_inside_encryption_loop(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Checkpoint do diário a cada 2 arquivos; disco cheio no 1º checkpoint da cifragem."""
    monkeypatch.setattr(create_mod, "_CHECKPOINT_FILES", 2)
    sizes = _sample(area)
    before = tree_digest(area.src)
    faults.fail_at("journal.write", 2, disk_full)
    with pytest.raises((OSError, OwlVaultError)):
        make_vault(area)
    _assert_interrupted(area, before)
    faults.reset()
    _assert_complete_and_faithful(area, before, _resume(area), len(sizes))


# --------------------------------------------------------------------------------------
# Falhas na inicialização (antes do segmento 0 do diário)


@pytest.mark.parametrize("kind", ["disk_full", "crash"])
def test_fault_at_first_header_copy_leaves_reusable_folder(area: Area, kind: str) -> None:
    _sample(area)
    before = tree_digest(area.src)
    faults.fail_at("header.write", 1, MAKERS[kind])
    with pytest.raises(RAISES[kind]):
        make_vault(area)
    assert tree_digest(area.src) == before
    vault = area.vault()
    assert not (vault / "complete.owl").exists()
    assert not (vault / "vault.owl").exists()
    assert _tmp_files(area) == []
    faults.reset()
    # sem cabeçalho não há o que retomar
    with pytest.raises(OwlVaultError):
        _resume(area)
    # a pasta ficou vazia: uma criação nova nela funciona
    assert [p.name for p in vault.iterdir()] == []
    assert make_vault(area).status == "success"
    assert do_verify(area).fully_ok


@pytest.mark.parametrize(
    ("op", "nth", "kind"),
    [
        ("header.write", 2, "crash"),
        ("header.rename", 2, "disk_full"),
        ("journal.write", 1, "disk_full"),
        ("journal.flush", 1, "crash"),
    ],
)
def test_fault_before_journal_segment_zero_is_incomplete_init(
    area: Area, op: str, nth: int, kind: str
) -> None:
    """ARCHITECTURE §4.2: sem segmento 0 ⇒ "inicialização incompleta"; nada é apagado."""
    _sample(area)
    before = tree_digest(area.src)
    faults.fail_at(op, nth, MAKERS[kind])
    with pytest.raises(RAISES[kind]):
        make_vault(area)
    assert tree_digest(area.src) == before
    vault = area.vault()
    assert not (vault / "complete.owl").exists()
    assert (vault / "vault.owl").is_file()
    names_before = sorted(p.name for p in vault.rglob("*"))
    faults.reset()
    with pytest.raises(StateError):
        _resume(area)
    # o app não apaga a pasta nem o cabeçalho automaticamente
    assert sorted(p.name for p in vault.rglob("*")) == names_before
    assert tree_digest(area.src) == before


def test_fault_writing_readme_is_resumable(area: Area) -> None:
    sizes = _sample(area)
    before = tree_digest(area.src)
    faults.fail_at("readme.write", 1, disk_full)
    with pytest.raises((OSError, OwlVaultError)):
        make_vault(area)
    _assert_interrupted(area, before)
    faults.reset()
    _assert_complete_and_faithful(area, before, _resume(area), len(sizes))


def test_readme_present_after_resume_from_crash_before_readme(area: Area) -> None:
    """FORMAT §1: um cofre concluído contém LEIA-ME.txt (explicação genérica)."""
    _sample(area)
    faults.fail_at("readme.write", 1, crash)
    with pytest.raises(Crash):
        make_vault(area)
    faults.reset()
    assert _resume(area).status == "success"
    assert (area.vault() / "LEIA-ME.txt").is_file()


# --------------------------------------------------------------------------------------
# Falha depois de complete.owl (limpeza final)


def test_crash_during_final_cleanup_after_completion_record(area: Area) -> None:
    """Queda ao remover os segmentos do diário: complete.owl já existe e autentica."""
    sizes = _sample(area)
    before = tree_digest(area.src)
    faults.fail_at("remove", len(sizes) + 1, crash)  # 1ª remoção após os 7 .chk
    with pytest.raises(Crash):
        make_vault(area)
    faults.reset()
    assert tree_digest(area.src) == before
    assert (area.vault() / "complete.owl").is_file()
    rep = do_verify(area)
    assert rep.completed, rep.creation_status
    assert rep.ok and rep.files_ok == len(sizes), rep.bad
    rest = do_restore(area)
    assert rest.ok, (rest.failed, rest.conflicts)
    assert tree_digest(area.dest()) == before
    # revisão de segurança [5]: a retomada termina a limpeza (sem recifrar nada)...
    cleaned = _resume(area)
    assert cleaned.status == "success"
    assert not (area.vault() / "journal").exists()
    assert do_verify(area).fully_ok
    # ...e depois disso não há mais nada para retomar
    with pytest.raises(StateError):
        _resume(area)


# --------------------------------------------------------------------------------------
# Falha repetida: na criação e de novo na retomada


@pytest.mark.parametrize(
    ("first", "second", "kind"),
    [
        (("blob.rename", 3), ("blob.write", 2), "disk_full"),
        (("blob.flush", 2), ("journal.write", 2), "crash"),  # manifest_written da retomada
        (("manifest.write", 1), ("manifest.rename", 1), "disk_full"),
        (("complete.write", 1), ("remove", 1), "crash"),  # .chk da retomada fica para trás
    ],
    ids=["blob-blob-diskfull", "blob-journal-crash", "manifest-manifest-diskfull", "complete-chk"],
)
def test_fault_again_during_resume(
    area: Area,
    monkeypatch: pytest.MonkeyPatch,
    first: tuple[str, int],
    second: tuple[str, int],
    kind: str,
) -> None:
    sizes = _sample(area)
    before = tree_digest(area.src)
    spy = IoSpy(monkeypatch)
    faults.fail_at(first[0], first[1], MAKERS[kind])
    with pytest.raises(RAISES[kind]):
        make_vault(area)
    faults.reset()
    faults.fail_at(second[0], second[1], MAKERS[kind])
    with pytest.raises(RAISES[kind]):
        _resume(area)
    _assert_interrupted(area, before)
    faults.reset()
    result = _resume(area)
    _assert_complete_and_faithful(area, before, result, len(sizes))
    spy.assert_blob_rules(preexisting=set())
