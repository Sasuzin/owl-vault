"""Adulteração adversarial de um cofre real (THREAT_MODEL I1/A2; FORMAT §4, §5.1, §5.4).

Para cada adulteração: Verificar deve listar o(s) arquivo(s) afetado(s) em ``report.bad``;
Restaurar NÃO pode produzir o arquivo afetado com o nome final nem deixar ``.part``, e todos
os outros arquivos devem ser restaurados fielmente. Verificar/Restaurar nunca alteram o cofre.

Um cofre "pristino" (e um segundo cofre da mesma origem, com a MESMA senha) é criado uma vez
por módulo com ``make_vault``; cada teste adultera uma cópia byte a byte dele (copiar um cofre
para outro disco é uso normal). Os testes que simulam queda criam o cofre do zero.
"""

from __future__ import annotations

import _winapi
import hashlib
import os
import random
import shutil
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from owl_vault.application.restore import MARKER_NAME, RestoreReport
from owl_vault.application.vault import open_vault, read_manifest
from owl_vault.application.verify import VerifyReport
from owl_vault.crypto.kdf import TESTING_POLICY
from owl_vault.domain.errors import (
    InconsistentVaultError,
    IntegrityError,
    OwlVaultError,
)
from owl_vault.domain.models import FileEntryRecord
from owl_vault.domain.names import display_path
from owl_vault.storage import faults
from owl_vault.storage.container import ContainerKind, read_container, seal
from owl_vault.storage.manifest import manifest_to_obj
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

C = SMALL_CHUNK
TAG = 16
BLOB_HDR = 64
CONTAINER_HDR = 64


def _rand(seed: int, n: int) -> bytes:
    return random.Random(seed).randbytes(n)  # noqa: S311 - dados sintéticos determinísticos


SPEC: dict[str, Any] = {
    "multi.bin": _rand(1, 4 * C + 100),  # 5 chunks (4 cheios + final de 100 bytes)
    "exato.bin": _rand(2, 3 * C),  # 3 chunks cheios (o último é o final)
    "pequeno.txt": b"ola mundo",
    "vazio.txt": b"",  # 1 chunk vazio (só a tag)
    "par-a.bin": _rand(3, C + 7),  # par-a e par-b têm o MESMO tamanho
    "par-b.bin": _rand(4, C + 7),
    "pasta vazia": {},
    "sub": {"outro.bin": _rand(5, 2 * C + 5), "fundo": {"leaf.txt": b"folha"}},
}
FILES = {
    "multi.bin",
    "exato.bin",
    "pequeno.txt",
    "vazio.txt",
    "par-a.bin",
    "par-b.bin",
    "sub\\outro.bin",
    "sub\\fundo\\leaf.txt",
}
N_FILES = len(FILES)


class Crash(BaseException):
    """Queda simulada: passa por cima do tratamento normal de erros."""


# --- cofre pristino (uma vez por módulo) -------------------------------------------------


@dataclass
class VaultInfo:
    path: Path
    master_key: bytes
    vault_id: bytes
    entries: dict[str, FileEntryRecord]
    manifest_obj: dict[str, Any]
    manifest_raw: bytes
    completion_obj: dict[str, Any]


@dataclass
class Pristine:
    before: dict[str, Any]  # tree_digest da origem
    main: VaultInfo
    other: VaultInfo  # outro cofre, mesma origem e MESMA senha


def _vault_info(path: Path) -> VaultInfo:
    opened = open_vault(str(path), PASSWORD, TESTING_POLICY)
    mread = read_manifest(opened)
    assert mread.notes == []
    done = read_container(
        opened.layout.complete, ContainerKind.COMPLETE, opened.master_key, opened.vault_id
    )
    return VaultInfo(
        path=path,
        master_key=opened.master_key,
        vault_id=opened.vault_id,
        entries={display_path(e.path): e for e in mread.manifest.files},
        manifest_obj=manifest_to_obj(mread.manifest),
        manifest_raw=mread.raw,
        completion_obj=dict(done.obj),
    )


@pytest.fixture(scope="module")
def pristine(tmp_path_factory: pytest.TempPathFactory) -> Pristine:
    faults.reset()
    base = tmp_path_factory.mktemp("tamper-pristine")
    a = Area(
        root=base,
        src=base / "origem",
        vaults=base / "cofres",
        testarea=base / "teste",
        out=base / "saida",
    )
    for p in (a.src, a.vaults, a.testarea, a.out):
        p.mkdir()
    write_tree(a.src, SPEC)
    assert make_vault(a).status == "success"
    assert make_vault(a, name="outro").status == "success"
    main = _vault_info(a.vault())
    other = _vault_info(a.vault("outro"))
    assert set(main.entries) == FILES
    assert main.vault_id != other.vault_id
    return Pristine(tree_digest(a.src), main, other)


@dataclass
class WS:
    """Cópias de trabalho dos dois cofres para um teste."""

    area: Area
    p: Pristine

    @property
    def vault(self) -> Path:
        return self.area.vault()

    @property
    def other(self) -> Path:
        """Cópia de trabalho do segundo cofre (copiada sob demanda)."""
        path = self.area.vault("outro")
        if not path.exists():
            shutil.copytree(self.p.other.path, path)
        return path

    def blob(self, rel: str, *, other: bool = False) -> Path:
        info = self.p.other if other else self.p.main
        root = self.other if other else self.vault
        fid = info.entries[rel].file_id.hex()
        return root / "data" / fid[:2] / f"{fid}.owlb"


@pytest.fixture
def ws(area: Area, pristine: Pristine) -> WS:
    shutil.copytree(pristine.main.path, area.vault())
    return WS(area, pristine)


# --- helpers -------------------------------------------------------------------------------


def _flip(data: bytes, offset: int, mask: int = 0x01) -> bytes:
    b = bytearray(data)
    b[offset] ^= mask
    return bytes(b)


def _chunk_spans(plain_size: int, c: int = C) -> list[tuple[int, int]]:
    """(offset, comprimento ct‖tag) de cada chunk do blob (FORMAT §4.2)."""
    n = max(1, -(-plain_size // c))
    spans = []
    off = BLOB_HDR
    for i in range(n):
        plain = c if i < n - 1 else plain_size - (n - 1) * c
        spans.append((off, plain + TAG))
        off += plain + TAG
    return spans


def _snapshot(root: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for d in dirnames:
            out[os.path.relpath(os.path.join(dirpath, d), root)] = b"<dir>"
        for f in filenames:
            full = os.path.join(dirpath, f)
            with open(full, "rb") as fh:
                out[os.path.relpath(full, root)] = hashlib.sha256(fh.read()).digest()
    return out


def _paths_of(messages: list[str]) -> set[str]:
    return {m.split(": ", 1)[0] for m in messages}


def _check_verify_flags(area: Area, bad: set[str]) -> VerifyReport:
    rep = do_verify(area)
    assert _paths_of(rep.bad) == bad, rep.bad
    assert rep.files_ok == N_FILES - len(bad)
    assert rep.total_files == N_FILES
    assert not rep.ok
    assert not rep.fully_ok
    return rep


def _check_restore_excludes(area: Area, before: dict[str, Any], bad: set[str]) -> RestoreReport:
    rep = do_restore(area)
    assert _paths_of(rep.failed) == bad, rep.failed
    assert rep.conflicts == []
    assert not rep.ok
    assert rep.restored == N_FILES - len(bad)
    root = area.dest()
    for rel in bad:
        assert not os.path.lexists(root / rel), f"{rel} foi produzido apesar da adulteração"
    _assert_no_temporaries(root)
    got = tree_digest(root)
    got.pop(MARKER_NAME, None)
    expected = {k: v for k, v in before.items() if k not in bad}
    assert got == expected
    return rep


def _assert_no_temporaries(root: Path) -> None:
    leftovers = [
        os.path.join(dp, f)
        for dp, _, fs in os.walk(root)
        for f in fs
        if f.endswith(".part") or f.startswith(".owl-")
    ]
    assert leftovers == []


def _check_full_restore(area: Area, before: dict[str, Any]) -> RestoreReport:
    rep = do_restore(area)
    assert rep.ok, (rep.failed, rep.conflicts)
    assert rep.restored == N_FILES
    root = area.dest()
    _assert_no_temporaries(root)
    assert not os.path.lexists(root / MARKER_NAME)
    assert tree_digest(root) == before
    return rep


def _check_blob_tamper(ws: WS, bad: set[str]) -> None:
    """Verificar aponta ``bad``; restauração os exclui; cofre intacto após as duas."""
    snap = _snapshot(ws.vault)
    _check_verify_flags(ws.area, bad)
    _check_restore_excludes(ws.area, ws.p.before, bad)
    assert _snapshot(ws.vault) == snap, "verificar/restaurar alteraram o cofre"


# --- linha de base -------------------------------------------------------------------------


def test_pristine_copy_is_clean(ws: WS) -> None:
    rep = do_verify(ws.area)
    assert rep.fully_ok, (rep.bad, rep.anomalies, rep.notes)
    assert rep.files_ok == N_FILES
    assert rep.notes == []
    assert "concluída e testada" in rep.creation_status
    _check_full_restore(ws.area, ws.p.before)


# --- bytes trocados dentro de um blob -------------------------------------------------------

Offset = Callable[[list[tuple[int, int]], int], int]

BLOB_FLIPS: list[tuple[str, str, Offset, int]] = [
    ("ct-first-chunk", "multi.bin", lambda sp, n: sp[0][0] + 10, 0x01),
    ("ct-middle-chunk", "multi.bin", lambda sp, n: sp[2][0] + 1000, 0x80),
    ("ct-final-chunk", "multi.bin", lambda sp, n: sp[-1][0] + 3, 0x01),
    ("ct-last-full-chunk-exact-multiple", "exato.bin", lambda sp, n: sp[-1][0], 0x40),
    ("tag-first-chunk", "multi.bin", lambda sp, n: sp[0][0] + sp[0][1] - TAG, 0x01),
    ("tag-final-chunk", "multi.bin", lambda sp, n: n - 1, 0x01),
    ("tag-empty-file", "vazio.txt", lambda sp, n: BLOB_HDR + 7, 0x01),
    ("ct-small-file", "pequeno.txt", lambda sp, n: BLOB_HDR, 0x01),
    ("ct-nested-file", "sub\\fundo\\leaf.txt", lambda sp, n: BLOB_HDR + 2, 0x10),
    ("hdr-magic", "multi.bin", lambda sp, n: 0, 0x01),
    ("hdr-format-version", "multi.bin", lambda sp, n: 9, 0x01),
    ("hdr-flags", "multi.bin", lambda sp, n: 15, 0x01),
    ("hdr-vault-id", "multi.bin", lambda sp, n: 16 + 5, 0x01),
    ("hdr-file-id", "multi.bin", lambda sp, n: 32 + 9, 0x01),
    ("hdr-chunk-size-invalid", "multi.bin", lambda sp, n: 50, 0x01),
    # 64 KiB -> 128 KiB (outra potência de 2 válida): muda o tamanho esperado do blob
    ("hdr-chunk-size-other-pow2", "multi.bin", lambda sp, n: 49, 0x03),
    # num arquivo de 1 chunk o tamanho esperado não muda: só o AAD denuncia
    ("hdr-chunk-size-other-pow2-small", "pequeno.txt", lambda sp, n: 49, 0x03),
    ("hdr-plaintext-size", "multi.bin", lambda sp, n: 59, 0x01),
    ("hdr-plaintext-size-huge", "multi.bin", lambda sp, n: 52, 0x80),
    ("hdr-plaintext-size-small", "pequeno.txt", lambda sp, n: 59, 0x01),
    ("hdr-reserved", "multi.bin", lambda sp, n: 63, 0x01),
]


@pytest.mark.parametrize(
    ("rel", "where", "mask"),
    [pytest.param(rel, where, mask, id=name) for name, rel, where, mask in BLOB_FLIPS],
)
def test_blob_byte_flip(ws: WS, rel: str, where: Offset, mask: int) -> None:
    path = ws.blob(rel)
    data = path.read_bytes()
    spans = _chunk_spans(ws.p.main.entries[rel].size)
    assert spans[-1][0] + spans[-1][1] == len(data)
    path.write_bytes(_flip(data, where(spans, len(data)), mask))
    _check_blob_tamper(ws, {rel})


# --- truncamento / extensão -----------------------------------------------------------------

Mutate = Callable[[bytes, list[tuple[int, int]]], bytes]


def _drop_final_and_fix_header(data: bytes, sp: list[tuple[int, int]]) -> bytes:
    """Remove o último chunk e reescreve plaintext_size para ficar coerente com o arquivo."""
    new_plain = sum(length - TAG for _, length in sp[:-1])
    hdr = bytearray(data[:BLOB_HDR])
    hdr[52:60] = struct.pack(">Q", new_plain)
    return bytes(hdr) + data[BLOB_HDR : sp[-1][0]]


SIZE_TAMPERS: list[tuple[str, str, Mutate]] = [
    ("truncate-1-byte", "multi.bin", lambda d, sp: d[:-1]),
    ("truncate-final-chunk", "multi.bin", lambda d, sp: d[: sp[-1][0]]),
    ("truncate-mid-chunk", "multi.bin", lambda d, sp: d[: sp[2][0] + 500]),
    ("truncate-to-header", "multi.bin", lambda d, sp: d[:BLOB_HDR]),
    ("truncate-inside-header", "multi.bin", lambda d, sp: d[:10]),
    ("truncate-to-empty", "multi.bin", lambda d, sp: b""),
    ("truncate-empty-file-tag", "vazio.txt", lambda d, sp: d[:BLOB_HDR]),
    ("extend-1-byte", "multi.bin", lambda d, sp: d + b"\x00"),
    ("extend-duplicate-chunk", "multi.bin", lambda d, sp: d + d[sp[0][0] : sp[0][0] + sp[0][1]]),
    ("extend-empty-file", "vazio.txt", lambda d, sp: d + d[BLOB_HDR:]),
    ("extend-small-file", "pequeno.txt", lambda d, sp: d + b"x" * 1000),
    ("drop-final-chunk-fix-header", "multi.bin", _drop_final_and_fix_header),
    ("drop-final-chunk-fix-header-exact", "exato.bin", _drop_final_and_fix_header),
]


@pytest.mark.parametrize(
    ("rel", "mutate"),
    [pytest.param(rel, fn, id=name) for name, rel, fn in SIZE_TAMPERS],
)
def test_blob_truncate_or_extend(ws: WS, rel: str, mutate: Mutate) -> None:
    path = ws.blob(rel)
    data = path.read_bytes()
    new = mutate(data, _chunk_spans(ws.p.main.entries[rel].size))
    assert new != data
    path.write_bytes(new)
    _check_blob_tamper(ws, {rel})


# --- reordenação de chunks --------------------------------------------------------------------


def _reorder(order: list[int]) -> Mutate:
    def fn(d: bytes, sp: list[tuple[int, int]]) -> bytes:
        chunks = [d[o : o + n] for o, n in sp]
        return d[:BLOB_HDR] + b"".join(chunks[i] for i in order)

    return fn


REORDERS: list[tuple[str, str, Mutate]] = [
    ("swap-chunks-0-1", "multi.bin", _reorder([1, 0, 2, 3, 4])),
    ("swap-chunks-2-3", "multi.bin", _reorder([0, 1, 3, 2, 4])),
    ("swap-full-chunk-with-final", "exato.bin", _reorder([0, 2, 1])),
    ("reverse-all-chunks", "exato.bin", _reorder([2, 1, 0])),
    ("replay-chunk-0-as-chunk-1", "multi.bin", _reorder([0, 0, 2, 3, 4])),
    ("replay-chunk-0-as-final", "exato.bin", _reorder([0, 1, 0])),
]


@pytest.mark.parametrize(
    ("rel", "mutate"),
    [pytest.param(rel, fn, id=name) for name, rel, fn in REORDERS],
)
def test_chunk_reorder(ws: WS, rel: str, mutate: Mutate) -> None:
    path = ws.blob(rel)
    data = path.read_bytes()
    new = mutate(data, _chunk_spans(ws.p.main.entries[rel].size))
    assert len(new) == len(data) and new != data
    path.write_bytes(new)
    _check_blob_tamper(ws, {rel})


def test_chunk_spliced_from_another_file(ws: WS) -> None:
    """Chunk 0 de multi.bin colado no lugar do chunk 0 de exato.bin (mesmo tamanho)."""
    src = ws.blob("multi.bin").read_bytes()
    dst_path = ws.blob("exato.bin")
    dst = bytearray(dst_path.read_bytes())
    o, n = _chunk_spans(4 * C + 100)[0]
    o2, n2 = _chunk_spans(3 * C)[0]
    assert n == n2
    dst[o2 : o2 + n2] = src[o : o + n]
    dst_path.write_bytes(bytes(dst))
    _check_blob_tamper(ws, {"exato.bin"})


def test_chunk_spliced_from_same_file_in_other_vault(ws: WS) -> None:
    """Mesmo texto claro, mesma senha, outro cofre: o chunk não autentica aqui."""
    foreign = ws.blob("multi.bin", other=True).read_bytes()
    path = ws.blob("multi.bin")
    data = bytearray(path.read_bytes())
    o, n = _chunk_spans(4 * C + 100)[1]
    data[o : o + n] = foreign[o : o + n]
    path.write_bytes(bytes(data))
    _check_blob_tamper(ws, {"multi.bin"})


# --- troca / cópia de arquivos de blob entre entradas ------------------------------------------


def _swap_files(a: Path, b: Path) -> None:
    tmp = a.with_name(a.name + ".swap")
    os.rename(a, tmp)
    os.rename(b, a)
    os.rename(tmp, b)


def test_swap_blobs_same_size(ws: WS) -> None:
    _swap_files(ws.blob("par-a.bin"), ws.blob("par-b.bin"))
    rep = do_verify(ws.area)
    # nenhum blob sobrando/estranho: só o conteúdo trocado
    assert rep.anomalies == []
    _check_blob_tamper(ws, {"par-a.bin", "par-b.bin"})


def test_swap_blobs_different_sizes(ws: WS) -> None:
    _swap_files(ws.blob("multi.bin"), ws.blob("pequeno.txt"))
    _check_blob_tamper(ws, {"multi.bin", "pequeno.txt"})


def test_swap_blobs_across_subfolders(ws: WS) -> None:
    _swap_files(ws.blob("sub\\outro.bin"), ws.blob("sub\\fundo\\leaf.txt"))
    _check_blob_tamper(ws, {"sub\\outro.bin", "sub\\fundo\\leaf.txt"})


def test_blob_overwritten_by_copy_of_another_entry(ws: WS) -> None:
    shutil.copyfile(ws.blob("par-a.bin"), ws.blob("par-b.bin"))
    _check_blob_tamper(ws, {"par-b.bin"})


def test_blob_replaced_by_hardlink_to_another_entry(ws: WS) -> None:
    target = ws.blob("par-b.bin")
    target.unlink()
    os.link(ws.blob("par-a.bin"), target)
    _check_blob_tamper(ws, {"par-b.bin"})


def test_blob_deleted(ws: WS) -> None:
    ws.blob("sub\\outro.bin").unlink()
    _check_blob_tamper(ws, {"sub\\outro.bin"})


def test_blob_replaced_by_directory(ws: WS) -> None:
    target = ws.blob("pequeno.txt")
    target.unlink()
    target.mkdir()
    _check_blob_tamper(ws, {"pequeno.txt"})


def test_blob_replaced_by_junction(ws: WS) -> None:
    decoy = ws.area.root / "alvo-junction"
    decoy.mkdir()
    target = ws.blob("pequeno.txt")
    target.unlink()
    _winapi.CreateJunction(str(decoy), str(target))
    _check_blob_tamper(ws, {"pequeno.txt"})


def test_blob_replaced_by_symlink_to_another_blob(ws: WS) -> None:
    target = ws.blob("par-b.bin")
    target.unlink()
    try:
        os.symlink(ws.blob("par-a.bin"), target)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("criar symlink exige privilégio (WinError 1314)")
        raise
    _check_blob_tamper(ws, {"par-b.bin"})


# --- blobs de outro cofre (mesma origem, mesma senha) -------------------------------------------


def test_blob_copied_from_other_vault(ws: WS) -> None:
    shutil.copyfile(ws.blob("multi.bin", other=True), ws.blob("multi.bin"))
    _check_blob_tamper(ws, {"multi.bin"})


def test_blob_from_other_vault_with_ids_rewritten(ws: WS) -> None:
    """Cabeçalho do blob estranho reescrito com vault_id/file_id deste cofre: chave errada."""
    foreign = bytearray(ws.blob("multi.bin", other=True).read_bytes())
    foreign[16:32] = ws.p.main.vault_id
    foreign[32:48] = ws.p.main.entries["multi.bin"].file_id
    ws.blob("multi.bin").write_bytes(bytes(foreign))
    _check_blob_tamper(ws, {"multi.bin"})


def test_extra_blob_from_other_vault_is_anomaly(ws: WS) -> None:
    """Blob de outro cofre acrescentado (com o próprio nome) em data/: anomalia, não arquivo."""
    src = ws.blob("pequeno.txt", other=True)
    dst = ws.vault / "data" / src.parent.name / src.name
    dst.parent.mkdir(exist_ok=True)
    shutil.copyfile(src, dst)
    snap = _snapshot(ws.vault)
    rep = do_verify(ws.area)
    assert rep.bad == []
    assert rep.files_ok == N_FILES
    assert any(src.name in a and "outro cofre" in a for a in rep.anomalies), rep.anomalies
    assert not rep.fully_ok
    _check_full_restore(ws.area, ws.p.before)
    assert _snapshot(ws.vault) == snap


# --- manifesto: uma cópia danificada ⇒ usa a outra e avisa (FORMAT §5.1) -------------------------

ManifestDamage = Callable[[bytes, WS], bytes | None]  # None = apagar o arquivo

MANIFEST_DAMAGE: list[tuple[str, ManifestDamage]] = [
    ("flip-magic", lambda d, w: _flip(d, 0)),
    ("flip-format-version", lambda d, w: _flip(d, 9)),
    # vault_id em claro do cabeçalho do contêiner (não autenticado antes do AEAD)
    ("flip-vault-id", lambda d, w: _flip(d, 16 + 4)),
    ("flip-key-id", lambda d, w: _flip(d, 32 + 4)),
    ("flip-nonce", lambda d, w: _flip(d, 48 + 4)),
    ("flip-reserved", lambda d, w: _flip(d, 63)),
    ("flip-ciphertext", lambda d, w: _flip(d, CONTAINER_HDR + 20)),
    ("flip-tag", lambda d, w: _flip(d, len(d) - 1)),
    ("truncate-half", lambda d, w: d[: len(d) // 2]),
    ("truncate-tiny", lambda d, w: d[:40]),
    ("extend-1-byte", lambda d, w: d + b"\x00"),
    ("empty-file", lambda d, w: b""),
    ("deleted", lambda d, w: None),
    ("replaced-by-complete-owl", lambda d, w: (w.vault / "complete.owl").read_bytes()),
    ("replaced-by-other-vault-manifest", lambda d, w: (w.other / "manifest.owl").read_bytes()),
]


@pytest.mark.parametrize("damaged", ["manifest.owl", "manifest.owl.bak"])
@pytest.mark.parametrize("damage", [pytest.param(fn, id=name) for name, fn in MANIFEST_DAMAGE])
def test_one_manifest_copy_damaged_falls_back(ws: WS, damaged: str, damage: ManifestDamage) -> None:
    survivor = "manifest.owl.bak" if damaged == "manifest.owl" else "manifest.owl"
    path = ws.vault / damaged
    new = damage(path.read_bytes(), ws)
    if new is None:
        path.unlink()
    else:
        path.write_bytes(new)
    snap = _snapshot(ws.vault)

    rep = do_verify(ws.area)
    assert rep.bad == [], rep.bad
    assert rep.files_ok == N_FILES
    assert rep.anomalies == []
    # problemas de cópia redundante ficam em report.redundancy e impedem "íntegro"
    assert any(f"usando {survivor}" in n for n in rep.redundancy), rep.redundancy
    assert any(n.startswith(damaged + ":") for n in rep.redundancy), rep.redundancy
    assert not rep.fully_ok
    # a cópia usada é byte a byte o manifesto original ⇒ conclusão continua válida
    assert rep.completed, rep.creation_status

    rest = _check_full_restore(ws.area, ws.p.before)
    assert any(f"usando {survivor}" in n for n in rest.notes), rest.notes
    # nada é "consertado" automaticamente: a cópia danificada continua como estava
    assert _snapshot(ws.vault) == snap


# --- manifesto: as duas cópias inutilizáveis ⇒ recusa ---------------------------------------------


def _assert_refused(
    ws: WS, exc_types: type[BaseException] | tuple[type[BaseException], ...]
) -> None:
    snap = _snapshot(ws.vault)
    with pytest.raises(exc_types):
        do_verify(ws.area)
    with pytest.raises(exc_types):
        do_restore(ws.area)
    # validação antes de qualquer escrita: o destino nem é criado
    assert not os.path.lexists(ws.area.dest())
    assert _snapshot(ws.vault) == snap


BOTH_DAMAGED: list[tuple[str, ManifestDamage, ManifestDamage]] = [
    (
        "both-ciphertext-flipped",
        lambda d, w: _flip(d, CONTAINER_HDR + 5),
        lambda d, w: _flip(d, CONTAINER_HDR + 7),
    ),
    ("truncated-and-tag-flipped", lambda d, w: d[:100], lambda d, w: _flip(d, len(d) - 1)),
    ("deleted-and-flipped", lambda d, w: None, lambda d, w: _flip(d, CONTAINER_HDR + 1)),
    ("flipped-and-deleted", lambda d, w: _flip(d, len(d) - 3), lambda d, w: None),
    ("both-empty", lambda d, w: b"", lambda d, w: b""),
]


@pytest.mark.parametrize(
    ("dmg_main", "dmg_bak"),
    [pytest.param(a, b, id=name) for name, a, b in BOTH_DAMAGED],
)
def test_both_manifest_copies_damaged(
    ws: WS, dmg_main: ManifestDamage, dmg_bak: ManifestDamage
) -> None:
    for name, fn in (("manifest.owl", dmg_main), ("manifest.owl.bak", dmg_bak)):
        path = ws.vault / name
        new = fn(path.read_bytes(), ws)
        if new is None:
            path.unlink()
        else:
            path.write_bytes(new)
    _assert_refused(ws, IntegrityError)


def test_both_manifests_deleted_refused(ws: WS) -> None:
    (ws.vault / "manifest.owl").unlink()
    (ws.vault / "manifest.owl.bak").unlink()
    _assert_refused(ws, OwlVaultError)


def test_both_manifests_from_other_vault_refused(ws: WS) -> None:
    foreign = (ws.other / "manifest.owl").read_bytes()
    (ws.vault / "manifest.owl").write_bytes(foreign)
    (ws.vault / "manifest.owl.bak").write_bytes(foreign)
    # nenhuma cópia é autêntica para ESTE cofre: corrupção (ou cofre misturado) — recusa
    _assert_refused(ws, (IntegrityError, InconsistentVaultError))


# --- manifesto: duas cópias autênticas e diferentes ⇒ InconsistentVaultError ----------------------


def _seal_manifest(ws: WS, obj: dict[str, Any]) -> bytes:
    return seal(ContainerKind.MANIFEST, ws.p.main.master_key, ws.p.main.vault_id, obj)


def _without(obj: dict[str, Any], rel: str) -> dict[str, Any]:
    o = dict(obj)
    o["entries"] = [e for e in obj["entries"] if "\\".join(e["path"]) != rel]
    assert len(o["entries"]) == len(obj["entries"]) - 1
    return o


def _with_mtime(obj: dict[str, Any], rel: str, delta: int) -> dict[str, Any]:
    o = dict(obj)
    o["entries"] = [dict(e) for e in obj["entries"]]
    for e in o["entries"]:
        if "\\".join(e["path"]) == rel:
            e["mtime_ns"] += delta
    return o


def _with_extra_dir(obj: dict[str, Any], name: str) -> dict[str, Any]:
    o = dict(obj)
    o["entries"] = [*obj["entries"], {"type": "dir", "path": [name]}]
    return o


DIVERGENT: list[tuple[str, str, Callable[[dict[str, Any]], dict[str, Any]]]] = [
    ("bak-resealed-same-content", "manifest.owl.bak", lambda o: o),
    ("bak-entry-removed", "manifest.owl.bak", lambda o: _without(o, "pequeno.txt")),
    ("main-entry-removed", "manifest.owl", lambda o: _without(o, "sub\\fundo\\leaf.txt")),
    ("main-mtime-changed", "manifest.owl", lambda o: _with_mtime(o, "multi.bin", 10**9)),
    ("bak-extra-dir", "manifest.owl.bak", lambda o: _with_extra_dir(o, "intrusa")),
]


@pytest.mark.parametrize(
    ("which", "edit"),
    [pytest.param(w, fn, id=name) for name, w, fn in DIVERGENT],
)
def test_authentic_but_different_manifests_refused(
    ws: WS, which: str, edit: Callable[[dict[str, Any]], dict[str, Any]]
) -> None:
    raw = _seal_manifest(ws, edit(ws.p.main.manifest_obj))
    assert raw != ws.p.main.manifest_raw
    (ws.vault / which).write_bytes(raw)
    _assert_refused(ws, InconsistentVaultError)


def test_both_manifests_resealed_identically_breaks_completion(ws: WS) -> None:
    """Manifestos autênticos e idênticos, mas não os bytes registrados em complete.owl."""
    raw = _seal_manifest(ws, ws.p.main.manifest_obj)
    (ws.vault / "manifest.owl").write_bytes(raw)
    (ws.vault / "manifest.owl.bak").write_bytes(raw)
    rep = do_verify(ws.area)
    assert rep.bad == []
    assert rep.files_ok == N_FILES
    assert not rep.completed
    assert "NÃO concluída" in rep.creation_status
    assert "concluída e testada" not in rep.creation_status
    assert not rep.fully_ok
    rest = _check_full_restore(ws.area, ws.p.before)
    assert "NÃO concluída" in rest.creation_status


# --- complete.owl ausente/adulterado ⇒ "criação NÃO concluída" (FORMAT §5.4) ---------------------


def _seal_completion(ws: WS, **changes: Any) -> bytes:
    obj = dict(ws.p.main.completion_obj)
    obj.update(changes)
    return seal(ContainerKind.COMPLETE, ws.p.main.master_key, ws.p.main.vault_id, obj)


CompletionDamage = Callable[[bytes, WS], bytes | None]

COMPLETION_DAMAGE: list[tuple[str, CompletionDamage]] = [
    ("deleted", lambda d, w: None),
    ("flip-magic", lambda d, w: _flip(d, 0)),
    ("flip-vault-id", lambda d, w: _flip(d, 16 + 2)),
    ("flip-ciphertext", lambda d, w: _flip(d, CONTAINER_HDR + 3)),
    ("flip-tag", lambda d, w: _flip(d, len(d) - 1)),
    ("truncated", lambda d, w: d[:70]),
    ("from-other-vault", lambda d, w: (w.other / "complete.owl").read_bytes()),
    ("replaced-by-manifest", lambda d, w: (w.vault / "manifest.owl").read_bytes()),
    ("forged-wrong-manifest-sha", lambda d, w: _seal_completion(w, manifest_sha256="00" * 32)),
    (
        "forged-other-vault-manifest-sha",
        lambda d, w: _seal_completion(
            w, manifest_sha256=hashlib.sha256(w.p.other.manifest_raw).hexdigest()
        ),
    ),
    ("forged-restore-test-failed", lambda d, w: _seal_completion(w, restore_test="failed")),
    (
        "forged-vault-id-in-body",
        lambda d, w: _seal_completion(w, vault_id=w.p.other.vault_id.hex()),
    ),
]


@pytest.mark.parametrize("damage", [pytest.param(fn, id=name) for name, fn in COMPLETION_DAMAGE])
def test_completion_record_missing_or_tampered(ws: WS, damage: CompletionDamage) -> None:
    path = ws.vault / "complete.owl"
    new = damage(path.read_bytes(), ws)
    if new is None:
        path.unlink()
    else:
        path.write_bytes(new)
    snap = _snapshot(ws.vault)
    rep = do_verify(ws.area)
    assert not rep.completed
    assert "NÃO concluída" in rep.creation_status, rep.creation_status
    assert "concluída e testada" not in rep.creation_status
    assert not rep.fully_ok
    # o conteúdo continua íntegro e verificável
    assert rep.bad == []
    assert rep.files_ok == N_FILES
    rest = _check_full_restore(ws.area, ws.p.before)
    assert "NÃO concluída" in rest.creation_status
    assert "concluída e testada" not in rest.creation_status
    assert _snapshot(ws.vault) == snap


# --- resíduos de diário / temporários -------------------------------------------------------------


def test_planted_journal_dir_is_anomaly(ws: WS) -> None:
    jdir = ws.vault / "journal"
    jdir.mkdir()
    (jdir / "0000000000000000.owlj").write_bytes(os.urandom(200))
    rep = do_verify(ws.area)
    assert rep.bad == []
    assert rep.files_ok == N_FILES
    assert rep.completed  # complete.owl autêntico é a autoridade
    assert any("journal" in a for a in rep.anomalies), rep.anomalies
    assert not rep.fully_ok
    _check_full_restore(ws.area, ws.p.before)


def test_leftover_temporaries_are_anomalies(ws: WS) -> None:
    fid = ws.p.main.entries["multi.bin"].file_id.hex()
    root_tmp = ws.vault / f"manifest.owl.{os.urandom(16).hex()}.tmp"
    root_tmp.write_bytes(b"resto")
    data_tmp = ws.vault / "data" / fid[:2] / f"{fid[:2]}{os.urandom(15).hex()}.tmp"
    data_tmp.write_bytes(b"resto")
    rep = do_verify(ws.area)
    assert rep.bad == []
    assert rep.files_ok == N_FILES
    assert any(root_tmp.name in a for a in rep.anomalies), rep.anomalies
    assert any(data_tmp.name in a for a in rep.anomalies), rep.anomalies
    assert not rep.fully_ok
    _check_full_restore(ws.area, ws.p.before)


def _crashed_vault(area: Area, op: str, nth: int) -> None:
    write_tree(area.src, SPEC)
    faults.fail_at(op, nth, lambda: Crash())
    with pytest.raises(Crash):
        make_vault(area)
    faults.reset()


def test_crash_before_completion_record(area: Area) -> None:
    """Queda ao gravar complete.owl: diário sobra; conteúdo íntegro; criação NÃO concluída."""
    _crashed_vault(area, "complete.write", 1)
    vault = area.vault()
    assert not (vault / "complete.owl").exists()
    assert (vault / "journal").is_dir()
    before = tree_digest(area.src)
    rep = do_verify(area)
    assert rep.bad == []
    assert rep.files_ok == N_FILES
    assert not rep.completed
    assert "NÃO concluída" in rep.creation_status
    assert any("journal" in a for a in rep.anomalies), rep.anomalies
    rest = _check_full_restore(area, before)
    assert "NÃO concluída" in rest.creation_status


def test_crash_before_manifest_backup(area: Area) -> None:
    """Queda ao gravar manifest.owl.bak: usa manifest.owl e avisa; criação NÃO concluída."""
    _crashed_vault(area, "manifest.write", 2)
    vault = area.vault()
    assert (vault / "manifest.owl").exists()
    assert not (vault / "manifest.owl.bak").exists()
    assert not any(p.name.endswith(".tmp") for p in vault.iterdir())
    before = tree_digest(area.src)
    rep = do_verify(area)
    assert rep.bad == []
    assert rep.files_ok == N_FILES
    assert not rep.completed
    assert "NÃO concluída" in rep.creation_status
    assert any(n.startswith("usando manifest.owl ") for n in rep.redundancy), rep.redundancy
    assert any("journal" in a for a in rep.anomalies), rep.anomalies
    _check_full_restore(area, before)


def test_crash_during_journal_cleanup(area: Area) -> None:
    """complete.owl gravado, queda ao remover o diário: concluída, mas com anomalia."""
    # as N primeiras remoções são os .chk do teste de restauração; a seguinte é do diário
    _crashed_vault(area, "remove", N_FILES + 1)
    vault = area.vault()
    assert (vault / "complete.owl").exists()
    assert (vault / "journal").is_dir()
    before = tree_digest(area.src)
    rep = do_verify(area)
    assert rep.bad == []
    assert rep.files_ok == N_FILES
    assert rep.completed, rep.creation_status
    assert any("journal" in a for a in rep.anomalies), rep.anomalies
    assert not rep.fully_ok
    _check_full_restore(area, before)


# --- várias adulterações simultâneas ------------------------------------------------------------


def test_many_tampers_at_once_only_affected_files_excluded(ws: WS) -> None:
    """Manifesto principal corrompido + blobs adulterados de formas diferentes."""
    m = ws.vault / "manifest.owl"
    m.write_bytes(_flip(m.read_bytes(), CONTAINER_HDR + 9))
    b = ws.blob("multi.bin")
    b.write_bytes(_flip(b.read_bytes(), BLOB_HDR + 3 * (C + TAG) + 1))
    e = ws.blob("exato.bin")
    e.write_bytes(e.read_bytes()[:-1])
    _swap_files(ws.blob("par-a.bin"), ws.blob("par-b.bin"))
    bad = {"multi.bin", "exato.bin", "par-a.bin", "par-b.bin"}
    rep = _check_verify_flags(ws.area, bad)
    assert any("usando manifest.owl.bak" in n for n in rep.redundancy), rep.redundancy
    snap = _snapshot(ws.vault)
    _check_restore_excludes(ws.area, ws.p.before, bad)
    assert _snapshot(ws.vault) == snap
