"""Restauração (ARCHITECTURE §4.4, FORMAT §7): destino, retomada com marcador, conflitos,
limpeza de ``.part``, mtime, pastas vazias e Mark-of-the-Web.

Somente pastas temporárias com dados sintéticos.
"""

from __future__ import annotations

import _winapi
import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any

import pytest

from owl_vault.application.progress import CancelToken, NullProgress
from owl_vault.application.protection import ProtectedPaths
from owl_vault.application.restore import (
    MARKER_NAME,
    RESTORE_LOCK_NAME,
    RestoreReport,
    inspect_destination,
    restore_vault,
)
from owl_vault.crypto.kdf import TESTING_POLICY
from owl_vault.domain.errors import (
    CancelledError,
    InsufficientSpaceError,
    OwlVaultError,
    StateError,
    UnsafePathError,
    VaultLockedError,
)
from owl_vault.storage import faults, winfs
from tests.conftest import (
    PASSWORD,
    SMALL_CHUNK,
    Area,
    do_restore,
    make_vault,
    tree_digest,
    write_tree,
)

_HEX32 = re.compile(r"[0-9a-f]{32}")
MOTW = b"[ZoneTransfer]\r\nZoneId=3\r\n"


class Crash(BaseException):
    """Queda simulada: passa por cima do tratamento normal de erros."""


# --- helpers -----------------------------------------------------------------------------


def _restore_to(area: Area, dest: Path, *, name: str = "cofre", **kw: object) -> RestoreReport:
    return restore_vault(
        str(area.vault(name)),
        PASSWORD,
        str(dest),
        policy=TESTING_POLICY,
        protected=ProtectedPaths.none(),
        **kw,  # type: ignore[arg-type]
    )


def _listing(root: Path) -> list[str]:
    """Todos os itens (arquivos e pastas) relativos a ``root``, ordenados."""
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        for n in dirnames + filenames:
            out.append(os.path.normpath(os.path.join(rel, n)))
    return sorted(out)


def _files(root: Path) -> list[str]:
    return sorted(k for k, v in tree_digest(root).items() if v[0] == "file")


def _resume_tree(area: Area) -> dict[str, Any]:
    """7 arquivos (1 vazio, 2 com vários chunks), 1 subpasta e 1 pasta vazia."""
    spec = {
        "a.txt": b"A" * 100,
        "b.bin": os.urandom(SMALL_CHUNK + 5),
        "c.txt": b"C" * 333,
        "d.txt": b"",
        "g.txt": b"G" * 7,
        "sub": {"e.txt": b"E" * 1000, "f.bin": os.urandom(3 * SMALL_CHUNK), "vazia": {}},
    }
    write_tree(area.src, spec)
    return tree_digest(area.src)


def _crash_restore_at_third_rename(area: Area, dest: Path) -> None:
    faults.fail_at("restore.rename", 3, Crash)
    with pytest.raises(Crash):
        _restore_to(area, dest)
    faults.reset()


def _read_marker(dest: Path) -> dict[str, object]:
    obj: dict[str, object] = json.loads((dest / MARKER_NAME).read_bytes().decode("ascii"))
    return obj


def _zone_stream(path: Path) -> bytes | None:
    try:
        with open(str(path) + ":Zone.Identifier", "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def _write_zone(path: Path, zone: int) -> None:
    try:
        with open(str(path) + ":Zone.Identifier", "wb") as fh:
            fh.write(f"[ZoneTransfer]\r\nZoneId={zone}\r\n".encode("ascii"))
    except OSError as exc:  # pragma: no cover - FS sem fluxos nomeados
        pytest.skip(f"sistema de arquivos temporário não suporta fluxos nomeados: {exc}")


def _junction(target: Path, link: Path) -> None:
    _winapi.CreateJunction(str(target), str(link))


# --- destino: recusas antes de escrever --------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        {"ja-existe.txt": b"dados do usuario"},
        {"pasta": {}},
        {".oculto": b"x"},
    ],
    ids=["file", "empty-subfolder", "dotfile"],
)
@pytest.mark.parametrize("allow_resume", [False, True], ids=["new", "allow_resume"])
def test_nonempty_destination_refused_before_anything_is_written(
    area: Area, content: dict[str, object], allow_resume: bool
) -> None:
    """Pasta não vazia SEM marcador: recusada mesmo com retomada permitida."""
    write_tree(area.src, {"a.txt": b"conteudo", "sub": {"b.txt": b"B"}})
    make_vault(area)
    dest = area.dest()
    dest.mkdir()
    write_tree(dest, content)
    before = tree_digest(dest)
    listing_before = _listing(dest)
    vault_before = tree_digest(area.vault())
    assert inspect_destination(str(dest)) == "nonempty"
    with pytest.raises(UnsafePathError):
        do_restore(area, allow_resume=allow_resume)
    assert _listing(dest) == listing_before
    assert tree_digest(dest) == before
    assert not (dest / MARKER_NAME).exists()
    assert not (dest / RESTORE_LOCK_NAME).exists()
    assert tree_digest(area.vault()) == vault_before


def test_empty_existing_destination_is_accepted(area: Area) -> None:
    write_tree(area.src, {"a.txt": b"conteudo", "vazia": {}})
    before = tree_digest(area.src)
    make_vault(area)
    area.dest().mkdir()
    assert inspect_destination(str(area.dest())) == "empty"
    rep = do_restore(area)
    assert rep.ok, (rep.failed, rep.conflicts)
    assert tree_digest(area.dest()) == before


def test_destination_parent_missing_refused(area: Area) -> None:
    write_tree(area.src, {"a.txt": b"x"})
    make_vault(area)
    dest = area.out / "nao-existe" / "restaurado"
    with pytest.raises(UnsafePathError):
        _restore_to(area, dest)
    assert not (area.out / "nao-existe").exists()


@pytest.mark.parametrize("where", ["inside", "equal", "ancestor"])
def test_destination_overlapping_vault_refused(area: Area, where: str) -> None:
    write_tree(area.src, {"a.txt": b"conteudo"})
    make_vault(area)
    vault = area.vault()
    dest = {"inside": vault / "restaurado", "equal": vault, "ancestor": area.vaults}[where]
    vault_before = _listing(vault)
    vault_digest = tree_digest(vault)
    with pytest.raises(UnsafePathError) as ei:
        _restore_to(area, dest)
    assert "cofre" in str(ei.value)
    assert _listing(vault) == vault_before
    assert tree_digest(vault) == vault_digest
    if where == "inside":
        assert not dest.exists()


@pytest.mark.parametrize("where", ["equal", "inside", "ancestor"])
def test_destination_overlapping_session_source_refused(area: Area, where: str) -> None:
    write_tree(area.src, {"a.txt": b"conteudo", "sub": {"b.txt": b"B"}})
    make_vault(area)
    src_before = tree_digest(area.src)
    listing_before = _listing(area.src)
    if where == "equal":
        dest, sources = area.src, [str(area.src)]
    elif where == "inside":
        dest, sources = area.src / "novo", [str(area.src)]
    else:
        # outra origem escolhida na sessão, contida no destino proposto
        other = area.out / "pai" / "fonte"
        other.mkdir(parents=True)
        dest, sources = area.out / "pai", [str(other)]
    with pytest.raises(UnsafePathError) as ei:
        _restore_to(area, dest, session_sources=sources)
    assert "origem" in str(ei.value)
    assert tree_digest(area.src) == src_before
    assert _listing(area.src) == listing_before
    if where == "inside":
        assert not dest.exists()


def test_destination_reaching_source_through_junction_refused(area: Area) -> None:
    """Comparação por caminho resolvido: um junction para a origem não engana a regra."""
    write_tree(area.src, {"a.txt": b"conteudo"})
    make_vault(area)
    link = area.out / "atalho"
    _junction(area.src, link)
    try:
        listing_before = _listing(area.src)
        with pytest.raises(UnsafePathError):
            _restore_to(area, link / "novo", session_sources=[str(area.src)])
        assert _listing(area.src) == listing_before
    finally:
        os.rmdir(link)


def test_destination_reaching_vault_through_junction_refused(area: Area) -> None:
    write_tree(area.src, {"a.txt": b"conteudo"})
    make_vault(area)
    link = area.out / "atalho-cofre"
    _junction(area.vault(), link)
    try:
        listing_before = _listing(area.vault())
        with pytest.raises(UnsafePathError):
            _restore_to(area, link / "novo")
        assert _listing(area.vault()) == listing_before
    finally:
        os.rmdir(link)


def test_destination_that_is_a_junction_refused(area: Area) -> None:
    write_tree(area.src, {"a.txt": b"conteudo"})
    make_vault(area)
    target = area.root / "alvo-vazio"
    target.mkdir()
    link = area.out / "destino-link"
    _junction(target, link)
    try:
        with pytest.raises(UnsafePathError):
            _restore_to(area, link)
        assert os.listdir(target) == []
    finally:
        os.rmdir(link)


def test_insufficient_space_refused_before_writing(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(area.src, {"a.txt": b"conteudo", "sub": {"b.txt": b"B"}})
    make_vault(area)
    monkeypatch.setattr(
        winfs, "volume_space", lambda _d: winfs.VolumeSpace(free_bytes=4096, cluster_size=4096)
    )
    with pytest.raises(OwlVaultError) as ei:
        do_restore(area)
    assert "Espaço insuficiente" in str(ei.value)
    assert not area.dest().exists()


def test_restore_lock_held_by_other_instance(area: Area) -> None:
    write_tree(area.src, {"a.txt": b"conteudo"})
    make_vault(area)
    dest = area.dest()
    dest.mkdir()
    lock = winfs.ExclusiveLock(winfs.to_extended(str(dest / RESTORE_LOCK_NAME)), "x")
    lock.acquire()
    try:
        with pytest.raises(VaultLockedError):
            do_restore(area)
        assert not (dest / MARKER_NAME).exists()
        assert not (dest / "a.txt").exists()
    finally:
        lock.release()
    rep = do_restore(area)
    assert rep.ok
    assert _listing(dest) == ["a.txt"]


# --- restauração fiel: marcador, mtime, pastas vazias ------------------------------------


def test_full_restore_removes_marker_restores_mtimes_and_empty_dirs(area: Area) -> None:
    write_tree(
        area.src,
        {
            "velho.txt": b"de 1980",
            "novo.bin": os.urandom(2 * SMALL_CHUNK + 3),
            "vazio.dat": b"",
            "vazia": {},
            "a": {"b": {"c": {}}, "x.txt": b"x", "d": {"e": {"f.txt": b"fundo"}}},
        },
    )
    mtimes = {
        "velho.txt": 315_532_800 * 10**9 + 1_234_500,  # 1980-01-01 + fração (múltiplo de 100 ns)
        "novo.bin": 1_000_000_000_123_456_700,
        "vazio.dat": 1_600_000_000 * 10**9,
        os.path.join("a", "x.txt"): 1_234_567_890 * 10**9,
        os.path.join("a", "d", "e", "f.txt"): 1_700_000_000_999_999_900,
    }
    for rel, ns in mtimes.items():
        os.utime(area.src / rel, ns=(ns, ns))
    before = tree_digest(area.src)
    vault_res = make_vault(area)
    assert vault_res.status == "success"
    vault_digest = tree_digest(area.vault())

    rep = do_restore(area)
    assert rep.ok, (rep.failed, rep.conflicts)
    assert "concluída e testada" in rep.creation_status
    assert rep.restored == 5
    assert rep.skipped_existing == 0
    assert rep.dirs_created == 6  # vazia, a, a\b, a\b\c, a\d, a\d\e
    dest = area.dest()
    assert tree_digest(dest) == before
    for rel, ns in mtimes.items():
        assert os.stat(dest / rel).st_mtime_ns == ns, rel
    for d in ("vazia", os.path.join("a", "b", "c")):
        assert (dest / d).is_dir() and os.listdir(dest / d) == []
    # marcador e trava removidos; nenhum temporário
    names = _listing(dest)
    assert MARKER_NAME not in names
    assert RESTORE_LOCK_NAME not in names
    assert not [n for n in names if n.endswith(".part")]
    assert inspect_destination(str(dest)) == "nonempty"
    # cofre e origem intactos
    assert tree_digest(area.vault()) == vault_digest
    assert tree_digest(area.src) == before


def test_marker_written_first_with_format_fields(area: Area) -> None:
    """FORMAT §7: marcador gravado antes de qualquer outra coisa, sem nomes."""
    _resume_tree(area)
    make_vault(area)
    dest = area.dest()
    faults.fail_at("restore.write", 1, Crash)
    with pytest.raises(Crash):
        do_restore(area)
    # só o marcador existe (nenhum .part sobrou, nenhum arquivo final, trava liberada)
    assert _listing(dest) == [MARKER_NAME]
    raw = (dest / MARKER_NAME).read_bytes()
    marker = json.loads(raw.decode("ascii"))
    assert set(marker) == {"app", "vault_id", "manifest_sha256", "restore_id", "phase"}
    assert marker["app"] == "Owl Vault"
    assert marker["phase"] == "restoring"
    header = (area.vault() / "vault.owl").read_bytes()
    assert marker["vault_id"] == header[16:32].hex()
    manifest_raw = (area.vault() / "manifest.owl").read_bytes()
    assert marker["manifest_sha256"] == hashlib.sha256(manifest_raw).hexdigest()
    assert _HEX32.fullmatch(str(marker["restore_id"]))
    for name in ("a.txt", "b.bin", "sub", "vazia", "e.txt"):
        assert name.encode() not in raw
    assert inspect_destination(str(dest)) == "resumable"


@pytest.mark.parametrize("op", ["marker.write", "marker.flush", "marker.rename"])
def test_crash_while_writing_marker_leaves_empty_destination(area: Area, op: str) -> None:
    write_tree(area.src, {"a.txt": b"conteudo", "sub": {"b.txt": b"B"}})
    before = tree_digest(area.src)
    make_vault(area)
    dest = area.dest()
    faults.fail_at(op, 1, Crash)
    with pytest.raises(Crash):
        do_restore(area)
    faults.reset()
    assert dest.is_dir()
    assert os.listdir(dest) == []
    assert inspect_destination(str(dest)) == "empty"
    rep = do_restore(area)  # pasta vazia: restauração normal, sem retomada
    assert rep.ok
    assert tree_digest(dest) == before


# --- retomada ----------------------------------------------------------------------------


def test_resume_after_crash_skips_correct_files_and_cleans_only_own_parts(area: Area) -> None:
    before = _resume_tree(area)
    make_vault(area)
    dest = area.dest()
    _crash_restore_at_third_rename(area, dest)

    restored_before = [f for f in _files(dest) if f != MARKER_NAME]
    assert len(restored_before) == 2
    assert (dest / MARKER_NAME).is_file()
    assert not [n for n in _listing(dest) if n.endswith(".part")]
    assert not (dest / RESTORE_LOCK_NAME).exists()
    assert inspect_destination(str(dest)) == "resumable"

    rid = str(_read_marker(dest)["restore_id"])
    other_rid = secrets.token_hex(16)
    assert other_rid != rid
    # resíduos de uma queda real (o .part não chegou a ser apagado pelo handle)
    own_root = dest / f".owl-{rid}-{secrets.token_hex(16)}.part"
    own_root.write_bytes(b"parcial")
    (dest / "sub").mkdir()  # pasta existente comum: aceita na retomada
    own_sub = dest / "sub" / f".owl-{rid}-{secrets.token_hex(16)}.part"
    own_sub.write_bytes(b"parcial 2")
    keep = {
        f".owl-{other_rid}-{secrets.token_hex(16)}.part": b"de outra restauracao",
        f".owl-{rid}-naohex.part": b"nome parecido",
        f".owl-{rid}-{secrets.token_hex(16)}.part.txt": b"outra extensao",
        f".owl-{rid.upper()}-{secrets.token_hex(16).upper()}.part": b"maiusculas",
        "nao-apagar.txt": b"arquivo do usuario",
    }
    for n, data in keep.items():
        (dest / n).write_bytes(data)
    own_dir = dest / f".owl-{rid}-{secrets.token_hex(16)}.part"
    own_dir.mkdir()  # pasta com nome de .part: não é arquivo, não pode ser apagada

    # um arquivo já restaurado e correto teve a data alterada: a retomada reaplica o mtime
    skipped = restored_before[0]
    os.utime(dest / skipped, ns=(10**18, 10**18))
    ino_before = {f: os.stat(dest / f).st_ino for f in restored_before}

    # sem confirmação explícita: StateError e nada muda
    listing = _listing(dest)
    with pytest.raises(StateError):
        _restore_to(area, dest)
    assert _listing(dest) == listing
    assert own_root.exists() and own_sub.exists()

    rep = _restore_to(area, dest, allow_resume=True)
    assert rep.ok, (rep.failed, rep.conflicts)
    assert rep.skipped_existing == 2
    assert rep.restored == 5

    # .part DESTA restauração apagados; todo o resto mantido
    assert not own_root.exists()
    assert not own_sub.exists()
    for n, data in keep.items():
        assert (dest / n).read_bytes() == data, n
    assert own_dir.is_dir()
    # arquivos corretos pulados (não reescritos) e com mtime reaplicado
    for f in restored_before:
        assert os.stat(dest / f).st_ino == ino_before[f], f
    # marcador e trava removidos
    assert not (dest / MARKER_NAME).exists()
    assert not (dest / RESTORE_LOCK_NAME).exists()
    # árvore igual à origem (ignorando os itens plantados pelo teste)
    got = tree_digest(dest)
    planted = set(keep) | {own_dir.name}
    got = {k: v for k, v in got.items() if k not in planted}
    assert got == before


def test_resume_reports_conflict_and_leaves_wrong_file_untouched(area: Area) -> None:
    _resume_tree(area)
    src_digest = tree_digest(area.src)
    make_vault(area)
    dest = area.dest()
    _crash_restore_at_third_rename(area, dest)

    restored = [f for f in _files(dest) if f != MARKER_NAME]
    assert len(restored) == 2
    expected_files = sorted(k for k, v in src_digest.items() if v[0] == "file")
    missing_root = sorted(f for f in expected_files if f not in restored and os.sep not in f)
    # (1) arquivo ainda não restaurado: alguém colocou conteúdo ERRADO no caminho final
    wrong_new = missing_root[0]
    size = (area.src / wrong_new).stat().st_size
    wrong_bytes_1 = (b"Z" * size) if size else b"!"
    (dest / wrong_new).write_bytes(wrong_bytes_1)
    # (2) arquivo já restaurado foi alterado depois (mesmo tamanho, hash diferente)
    tampered = next(f for f in restored if (dest / f).stat().st_size > 0)
    orig = (dest / tampered).read_bytes()
    wrong_bytes_2 = bytes([orig[0] ^ 0xFF]) + orig[1:]
    (dest / tampered).write_bytes(wrong_bytes_2)
    snap = {
        f: ((dest / f).read_bytes(), os.stat(dest / f).st_mtime_ns, os.stat(dest / f).st_ino)
        for f in (wrong_new, tampered)
    }

    rep = _restore_to(area, dest, allow_resume=True)
    assert not rep.ok
    assert len(rep.conflicts) == 2, rep.conflicts
    assert any(wrong_new in c for c in rep.conflicts), rep.conflicts
    assert any(tampered in c for c in rep.conflicts), rep.conflicts
    assert not rep.failed
    # intocados (conteúdo, data e identidade)
    for f, (data, mtime, ino) in snap.items():
        assert (dest / f).read_bytes() == data
        assert os.stat(dest / f).st_mtime_ns == mtime
        assert os.stat(dest / f).st_ino == ino
    # todo o resto foi restaurado corretamente
    got = tree_digest(dest)
    for rel, val in src_digest.items():
        if rel in snap:
            continue
        assert got.get(rel) == val, rel
    assert not [n for n in _listing(dest) if n.endswith(".part")]


def test_resume_with_marker_of_another_vault_refused(area: Area) -> None:
    _resume_tree(area)
    make_vault(area)
    make_vault(area, name="outro")
    dest = area.dest()
    _crash_restore_at_third_rename(area, dest)
    listing = _listing(dest)
    digest = tree_digest(dest)
    with pytest.raises(StateError):
        _restore_to(area, dest, name="outro", allow_resume=True)
    assert _listing(dest) == listing
    assert tree_digest(dest) == digest


def test_disk_full_during_restore_then_resume(area: Area) -> None:
    before = _resume_tree(area)
    make_vault(area)
    dest = area.dest()
    faults.fail_at("restore.write", 4, lambda: OSError(28, "No space left on device"))
    with pytest.raises(InsufficientSpaceError):
        do_restore(area)
    faults.reset()
    assert (dest / MARKER_NAME).is_file()
    assert not [n for n in _listing(dest) if n.endswith(".part")]
    assert not (dest / RESTORE_LOCK_NAME).exists()
    rep = _restore_to(area, dest, allow_resume=True)
    assert rep.ok, (rep.failed, rep.conflicts)
    assert rep.restored + rep.skipped_existing == 7
    assert rep.skipped_existing >= 1
    assert tree_digest(dest) == before


def test_cancel_then_resume(area: Area) -> None:
    before = _resume_tree(area)
    make_vault(area)
    dest = area.dest()
    token = CancelToken()

    class CancelAfterFirstFile(NullProgress):
        def advance(self, nbytes: int = 0, nitems: int = 0) -> None:
            if nitems:
                token.cancel()

    with pytest.raises(CancelledError):
        _restore_to(area, dest, cancel=token, progress=CancelAfterFirstFile())
    assert (dest / MARKER_NAME).is_file()
    assert len([f for f in _files(dest) if f != MARKER_NAME]) == 1
    assert not [n for n in _listing(dest) if n.endswith(".part")]
    rep = _restore_to(area, dest, allow_resume=True)
    assert rep.ok
    assert rep.skipped_existing == 1
    assert rep.restored == 6
    assert tree_digest(dest) == before


@pytest.mark.parametrize("with_subdir", [False, True], ids=["files-only", "dir-first"])
def test_resume_never_writes_through_planted_junction(area: Area, with_subdir: bool) -> None:
    """Retomada: pasta existente que é ponto de reparse não é aceita (§4.4 passo 6) e nada
    pode ser criado fora do destino através dela (nem arquivos, nem pastas)."""
    sub: dict[str, object] = {"z.txt": b"dentro de sub", "y.txt": b"outro"}
    if with_subdir:
        sub["0pasta"] = {}  # ordenada antes dos arquivos de sub
    write_tree(
        area.src,
        {"a.txt": b"A", "b.txt": b"B", "c.txt": b"C", "sub": sub},
    )
    make_vault(area)
    dest = area.dest()
    _crash_restore_at_third_rename(area, dest)
    assert not (dest / "sub").exists()
    rid = str(_read_marker(dest)["restore_id"])

    outside = area.root / "fora"
    outside.mkdir()
    bait = f".owl-{rid}-{secrets.token_hex(16)}.part"
    (outside / bait).write_bytes(b"nao e do destino")
    _junction(outside, dest / "sub")
    try:
        raised: BaseException | None = None
        rep: RestoreReport | None = None
        try:
            rep = _restore_to(area, dest, allow_resume=True)
        except OwlVaultError as exc:
            raised = exc
        # nada criado nem apagado fora do destino
        assert sorted(os.listdir(outside)) == [bait]
        assert (outside / bait).read_bytes() == b"nao e do destino"
        if raised is None:
            assert rep is not None and not rep.ok
            assert any("sub" in c for c in rep.conflicts + rep.failed)
    finally:
        os.rmdir(dest / "sub")


# --- falhas parciais ---------------------------------------------------------------------


def _blob_paths(area: Area, name: str = "cofre") -> list[Path]:
    return sorted((area.vault(name) / "data").rglob("*.owlb"))


def _sha_of_blob_map(area: Area) -> dict[str, str]:
    """file_id hex → caminho relativo (lido do manifesto decifrado)."""
    from owl_vault.application.vault import open_vault, read_manifest

    opened = open_vault(str(area.vault()), PASSWORD, TESTING_POLICY)
    m = read_manifest(opened).manifest
    return {e.file_id.hex(): os.path.join(*e.path) for e in m.files}


def test_missing_blob_restores_the_rest_and_reports(area: Area) -> None:
    _resume_tree(area)
    src_digest = tree_digest(area.src)
    make_vault(area)
    mapping = _sha_of_blob_map(area)
    victim = next(p for p in _blob_paths(area) if mapping[p.stem] == os.path.join("sub", "e.txt"))
    victim.unlink()
    rep = do_restore(area)
    assert not rep.ok
    assert len(rep.failed) == 1 and "e.txt" in rep.failed[0], rep.failed
    assert rep.restored == 6
    dest = area.dest()
    assert not (dest / "sub" / "e.txt").exists()
    got = tree_digest(dest)
    for rel, val in src_digest.items():
        if rel != os.path.join("sub", "e.txt"):
            assert got.get(rel) == val, rel
    assert not [n for n in _listing(dest) if n.endswith(".part")]


def test_corrupted_blob_is_not_restored_and_no_part_left(area: Area) -> None:
    _resume_tree(area)
    src_digest = tree_digest(area.src)
    make_vault(area)
    mapping = _sha_of_blob_map(area)
    victim = next(p for p in _blob_paths(area) if mapping[p.stem] == os.path.join("sub", "f.bin"))
    data = bytearray(victim.read_bytes())
    data[64 + SMALL_CHUNK + 16 + 5] ^= 0x01  # segundo chunk (tamanho do blob inalterado)
    victim.write_bytes(bytes(data))
    rep = do_restore(area)
    assert not rep.ok
    assert len(rep.failed) == 1 and "f.bin" in rep.failed[0], rep.failed
    assert rep.restored == 6
    dest = area.dest()
    assert not (dest / "sub" / "f.bin").exists()
    assert not [n for n in _listing(dest) if n.endswith(".part")]
    got = tree_digest(dest)
    for rel, val in src_digest.items():
        if rel != os.path.join("sub", "f.bin"):
            assert got.get(rel) == val, rel


# --- Mark-of-the-Web ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("carrier", "zone", "expect_motw"),
    [
        (None, None, False),
        ("vault.owl", 3, True),
        ("vault.owl", 4, True),
        ("vault.owl", 2, False),
        ("manifest.owl", 3, True),
    ],
    ids=["no-zone", "vault-zone3", "vault-zone4", "vault-zone2", "manifest-zone3"],
)
def test_mark_of_the_web_propagation(
    area: Area, carrier: str | None, zone: int | None, expect_motw: bool
) -> None:
    write_tree(
        area.src,
        {"doc.txt": b"texto", "vazio.bin": b"", "sub": {"prog.exe": b"MZ fake", "v": {}}},
    )
    before = tree_digest(area.src)
    make_vault(area)
    if carrier is not None and zone is not None:
        _write_zone(area.vault() / carrier, zone)
    rep = do_restore(area)
    assert rep.ok, (rep.failed, rep.conflicts)
    assert not [w for w in rep.warnings if "marca" in w.lower()], rep.warnings
    dest = area.dest()
    assert tree_digest(dest) == before
    for rel in ("doc.txt", "vazio.bin", os.path.join("sub", "prog.exe")):
        stream = _zone_stream(dest / rel)
        if expect_motw:
            assert stream == MOTW, (rel, stream)
        else:
            assert stream is None, (rel, stream)
