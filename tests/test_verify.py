"""Verificar cofre (ARCHITECTURE §4.3, FORMAT §9): somente leitura; blobs ausentes, extras,
pasta ``hh`` errada, itens desconhecidos, diário remanescente, ``complete.owl`` ausente e
cofre em pasta/mídia somente leitura.

Somente pastas temporárias com dados sintéticos.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from owl_vault.application.vault import open_vault, read_manifest
from owl_vault.crypto.kdf import TESTING_POLICY
from owl_vault.domain.errors import VaultLockedError
from owl_vault.storage import winfs
from owl_vault.storage.layout import LOCK_NAME
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

N_FILES = 6


def _sample(area: Area) -> None:
    write_tree(
        area.src,
        {
            "a.txt": b"conteudo a",
            "vazio.txt": b"",
            "grande.bin": os.urandom(2 * SMALL_CHUNK + 11),
            "sub": {"b.txt": b"B" * 500, "c.bin": os.urandom(SMALL_CHUNK), "vazia": {}},
            "outra": {"a.txt": b"mesmo nome"},
        },
    )


def _vault_with_sample(area: Area) -> Path:
    _sample(area)
    res = make_vault(area)
    assert res.status == "success"
    return area.vault()


def _blob_map(area: Area, name: str = "cofre") -> dict[str, Path]:
    """caminho relativo (display) → caminho do blob."""
    opened = open_vault(str(area.vault(name)), PASSWORD, TESTING_POLICY)
    m = read_manifest(opened).manifest
    vault = area.vault(name)
    out: dict[str, Path] = {}
    for e in m.files:
        h = e.file_id.hex()
        out["\\".join(e.path)] = vault / "data" / h[:2] / f"{h}.owlb"
    return out


def _all_blobs(vault: Path) -> list[Path]:
    return sorted((vault / "data").rglob("*.owlb"))


def _listing(root: Path) -> list[str]:
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        for n in dirnames + filenames:
            out.append(os.path.normpath(os.path.join(rel, n)))
    return sorted(out)


def _new_blob_name(vault: Path, prefix: str | None = None) -> tuple[str, str]:
    while True:
        h = secrets.token_hex(16)
        if prefix is not None:
            h = prefix + h[2:]
        if not (vault / "data" / h[:2] / f"{h}.owlb").exists():
            return h[:2], f"{h}.owlb"


def _anoms(report: object, needle: str) -> list[str]:
    return [a for a in report.anomalies if needle in a]  # type: ignore[attr-defined]


# --- cofre íntegro -----------------------------------------------------------------------


def test_pristine_vault_is_fully_ok_and_untouched(area: Area) -> None:
    vault = _vault_with_sample(area)
    digest = tree_digest(vault)
    listing = _listing(vault)
    rep = do_verify(area)
    assert rep.fully_ok, (rep.bad, rep.anomalies, rep.notes)
    assert rep.ok
    assert rep.completed
    assert rep.files_ok == rep.total_files == N_FILES
    assert rep.total_bytes == sum(p.stat().st_size for p in area.src.rglob("*") if p.is_file())
    assert rep.bad == [] and rep.anomalies == []
    assert "concluída e testada" in rep.creation_status
    assert "NÃO" not in rep.creation_status
    assert rep.lock_note == ""
    # somente leitura: nada mudou, a trava não ficou para trás
    assert tree_digest(vault) == digest
    assert _listing(vault) == listing
    assert not (vault / LOCK_NAME).exists()


# --- blobs -------------------------------------------------------------------------------


def test_missing_blob_is_bad(area: Area) -> None:
    vault = _vault_with_sample(area)
    blobs = _blob_map(area)
    victim = "sub\\b.txt"
    blobs[victim].unlink()
    rep = do_verify(area)
    assert not rep.ok and not rep.fully_ok
    assert len(rep.bad) == 1, rep.bad
    assert victim in rep.bad[0] and "ausente" in rep.bad[0]
    assert rep.files_ok == N_FILES - 1
    assert rep.anomalies == []
    assert rep.completed  # a criação foi concluída; o dano é posterior
    assert vault.is_dir()


def test_extra_unreferenced_blob_is_anomaly(area: Area) -> None:
    vault = _vault_with_sample(area)
    src_blob = _all_blobs(vault)[0]
    hh, name = _new_blob_name(vault)
    (vault / "data" / hh).mkdir(exist_ok=True)
    shutil.copyfile(src_blob, vault / "data" / hh / name)
    rep = do_verify(area)
    assert rep.ok, rep.bad
    assert not rep.fully_ok
    assert rep.files_ok == N_FILES
    assert len(rep.anomalies) == 1, rep.anomalies
    assert "não referenciado" in rep.anomalies[0] and name in rep.anomalies[0]


def test_unreferenced_blob_from_other_vault_is_anomaly(area: Area) -> None:
    vault = _vault_with_sample(area)
    make_vault(area, name="outro")
    foreign = _all_blobs(area.vault("outro"))[0]
    hh, name = _new_blob_name(vault)
    (vault / "data" / hh).mkdir(exist_ok=True)
    shutil.copyfile(foreign, vault / "data" / hh / name)
    rep = do_verify(area)
    assert rep.ok, rep.bad
    assert not rep.fully_ok
    assert len(rep.anomalies) == 1, rep.anomalies
    assert "outro cofre" in rep.anomalies[0] and name in rep.anomalies[0]


def test_unreadable_unreferenced_blob_is_anomaly(area: Area) -> None:
    vault = _vault_with_sample(area)
    hh, name = _new_blob_name(vault)
    (vault / "data" / hh).mkdir(exist_ok=True)
    (vault / "data" / hh / name).write_bytes(b"lixo" * 10)
    rep = do_verify(area)
    assert rep.ok, rep.bad
    assert not rep.fully_ok
    assert len(rep.anomalies) == 1, rep.anomalies
    assert name in rep.anomalies[0]


def test_referenced_blob_in_wrong_hh_folder(area: Area) -> None:
    vault = _vault_with_sample(area)
    blobs = _blob_map(area)
    victim = "grande.bin"
    blob = blobs[victim]
    right_hh = blob.parent.name
    wrong_hh = "00" if right_hh != "00" else "ff"
    (vault / "data" / wrong_hh).mkdir(exist_ok=True)
    os.replace(blob, vault / "data" / wrong_hh / blob.name)
    rep = do_verify(area)
    # o arquivo não está onde deveria: ruim; e o blob deslocado é anomalia "pasta hh errada"
    assert len(rep.bad) == 1 and victim in rep.bad[0], rep.bad
    assert rep.files_ok == N_FILES - 1
    wrong = _anoms(rep, "subpasta errada")
    assert len(wrong) == 1 and blob.name in wrong[0], rep.anomalies
    assert len(rep.anomalies) == 1, rep.anomalies
    assert not rep.fully_ok


def test_unreferenced_blob_in_wrong_hh_folder(area: Area) -> None:
    vault = _vault_with_sample(area)
    _, name = _new_blob_name(vault, prefix="ab")
    wrong = "cd"
    (vault / "data" / wrong).mkdir(exist_ok=True)
    shutil.copyfile(_all_blobs(vault)[0], vault / "data" / wrong / name)
    rep = do_verify(area)
    assert rep.ok
    assert len(rep.anomalies) == 1, rep.anomalies
    assert "subpasta errada" in rep.anomalies[0] and name in rep.anomalies[0]


def test_corrupted_chunk_is_bad(area: Area) -> None:
    _vault_with_sample(area)
    blobs = _blob_map(area)
    victim = "grande.bin"
    data = bytearray(blobs[victim].read_bytes())
    data[64 + SMALL_CHUNK + 16 + 3] ^= 0x80  # segundo chunk; tamanho inalterado
    blobs[victim].write_bytes(bytes(data))
    rep = do_verify(area)
    assert len(rep.bad) == 1 and victim in rep.bad[0], rep.bad
    assert rep.files_ok == N_FILES - 1
    assert rep.anomalies == []
    assert not rep.ok


def test_truncated_blob_is_bad(area: Area) -> None:
    _vault_with_sample(area)
    blobs = _blob_map(area)
    victim = "sub\\c.bin"
    data = blobs[victim].read_bytes()
    blobs[victim].write_bytes(data[:-1])
    rep = do_verify(area)
    assert len(rep.bad) == 1 and victim in rep.bad[0], rep.bad
    assert rep.files_ok == N_FILES - 1
    assert not rep.ok


# --- itens estranhos no cofre ------------------------------------------------------------


def test_unknown_items_in_vault_root(area: Area) -> None:
    vault = _vault_with_sample(area)
    (vault / "notas.txt").write_bytes(b"algo")
    (vault / "pasta-estranha").mkdir()
    rep = do_verify(area)
    assert rep.ok, rep.bad
    assert rep.files_ok == N_FILES
    assert not rep.fully_ok
    unknown = _anoms(rep, "desconhecido")
    assert len(unknown) == 2 and len(rep.anomalies) == 2, rep.anomalies
    assert any("notas.txt" in a for a in unknown)
    assert any("pasta-estranha" in a for a in unknown)


def test_unknown_items_and_tmp_in_data(area: Area) -> None:
    vault = _vault_with_sample(area)
    data = vault / "data"
    (data / "zz").mkdir()  # não é hex
    (data / "notas.txt").write_bytes(b"x")
    hh = _all_blobs(vault)[0].parent
    tmp_name = f"{hh.name}{secrets.token_hex(15)}.tmp"
    (hh / tmp_name).write_bytes(b"resto de criacao")
    (hh / "leia.txt").write_bytes(b"x")
    rep = do_verify(area)
    assert rep.ok, rep.bad
    assert rep.files_ok == N_FILES
    assert not rep.fully_ok
    assert len(rep.anomalies) == 4, rep.anomalies
    for needle in ("zz", "notas.txt", tmp_name, "leia.txt"):
        assert any(needle in a for a in rep.anomalies), (needle, rep.anomalies)


def test_leftover_journal_dir_is_anomaly(area: Area) -> None:
    vault = _vault_with_sample(area)
    assert not (vault / "journal").exists()
    (vault / "journal").mkdir()
    rep = do_verify(area)
    assert rep.ok, rep.bad
    assert rep.files_ok == N_FILES
    assert not rep.fully_ok
    assert len(rep.anomalies) == 1, rep.anomalies
    assert "journal" in rep.anomalies[0]
    assert not _anoms(rep, "desconhecido")


def test_missing_completion_record(area: Area) -> None:
    vault = _vault_with_sample(area)
    (vault / "complete.owl").unlink()
    rep = do_verify(area)
    assert rep.ok, rep.bad
    assert rep.files_ok == N_FILES
    assert not rep.completed
    assert not rep.fully_ok
    assert "NÃO concluída" in rep.creation_status


def test_tampered_completion_record(area: Area) -> None:
    vault = _vault_with_sample(area)
    p = vault / "complete.owl"
    data = bytearray(p.read_bytes())
    data[-1] ^= 0x01
    p.write_bytes(bytes(data))
    rep = do_verify(area)
    assert rep.ok, rep.bad
    assert not rep.completed
    assert not rep.fully_ok
    assert "NÃO concluída" in rep.creation_status


def _flip(p: Path, offset: int) -> None:
    data = bytearray(p.read_bytes())
    data[offset] ^= 0x01
    p.write_bytes(bytes(data))


@pytest.mark.parametrize(
    "damage",
    ["header-bak-tampered", "header-bak-missing", "manifest-bak-tampered", "manifest-bak-missing"],
)
def test_damaged_redundant_copy_is_reported(area: Area, damage: str) -> None:
    """FORMAT §3.1 passo 5 / §5.1: a verificação reporta a cópia redundante danificada mesmo
    quando o desbloqueio funciona pela outra."""
    vault = _vault_with_sample(area)
    target = vault / ("vault.owl.bak" if damage.startswith("header") else "manifest.owl.bak")
    if damage.endswith("missing"):
        target.unlink()
    else:
        _flip(target, 100 if damage.startswith("header") else target.stat().st_size - 1)
    rep = do_verify(area)
    assert rep.ok, rep.bad
    assert rep.files_ok == N_FILES
    assert rep.completed
    assert any(target.name in n for n in rep.redundancy), rep.redundancy
    assert not rep.fully_ok  # redundância perdida não pode ser "cofre íntegro"


# --- trava e somente leitura -------------------------------------------------------------


def test_verify_refuses_while_vault_is_locked(area: Area) -> None:
    vault = _vault_with_sample(area)
    lock = winfs.ExclusiveLock(winfs.to_extended(str(vault / LOCK_NAME)), "O cofre")
    lock.acquire()
    try:
        with pytest.raises(VaultLockedError):
            do_verify(area)
    finally:
        lock.release()
    assert do_verify(area).fully_ok


def test_verify_on_write_protected_media_proceeds_without_lock(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mídia somente leitura (simulada): criar a trava falha com ERROR_WRITE_PROTECT (19)."""
    _vault_with_sample(area)
    real = winfs._create_file

    def fake(path: str, access: int, share: int, disposition: int, flags: int) -> int:
        if path.endswith("\\" + LOCK_NAME):
            raise winfs._os_error(19, path)
        return real(path, access, share, disposition, flags)

    monkeypatch.setattr(winfs, "_create_file", fake)
    rep = do_verify(area)
    assert rep.fully_ok, (rep.bad, rep.anomalies, rep.notes)
    assert rep.lock_note  # avisa que verificou sem trava


def test_verify_with_read_only_vault_files(area: Area) -> None:
    """Cofre copiado de mídia óptica: todos os arquivos com atributo somente leitura."""
    vault = _vault_with_sample(area)
    files = [p for p in vault.rglob("*") if p.is_file()]
    for p in files:
        os.chmod(p, stat.S_IREAD)
    try:
        digest = tree_digest(vault)
        rep = do_verify(area)
        assert rep.fully_ok, (rep.bad, rep.anomalies, rep.notes)
        assert tree_digest(vault) == digest
        rest = do_restore(area)
        assert rest.ok, (rest.failed, rest.conflicts)
        assert tree_digest(area.dest()) == tree_digest(area.src)
    finally:
        for p in files:
            os.chmod(p, stat.S_IREAD | stat.S_IWRITE)


def _system_tool(name: str) -> str:
    root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
    exe = os.path.join(root, "System32", name)
    if not os.path.isfile(exe):
        pytest.skip(f"{name} não encontrado")
    return exe


def _current_sid() -> str:
    out = subprocess.run(  # noqa: S603 - executável do sistema, argumentos fixos
        [_system_tool("whoami.exe"), "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    sid = out.split(",")[-1].strip().strip('"')
    if not sid.startswith("S-1-"):
        pytest.skip("não foi possível obter o SID do usuário atual")
    return sid


def test_verify_in_read_only_folder(area: Area) -> None:
    """Pasta do cofre sem permissão de escrita (ACL nega criar arquivos/pastas nela; a
    pasta é temporária do teste e a ACL é removida no final):
    FORMAT §9 — Verificar tenta a trava; sem poder gravar, prossegue sem ela e avisa."""
    vault = _vault_with_sample(area)
    sid = _current_sid()
    icacls = _system_tool("icacls.exe")
    r = subprocess.run(  # noqa: S603 - executável do sistema, pasta temporária do teste
        [icacls, str(vault), "/deny", f"*{sid}:(WD,AD)"],
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        pytest.skip(f"icacls não conseguiu negar escrita: {r.stdout} {r.stderr}")
    try:
        try:
            (vault / "sonda.tmp").write_bytes(b"x")
        except PermissionError:
            pass
        else:
            (vault / "sonda.tmp").unlink()
            pytest.skip("a ACL de negação não teve efeito neste sistema")
        rep = do_verify(area)
        assert rep.fully_ok, (rep.bad, rep.anomalies, rep.notes)
        assert rep.lock_note
    finally:
        subprocess.run(  # noqa: S603 - executável do sistema, pasta temporária do teste
            [icacls, str(vault), "/remove:d", f"*{sid}"], capture_output=True, check=False
        )
