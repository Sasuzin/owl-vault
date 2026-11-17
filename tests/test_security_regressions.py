"""Regressões dos achados confirmados na revisão de segurança do código."""

from __future__ import annotations

import _winapi
import hashlib
import os
import shutil
from pathlib import Path

import pytest

from owl_vault.application import create as create_mod
from owl_vault.application.common import validate_new_password
from owl_vault.application.create import inspect_vault_dir, resume_create
from owl_vault.application.protection import ProtectedPaths
from owl_vault.application.salvage import salvage_vault
from owl_vault.application.vault import open_vault
from owl_vault.crypto.kdf import TESTING_POLICY
from owl_vault.domain.errors import OwlVaultError, UnsafePathError
from owl_vault.storage import faults, winfs
from tests.conftest import (
    PASSWORD,
    Area,
    do_restore,
    do_verify,
    make_vault,
    tree_digest,
    write_tree,
)


class Crash(BaseException):
    pass


def _sample(area: Area) -> None:
    write_tree(
        area.src,
        {
            "a.txt": b"conteudo A",
            "b.bin": os.urandom(150_000),
            "sub": {"c.txt": b"C" * 500, "d.txt": b"D"},
        },
    )


def _interrupt_during_encryption(area: Area) -> None:
    faults.fail_at("blob.rename", 2, Crash)
    with pytest.raises(Crash):
        make_vault(area)
    faults.reset()


# [0]/[3] retomada: a pasta no caminho registrado precisa ser a MESMA (identidade)
def test_resume_refuses_when_other_folder_took_the_recorded_path(area: Area) -> None:
    _sample(area)
    _interrupt_during_encryption(area)
    moved = area.root / "origem-movida"
    area.src.rename(moved)
    area.src.mkdir()
    (area.src / "OUTRA-PASTA.txt").write_bytes(b"nao e a origem")
    for chosen in (moved, area.src):
        with pytest.raises(UnsafePathError):
            resume_create(
                str(area.vault()),
                str(chosen),
                PASSWORD,
                kdf_policy=TESTING_POLICY,
                protected=ProtectedPaths.none(),
            )
    # devolver a pasta original ao caminho registrado permite concluir corretamente
    shutil.rmtree(area.src)
    moved.rename(area.src)
    result = resume_create(
        str(area.vault()),
        str(area.src),
        PASSWORD,
        kdf_policy=TESTING_POLICY,
        protected=ProtectedPaths.none(),
    )
    assert result.status == "success"
    assert do_restore(area).ok
    assert tree_digest(area.dest()) == tree_digest(area.src)


# [1]/[4] trava que não é um arquivo comum: recusa e NÃO apaga o alvo
def test_lock_that_is_a_junction_is_refused_and_target_untouched(area: Area) -> None:
    _sample(area)
    make_vault(area)
    victim_dir = area.root / "vitima"
    victim_dir.mkdir()
    (victim_dir / "tese.docx").write_bytes(b"trabalho importante")
    _winapi.CreateJunction(str(victim_dir), str(area.vault() / ".owlvault.lock"))
    lock = winfs.ExclusiveLock(winfs.to_extended(str(area.vault() / ".owlvault.lock")), "O cofre")
    with pytest.raises(UnsafePathError):
        lock.acquire()
    rep = do_verify(area)  # verificação prossegue sem trava e acusa a anomalia
    assert rep.ok
    assert not rep.fully_ok
    assert any("trava" in a for a in rep.anomalies)
    assert (victim_dir / "tese.docx").read_bytes() == b"trabalho importante"


def test_lock_with_extra_hard_link_is_refused(area: Area) -> None:
    _sample(area)
    make_vault(area)
    victim = area.root / "vitima.txt"
    victim.write_bytes(b"nao apagar")
    os.link(victim, area.vault() / ".owlvault.lock")
    lock = winfs.ExclusiveLock(winfs.to_extended(str(area.vault() / ".owlvault.lock")), "O cofre")
    with pytest.raises(UnsafePathError):
        lock.acquire()
    assert victim.read_bytes() == b"nao apagar"


# [2] cópia redundante danificada não é "íntegro"
def test_verify_not_fully_ok_when_header_backup_damaged(area: Area) -> None:
    _sample(area)
    make_vault(area)
    (area.vault() / "vault.owl.bak").unlink()
    rep = do_verify(area)
    assert rep.ok and rep.completed
    assert rep.redundancy
    assert not rep.fully_ok


# [5]/[15] limpeza final interrompida: Retomar apenas remove resíduos
def test_resume_finishes_cleanup_of_completed_vault(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sample(area)
    real = create_mod.cleanup_after_completion

    def crash_cleanup(*args: object, **kwargs: object) -> None:
        raise Crash()

    monkeypatch.setattr(create_mod, "cleanup_after_completion", crash_cleanup)
    with pytest.raises(Crash):
        make_vault(area)
    monkeypatch.setattr(create_mod, "cleanup_after_completion", real)
    assert (area.vault() / "complete.owl").exists()
    assert (area.vault() / "journal").exists()
    assert inspect_vault_dir(str(area.vault())).kind == "vault-incomplete"
    assert not do_verify(area).fully_ok
    result = resume_create(
        str(area.vault()),
        str(area.src),
        PASSWORD,
        kdf_policy=TESTING_POLICY,
        protected=ProtectedPaths.none(),
    )
    assert result.status == "success"
    assert any("resíduos" in n for n in result.notes)
    assert not (area.vault() / "journal").exists()
    assert list(area.testarea.iterdir()) == []
    assert do_verify(area).fully_ok


# [7] senha com caracteres invisíveis (BOM, U+FFFD) é recusada
@pytest.mark.parametrize("bad", ["﻿SenhaLonga123", "Senha�Longa123", "Senha\x07Longa123"])
def test_password_with_invisible_chars_rejected(bad: str) -> None:
    with pytest.raises(OwlVaultError):
        validate_new_password(bad)


# [9] salvamento ignora vault_id em claro corrompido quando o .bak sumiu
def test_salvage_ignores_corrupted_plaintext_hint(area: Area) -> None:
    _sample(area)
    make_vault(area)
    m = area.vault() / "manifest.owl"
    data = bytearray(m.read_bytes())
    data[20] ^= 0x01  # vault_id em claro
    m.write_bytes(bytes(data))
    (area.vault() / "manifest.owl.bak").unlink()
    with pytest.raises(OwlVaultError):
        open_vault(str(area.vault()), PASSWORD, TESTING_POLICY)  # restauração/verificação recusam
    report = salvage_vault(
        str(area.vault()),
        PASSWORD,
        str(area.dest("emergencia")),
        policy=TESTING_POLICY,
        protected=ProtectedPaths.none(),
    )
    assert report.recovered == 4 and not report.failed
    got = sorted(
        hashlib.sha256(p.read_bytes()).hexdigest() for p in area.dest("emergencia").iterdir()
    )
    want = sorted(
        hashlib.sha256(p.read_bytes()).hexdigest() for p in area.src.rglob("*") if p.is_file()
    )
    assert got == want


# [11]/[12]/[16] retomada de restauração nunca atravessa link nem escreve fora do destino
def test_restore_resume_never_touches_files_behind_junction(area: Area) -> None:
    _sample(area)
    make_vault(area)
    faults.fail_at("restore.rename", 2, Crash)
    with pytest.raises(Crash):
        do_restore(area)
    faults.reset()
    dest = area.dest()
    outside = area.root / "fora"
    outside.mkdir()
    (outside / "c.txt").write_bytes(b"C" * 500)  # idêntico ao do cofre
    os.utime(outside / "c.txt", ns=(1_000_000_000_000_000_000, 1_000_000_000_000_000_000))
    before = (outside / "c.txt").stat().st_mtime_ns
    sub = dest / "sub"
    if sub.exists():
        shutil.rmtree(sub)
    _winapi.CreateJunction(str(outside), str(sub))
    rep = do_restore(area, allow_resume=True)
    assert not rep.ok  # 'sub' é conflito
    assert any(c.startswith("sub") for c in rep.conflicts + rep.failed)
    assert (outside / "c.txt").stat().st_mtime_ns == before
    assert sorted(p.name for p in outside.iterdir()) == ["c.txt"]


# [22] ponto final em componente intermediário é recusado (não muda de pasta em silêncio)
def test_to_extended_refuses_trailing_dot_in_any_component(tmp_path: Path) -> None:
    with pytest.raises(UnsafePathError):
        winfs.to_extended(str(tmp_path) + "\\proj.\\docs")
    with pytest.raises(UnsafePathError):
        winfs.to_extended(str(tmp_path) + "\\proj \\docs")
    assert winfs.to_extended(str(tmp_path) + "\\proj\\..\\docs").endswith("\\docs")
