"""Fixtures compartilhadas. Todos os testes usam SOMENTE pastas temporárias sintéticas."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from owl_vault.application import install
from owl_vault.application.create import CreateResult, create_vault
from owl_vault.application.progress import CancelToken, RecordingProgress
from owl_vault.application.protection import ProtectedPaths
from owl_vault.application.restore import RestoreReport, restore_vault
from owl_vault.application.verify import VerifyReport, verify_vault
from owl_vault.crypto.kdf import TESTING_PARAMS, TESTING_POLICY
from owl_vault.storage import faults

PASSWORD = "correct horse battery staple"
SMALL_CHUNK = 64 * 1024


@pytest.fixture(autouse=True)
def _reset_faults() -> Iterator[None]:
    faults.reset()
    yield
    faults.reset()


@pytest.fixture(autouse=True)
def _sem_area_de_trabalho_real(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nenhum teste cria atalho na Área de Trabalho real: quem precisa dela usa uma pasta
    temporária (``install.desktop_dir`` trocado no próprio teste)."""
    monkeypatch.setattr(install, "desktop_dir", lambda: None)


@dataclass
class Area:
    """Pastas isoladas de um teste."""

    root: Path
    src: Path
    vaults: Path
    testarea: Path
    out: Path

    def vault(self, name: str = "cofre") -> Path:
        return self.vaults / name

    def dest(self, name: str = "restaurado") -> Path:
        return self.out / name


@pytest.fixture
def area(tmp_path: Path) -> Area:
    a = Area(
        root=tmp_path,
        src=tmp_path / "origem",
        vaults=tmp_path / "cofres",
        testarea=tmp_path / "teste",
        out=tmp_path / "saida",
    )
    for p in (a.src, a.vaults, a.testarea, a.out):
        p.mkdir()
    return a


def write_tree(root: Path, spec: dict[str, Any]) -> None:
    """``{"a.txt": b"...", "sub": {"b.bin": b"..."}, "vazia": {}}``."""
    for name, value in spec.items():
        p = root / name
        if isinstance(value, dict):
            p.mkdir()
            write_tree(p, value)
        else:
            p.write_bytes(value)


def tree_digest(root: Path) -> dict[str, Any]:
    """Mapa relativo → ('dir',) ou ('file', sha256, mtime_ns)."""
    out: dict[str, Any] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        for d in dirnames:
            out[os.path.normpath(os.path.join(rel, d))] = ("dir",)
        for f in filenames:
            full = os.path.join(dirpath, f)
            with open(full, "rb") as fh:
                h = hashlib.sha256(fh.read()).hexdigest()
            out[os.path.normpath(os.path.join(rel, f))] = ("file", h, os.stat(full).st_mtime_ns)
    return out


def make_vault(
    area: Area,
    *,
    name: str = "cofre",
    password: str = PASSWORD,
    chunk_size: int = SMALL_CHUNK,
    cancel: CancelToken | None = None,
    progress: RecordingProgress | None = None,
    **kw: Any,
) -> CreateResult:
    return create_vault(
        str(area.src),
        str(area.vault(name)),
        password,
        test_parent=str(area.testarea),
        kdf_params=TESTING_PARAMS,
        kdf_policy=TESTING_POLICY,
        chunk_size=chunk_size,
        protected=ProtectedPaths.none(),
        progress=progress,
        cancel=cancel,
        **kw,
    )


def do_verify(area: Area, name: str = "cofre", password: str = PASSWORD) -> VerifyReport:
    return verify_vault(str(area.vault(name)), password, policy=TESTING_POLICY)


def do_restore(
    area: Area,
    dest: str = "restaurado",
    name: str = "cofre",
    password: str = PASSWORD,
    **kw: Any,
) -> RestoreReport:
    return restore_vault(
        str(area.vault(name)),
        password,
        str(area.dest(dest)),
        policy=TESTING_POLICY,
        protected=ProtectedPaths.none(),
        **kw,
    )


@pytest.fixture
def tree_digest_fn() -> Callable[[Path], dict[str, Any]]:
    return tree_digest
