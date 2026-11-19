"""Título das janelas como o Windows o recebe (sem o " - Owl Vault" que o Qt acrescentava).

Roda num processo à parte com a plataforma real do Windows (``QT_QPA_PLATFORM=windows``): a
plataforma ``offscreen`` dos outros testes não formata títulos. A janela nativa é criada com
``winId()`` e NUNCA é mostrada na tela.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from owl_vault import version_label
from owl_vault.ui import strings as S

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="título nativo do Windows")

SRC = Path(__file__).resolve().parents[1] / "src"

SCRIPT = textwrap.dedent(
    """
    import ctypes, json, sys
    from PySide6.QtWidgets import QApplication, QWidget
    from owl_vault.ui.app import configure_app

    app = QApplication(["owl-vault-teste"])
    configure_app(app)
    vistos = []
    for titulo in json.loads(sys.argv[1]):
        w = QWidget()
        w.setWindowTitle(titulo)
        hwnd = int(w.winId())  # cria a janela nativa sem mostrá-la
        buf = ctypes.create_unicode_buffer(512)
        ctypes.windll.user32.GetWindowTextW(hwnd, buf, 512)
        vistos.append(buf.value)
        assert not w.isVisible()
        w.deleteLater()
    print(json.dumps(vistos))
    """
)


def _titulos_nativos(titulos: list[str]) -> list[str]:
    env = {**os.environ, "QT_QPA_PLATFORM": "windows", "PYTHONPATH": str(SRC)}
    proc = subprocess.run(  # noqa: S603 - o próprio Python dos testes
        [sys.executable, "-c", SCRIPT, json.dumps(titulos)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return list(json.loads(proc.stdout.strip().splitlines()[-1]))


def test_titulos_das_janelas_sem_nome_duplicado() -> None:
    """Antes: "Owl Vault v0.3.2 · build 10 · 843d2dd - Owl Vault" na janela principal e
    "Owl Vault — Cópia criptografada - Owl Vault" (``setApplicationDisplayName``)."""
    titulos = [
        f"Owl Vault {version_label()}",  # janela principal (owl_window.py)
        S.COPIA_TITULO_JANELA,
        f"{S.APP_TITLE} — pré-verificação",
        "Sobre o Owl Vault",
        "Owl Vault",
    ]
    assert _titulos_nativos(titulos) == titulos
