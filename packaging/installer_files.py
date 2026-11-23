"""Grava ``dist/instalador/`` (marcas que o instalador põe ao lado do exe) e imprime a versão.

Uso (packaging/build.ps1, depois do PyInstaller): ``python packaging/installer_files.py``.
A saída é a versão de quatro partes do exe (``0.5.0.16``), passada ao ISCC como AppVersion.
As marcas descrevem exatamente ``dist/OwlVault.exe`` (install.installer_files).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from owl_vault.application import install  # noqa: E402


def main() -> int:
    exe = ROOT / "dist" / install.EXE_NAME
    out = ROOT / "dist" / "instalador"
    out.mkdir(parents=True, exist_ok=True)
    for name, data in install.installer_files(exe).items():
        (out / name).write_bytes(data)
    print(".".join(str(x) for x in install.current_version()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
