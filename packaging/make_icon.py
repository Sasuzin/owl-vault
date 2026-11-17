"""Gera ``packaging/owl.ico`` (ícone do executável) a partir da logo em ``owl_vault.ui.icon``.

ICO com imagens PNG embutidas (16–256 px). Não depende de Pillow.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from PySide6.QtGui import QGuiApplication  # noqa: E402

from owl_vault.ui.icon import ico_bytes  # noqa: E402


def main() -> None:
    _app = QGuiApplication(sys.argv)
    out = HERE / "owl.ico"
    out.write_bytes(ico_bytes())
    print(f"ícone gerado: {out}")


if __name__ == "__main__":
    main()
