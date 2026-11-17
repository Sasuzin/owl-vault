"""Gera ``packaging/owl.ico`` (ícone provisório) a partir do desenho em ``owl_vault.ui.icon``.

ICO com imagens PNG embutidas (16–256 px). Não depende de Pillow.
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from PySide6.QtCore import QBuffer, QByteArray, QIODevice  # noqa: E402
from PySide6.QtGui import QGuiApplication  # noqa: E402

from owl_vault.ui.icon import owl_image  # noqa: E402

SIZES = (16, 24, 32, 48, 64, 128, 256)


def png_bytes(size: int) -> bytes:
    data = QByteArray()
    buf = QBuffer(data)
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    owl_image(size).save(buf, "PNG")
    buf.close()
    return bytes(data.data())


def main() -> None:
    _app = QGuiApplication(sys.argv)
    images = [(s, png_bytes(s)) for s in SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    blobs = b""
    for size, png in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        blobs += png
        offset += len(png)
    out = HERE / "owl.ico"
    out.write_bytes(header + entries + blobs)
    print(f"ícone gerado: {out}")


if __name__ == "__main__":
    main()
