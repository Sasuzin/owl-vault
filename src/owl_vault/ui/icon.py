"""Identidade visual do Owl Vault: escudo com a coruja e o cadeado (logo oficial).

O desenho vem de ``assets/owl-shield.png``, extraído da logo original
(``packaging/brand/owl-vault-logo-original.webp``) por ``packaging/brand/extract_logo.py``.
O nome "Owl Vault" é desenhado como texto ("Owl" claro + "Vault" roxo), para ficar nítido
em qualquer tamanho.
"""

from __future__ import annotations

import struct
from functools import lru_cache
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRect, QRectF, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetricsF,
    QIcon,
    QImage,
    QLinearGradient,
    QPainter,
    QPen,
    QPixmap,
)

ASSET = Path(__file__).resolve().parent / "assets" / "owl-shield.png"
SMALL_ICON_MAX = 24  # até este tamanho o ícone mostra só a cabeça da coruja

# --- paleta da marca (amostrada da logo) ------------------------------------------------
WORD_LIGHT = QColor("#f1ecff")  # "Owl"
WORD_PURPLE = QColor("#a93cff")  # "Vault"
BRAND_DARK = QColor("#0d0624")  # interior do escudo
BRAND_PURPLE = QColor("#8b2cf5")


@lru_cache(maxsize=1)
def _shield() -> QImage:
    img = QImage(str(ASSET))
    if img.isNull():  # pragma: no cover - o asset faz parte do pacote e do executável
        img = QImage(256, 268, QImage.Format.Format_ARGB32_Premultiplied)
        img.fill(Qt.GlobalColor.transparent)
        p = QPainter(img)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(BRAND_PURPLE)
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(QRectF(16, 16, 224, 236), 40, 40)
        p.end()
    return img.convertToFormat(QImage.Format.Format_ARGB32_Premultiplied)


def asset_available() -> bool:
    return not QImage(str(ASSET)).isNull()


def paint_shield(p: QPainter, target: QRectF) -> None:
    """Desenha o escudo ajustado a ``target`` (mantendo a proporção, centralizado)."""
    src = _shield()
    scale = min(target.width() / src.width(), target.height() / src.height())
    w, h = src.width() * scale, src.height() * scale
    x = target.x() + (target.width() - w) / 2
    y = target.y() + (target.height() - h) / 2
    p.save()
    p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    p.drawImage(QRectF(x, y, w, h), src)
    p.restore()


def owl_image(size: int) -> QImage:
    """Ícone quadrado com fundo transparente (escudo centralizado)."""
    img = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    img.fill(Qt.GlobalColor.transparent)
    # Redução em etapas (metade por vez) evita serrilhado nos tamanhos pequenos.
    src = _shield()
    if size <= SMALL_ICON_MAX:
        # Em 16–24 px o escudo inteiro vira um borrão: usa só a cabeça da coruja
        # (orelhas, olhos e sobrancelhas continuam reconhecíveis).
        w, h = src.width(), src.height()
        src = src.copy(
            QRect(round(0.123 * w), round(0.039 * h), round(0.757 * w), round(0.723 * h))
        )
    target_h = max(1, round(size * 0.98))
    while src.height() > target_h * 2:
        src = src.scaledToHeight(src.height() // 2, Qt.TransformationMode.SmoothTransformation)
    small = src.scaledToHeight(target_h, Qt.TransformationMode.SmoothTransformation)
    if small.width() > size:
        small = small.scaledToWidth(size, Qt.TransformationMode.SmoothTransformation)
    p = QPainter(img)
    p.drawImage(QPointF((size - small.width()) / 2, (size - small.height()) / 2), small)
    p.end()
    return img


ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)


def ico_bytes(sizes: tuple[int, ...] = ICO_SIZES) -> bytes:
    """Arquivo .ico (imagens PNG embutidas) com o escudo da coruja. Sem dependências."""
    pngs: list[tuple[int, bytes]] = []
    for size in sizes:
        data = QByteArray()
        buf = QBuffer(data)
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        owl_image(size).save(buf, "PNG")  # type: ignore[call-overload]  # o PySide aceita str em tempo de execução
        buf.close()
        pngs.append((size, bytes(data.data())))
    header = struct.pack("<HHH", 0, 1, len(pngs))
    offset = 6 + 16 * len(pngs)
    entries = b""
    blobs = b""
    for size, png in pngs:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        blobs += png
        offset += len(png)
    return header + entries + blobs


def owl_icon() -> QIcon:
    icon = QIcon()
    for size in (16, 20, 24, 32, 40, 48, 64, 128, 256):
        icon.addPixmap(QPixmap.fromImage(owl_image(size)))
    return icon


def wordmark_font(pixel_size: float) -> QFont:
    font = QFont("Segoe UI")
    font.setPixelSize(max(1, round(pixel_size)))
    font.setWeight(QFont.Weight.Bold)
    return font


def paint_wordmark(
    p: QPainter, origin: QPointF, pixel_size: float, light: QColor = WORD_LIGHT
) -> float:
    """Escreve "Owl" (claro) + "Vault" (roxo) a partir de ``origin`` (linha de base).
    Retorna a largura total."""
    font = wordmark_font(pixel_size)
    fm = QFontMetricsF(font)
    p.setFont(font)
    p.setPen(light)
    p.drawText(origin, "Owl")
    x = origin.x() + fm.horizontalAdvance("Owl ")
    p.setPen(WORD_PURPLE)
    p.drawText(QPointF(x, origin.y()), "Vault")
    return fm.horizontalAdvance("Owl Vault")


def logo_image(width: int) -> QImage:
    """Logo completo (escudo + nome) sobre um cartão escuro arredondado."""
    height = round(width * 1.18)
    img = QImage(width, height, QImage.Format.Format_ARGB32_Premultiplied)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setRenderHint(QPainter.RenderHint.TextAntialiasing)
    card = QRectF(0.5, 0.5, width - 1, height - 1)
    grad = QLinearGradient(card.topLeft(), card.bottomLeft())
    grad.setColorAt(0.0, QColor("#150b30"))
    grad.setColorAt(1.0, QColor("#07040f"))
    p.setPen(QPen(QColor(169, 60, 255, 90), 1.0))
    p.setBrush(QBrush(grad))
    p.drawRoundedRect(card, width * 0.12, width * 0.12)
    paint_shield(p, QRectF(width * 0.12, height * 0.06, width * 0.76, height * 0.70))
    px = width * 0.15
    total = QFontMetricsF(wordmark_font(px)).horizontalAdvance("Owl Vault")
    paint_wordmark(p, QPointF((width - total) / 2, height * 0.92), px)
    p.end()
    return img
