"""Ícone provisório de coruja desenhado com QPainter (sem arquivos de imagem)."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QIcon, QImage, QPainter, QPainterPath, QPen, QPixmap


def owl_image(size: int) -> QImage:
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    s = size / 64.0
    p.scale(s, s)
    p.setPen(Qt.PenStyle.NoPen)
    # orelhas
    body = QColor("#6B4F3A")
    ears = QPainterPath()
    ears.moveTo(14, 18)
    ears.lineTo(18, 4)
    ears.lineTo(26, 14)
    ears.moveTo(50, 18)
    ears.lineTo(46, 4)
    ears.lineTo(38, 14)
    p.setBrush(QBrush(body))
    p.drawPath(ears)
    # corpo
    p.drawEllipse(QRectF(8, 10, 48, 50))
    # barriga
    p.setBrush(QBrush(QColor("#C9A27E")))
    p.drawEllipse(QRectF(18, 32, 28, 26))
    # olhos
    p.setBrush(QBrush(QColor("#F4E9D8")))
    p.drawEllipse(QRectF(13, 16, 18, 18))
    p.drawEllipse(QRectF(33, 16, 18, 18))
    p.setBrush(QBrush(QColor("#1E1A17")))
    p.drawEllipse(QRectF(18, 21, 8, 8))
    p.drawEllipse(QRectF(38, 21, 8, 8))
    p.setBrush(QBrush(QColor("#FFFFFF")))
    p.drawEllipse(QRectF(21, 22, 2.5, 2.5))
    p.drawEllipse(QRectF(41, 22, 2.5, 2.5))
    # bico
    p.setBrush(QBrush(QColor("#E8A33D")))
    beak = QPainterPath()
    beak.moveTo(QPointF(29, 33))
    beak.lineTo(QPointF(35, 33))
    beak.lineTo(QPointF(32, 39))
    beak.closeSubpath()
    p.drawPath(beak)
    # contorno discreto
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.setPen(QPen(QColor(0, 0, 0, 60), 1.0))
    p.drawEllipse(QRectF(8, 10, 48, 50))
    p.end()
    return img


def owl_icon() -> QIcon:
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(QPixmap.fromImage(owl_image(size)))
    return icon
