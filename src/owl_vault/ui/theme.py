"""Tema claro/escuro (Fusion + QPalette). Preferência salva em QSettings (sem caminhos)."""

from __future__ import annotations

from PySide6.QtCore import QSettings
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

_KEY = "ui/theme"


def settings() -> QSettings:
    return QSettings("Owl Vault", "Owl Vault")


def saved_theme() -> str:
    value = settings().value(_KEY, "light")
    return value if value in ("light", "dark") else "light"


def save_theme(theme: str) -> None:
    settings().setValue(_KEY, theme)


def apply_theme(app: QApplication, theme: str) -> None:
    app.setStyle("Fusion")
    if theme != "dark":
        app.setPalette(app.style().standardPalette())
        app.setStyleSheet(_BASE_QSS + _LIGHT_QSS)
        return
    pal = QPalette()
    dark = QColor(32, 33, 36)
    mid = QColor(45, 47, 51)
    text = QColor(232, 234, 237)
    accent = QColor(201, 162, 126)
    pal.setColor(QPalette.ColorRole.Window, dark)
    pal.setColor(QPalette.ColorRole.WindowText, text)
    pal.setColor(QPalette.ColorRole.Base, QColor(24, 25, 27))
    pal.setColor(QPalette.ColorRole.AlternateBase, mid)
    pal.setColor(QPalette.ColorRole.ToolTipBase, mid)
    pal.setColor(QPalette.ColorRole.ToolTipText, text)
    pal.setColor(QPalette.ColorRole.Text, text)
    pal.setColor(QPalette.ColorRole.Button, mid)
    pal.setColor(QPalette.ColorRole.ButtonText, text)
    pal.setColor(QPalette.ColorRole.Highlight, accent)
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(20, 20, 20))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(150, 150, 150))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(120, 120, 120))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(120, 120, 120))
    app.setPalette(pal)
    app.setStyleSheet(_BASE_QSS + _DARK_QSS)


_BASE_QSS = """
QLabel#banner { padding: 10px; border-radius: 6px; font-weight: 600; }
QPushButton#primary { padding: 6px 14px; font-weight: 600; }
"""
_LIGHT_QSS = """
QLabel#banner { background: #FFF4D6; color: #5A4300; border: 1px solid #E8C96A; }
QLabel#hint { color: #4A4F55; }
"""
_DARK_QSS = """
QLabel#banner { background: #3A3220; color: #F2DFA8; border: 1px solid #6B5A2A; }
QLabel#hint { color: #A0A4AA; }
"""
