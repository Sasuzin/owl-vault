"""Aplica o tema "Cofre" (Claude Design, Estilo 5) ao aplicativo.

As cores, raios e espaçamentos vivem SÓ em ``ui/tema/theme_cofre.py`` (tokens) e a folha de
estilo em ``ui/tema/owlvault.qss``. Este módulo junta as três coisas que o QSS não resolve:

* a ``QPalette`` (diálogos nativos, cursores de texto, itens sem QSS) — dos mesmos tokens;
* a caixa de seleção desenhada em Python (``OwlStyle``): estilizar ``QCheckBox::indicator``
  por QSS faz o Qt esconder o ✓;
* o esquema claro/escuro da barra de título do Windows.

A preferência de tema fica em QSettings (nenhum caminho é salvo). Escuro ("Cofre") é o padrão.
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, QSettings, Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPalette, QPen
from PySide6.QtWidgets import (
    QApplication,
    QProxyStyle,
    QStyle,
    QStyleFactory,
    QStyleOption,
    QWidget,
)

from owl_vault.ui.tema.theme_cofre import montar_qss, tokens

_KEY = "ui/theme"
DEFAULT_THEME = "dark"


def settings() -> QSettings:
    return QSettings("Owl Vault", "Owl Vault")


def saved_theme() -> str:
    value = settings().value(_KEY, DEFAULT_THEME)
    return value if value in ("dark", "light") else DEFAULT_THEME


def save_theme(theme: str) -> None:
    settings().setValue(_KEY, theme)


def current_tokens() -> dict[str, str]:
    app = QApplication.instance()
    theme = app.property("owlTheme") if app is not None else None
    return tokens(theme if isinstance(theme, str) else DEFAULT_THEME)


class OwlStyle(QProxyStyle):
    """Fusion com a caixa de seleção redesenhada com os tokens do tema."""

    def __init__(self, t: dict[str, str]) -> None:
        super().__init__(QStyleFactory.create("Fusion"))
        self._t = t

    def drawPrimitive(
        self,
        element: QStyle.PrimitiveElement,
        option: QStyleOption,
        painter: QPainter,
        widget: QWidget | None = None,
    ) -> None:
        if element != QStyle.PrimitiveElement.PE_IndicatorCheckBox:
            super().drawPrimitive(element, option, painter, widget)
            return
        t = self._t
        state = option.state
        on = bool(state & QStyle.StateFlag.State_On)
        enabled = bool(state & QStyle.StateFlag.State_Enabled)
        hover = bool(state & QStyle.StateFlag.State_MouseOver)
        focus = bool(state & QStyle.StateFlag.State_HasFocus)
        rect = QRectF(option.rect).adjusted(1.0, 1.0, -1.0, -1.0)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        if not enabled:
            fill, edge = QColor(t["panel-alt"]), QColor(t["border"])
        elif on:
            fill, edge = QColor(t["accent"]), QColor(t["focus"] if focus else t["accent"])
        else:
            fill = QColor(t["field"])
            edge = QColor(t["focus"] if (hover or focus) else t["border-strong"])
        painter.setPen(QPen(edge, 2.0 if focus else 1.2))
        painter.setBrush(fill)
        painter.drawRoundedRect(rect, 4.0, 4.0)
        if on:
            mark = QPainterPath()
            w, h = rect.width(), rect.height()
            mark.moveTo(QPointF(rect.x() + w * 0.22, rect.y() + h * 0.52))
            mark.lineTo(QPointF(rect.x() + w * 0.43, rect.y() + h * 0.72))
            mark.lineTo(QPointF(rect.x() + w * 0.78, rect.y() + h * 0.30))
            pen = QPen(QColor(t["accent-ink"] if enabled else t["ink-muted"]), max(1.6, w * 0.14))
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(mark)
        painter.restore()

    def pixelMetric(
        self,
        metric: QStyle.PixelMetric,
        option: QStyleOption | None = None,
        widget: QWidget | None = None,
    ) -> int:
        if metric in (
            QStyle.PixelMetric.PM_IndicatorWidth,
            QStyle.PixelMetric.PM_IndicatorHeight,
        ):
            return 18
        return super().pixelMetric(metric, option, widget)


def apply_theme(app: QApplication, theme: str) -> None:
    theme = theme if theme in ("dark", "light") else DEFAULT_THEME
    t = tokens(theme)
    app.setProperty("owlTheme", theme)
    app.setStyle(OwlStyle(t))
    app.setPalette(_qpalette(t))
    app.setStyleSheet(montar_qss(tema=theme))
    # barra de título e controles nativos do Windows acompanham o tema (Qt ≥ 6.8)
    try:
        app.styleHints().setColorScheme(
            Qt.ColorScheme.Dark if theme == "dark" else Qt.ColorScheme.Light
        )
    except AttributeError:  # pragma: no cover - Qt antigo
        pass


def _qpalette(t: dict[str, str]) -> QPalette:
    pal = QPalette()
    role = QPalette.ColorRole
    c = QColor
    pal.setColor(role.Window, c(t["app-bg"]))
    pal.setColor(role.WindowText, c(t["ink"]))
    pal.setColor(role.Base, c(t["field"]))
    pal.setColor(role.AlternateBase, c(t["panel-alt"]))
    pal.setColor(role.ToolTipBase, c(t["panel-alt"]))
    pal.setColor(role.ToolTipText, c(t["ink"]))
    pal.setColor(role.Text, c(t["ink"]))
    pal.setColor(role.Button, c(t["panel"]))
    pal.setColor(role.ButtonText, c(t["ink"]))
    pal.setColor(role.BrightText, c(t["accent-text"]))
    pal.setColor(role.Highlight, c(t["accent"]))
    pal.setColor(role.HighlightedText, c(t["accent-ink"]))
    pal.setColor(role.Accent, c(t["accent"]))
    pal.setColor(role.Link, c(t["accent-text"]))
    pal.setColor(role.PlaceholderText, c(t["ink-muted"]))
    pal.setColor(role.Mid, c(t["border"]))
    pal.setColor(role.Dark, c(t["border-strong"]))
    for r in (role.Text, role.ButtonText, role.WindowText):
        pal.setColor(QPalette.ColorGroup.Disabled, r, c(t["ink-muted"]))
    return pal
