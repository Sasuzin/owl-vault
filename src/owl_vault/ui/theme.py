"""Tema roxo do Owl Vault (Fusion + QPalette + QSS).

Dois modos, ambos com a identidade roxa da logo:
* ``dark`` (padrão): fundo índigo quase preto, superfícies roxo-escuras, acento violeta;
* ``light``: lavanda clara com acento violeta.

Contraste conferido pelas regras WCAG 2.1 (texto ≥ 4,5:1; contornos, foco e indicadores
≥ 3:1). A preferência fica em QSettings (nenhum caminho é salvo).
"""

from __future__ import annotations

from dataclasses import dataclass

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

_KEY = "ui/theme"
DEFAULT_THEME = "dark"


@dataclass(frozen=True, slots=True)
class Palette:
    window: str
    surface: str  # campos, listas
    surface_alt: str  # cartões, abas
    button: str
    button_hover: str
    border: str  # divisórias decorativas
    border_strong: str
    control_border: str  # contorno de controles (campos, caixas): ≥ 3:1
    text: str
    muted: str
    accent: str  # violeta principal
    accent_hover: str
    accent_pressed: str
    accent_text: str  # texto sobre o acento
    selection: str
    selection_text: str
    banner_bg: str
    banner_text: str
    banner_edge: str  # destaque âmbar: o aviso continua chamando a atenção
    disabled: str


# Cores derivadas da logo: interior do escudo índigo quase preto (#0d0624), coruja roxa
# (#34037c → #7d0de2) e o "Vault" violeta vivo (#a93cff).
DARK = Palette(
    window="#0e0a1a",
    surface="#150f27",
    surface_alt="#1a1231",
    button="#251943",
    button_hover="#302055",
    border="#33255a",
    border_strong="#4e3489",
    control_border="#7d68c9",
    text="#efeafb",
    muted="#b2a5d4",
    accent="#8326e8",
    accent_hover="#9440f5",
    accent_pressed="#6d17cc",
    accent_text="#ffffff",
    selection="#6a24c4",
    selection_text="#ffffff",
    banner_bg="#1f1340",
    banner_text="#f2e9ff",
    banner_edge="#f2b84b",
    disabled="#7c70a0",
)

LIGHT = Palette(
    window="#f7f2ff",
    surface="#ffffff",
    surface_alt="#f1e8ff",
    button="#ece0ff",
    button_hover="#e0cdff",
    border="#dbc9fa",
    border_strong="#c0a1f2",
    control_border="#7f63cf",
    text="#1e1438",
    muted="#55467a",
    accent="#7a1fdc",
    accent_hover="#8a2cf0",
    accent_pressed="#6516bd",
    accent_text="#ffffff",
    selection="#d6bcff",
    selection_text="#1e1438",
    banner_bg="#efe3ff",
    banner_text="#2e1366",
    banner_edge="#b87900",
    disabled="#776b9d",
)


def settings() -> QSettings:
    return QSettings("Owl Vault", "Owl Vault")


def saved_theme() -> str:
    value = settings().value(_KEY, DEFAULT_THEME)
    return value if value in ("light", "dark") else DEFAULT_THEME


def save_theme(theme: str) -> None:
    settings().setValue(_KEY, theme)


def palette_for(theme: str) -> Palette:
    return LIGHT if theme == "light" else DARK


class OwlStyle(QProxyStyle):
    """Fusion com a caixa de seleção redesenhada: contorno visível e ✓ sobre o roxo.

    (A caixa padrão do Fusion some no tema escuro, e estilizá-la por QSS remove o ✓.)
    """

    def __init__(self, palette: Palette) -> None:
        super().__init__(QStyleFactory.create("Fusion"))
        self._c = palette

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
        c = self._c
        state = option.state
        on = bool(state & QStyle.StateFlag.State_On)
        enabled = bool(state & QStyle.StateFlag.State_Enabled)
        hover = bool(state & QStyle.StateFlag.State_MouseOver)
        focus = bool(state & QStyle.StateFlag.State_HasFocus)
        rect = QRectF(option.rect).adjusted(1.0, 1.0, -1.0, -1.0)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        if not enabled:
            fill, edge = QColor(c.surface_alt), QColor(c.disabled)
        elif on:
            fill, edge = QColor(c.accent), QColor(c.accent)
        else:
            fill = QColor(c.surface)
            edge = QColor(c.accent if (hover or focus) else c.control_border)
        painter.setPen(QPen(edge, 2.0 if focus else 1.2))
        painter.setBrush(fill)
        painter.drawRoundedRect(rect, 3.5, 3.5)
        if on:
            mark = QPainterPath()
            w, h = rect.width(), rect.height()
            mark.moveTo(QPointF(rect.x() + w * 0.22, rect.y() + h * 0.52))
            mark.lineTo(QPointF(rect.x() + w * 0.43, rect.y() + h * 0.72))
            mark.lineTo(QPointF(rect.x() + w * 0.78, rect.y() + h * 0.30))
            pen = QPen(QColor(c.accent_text if enabled else c.disabled), max(1.6, w * 0.14))
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(mark)
        painter.restore()


def apply_theme(app: QApplication, theme: str) -> None:
    pal_def = palette_for(theme)
    app.setStyle(OwlStyle(pal_def))
    app.setPalette(_qpalette(pal_def))
    app.setStyleSheet(stylesheet(pal_def))
    # barra de título e controles nativos do Windows acompanham o tema (Qt ≥ 6.8)
    try:
        app.styleHints().setColorScheme(
            Qt.ColorScheme.Dark if theme == "dark" else Qt.ColorScheme.Light
        )
    except AttributeError:  # pragma: no cover - Qt antigo
        pass


def _qpalette(c: Palette) -> QPalette:
    pal = QPalette()
    role = QPalette.ColorRole
    pal.setColor(role.Window, QColor(c.window))
    pal.setColor(role.WindowText, QColor(c.text))
    pal.setColor(role.Base, QColor(c.surface))
    pal.setColor(role.AlternateBase, QColor(c.surface_alt))
    pal.setColor(role.ToolTipBase, QColor(c.surface_alt))
    pal.setColor(role.ToolTipText, QColor(c.text))
    pal.setColor(role.Text, QColor(c.text))
    pal.setColor(role.Button, QColor(c.button))
    pal.setColor(role.ButtonText, QColor(c.text))
    pal.setColor(role.BrightText, QColor(c.accent_text))
    pal.setColor(role.Highlight, QColor(c.accent))
    pal.setColor(role.HighlightedText, QColor(c.accent_text))
    pal.setColor(role.Accent, QColor(c.accent))
    pal.setColor(role.Link, QColor(c.accent_hover))
    pal.setColor(role.PlaceholderText, QColor(c.muted))
    pal.setColor(role.Mid, QColor(c.border))
    pal.setColor(role.Dark, QColor(c.border_strong))
    for r in (role.Text, role.ButtonText, role.WindowText):
        pal.setColor(QPalette.ColorGroup.Disabled, r, QColor(c.disabled))
    return pal


def stylesheet(c: Palette) -> str:
    return f"""
QMainWindow, QDialog {{ background: {c.window}; }}
QWidget {{ font-size: 10pt; }}
QLabel#banner {{
    background: {c.banner_bg}; color: {c.banner_text};
    border: 1px solid {c.border_strong}; border-left: 4px solid {c.banner_edge};
    border-radius: 8px; padding: 10px 12px; font-weight: 600;
}}
QLabel#hint {{ color: {c.muted}; }}
QLabel#pageTitle {{ font-size: 14pt; font-weight: 700; }}
QLabel#error {{ color: {c.banner_edge}; font-weight: 600; }}
QLabel#rowName {{ font-size: 11pt; font-weight: 700; }}
QLabel#rowPath {{ color: {c.muted}; }}
QLabel#stateLocked {{ color: {c.accent_hover}; font-weight: 600; }}
QLabel#stateOpen {{ color: {c.banner_edge}; font-weight: 600; }}
QLabel#stateAttention {{ color: {c.banner_edge}; font-weight: 700; }}
QFrame#card {{
    background: {c.surface_alt}; border: 1px solid {c.border}; border-radius: 10px;
}}
QFrame#card:hover {{ border-color: {c.border_strong}; }}
QFrame#openBanner {{
    background: {c.banner_bg}; border: 1px solid {c.border_strong};
    border-left: 4px solid {c.banner_edge}; border-radius: 8px;
}}
QFrame#openBanner QLabel {{ color: {c.banner_text}; font-weight: 600; }}
QPushButton#link {{
    background: transparent; border: none; color: {c.accent_hover}; padding: 2px 0;
    text-decoration: underline; text-align: left;
}}
QPushButton#link:hover {{ color: {c.text}; }}
QPushButton#link:focus {{ border: none; padding: 2px 0; color: {c.text}; }}
QToolButton#more {{
    background: {c.button}; color: {c.text}; border: 1px solid {c.border_strong};
    border-radius: 8px; padding: 4px 10px; font-size: 12pt;
}}
QToolButton#more:hover {{ background: {c.button_hover}; }}
QToolButton#more::menu-indicator {{ image: none; width: 0; }}
QScrollArea {{ background: transparent; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QListWidget {{
    background: {c.surface}; color: {c.text}; border: 1px solid {c.control_border};
    border-radius: 6px;
}}
QLabel#brandTitle {{ font-size: 16pt; font-weight: 700; }}
QLabel#brandSubtitle {{ color: {c.muted}; }}
QWidget#header {{ background: transparent; }}

QPushButton {{
    background: {c.button}; color: {c.text};
    border: 1px solid {c.border_strong}; border-radius: 8px; padding: 6px 14px;
}}
QPushButton:hover {{ background: {c.button_hover}; }}
QPushButton:pressed {{ background: {c.border_strong}; }}
QPushButton:disabled {{ color: {c.disabled}; border-color: {c.border}; background: {c.surface_alt}; }}
QPushButton#primary {{
    background: {c.accent}; color: {c.accent_text}; border: 1px solid {c.accent};
    font-weight: 700; padding: 7px 16px;
}}
QPushButton#primary:hover {{ background: {c.accent_hover}; border-color: {c.accent_hover}; }}
QPushButton#primary:pressed {{ background: {c.accent_pressed}; }}
QPushButton#primary:disabled {{ background: {c.surface_alt}; color: {c.disabled}; border-color: {c.border}; }}
QPushButton:focus {{ border: 2px solid {c.accent}; padding: 5px 13px; }}
QPushButton#primary:focus {{ border: 2px solid {c.text}; padding: 6px 15px; }}

QLineEdit, QPlainTextEdit {{
    background: {c.surface}; color: {c.text};
    border: 1px solid {c.control_border}; border-radius: 6px; padding: 5px 8px;
    selection-background-color: {c.selection}; selection-color: {c.selection_text};
    placeholder-text-color: {c.muted};
}}
QLineEdit:focus, QPlainTextEdit:focus {{ border: 2px solid {c.accent}; padding: 4px 7px; }}
QLineEdit:disabled, QPlainTextEdit:disabled {{ color: {c.disabled}; border-color: {c.border}; }}

QTabWidget::pane {{
    background: {c.surface_alt}; border: 1px solid {c.border}; border-radius: 10px;
    top: -1px; padding: 6px;
}}
QTabBar::tab {{
    background: transparent; color: {c.muted}; padding: 8px 16px; margin-right: 4px;
    border: none; border-bottom: 3px solid transparent; font-weight: 600;
}}
QTabBar::tab:selected {{ color: {c.text}; border-bottom: 3px solid {c.accent}; }}
QTabBar::tab:hover:!selected {{ color: {c.text}; border-bottom: 3px solid {c.border_strong}; }}

QProgressBar {{
    background: {c.surface}; border: 1px solid {c.control_border}; border-radius: 7px;
    min-height: 14px; max-height: 14px;
}}
QProgressBar::chunk {{
    border-radius: 6px;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {c.accent_pressed}, stop:1 {c.accent_hover});
}}

QGroupBox {{
    border: 1px solid {c.border}; border-radius: 8px; margin-top: 14px; padding-top: 8px;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; color: {c.muted}; }}
QCheckBox {{ spacing: 8px; }}

QMenuBar {{ background: {c.window}; color: {c.text}; }}
QMenuBar::item:selected {{ background: {c.button_hover}; border-radius: 4px; }}
QMenu {{ background: {c.surface_alt}; color: {c.text}; border: 1px solid {c.border}; padding: 4px; }}
QMenu::item {{ padding: 6px 18px; border-radius: 4px; }}
QMenu::item:selected {{ background: {c.accent}; color: {c.accent_text}; }}
QMenu::item:disabled {{ color: {c.disabled}; background: transparent; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {c.control_border}; border-radius: 4px; min-height: 24px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {c.control_border}; border-radius: 4px; min-width: 24px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QToolTip {{ background: {c.surface_alt}; color: {c.text}; border: 1px solid {c.border_strong}; }}
QWidget:disabled {{ color: {c.disabled}; }}
"""
