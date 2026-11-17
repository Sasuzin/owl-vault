"""Componentes compartilhados da interface: cabeçalho, campos, seletor de pasta, progresso."""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Sequence

from PySide6.QtCore import QSettings, Qt, Slot
from PySide6.QtGui import QCloseEvent, QGuiApplication, QImage, QKeyEvent, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from owl_vault.storage import winfs
from owl_vault.ui.icon import WORD_PURPLE, owl_image
from owl_vault.ui.workers import JobRunner


def clear_qt_dialog_history() -> None:
    """Melhor esforço: o Qt guarda a última pasta usada no registro (THREAT_MODEL §4)."""
    s = QSettings(QSettings.Scope.UserScope, "QtProject")
    s.beginGroup("FileDialog")
    for key in ("lastVisited", "history"):
        s.remove(key)
    s.endGroup()
    s.sync()


def choose_folder(parent: QWidget, title: str, start: str = "") -> str | None:
    path = QFileDialog.getExistingDirectory(parent, title, start)
    clear_qt_dialog_history()
    return os.path.normpath(path) if path else None


def open_in_explorer(path: str) -> None:
    try:
        os.startfile(winfs.strip_extended(path))  # noqa: S606
    except OSError:
        pass


def hidpi(render: Callable[[int], QImage], logical: int) -> QPixmap:
    """Gera a imagem na densidade real da tela (nítida em escala de 125%/150%)."""
    screen = QGuiApplication.primaryScreen()
    dpr = screen.devicePixelRatio() if screen is not None else 1.0
    pixmap = QPixmap.fromImage(render(max(1, round(logical * dpr))))
    pixmap.setDevicePixelRatio(dpr)
    return pixmap


def brand_header(subtitle: str = "Pastas protegidas") -> QWidget:
    """Coruja + "Owl Vault" (Vault em roxo), como no logo."""
    header = QWidget()
    header.setObjectName("header")
    lay = QHBoxLayout(header)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(12)
    owl = QLabel()
    owl.setPixmap(hidpi(lambda px: owl_image(px), 48))
    owl.setFixedSize(48, 48)
    lay.addWidget(owl)
    texts = QVBoxLayout()
    texts.setSpacing(0)
    title = QLabel(f'Owl <span style="color:{WORD_PURPLE.name()}">Vault</span>')
    title.setObjectName("brandTitle")
    title.setTextFormat(Qt.TextFormat.RichText)
    sub = QLabel(subtitle)
    sub.setObjectName("brandSubtitle")
    texts.addWidget(title)
    texts.addWidget(sub)
    lay.addLayout(texts)
    lay.addStretch(1)
    return header


def wipe(edit: QLineEdit) -> None:
    """``setText("")`` também descarta o histórico de desfazer (``clear()`` o manteria)."""
    edit.setText("")


def secret_edit(placeholder: str, *, digits: bool = False) -> QLineEdit:
    e = QLineEdit()
    e.setEchoMode(QLineEdit.EchoMode.Password)
    e.setPlaceholderText(placeholder)
    e.setAccessibleName(placeholder)
    if digits:
        e.setMaxLength(12)
        e.setInputMethodHints(Qt.InputMethodHint.ImhDigitsOnly)
    return e


def hint(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("hint")
    lbl.setWordWrap(True)
    return lbl


def title_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("pageTitle")
    lbl.setWordWrap(True)
    return lbl


def body(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lbl


def link_button(text: str) -> QPushButton:
    b = QPushButton(text)
    b.setObjectName("link")
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    b.setFlat(True)
    return b


def primary_button(text: str) -> QPushButton:
    b = QPushButton(text)
    b.setObjectName("primary")
    b.setDefault(True)
    return b


def error_label() -> QLabel:
    lbl = QLabel("")
    lbl.setObjectName("error")
    lbl.setWordWrap(True)
    lbl.hide()
    return lbl


def show_error(lbl: QLabel, text: str) -> None:
    lbl.setText(text)
    lbl.setVisible(bool(text))


def fmt_size(n: int) -> str:
    units = ["bytes", "KB", "MB", "GB", "TB"]
    value = float(n)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "bytes":
                return f"{int(value)} bytes"
            return f"{value:.1f} {unit}".replace(".", ",")
        value /= 1024
    return f"{n} bytes"


def fmt_int(n: int) -> str:
    return f"{n:,}".replace(",", ".")


def fmt_duration(seconds: float) -> str:
    if seconds < 90:
        return "menos de 2 minutos"
    minutes = round(seconds / 60)
    if minutes < 60:
        return f"cerca de {minutes} minutos"
    hours = minutes / 60
    if hours < 1.5:
        return "cerca de 1 hora"
    return f"cerca de {round(hours)} horas"


def short_list(items: Sequence[str], limit: int = 5) -> str:
    shown = ", ".join(items[:limit])
    if len(items) > limit:
        shown += f" e mais {len(items) - limit}"
    return shown


def list_box(items: Sequence[str], height: int = 110) -> QPlainTextEdit:
    text = QPlainTextEdit()
    text.setReadOnly(True)
    text.setPlainText("\n".join(f"• {i}" for i in items))
    text.setMinimumHeight(min(height, 26 + 20 * len(items)))
    text.setMaximumHeight(height + 60)
    return text


# --- progresso (T6) ---------------------------------------------------------------------

#: etapa do motor → texto da tela de progresso (UI_SPEC_V2 T6)
_LOCK_STAGES = [
    ("Pré-verificação", "Conferindo a pasta"),
    ("Conferindo a pasta", "Conferindo a pasta"),
    ("Calibrando", "Preparando a proteção"),
    ("Derivando", "Preparando a proteção"),
    ("Criptografando", "1/4 Guardando os arquivos"),
    ("Verificando", "2/4 Conferindo"),
    ("Teste de restauração", "3/4 Testando a recuperação"),
    ("Comparando", "3/4 Testando a recuperação"),
    ("Finalizando", "3/4 Testando a recuperação"),
    ("Apagando", "4/4 Apagando as cópias legíveis"),
]
_UNLOCK_STAGES = [
    ("Abrindo o cofre", "Preparando"),
    ("Conferindo o cofre", "Conferindo os dados protegidos"),
    ("Restaurando", "Abrindo"),
]
_GENERIC_STAGES = [
    ("Pré-verificação", "Conferindo a pasta"),
    ("Abrindo o cofre", "Preparando"),
    ("Verificando blocos", "Conferindo os arquivos"),
    ("Conferindo o cofre", "Conferindo os dados protegidos"),
    ("Restaurando", "Recuperando os arquivos"),
    ("Criptografando", "Guardando os arquivos"),
    ("Teste de restauração", "Testando a recuperação"),
]


def _map_stage(mode: str, name: str) -> str:
    table = {"lock": _LOCK_STAGES, "unlock": _UNLOCK_STAGES}.get(mode, _GENERIC_STAGES)
    for prefix, text in table:
        if name.startswith(prefix):
            return text
    return name


class ProgressDialog(QDialog):
    """Tela de progresso modal. Fecha sozinha quando o trabalho termina (``finish``)."""

    def __init__(
        self,
        parent: QWidget,
        title: str,
        runner: JobRunner,
        *,
        mode: str = "generic",
        note: str = "",
        cancellable: bool = True,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Owl Vault")
        self.setModal(True)
        self.setMinimumWidth(480)
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, False)
        self._runner = runner
        self._mode = mode
        self._finished = False
        self._totals = (0, 0)
        self._done = [0, 0]
        self._t0 = time.monotonic()
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(title_label(title))
        self.stage = QLabel("Preparando…")
        self.stage.setWordWrap(True)
        lay.addWidget(self.stage)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setRange(0, 0)
        lay.addWidget(self.bar)
        self.eta = hint("")
        lay.addWidget(self.eta)
        if note:
            lay.addWidget(hint(note))
        row = QHBoxLayout()
        row.addStretch(1)
        self.cancel_button = QPushButton("Cancelar")
        self.cancel_button.clicked.connect(self._cancel)
        self.cancel_button.setVisible(cancellable)
        row.addWidget(self.cancel_button)
        lay.addLayout(row)
        b = runner.bridge
        b.stage.connect(self._on_stage)
        b.advance.connect(self._on_advance)

    @Slot(str, object, object)
    def _on_stage(self, name: str, total_bytes: object, total_items: object) -> None:
        self._stage_text = _map_stage(self._mode, name)
        self.stage.setText(self._stage_text)
        tb = int(total_bytes) if isinstance(total_bytes, int) else 0
        ti = int(total_items) if isinstance(total_items, int) else 0
        self._totals = (tb, ti)
        self._done = [0, 0]
        self._t0 = time.monotonic()
        self.eta.setText("")
        if tb or ti:
            self.bar.setRange(0, 1000)
            self.bar.setValue(0)
        else:
            self.bar.setRange(0, 0)
        if self._mode == "lock" and name.startswith("Apagando"):
            self.cancel_button.setText("Parar depois do arquivo atual")
        if self._mode == "lock" and self._stage_text.startswith("1/4"):
            self.stage.setText(f"{self._stage_text} (0 de {fmt_int(ti)})")

    @Slot(object, object)
    def _on_advance(self, nbytes: object, nitems: object) -> None:
        self._done[0] += int(nbytes) if isinstance(nbytes, int) else 0
        self._done[1] += int(nitems) if isinstance(nitems, int) else 0
        tb, ti = self._totals
        frac = self._done[0] / tb if tb else (self._done[1] / ti if ti else 0.0)
        self.bar.setValue(min(1000, int(frac * 1000)))
        if ti:
            self.stage.setText(
                f"{self._stage_text} ({fmt_int(min(self._done[1], ti))} de {fmt_int(ti)})"
            )
        elapsed = time.monotonic() - self._t0
        if frac > 0.03 and elapsed > 3:
            remaining = elapsed * (1 - frac) / frac
            self.eta.setText(f"Tempo restante: {fmt_duration(remaining)}")

    def _cancel(self) -> None:
        self._runner.cancel()
        self.cancel_button.setEnabled(False)
        self.stage.setText("Parando num ponto seguro…")

    def finish(self) -> None:
        self._finished = True
        b = self._runner.bridge
        for sig, slot in ((b.stage, self._on_stage), (b.advance, self._on_advance)):
            try:
                sig.disconnect(slot)
            except (RuntimeError, TypeError):
                pass
        self.accept()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._finished:
            event.accept()
        else:
            event.ignore()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Escape and not self._finished:
            if self.cancel_button.isVisible() and self.cancel_button.isEnabled():
                self._cancel()
            return
        super().keyPressEvent(event)
