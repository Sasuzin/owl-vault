"""Peças compartilhadas da interface: seletor de pasta, formatação, campos e tela de progresso.

Os helpers antigos (``title_label``, ``body``, ``hint``, ``link_button``, ``primary_button``,
``error_label``, ``brand_header``) continuam aqui para quem ainda os usa, mas produzem os
``objectName`` do tema "Cofre" (``titulo``, ``subtitulo``, ``nota``, ``discreto``, ``primario``,
``erro``, ``marca``/``marcaRoxo``) — as cores vêm só do QSS (``ui/tema/owlvault.qss``).
"""

from __future__ import annotations

import html
import os
import time
from collections.abc import Callable, Sequence

from PySide6.QtCore import QEvent, QSettings, QSize, Qt, SignalInstance, Slot
from PySide6.QtGui import (
    QCloseEvent,
    QColor,
    QGuiApplication,
    QImage,
    QKeyEvent,
    QPixmap,
    QShowEvent,
    QTextCharFormat,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from owl_vault.storage import winfs
from owl_vault.ui.icon import owl_image
from owl_vault.ui.theme import current_tokens
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
    """Coruja + "Owl Vault" (Vault em roxo, pelo QSS ``#marcaRoxo``) + subtítulo em nota."""
    header = QWidget()
    header.setObjectName("transparente")
    lay = QHBoxLayout(header)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(12)
    owl = QLabel()
    owl.setPixmap(hidpi(lambda px: owl_image(px), 48))
    owl.setFixedSize(48, 48)
    owl.setAccessibleName("Owl Vault")
    lay.addWidget(owl)
    texts = QVBoxLayout()
    texts.setSpacing(0)
    nome = QHBoxLayout()
    nome.setSpacing(5)
    owl_txt = QLabel("Owl")
    owl_txt.setObjectName("marca")
    vault_txt = QLabel("Vault")
    vault_txt.setObjectName("marcaRoxo")
    nome.addWidget(owl_txt)
    nome.addWidget(vault_txt)
    nome.addStretch(1)
    sub = QLabel(subtitle)
    sub.setObjectName("nota")
    texts.addLayout(nome)
    texts.addWidget(sub)
    lay.addLayout(texts)
    lay.addStretch(1)
    return header


def fit_to_content(window: QWidget, width: int, *, clamp_to_screen: bool = False) -> None:
    """Tamanho fixo pelo conteúdo, como o QMessageBox: largura ``width`` (ou mais, se o
    conteúdo pedir) e a altura que os textos com quebra de linha precisam NESSA largura.

    Sem isso o Qt mede os textos numa largura menor (sobra um vão) e ainda limita a janela a
    2/3 da tela (corta texto). ``clamp_to_screen``: não passa da altura útil da tela — só para
    janelas com uma área de rolagem que pode encolher.
    """
    lay = window.layout()
    if lay is None:
        return
    minimo = lay.totalMinimumSize()
    w = max(width, minimo.width())
    h = lay.totalHeightForWidth(w) if lay.hasHeightForWidth() else lay.totalSizeHint().height()
    h = max(h, minimo.height())
    screen = window.screen()
    if clamp_to_screen and screen is not None:
        h = max(minimo.height(), min(h, screen.availableGeometry().height() - 80))
    if window.minimumSize() != QSize(w, h) or window.maximumSize() != QSize(w, h):
        window.setFixedSize(w, h)


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
    """Texto auxiliar pequeno (``QLabel#nota``, 12px)."""
    lbl = QLabel(text)
    lbl.setObjectName("nota")
    lbl.setWordWrap(True)
    return lbl


def title_label(text: str) -> QLabel:
    """Título da tela ou do cartão (``QLabel#titulo``, 22px)."""
    lbl = QLabel(text)
    lbl.setObjectName("titulo")
    lbl.setWordWrap(True)
    return lbl


def body(text: str) -> QLabel:
    """Texto de explicação abaixo do título (``QLabel#subtitulo``, 14px)."""
    lbl = QLabel(text)
    lbl.setObjectName("subtitulo")
    lbl.setWordWrap(True)
    lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lbl


def link_button(text: str) -> QPushButton:
    """Botão de texto, sem moldura (``QPushButton#discreto``)."""
    b = QPushButton(text)
    b.setObjectName("discreto")
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    b.setAutoDefault(False)
    b.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
    return b


def primary_button(text: str) -> QPushButton:
    """Ação principal (``QPushButton#primario``, pílula) — é o botão padrão (Enter)."""
    b = QPushButton(text)
    b.setObjectName("primario")
    b.setDefault(True)
    return b


def error_label() -> QLabel:
    """Mensagem de validação (``QLabel#erro``), escondida até ter texto."""
    lbl = QLabel("")
    lbl.setObjectName("erro")
    lbl.setWordWrap(True)
    lbl.hide()
    return lbl


def show_error(lbl: QLabel, text: str) -> None:
    lbl.setText(text)
    lbl.setVisible(bool(text))


def fmt_size(n: int) -> str:
    """Tamanho em português ("1,5 KB"). Arredonda ANTES de escolher a unidade: 1 MiB - 1 byte
    vira "1,0 MB", nunca "1024,0 KB"."""
    if n < 1024:
        return f"{int(n)} bytes"
    units = ["KB", "MB", "GB", "TB"]
    value = n / 1024
    for unit in units:
        text = f"{value:.1f}"
        if float(text) < 1024 or unit == units[-1]:
            return f"{text} {unit}".replace(".", ",")
        value /= 1024
    return f"{n} bytes"  # pragma: no cover - o laço sempre devolve na última unidade


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
    text.setTabChangesFocus(True)
    text.setPlainText("\n".join(f"• {i}" for i in items))
    text.setMinimumHeight(min(height, 26 + 20 * len(items)))
    text.setMaximumHeight(height + 60)
    text.setAccessibleName("Detalhes")
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
    """Tela de progresso modal (T6) no visual "Cofre". Fecha sozinha com ``finish``.

    Cartão com título, etapa atual, barra (6px, cor ``ok``), tempo restante em nota, um
    ``QPlainTextEdit#log`` opcional com as etapas (``log=True``), a ``note`` numa caixa de
    aviso e o botão Cancelar. Esc cancela; o X da janela não fecha.
    """

    def __init__(
        self,
        parent: QWidget,
        title: str,
        runner: JobRunner,
        *,
        mode: str = "generic",
        note: str = "",
        cancellable: bool = True,
        log: bool = False,
    ) -> None:
        # componentes.py importa este módulo: o import fica aqui para não fazer um ciclo
        from owl_vault.ui import componentes as comp  # noqa: PLC0415

        super().__init__(parent)
        self.setWindowTitle("Owl Vault")
        self.setModal(True)
        self.setMinimumWidth(520)
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, False)
        self._runner = runner
        self._mode = mode
        self._finished = False
        self._totals = (0, 0)
        self._done = [0, 0]
        self._t0 = time.monotonic()
        self._stage_text = "Preparando…"
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        self.card, lay = comp.cartao()
        outer.addWidget(self.card)
        self.title = comp.titulo(title)
        self.title.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self.title)
        self.stage = QLabel(self._stage_text)
        self.stage.setObjectName("etapa")
        self.stage.setWordWrap(True)
        self.stage.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self.stage)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setRange(0, 0)
        self.bar.setAccessibleName("Progresso")
        lay.addWidget(self.bar)
        self.eta = comp.nota("")
        lay.addWidget(self.eta)
        self.log_box: QPlainTextEdit | None = None
        if log:
            box = QPlainTextEdit()
            box.setObjectName("log")
            box.setReadOnly(True)
            box.setTabChangesFocus(True)
            box.setMaximumBlockCount(5000)
            box.setMinimumHeight(160)
            box.setAccessibleName("Etapas")
            lay.addWidget(box, 1)
            self.log_box = box
        self.notice = comp.Aviso(html.escape(note))
        lay.addWidget(self.notice)
        lay.addSpacing(8)
        row = QHBoxLayout()
        row.setSpacing(12)
        row.addStretch(1)
        self.cancel_button = comp.botao("Cancelar")
        self.cancel_button.clicked.connect(self._cancel)
        self.cancel_button.setVisible(cancellable)
        row.addWidget(self.cancel_button)
        lay.addLayout(row)
        b = runner.bridge
        b.stage.connect(self._on_stage)
        b.advance.connect(self._on_advance)
        if self.log_box is not None:
            b.info.connect(self._on_info)
            b.warning.connect(self._on_warning)

    def showEvent(self, event: QShowEvent) -> None:
        fit_to_content(self, 520)  # antes de centralizar sobre a janela-mãe
        super().showEvent(event)

    def event(self, event: QEvent) -> bool:
        handled = super().event(event)
        if event.type() == QEvent.Type.LayoutRequest and self.isVisible():
            fit_to_content(self, 520)  # um texto mudou de tamanho: a altura acompanha
        return handled

    # ------------------------------------------------------------------ registro
    def _log(self, text: str, cor: str = "") -> None:
        """Uma linha no registro; cor por ``QTextCharFormat`` (nunca HTML)."""
        box = self.log_box
        if box is None:
            return
        fmt = QTextCharFormat()
        if cor:
            fmt.setForeground(QColor(current_tokens()[cor]))
        cursor = QTextCursor(box.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        if not box.document().isEmpty():
            cursor.insertBlock()
        cursor.insertText(f"{time.strftime('%H:%M:%S')}  {text}", fmt)
        bar = box.verticalScrollBar()
        bar.setValue(bar.maximum())

    @Slot(str)
    def _on_info(self, message: str) -> None:
        self._log(message)

    @Slot(str)
    def _on_warning(self, message: str) -> None:
        self._log(message, "warn")

    # ------------------------------------------------------------------ progresso
    @Slot(str, object, object)
    def _on_stage(self, name: str, total_bytes: object, total_items: object) -> None:
        self._stage_text = _map_stage(self._mode, name)
        self.stage.setText(self._stage_text)
        self._log(self._stage_text)
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
        self._log("Parando num ponto seguro…", "warn")

    def finish(self) -> None:
        self._finished = True
        b = self._runner.bridge
        _disconnect(b.stage, self._on_stage)
        _disconnect(b.advance, self._on_advance)
        if self.log_box is not None:
            _disconnect(b.info, self._on_info)
            _disconnect(b.warning, self._on_warning)
        self.accept()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._finished:
            event.accept()
        else:
            event.ignore()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Escape and not self._finished:
            if not self.cancel_button.isHidden() and self.cancel_button.isEnabled():
                self._cancel()
            return
        super().keyPressEvent(event)


def _disconnect(signal: SignalInstance, slot: Callable[..., None]) -> None:
    try:
        signal.disconnect(slot)
    except (RuntimeError, TypeError):
        pass
