"""Telas da janela principal: assistente (T1/T2), desbloqueio (T3) e lista de pastas (T4)."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QIcon, QResizeEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QStyle,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from owl_vault.application.common import password_strength
from owl_vault.application.lockers import FolderView
from owl_vault.application.profile import validate_master_password, validate_pin
from owl_vault.domain.errors import OwlVaultError
from owl_vault.domain.limits import MIN_PASSWORD_LENGTH
from owl_vault.storage import winfs
from owl_vault.ui.common import (
    body,
    brand_header,
    error_label,
    hidpi,
    hint,
    link_button,
    primary_button,
    secret_edit,
    show_error,
    title_label,
    wipe,
)
from owl_vault.ui.icon import logo_image, owl_icon


def _centered(inner: QWidget, width: int = 440) -> QWidget:
    outer = QWidget()
    lay = QHBoxLayout(outer)
    lay.addStretch(1)
    inner.setMaximumWidth(width)
    inner.setMinimumWidth(min(width, 360))
    lay.addWidget(inner, 3)
    lay.addStretch(1)
    return outer


def _logo() -> QLabel:
    lbl = QLabel()
    lbl.setPixmap(hidpi(lambda px: logo_image(px), 150))
    lbl.setAlignment(Qt.AlignmentFlag.AlignHCenter)
    return lbl


# --- T1/T2 ------------------------------------------------------------------------------


class SetupPage(QWidget):
    """Assistente de 2 passos. Emite ``finished(senha_mestra, pin, quer_recuperar)``."""

    finished = Signal(str, str, bool)

    def __init__(self) -> None:
        super().__init__()
        self.wants_recover = False
        self.stack = QStackedWidget()
        self.stack.addWidget(self._step1())
        self.stack.addWidget(self._step2())
        col = QWidget()
        lay = QVBoxLayout(col)
        lay.addStretch(1)
        lay.addWidget(_logo())
        lay.addSpacing(8)
        lay.addWidget(self.stack)
        lay.addStretch(2)
        root = QVBoxLayout(self)
        root.addWidget(_centered(col, 460))

    def _step1(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)
        lay.addWidget(hint("Passo 1 de 2"))
        lay.addWidget(title_label("Crie sua senha mestra"))
        lay.addWidget(
            body(
                "A senha mestra abre suas pastas em qualquer computador. Se você esquecê-la, "
                "ninguém consegue recuperar os arquivos — nem o Owl Vault."
            )
        )
        self.sm1 = secret_edit(f"Senha mestra (mínimo {MIN_PASSWORD_LENGTH} caracteres)")
        self.sm2 = secret_edit("Repita a senha mestra")
        self.strength = hint("")
        self.sm1.textChanged.connect(self._update_strength)
        self.noted = QCheckBox("Anotei minha senha mestra em um lugar seguro.")
        self.err1 = error_label()
        go = primary_button("Continuar")
        go.clicked.connect(self._next)
        self.sm2.returnPressed.connect(self._next)
        recover = link_button("Já usei o Owl Vault — recuperar minhas pastas")
        recover.clicked.connect(self._recover_hint)
        for x in (self.sm1, self.sm2, self.strength, self.noted, self.err1):
            lay.addWidget(x)
        lay.addWidget(go, 0, Qt.AlignmentFlag.AlignRight)
        lay.addWidget(recover, 0, Qt.AlignmentFlag.AlignLeft)
        return w

    def _step2(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)
        lay.addWidget(hint("Passo 2 de 2"))
        lay.addWidget(title_label("Crie seu PIN"))
        lay.addWidget(
            body(
                "Use o PIN no dia a dia, só neste computador. Ele é mais fraco que a senha "
                "mestra: não use datas nem sequências como 123456."
            )
        )
        self.pin1 = secret_edit("PIN (6 a 12 números)", digits=True)
        self.pin2 = secret_edit("Repita o PIN", digits=True)
        self.err2 = error_label()
        self.busy = hint("")
        row = QHBoxLayout()
        back = QPushButton("Voltar")
        back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.done_button = primary_button("Concluir")
        self.done_button.clicked.connect(self._finish)
        self.pin2.returnPressed.connect(self._finish)
        row.addWidget(back)
        row.addStretch(1)
        row.addWidget(self.done_button)
        for x in (self.pin1, self.pin2, self.err2, self.busy):
            lay.addWidget(x)
        lay.addLayout(row)
        return w

    def _update_strength(self) -> None:
        st = password_strength(self.sm1.text())
        self.strength.setText(f"Força estimada: {st.label}" if self.sm1.text() else "")

    def _recover_hint(self) -> None:
        self.wants_recover = True
        show_error(
            self.err1,
            "Crie o acesso deste computador digitando a MESMA senha mestra que você usava. "
            "Depois do PIN, o Owl Vault pede a pasta para recuperar.",
        )

    def _next(self) -> None:
        try:
            validate_master_password(self.sm1.text())
        except OwlVaultError as exc:
            show_error(self.err1, str(exc))
            return
        if self.sm1.text() != self.sm2.text():
            show_error(self.err1, "As duas senhas não são iguais.")
            return
        if not self.noted.isChecked():
            show_error(self.err1, "Marque 'Anotei minha senha mestra em um lugar seguro.'")
            return
        show_error(self.err1, "")
        self.stack.setCurrentIndex(1)
        self.pin1.setFocus()

    def _finish(self) -> None:
        try:
            validate_pin(self.pin1.text())
        except OwlVaultError as exc:
            show_error(self.err2, str(exc))
            return
        if self.pin1.text() != self.pin2.text():
            show_error(self.err2, "Os dois PINs não são iguais.")
            return
        show_error(self.err2, "")
        sm, pin = self.sm1.text(), self.pin1.text()
        for e in (self.sm1, self.sm2, self.pin1, self.pin2):
            wipe(e)
        self.finished.emit(sm, pin, self.wants_recover)

    def set_busy(self, busy: bool, text: str = "") -> None:
        self.done_button.setEnabled(not busy)
        self.busy.setText(text)

    def show_failure(self, text: str) -> None:
        self.stack.setCurrentIndex(0)
        show_error(self.err1, text)


# --- T3 ---------------------------------------------------------------------------------


class UnlockPage(QWidget):
    """Digite seu PIN / senha mestra. Emite ``submitted(segredo, é_senha_mestra)``."""

    submitted = Signal(str, bool)
    new_master_requested = Signal()
    use_pin_once = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.master = False
        self.master_failures = 0
        self.practice = False
        col = QWidget()
        lay = QVBoxLayout(col)
        lay.setSpacing(10)
        lay.addStretch(1)
        lay.addWidget(_logo())
        self.title = title_label("Digite seu PIN")
        self.title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.text = body("")
        self.text.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.edit = secret_edit("PIN", digits=True)
        self.edit.returnPressed.connect(self._submit)
        self.err = error_label()
        self.go = primary_button("Entrar")
        self.go.clicked.connect(self._submit)
        links = QHBoxLayout()
        self.switch = link_button("Usar a senha mestra")
        self.switch.clicked.connect(self._toggle)
        self.forgot = link_button("Esqueci o PIN")
        self.forgot.clicked.connect(self._forgot)
        links.addWidget(self.switch)
        links.addStretch(1)
        links.addWidget(self.forgot)
        self.extra = QWidget()
        ex = QHBoxLayout(self.extra)
        ex.setContentsMargins(0, 0, 0, 0)
        new_master = QPushButton("Criar nova senha mestra")
        new_master.clicked.connect(self.new_master_requested.emit)
        once = QPushButton("Usar o PIN desta vez")
        once.clicked.connect(self.use_pin_once.emit)
        ex.addWidget(new_master)
        ex.addWidget(once)
        self.extra.hide()
        for x in (self.title, self.text, self.edit, self.err):
            lay.addWidget(x)
        lay.addWidget(self.go, 0, Qt.AlignmentFlag.AlignRight)
        lay.addLayout(links)
        lay.addWidget(self.extra)
        lay.addStretch(2)
        root = QVBoxLayout(self)
        root.addWidget(_centered(col, 420))

    def configure(
        self,
        *,
        master: bool,
        title: str = "",
        text: str = "",
        allow_switch: bool = True,
        practice: bool = False,
        error: str = "",
    ) -> None:
        self.master = master
        self.practice = practice
        self.master_failures = 0
        self.extra.hide()
        wipe(self.edit)
        if master:
            self.edit.setPlaceholderText("Senha mestra")
            self.edit.setMaxLength(1024)
            self.edit.setInputMethodHints(Qt.InputMethodHint.ImhNone)
            self.switch.setText("Usar o PIN")
        else:
            self.edit.setPlaceholderText("PIN")
            self.edit.setMaxLength(12)
            self.edit.setInputMethodHints(Qt.InputMethodHint.ImhDigitsOnly)
            self.switch.setText("Usar a senha mestra")
        self.edit.setAccessibleName(self.edit.placeholderText())
        self.title.setText(title or ("Digite sua senha mestra" if master else "Digite seu PIN"))
        self.text.setText(text)
        self.text.setVisible(bool(text))
        self.switch.setVisible(allow_switch and not practice)
        self.forgot.setVisible(not master)
        show_error(self.err, error)
        self.set_busy(False)
        self.edit.setFocus()

    def _toggle(self) -> None:
        self.configure(master=not self.master)

    def _forgot(self) -> None:
        self.configure(
            master=True,
            text="Digite sua senha mestra. Depois você cria um PIN novo em ☰ > Alterar PIN.",
        )

    def _submit(self) -> None:
        value = self.edit.text()
        if not value:
            show_error(self.err, "Digite a senha mestra." if self.master else "Digite o PIN.")
            return
        wipe(self.edit)
        self.set_busy(True)
        self.submitted.emit(value, self.master)

    def set_busy(self, busy: bool) -> None:
        self.go.setEnabled(not busy)
        self.edit.setEnabled(not busy)
        self.go.setText("Abrindo…" if busy else "Entrar")
        if not busy:
            self.edit.setFocus()

    def fail(self, text: str) -> None:
        self.set_busy(False)
        show_error(self.err, text)
        if self.master and self.practice:
            self.master_failures += 1
            if self.master_failures >= 3:
                show_error(
                    self.err,
                    text + " Esqueceu? Enquanto o PIN funciona, você pode criar uma nova.",
                )
                self.extra.show()


# --- T4 ---------------------------------------------------------------------------------


class ElidedLabel(QLabel):
    """Rótulo de uma linha que corta o meio do texto com "…" (caminhos longos)."""

    def __init__(self, text: str) -> None:
        super().__init__(text)
        self._full = text
        self.setToolTip(text)
        self.setMinimumWidth(40)

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        metrics = self.fontMetrics()
        self.setText(metrics.elidedText(self._full, Qt.TextElideMode.ElideMiddle, self.width()))

    def minimumSizeHint(self):  # type: ignore[no-untyped-def]
        hint = super().minimumSizeHint()
        hint.setWidth(40)
        return hint


_STATE_COLORS = {"abrir": "stateLocked", "trancar": "stateOpen", "resolver": "stateAttention"}


class FolderRow(QFrame):
    def __init__(
        self,
        view: FolderView,
        on_action: Callable[[str, str], None],
        menu_items: list[tuple[str, str]],
    ) -> None:
        super().__init__()
        self.setObjectName("card")
        rec = view.record
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 10, 10, 10)
        lay.setSpacing(12)
        icon = QLabel()
        style = self.style()
        if view.action == "abrir":
            qicon: QIcon = owl_icon()
        elif view.action == "trancar":
            qicon = style.standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon)
        else:
            qicon = style.standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning)
        icon.setPixmap(qicon.pixmap(32, 32))
        icon.setFixedSize(34, 34)
        lay.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)
        texts = QVBoxLayout()
        texts.setSpacing(1)
        name = QLabel(rec.name)
        name.setObjectName("rowName")
        where = ElidedLabel(winfs.strip_extended(winfs.parent_of(rec.path)))
        where.setObjectName("rowPath")
        state = QLabel(view.label)
        state.setObjectName(_STATE_COLORS.get(view.action, "rowPath"))
        texts.addWidget(name)
        texts.addWidget(where)
        texts.addWidget(state)
        if view.attention and view.action == "resolver":
            att = QLabel(view.attention)
            att.setObjectName("hint")
            att.setWordWrap(True)
            texts.addWidget(att)
        lay.addLayout(texts, 1)
        labels = {"abrir": "Abrir", "trancar": "Trancar", "resolver": "Resolver…"}
        if view.action:
            btn = (
                primary_button(labels[view.action])
                if view.action != "resolver"
                else QPushButton(labels[view.action])
            )
            btn.setDefault(False)
            btn.clicked.connect(lambda: on_action(rec.id, view.action))
            btn.setAccessibleName(f"{labels[view.action]} {rec.name}")
            lay.addWidget(btn, 0, Qt.AlignmentFlag.AlignVCenter)
        if menu_items:
            more = QToolButton()
            more.setText("⋯")
            more.setObjectName("more")
            more.setAccessibleName(f"Mais opções de {rec.name}")
            more.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
            menu = QMenu(more)
            for label, key in menu_items:
                if key == "-":
                    menu.addSeparator()
                    continue
                act = menu.addAction(label)
                act.triggered.connect(lambda _c=False, k=key: on_action(rec.id, k))
            more.setMenu(menu)
            lay.addWidget(more, 0, Qt.AlignmentFlag.AlignVCenter)


def row_menu(view: FolderView) -> list[tuple[str, str]]:
    """Menu ⋯ por estado (T4)."""
    rec = view.record
    items: list[tuple[str, str]] = []
    if view.issue == "indisponivel":
        return [("Tirar da lista", "forget")]
    if view.action == "resolver" and view.base_action:
        items.append(("Abrir" if view.base_action == "abrir" else "Trancar", view.base_action))
    state = rec.state
    if state == "trancada":
        if rec.hidden:
            items.append(("Mostrar no Explorer", "show"))
        else:
            items.append(("Esconder do Explorer", "hide"))
        items.append(("Verificar arquivos", "verify"))
        items.append(("Remover proteção…", "remove"))
    elif state == "aberta":
        items.append(("Abrir a pasta no Explorer", "explore"))
        items.append(("Trancar e esconder", "lock_hide"))
        items.append(("Remover proteção…", "remove"))
    if view.issue == "nao_encontrada":
        items = [("Procurar a pasta…", "relocate"), ("Tirar da lista", "forget")]
    return items


class HomePage(QWidget):
    """Lista "Pastas protegidas"."""

    protect_clicked = Signal()
    lock_all_clicked = Signal()

    def __init__(self, menu: QMenu) -> None:
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 14, 18, 14)
        root.setSpacing(12)
        top = QHBoxLayout()
        top.addWidget(brand_header(), 1)
        self.protect = primary_button("+ Proteger uma pasta…")
        self.protect.setDefault(False)
        self.protect.clicked.connect(self.protect_clicked.emit)
        top.addWidget(self.protect, 0, Qt.AlignmentFlag.AlignVCenter)
        burger = QToolButton()
        burger.setText("☰")
        burger.setObjectName("more")
        burger.setAccessibleName("Menu")
        burger.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        burger.setMenu(menu)
        top.addWidget(burger, 0, Qt.AlignmentFlag.AlignVCenter)
        root.addLayout(top)

        self.banner = QFrame()
        self.banner.setObjectName("openBanner")
        bl = QHBoxLayout(self.banner)
        bl.setContentsMargins(12, 8, 8, 8)
        self.banner_text = QLabel("")
        self.banner_text.setWordWrap(True)
        lock_all = QPushButton("Trancar agora")
        lock_all.clicked.connect(self.lock_all_clicked.emit)
        bl.addWidget(self.banner_text, 1)
        bl.addWidget(lock_all)
        self.banner.hide()
        root.addWidget(self.banner)

        root.addWidget(QLabel("<b>Pastas protegidas</b>"))
        self.list_area = QScrollArea()
        self.list_area.setWidgetResizable(True)
        self.list_area.setFrameShape(QFrame.Shape.NoFrame)
        self.list_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        root.addWidget(self.list_area, 1)
        self.notice = hint("")
        self.notice.hide()
        root.addWidget(self.notice)
        self.set_rows([], lambda _i, _a: None)

    def set_rows(self, views: list[FolderView], on_action: Callable[[str, str], None]) -> None:
        holder = QWidget()
        lay = QVBoxLayout(holder)
        lay.setContentsMargins(0, 0, 4, 0)
        lay.setSpacing(8)
        if not views:
            empty = body(
                "Nenhuma pasta protegida ainda. Clique em 'Proteger uma pasta…' e escolha a pasta "
                "que você quer trancar."
            )
            empty.setObjectName("hint")
            lay.addWidget(empty)
        for v in views:
            lay.addWidget(FolderRow(v, on_action, row_menu(v)))
        lay.addStretch(1)
        old = self.list_area.takeWidget()
        if old is not None:
            old.deleteLater()
        self.list_area.setWidget(holder)
        opened = [v for v in views if v.record.state == "aberta"]
        if opened:
            n = len(opened)
            self.banner_text.setText(
                "1 pasta está aberta e visível neste computador."
                if n == 1
                else f"{n} pastas estão abertas e visíveis neste computador."
            )
            self.banner.show()
        else:
            self.banner.hide()

    def clear(self) -> None:
        """Ao bloquear: nada de nomes de pasta na tela."""
        self.set_rows([], lambda _i, _a: None)
        self.notice.hide()

    def set_notice(self, text: str) -> None:
        self.notice.setText(text)
        self.notice.setVisible(bool(text))
