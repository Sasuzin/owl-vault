"""Diálogos das pastas protegidas (UI_SPEC_V2 T5–T15). Só PIN ou senha mestra são digitados."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from owl_vault.application.common import password_strength
from owl_vault.domain.limits import MIN_PASSWORD_LENGTH
from owl_vault.ui.common import (
    body,
    error_label,
    fmt_duration,
    fmt_int,
    fmt_size,
    hint,
    link_button,
    list_box,
    primary_button,
    secret_edit,
    show_error,
    title_label,
    wipe,
)

LIMITS_TEXT = [
    "Uma pasta aberta pode ser lida por qualquer pessoa que use este computador.",
    "O Windows deixa rastros: itens Recentes, listas de atalhos, índice de pesquisa, miniaturas, "
    "o próprio SSD e backups podem guardar cópias ou nomes dos arquivos.",
    "O nome da pasta trancada continua visível; use 'Esconder do Explorer' se o nome for sensível.",
    "O PIN é mais fraco que a senha mestra: ele só funciona neste computador e nesta conta.",
    "Apagar a pasta trancada apaga os arquivos criptografados que estão dentro dela.",
    "Copiar a pasta trancada inteira (com os itens ocultos) é o seu backup.",
    "O Owl Vault não protege contra vírus nem contra quem controla este computador enquanto "
    "a pasta está aberta.",
]


class ChoiceDialog(QDialog):
    """Uma explicação, uma lista opcional ("Detalhes") e até 3 botões. ``choice`` = chave."""

    def __init__(
        self,
        parent: QWidget | None,
        title: str,
        text: str,
        buttons: Sequence[tuple[str, str]],
        *,
        details: Sequence[str] = (),
        details_open: bool = False,
        primary: str | None = None,
        width: int = 520,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Owl Vault")
        self.setMinimumWidth(width)
        self.choice = ""
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(title_label(title))
        if text:
            lay.addWidget(body(text))
        if details:
            box = list_box(details)
            if not details_open and len(details) > 1:
                toggle = link_button(f"Detalhes ({fmt_int(len(details))})")
                toggle.clicked.connect(lambda: box.setVisible(not box.isVisible()))
                box.hide()
                lay.addWidget(toggle, 0, Qt.AlignmentFlag.AlignLeft)
            lay.addWidget(box)
        row = QHBoxLayout()
        row.addStretch(1)
        first = True
        for label, key in buttons:
            is_primary = key == primary if primary is not None else first
            btn = primary_button(label) if is_primary else QPushButton(label)
            btn.clicked.connect(lambda _c=False, k=key: self._pick(k))
            row.addWidget(btn)
            first = False
        lay.addLayout(row)

    def _pick(self, key: str) -> None:
        self.choice = key
        self.accept()


def ask(
    parent: QWidget | None, title: str, text: str, buttons: Sequence[tuple[str, str]], **kw: object
) -> str:
    dlg = ChoiceDialog(parent, title, text, buttons, **kw)  # type: ignore[arg-type]
    dlg.exec()
    return dlg.choice


def inform(parent: QWidget | None, title: str, text: str, details: Sequence[str] = ()) -> None:
    ask(parent, title, text, [("OK", "ok")], details=details, details_open=True)


class ConfirmProtectDialog(QDialog):
    """T5d — 'Proteger "<Nome>"?'"""

    def __init__(
        self, parent: QWidget, name: str, files: int, total: int, first_time: bool
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Owl Vault")
        self.setMinimumWidth(560)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(title_label(f"Proteger '{name}'?"))
        summary = f"{fmt_int(files)} arquivo(s) · {fmt_size(total)}"
        seconds = total / (60 * 1024 * 1024) * 2.2 + files * 0.01  # ~60 MB/s, 3 passadas
        if seconds > 120:
            summary += f" · pode levar {fmt_duration(seconds)}."
        lay.addWidget(body(summary))
        bullets = [
            "Os arquivos ficam guardados, criptografados, dentro da própria pasta. As cópias "
            "legíveis são apagadas (não vão para a Lixeira).",
            "Para abrir, use o atalho dentro da pasta ou o Owl Vault, com o seu PIN.",
            "Cópias que já existem em outros lugares (Lixeira, OneDrive, backups, versões "
            "anteriores) não são apagadas. Recomendamos ativar o BitLocker.",
            "Ao abrir, os arquivos voltam com nome, conteúdo e data de modificação; data de "
            "criação, atributos e permissões não voltam.",
            "Enquanto aberta, a pasta ocupa o dobro do espaço.",
        ]
        lay.addWidget(body("\n".join(f"•  {b}" for b in bullets)))
        self.ack: QCheckBox | None = None
        if first_time:
            self.ack = QCheckBox("Entendi")
            self.ack.toggled.connect(self._update)
            lay.addWidget(self.ack)
        row = QHBoxLayout()
        row.addStretch(1)
        self.ok = primary_button("Proteger")
        self.ok.clicked.connect(self.accept)
        cancel = QPushButton("Cancelar")
        cancel.clicked.connect(self.reject)
        row.addWidget(self.ok)
        row.addWidget(cancel)
        lay.addLayout(row)
        self._update()

    def _update(self) -> None:
        self.ok.setEnabled(self.ack is None or self.ack.isChecked())


class SecretDialog(QDialog):
    """PIN ou senha mestra (desbloquear, abrir pelo atalho, remover proteção, recuperar).

    ``allow_master``: mostra o link "Usar a senha mestra" (troca o campo).
    """

    def __init__(
        self,
        parent: QWidget | None,
        title: str,
        text: str,
        button: str,
        *,
        master: bool = False,
        allow_master: bool = True,
        error: str = "",
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Owl Vault")
        self.setMinimumWidth(440)
        self.master = master
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(title_label(title))
        if text:
            lay.addWidget(body(text))
        self.edit = secret_edit("", digits=not master)
        lay.addWidget(self.edit)
        self.err = error_label()
        lay.addWidget(self.err)
        show_error(self.err, error)
        self.switch = link_button("")
        self.switch.clicked.connect(self._toggle)
        self.switch.setVisible(allow_master)
        lay.addWidget(self.switch, 0, Qt.AlignmentFlag.AlignLeft)
        row = QHBoxLayout()
        row.addStretch(1)
        ok = primary_button(button)
        ok.clicked.connect(self._accept)
        cancel = QPushButton("Cancelar")
        cancel.clicked.connect(self.reject)
        row.addWidget(ok)
        row.addWidget(cancel)
        lay.addLayout(row)
        self._apply()

    def _apply(self) -> None:
        if self.master:
            self.edit.setPlaceholderText("Senha mestra")
            self.edit.setMaxLength(1024)
            self.switch.setText("Usar o PIN")
        else:
            self.edit.setPlaceholderText("PIN")
            self.edit.setMaxLength(12)
            self.switch.setText("Usar a senha mestra")
        self.edit.setAccessibleName(self.edit.placeholderText())
        self.edit.setFocus()

    def _toggle(self) -> None:
        self.master = not self.master
        wipe(self.edit)
        show_error(self.err, "")
        self._apply()

    def _accept(self) -> None:
        if not self.edit.text():
            show_error(self.err, "Digite a senha mestra." if self.master else "Digite o PIN.")
            return
        self.accept()

    def take(self) -> str:
        value = self.edit.text()
        wipe(self.edit)
        return value


class NewSecretDialog(QDialog):
    """Novo PIN ×2 ou nova senha mestra ×2 (+ 'Anotei')."""

    def __init__(self, parent: QWidget | None, *, master: bool, title: str, text: str) -> None:
        super().__init__(parent)
        self.setWindowTitle("Owl Vault")
        self.setMinimumWidth(460)
        self.master = master
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(title_label(title))
        lay.addWidget(body(text))
        if master:
            self.a = secret_edit(f"Senha mestra (mínimo {MIN_PASSWORD_LENGTH} caracteres)")
            self.b = secret_edit("Repita a senha mestra")
            self.strength = hint("")
            self.a.textChanged.connect(self._strength)
        else:
            self.a = secret_edit("Novo PIN (6 a 12 números)", digits=True)
            self.b = secret_edit("Repita o novo PIN", digits=True)
        lay.addWidget(self.a)
        lay.addWidget(self.b)
        self.ack: QCheckBox | None = None
        if master:
            lay.addWidget(self.strength)
            self.ack = QCheckBox("Anotei minha senha mestra em um lugar seguro.")
            lay.addWidget(self.ack)
        self.err = error_label()
        lay.addWidget(self.err)
        row = QHBoxLayout()
        row.addStretch(1)
        ok = primary_button("Salvar")
        ok.clicked.connect(self._accept)
        cancel = QPushButton("Cancelar")
        cancel.clicked.connect(self.reject)
        row.addWidget(ok)
        row.addWidget(cancel)
        lay.addLayout(row)

    def _strength(self) -> None:
        st = password_strength(self.a.text())
        self.strength.setText(f"Força estimada: {st.label}" if self.a.text() else "")

    def _accept(self) -> None:
        a, b = self.a.text(), self.b.text()
        if self.master:
            from owl_vault.application.profile import validate_master_password  # noqa: PLC0415

            try:
                validate_master_password(a)
            except Exception as exc:
                show_error(self.err, str(exc))
                return
            if self.ack is not None and not self.ack.isChecked():
                show_error(self.err, "Marque 'Anotei minha senha mestra em um lugar seguro.'")
                return
        else:
            from owl_vault.application.profile import validate_pin  # noqa: PLC0415

            try:
                validate_pin(a)
            except Exception as exc:
                show_error(self.err, str(exc))
                return
        if a != b:
            show_error(self.err, "Os dois campos não são iguais.")
            return
        self.accept()

    def take(self) -> str:
        value = self.a.text()
        wipe(self.a)
        wipe(self.b)
        return value


class ChangePinDialog(QDialog):
    """T13 — PIN atual + novo ×2; 'Esqueci o PIN' troca o primeiro campo pela senha mestra."""

    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Owl Vault")
        self.setMinimumWidth(440)
        self.master = False
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(title_label("Alterar PIN"))
        self.current = secret_edit("PIN atual", digits=True)
        self.new1 = secret_edit("Novo PIN (6 a 12 números)", digits=True)
        self.new2 = secret_edit("Repita o novo PIN", digits=True)
        for w in (self.current, self.new1, self.new2):
            lay.addWidget(w)
        forgot = link_button("Esqueci o PIN")
        forgot.clicked.connect(self._forgot)
        lay.addWidget(forgot, 0, Qt.AlignmentFlag.AlignLeft)
        self.forgot = forgot
        self.err = error_label()
        lay.addWidget(self.err)
        row = QHBoxLayout()
        row.addStretch(1)
        ok = primary_button("Salvar")
        ok.clicked.connect(self._accept)
        cancel = QPushButton("Cancelar")
        cancel.clicked.connect(self.reject)
        row.addWidget(ok)
        row.addWidget(cancel)
        lay.addLayout(row)

    def _forgot(self) -> None:
        self.master = True
        wipe(self.current)
        self.current.setPlaceholderText("Senha mestra")
        self.current.setAccessibleName("Senha mestra")
        self.current.setMaxLength(1024)
        self.forgot.hide()

    def _accept(self) -> None:
        from owl_vault.application.profile import validate_pin  # noqa: PLC0415

        if not self.current.text():
            show_error(self.err, "Digite a senha mestra." if self.master else "Digite o PIN atual.")
            return
        try:
            validate_pin(self.new1.text())
        except Exception as exc:
            show_error(self.err, str(exc))
            return
        if self.new1.text() != self.new2.text():
            show_error(self.err, "Os dois campos do novo PIN não são iguais.")
            return
        self.accept()

    def take(self) -> tuple[str, str, bool]:
        values = (self.current.text(), self.new1.text(), self.master)
        for w in (self.current, self.new1, self.new2):
            wipe(w)
        return values


class PickDialog(QDialog):
    """Lista para marcar (T12 com mais de uma pasta recuperável)."""

    def __init__(self, parent: QWidget | None, title: str, text: str, items: Sequence[str]) -> None:
        super().__init__(parent)
        self.setWindowTitle("Owl Vault")
        self.setMinimumWidth(460)
        lay = QVBoxLayout(self)
        lay.addWidget(title_label(title))
        lay.addWidget(body(text))
        self.list = QListWidget()
        for it in items:
            item = QListWidgetItem(it)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            self.list.addItem(item)
        lay.addWidget(self.list)
        row = QHBoxLayout()
        row.addStretch(1)
        ok = primary_button("Continuar")
        ok.clicked.connect(self.accept)
        cancel = QPushButton("Cancelar")
        cancel.clicked.connect(self.reject)
        row.addWidget(ok)
        row.addWidget(cancel)
        lay.addLayout(row)

    def checked(self) -> list[int]:
        return [
            i
            for i in range(self.list.count())
            if self.list.item(i).checkState() == Qt.CheckState.Checked
        ]


def limits_dialog(parent: QWidget | None) -> None:
    inform(parent, "Limites da proteção", "\n\n".join(f"•  {t}" for t in LIMITS_TEXT))


def make_label(text: str, name: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName(name)
    return lbl


__all__ = [
    "ChangePinDialog",
    "ChoiceDialog",
    "ConfirmProtectDialog",
    "NewSecretDialog",
    "PickDialog",
    "SecretDialog",
    "ask",
    "inform",
    "limits_dialog",
    "make_label",
]
_ = QLineEdit
