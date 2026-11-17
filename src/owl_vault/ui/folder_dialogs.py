"""Diálogos das pastas protegidas (UI_SPEC_V2 T5–T15) no visual "Cofre" (Estilo 5).

Todos têm a mesma forma: fundo ``app-bg`` e um ``cartao()`` (margens 24, espaçamento 12) com
título, texto, caixa ``Aviso`` quando é alerta, "Detalhes (N)" recolhível e a linha de botões à
direita — o primário (pílula roxa) é o botão padrão, os secundários são contornados e os
destrutivos usam ``botao_perigo``. Esc cancela (``choice`` = ""). Tab segue a ordem de leitura.
Só PIN ou senha mestra são digitados; nenhuma cor aqui (tudo vem do QSS).
"""

from __future__ import annotations

import html
import itertools
from collections.abc import Sequence

from PySide6.QtCore import QEvent, QSize, Qt
from PySide6.QtGui import QShowEvent
from PySide6.QtWidgets import (
    QBoxLayout,
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from owl_vault.domain.limits import MIN_PASSWORD_LENGTH
from owl_vault.ui.common import fit_to_content, fmt_duration, fmt_int, fmt_size, show_error
from owl_vault.ui.componentes import (
    Aviso,
    CampoSenha,
    LinhaChecagem,
    MedidorForca,
    botao,
    botao_discreto,
    botao_perigo,
    botao_primario,
    cartao,
    erro,
    lista_detalhes,
    nota,
    rotulo,
    subtitulo,
    titulo,
    transparente,
)

#: largura mínima de um diálogo e margem entre a borda da janela e o cartão
LARGURA = 520
MARGEM = 24
#: até esta largura os botões ficam lado a lado; acima, um embaixo do outro
LARGURA_MAXIMA_BOTOES = 680

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

#: título curto de cada limite (T15), na mesma ordem de ``LIMITS_TEXT``
LIMITS_TITLES = [
    "Pasta aberta fica legível",
    "O Windows deixa rastros",
    "O nome continua visível",
    "O PIN é mais fraco que a senha mestra",
    "Apagar a pasta apaga os arquivos",
    "O seu backup é a pasta trancada inteira",
    "Não protege contra vírus",
]

PROTECT_BULLETS = [
    "Os arquivos ficam guardados, criptografados, dentro da própria pasta. As cópias "
    "legíveis são apagadas (não vão para a Lixeira).",
    "Para abrir, use o atalho dentro da pasta ou o Owl Vault, com o seu PIN.",
    "Ao abrir, os arquivos voltam com nome, conteúdo e data de modificação; data de "
    "criação, atributos e permissões não voltam.",
    "Enquanto aberta, a pasta ocupa o dobro do espaço.",
]
#: o item da confirmação que é um alerta: vai para a caixa de aviso (não some)
PROTECT_WARNING = (
    "Cópias que já existem em outros lugares (Lixeira, OneDrive, backups, versões "
    "anteriores) não são apagadas. Recomendamos ativar o BitLocker."
)

MASTER_LOSS_WARNING = (
    "Se você esquecer a senha mestra, ninguém consegue recuperar os arquivos — nem o Owl Vault."
)
PIN_RULES = "6 a 12 números. Não use datas nem sequências como 123456."


# --- peças -------------------------------------------------------------------------------


def _puro(lbl: QLabel) -> QLabel:
    """Nomes de pastas e arquivos nunca viram HTML (um nome com "<b>" aparece como está)."""
    lbl.setTextFormat(Qt.TextFormat.PlainText)
    return lbl


def tab_order(widgets: Sequence[QWidget]) -> None:
    """Encadeia o Tab na ordem dada (a ordem de leitura), pulando o que não recebe Tab."""
    focaveis = [w for w in widgets if w.focusPolicy() & Qt.FocusPolicy.TabFocus]
    for a, b in itertools.pairwise(focaveis):
        QWidget.setTabOrder(a, b)


class _DialogoCofre(QDialog):
    """Fundo ``app-bg`` + ``QFrame#cartao``; ``self.corpo`` é o layout do cartão."""

    #: só a janela dos limites (com rolagem) encolhe para caber numa tela baixa
    _clamp_to_screen = False

    def __init__(self, parent: QWidget | None, width: int = LARGURA) -> None:
        super().__init__(parent)
        self.setWindowTitle("Owl Vault")
        self.setMinimumWidth(width)
        self._largura = width
        externo = QVBoxLayout(self)
        externo.setContentsMargins(MARGEM, MARGEM, MARGEM, MARGEM)
        self.card, self.corpo = cartao()
        externo.addWidget(self.card)
        self.title_label = _puro(titulo(""))
        self.text_label = _puro(subtitulo(""))
        self.corpo.addWidget(self.title_label)
        self.corpo.addWidget(self.text_label)
        self.button_box: QBoxLayout | None = None

    def fit(self) -> None:
        """Tamanho fixo pelo conteúdo (largura mínima e a altura que os textos pedem)."""
        fit_to_content(self, self._largura, clamp_to_screen=self._clamp_to_screen)

    def showEvent(self, event: QShowEvent) -> None:
        self.fit()  # antes de o QDialog centralizar sobre a janela-mãe
        super().showEvent(event)

    def event(self, event: QEvent) -> bool:
        handled = super().event(event)
        if event.type() == QEvent.Type.LayoutRequest and self.isVisible():
            self.fit()  # apareceu um erro ou os detalhes: a altura acompanha
        return handled

    def _cabecalho(self, title: str, text: str) -> None:
        self.title_label.setText(title)
        self.text_label.setText(text)
        self.text_label.setVisible(bool(text))

    def _campo(self, label: str, edit: QWidget) -> QLabel:
        """Rótulo (13px, negrito) e o campo logo abaixo (12px entre os dois)."""
        lbl = rotulo(label)
        lbl.setBuddy(edit)
        self.corpo.addWidget(lbl)
        self.corpo.addWidget(edit)
        return lbl

    def _botoes(self, botoes: Sequence[QPushButton]) -> None:
        """Linha de botões à direita; se não cabem, um embaixo do outro, na largura toda."""
        self.corpo.addSpacing(8)
        cabe = max(self.minimumWidth(), LARGURA_MAXIMA_BOTOES) - 2 * MARGEM - 2 * 24
        total = sum(b.sizeHint().width() for b in botoes) + 12 * max(0, len(botoes) - 1)
        box: QBoxLayout
        if total <= cabe or len(botoes) < 2:
            box = QHBoxLayout()
            box.addStretch(1)
            for b in botoes:
                box.addWidget(b)
        else:
            box = QVBoxLayout()
            for b in botoes:
                b.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                box.addWidget(b)
        box.setSpacing(12)
        self.corpo.addLayout(box)
        self.button_box = box


# --- escolha (T5c, T7, T8, T9, T11...) --------------------------------------------------


class ChoiceDialog(_DialogoCofre):
    """Uma explicação, um aviso opcional, uma lista "Detalhes" e até 3 botões.

    ``choice`` = chave do botão clicado ("" se cancelou com Esc ou fechou a janela).
    ``primary``: chave do botão padrão (o primeiro, se None). ``perigo``: chave do botão
    destrutivo (contorno vermelho). ``aviso``: texto da caixa de alerta (texto puro).
    """

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
        width: int = LARGURA,
        perigo: str | None = None,
        aviso: str = "",
    ) -> None:
        super().__init__(parent, width)
        self.choice = ""
        self._cabecalho(title, text)
        self.notice = Aviso(html.escape(aviso))
        self.corpo.addWidget(self.notice)
        self.details_box: QPlainTextEdit | None = None
        self.details_toggle: QPushButton | None = None
        self._n_details = len(details)
        ordem: list[QWidget] = []
        if details:
            box = lista_detalhes(details)
            box.setTabChangesFocus(True)
            # lista curta: a caixa tem a altura do conteúdo (sem um vão vazio embaixo)
            box.setMaximumHeight(max(box.minimumHeight(), min(220, 28 + 20 * len(details))))
            self.details_box = box
            if not details_open and len(details) > 1:
                toggle = botao_discreto("")
                toggle.setCheckable(True)
                toggle.toggled.connect(self._show_details)
                self.details_toggle = toggle
                self.corpo.addWidget(toggle, 0, Qt.AlignmentFlag.AlignLeft)
                ordem.append(toggle)
                self._show_details(False)
            self.corpo.addWidget(box)
            ordem.append(box)
        primary_key = primary if primary is not None else (buttons[0][1] if buttons else None)
        self.buttons: dict[str, QPushButton] = {}
        lista: list[QPushButton] = []
        for label, key in buttons:
            if key == perigo:
                btn = botao_perigo(label)
            elif key == primary_key:
                btn = botao_primario(label)
            else:
                btn = botao(label)
            btn.setDefault(key == primary_key)
            btn.setAutoDefault(key == primary_key)
            btn.clicked.connect(lambda _c=False, k=key: self._pick(k))
            self.buttons[key] = btn
            lista.append(btn)
        self._botoes(lista)
        tab_order([*ordem, *lista])
        if primary_key in self.buttons:
            self.buttons[primary_key].setFocus()

    def _show_details(self, visible: bool) -> None:
        if self.details_box is None or self.details_toggle is None:
            return
        n = self._n_details
        self.details_toggle.setText(f"{'▾' if visible else '▸'} Detalhes ({fmt_int(n)})")
        self.details_toggle.setAccessibleName(
            f"{'Ocultar' if visible else 'Mostrar'} detalhes ({fmt_int(n)})"
        )
        self.details_box.setVisible(visible)
        if self.isVisible():
            self.fit()

    def _pick(self, key: str) -> None:
        self.choice = key
        self.accept()


def ask(
    parent: QWidget | None, title: str, text: str, buttons: Sequence[tuple[str, str]], **kw: object
) -> str:
    """Mostra um ``ChoiceDialog`` e devolve a chave escolhida ("" = cancelou)."""
    dlg = ChoiceDialog(parent, title, text, buttons, **kw)  # type: ignore[arg-type]
    dlg.exec()
    return dlg.choice


def inform(
    parent: QWidget | None,
    title: str,
    text: str,
    details: Sequence[str] = (),
    *,
    aviso: str = "",
) -> None:
    ask(parent, title, text, [("OK", "ok")], details=details, details_open=True, aviso=aviso)


# --- T5d: confirmar a proteção -----------------------------------------------------------


class ConfirmProtectDialog(_DialogoCofre):
    """T5d — 'Proteger "<Nome>"?' (na 1ª proteção, "Entendi" é obrigatório)."""

    def __init__(
        self, parent: QWidget, name: str, files: int, total: int, first_time: bool
    ) -> None:
        super().__init__(parent, 560)
        summary = f"{fmt_int(files)} arquivo(s) · {fmt_size(total)}"
        seconds = total / (60 * 1024 * 1024) * 2.2 + files * 0.01  # ~60 MB/s, 3 passadas
        if seconds > 120:
            summary += f" · pode levar {fmt_duration(seconds)}."
        self._cabecalho(f"Proteger '{name}'?", summary)
        lista, lay = transparente()
        lay.setSpacing(8)
        for texto in PROTECT_BULLETS:
            linha, ll = transparente(QHBoxLayout)
            ll.setSpacing(10)
            marcador = QLabel("•")
            marcador.setObjectName("marcador")
            ll.addWidget(marcador, 0, Qt.AlignmentFlag.AlignTop)
            corpo = _puro(QLabel(texto))
            corpo.setObjectName("corpo")
            corpo.setWordWrap(True)
            ll.addWidget(corpo, 1)
            lay.addWidget(linha)
        self.corpo.addWidget(lista)
        self.notice = Aviso(html.escape(PROTECT_WARNING))
        self.corpo.addWidget(self.notice)
        self.ack: QCheckBox | None = None
        if first_time:
            self.ack = QCheckBox("Entendi")
            self.ack.toggled.connect(self._update)
            self.corpo.addWidget(self.ack)
        self.ok = botao_primario("Proteger")
        self.ok.clicked.connect(self.accept)
        cancel = botao("Cancelar")
        cancel.clicked.connect(self.reject)
        self._botoes([self.ok, cancel])
        tab_order([w for w in (self.ack, self.ok, cancel) if w is not None])
        if self.ack is not None:
            self.ack.setFocus()
        else:
            self.ok.setFocus()
        self._update()

    def _update(self) -> None:
        self.ok.setEnabled(self.ack is None or self.ack.isChecked())


# --- PIN / senha mestra ------------------------------------------------------------------


def _modo_segredo(edit: CampoSenha, master: bool, nome: str, placeholder: str) -> None:
    """Ajusta o campo para senha mestra (até 1024) ou PIN (até 12 números)."""
    edit.limpar()
    edit.setMaxLength(1024 if master else 12)
    edit.setInputMethodHints(
        Qt.InputMethodHint.ImhSensitiveData | Qt.InputMethodHint.ImhNoPredictiveText
        if master
        else Qt.InputMethodHint.ImhDigitsOnly
    )
    edit.setPlaceholderText(placeholder)
    edit.setAccessibleName(nome)


class SecretDialog(_DialogoCofre):
    """PIN ou senha mestra (desbloquear, abrir pelo atalho, remover proteção, recuperar).

    ``allow_master``: mostra o link "Usar a senha mestra" / "Usar o PIN" (troca o campo).
    ``perigo``: o botão de ação é destrutivo (ex.: "Remover proteção") — contorno vermelho,
    continua sendo o botão padrão (Enter depois de digitar).
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
        perigo: bool = False,
    ) -> None:
        super().__init__(parent, LARGURA)
        self.master = master
        self._cabecalho(title, text)
        self.corpo.addSpacing(4)
        self.edit = CampoSenha("", digitos=not master)
        self.label = self._campo("", self.edit)
        self.err = erro()
        self.corpo.addWidget(self.err)
        show_error(self.err, error)
        self.switch = botao_discreto("")
        self.switch.clicked.connect(self._toggle)
        self.switch.setVisible(allow_master)
        self.corpo.addWidget(self.switch, 0, Qt.AlignmentFlag.AlignLeft)
        self.ok = botao_perigo(button) if perigo else botao_primario(button)
        self.ok.setDefault(True)
        self.ok.setAutoDefault(True)
        self.ok.clicked.connect(self._accept)
        cancel = botao("Cancelar")
        cancel.clicked.connect(self.reject)
        self._botoes([self.ok, cancel])
        tab_order([self.edit, self.edit.mostrar, self.switch, self.ok, cancel])
        self._apply()

    def _apply(self) -> None:
        nome = "Senha mestra" if self.master else "PIN"
        dica = "Digite a sua senha mestra" if self.master else "Digite o seu PIN"
        _modo_segredo(self.edit, self.master, nome, dica)
        self.label.setText(nome)
        self.switch.setText("Usar o PIN" if self.master else "Usar a senha mestra")
        self.edit.setFocus()

    def _toggle(self) -> None:
        self.master = not self.master
        show_error(self.err, "")
        self._apply()

    def _accept(self) -> None:
        if not self.edit.text():
            show_error(self.err, "Digite a senha mestra." if self.master else "Digite o PIN.")
            self.edit.setFocus()
            return
        self.accept()

    def take(self) -> str:
        value = self.edit.text()
        self.edit.limpar()
        return value


class NewSecretDialog(_DialogoCofre):
    """Novo PIN ×2 ou nova senha mestra ×2 (+ medidor de força, aviso e 'Anotei')."""

    def __init__(self, parent: QWidget | None, *, master: bool, title: str, text: str) -> None:
        super().__init__(parent, LARGURA)
        self.master = master
        self._cabecalho(title, text)
        self.corpo.addSpacing(4)
        self.strength: MedidorForca | None = None
        self.notice: Aviso | None = None
        self.ack: QCheckBox | None = None
        ordem: list[QWidget] = []
        if master:
            self.a = CampoSenha(f"Mínimo {MIN_PASSWORD_LENGTH} caracteres")
            self._campo("Senha mestra", self.a)
            self.a.setAccessibleName("Senha mestra")
            self.strength = MedidorForca()
            self.corpo.addWidget(self.strength)
            self.a.textChanged.connect(self._strength)
            self.corpo.addSpacing(4)
            self.b = CampoSenha("Repita a senha mestra")
            self._campo("Confirmação", self.b)
            self.notice = Aviso(html.escape(MASTER_LOSS_WARNING))
            self.corpo.addWidget(self.notice)
            self.ack = QCheckBox("Anotei minha senha mestra em um lugar seguro.")
            self.corpo.addWidget(self.ack)
        else:
            self.a = CampoSenha("6 a 12 números", digitos=True)
            self._campo("Novo PIN", self.a)
            self.a.setAccessibleName("Novo PIN")
            self.b = CampoSenha("Repita o novo PIN", digitos=True)
            self._campo("Confirmação", self.b)
            self.corpo.addWidget(nota(PIN_RULES))
        ordem += [self.a, self.a.mostrar, self.b, self.b.mostrar]
        if self.ack is not None:
            ordem.append(self.ack)
        self.err = erro()
        self.corpo.addWidget(self.err)
        self.ok = botao_primario("Salvar")
        self.ok.clicked.connect(self._accept)
        cancel = botao("Cancelar")
        cancel.clicked.connect(self.reject)
        self._botoes([self.ok, cancel])
        tab_order([*ordem, self.ok, cancel])
        self.a.setFocus()

    def _strength(self) -> None:
        if self.strength is not None:
            self.strength.atualizar(self.a.text())

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
        self.a.limpar()
        self.b.limpar()
        return value


class ChangePinDialog(_DialogoCofre):
    """T13 — PIN atual + novo ×2; 'Esqueci o PIN' troca o primeiro campo pela senha mestra."""

    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent, LARGURA)
        self.master = False
        self._cabecalho("Alterar PIN", "Digite o PIN atual e escolha um novo.")
        self.corpo.addSpacing(4)
        self.current = CampoSenha("Digite o PIN que você usa hoje", digitos=True)
        self.current_label = self._campo("PIN atual", self.current)
        self.current.setAccessibleName("PIN atual")
        self.forgot = botao_discreto("Esqueci o PIN")
        self.forgot.clicked.connect(self._forgot)
        self.corpo.addWidget(self.forgot, 0, Qt.AlignmentFlag.AlignLeft)
        self.new1 = CampoSenha("6 a 12 números", digitos=True)
        self._campo("Novo PIN", self.new1)
        self.new1.setAccessibleName("Novo PIN")
        self.new2 = CampoSenha("Repita o novo PIN", digitos=True)
        self._campo("Confirmação", self.new2)
        self.corpo.addWidget(nota(PIN_RULES))
        self.err = erro()
        self.corpo.addWidget(self.err)
        self.ok = botao_primario("Salvar")
        self.ok.clicked.connect(self._accept)
        cancel = botao("Cancelar")
        cancel.clicked.connect(self.reject)
        self._botoes([self.ok, cancel])
        tab_order(
            [
                self.current,
                self.current.mostrar,
                self.forgot,
                self.new1,
                self.new1.mostrar,
                self.new2,
                self.new2.mostrar,
                self.ok,
                cancel,
            ]
        )
        self.current.setFocus()

    def _forgot(self) -> None:
        self.master = True
        _modo_segredo(self.current, True, "Senha mestra", "Digite a sua senha mestra")
        self.current_label.setText("Senha mestra")
        self.text_label.setText("Digite a sua senha mestra e escolha um PIN novo.")
        self.forgot.hide()
        show_error(self.err, "")
        self.current.setFocus()

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
            w.limpar()
        return values


# --- T12: escolher entre várias pastas ---------------------------------------------------


class PickDialog(_DialogoCofre):
    """Lista para marcar (T12 com mais de uma pasta recuperável)."""

    def __init__(self, parent: QWidget | None, title: str, text: str, items: Sequence[str]) -> None:
        super().__init__(parent, LARGURA)
        self._cabecalho(title, text)
        self.list = QListWidget()
        self.list.setAccessibleName(title)
        for it in items:
            item = QListWidgetItem(it)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            self.list.addItem(item)
        # cada linha tem 32px (QSS) + respiro; a lista tem a altura do conteúdo (até 240)
        self.list.setFixedHeight(min(240, 14 + 34 * max(1, len(items))))
        self.list.itemChanged.connect(self._update)
        self.corpo.addWidget(self.list)
        self.ok = botao_primario("Continuar")
        self.ok.clicked.connect(self.accept)
        cancel = botao("Cancelar")
        cancel.clicked.connect(self.reject)
        self._botoes([self.ok, cancel])
        tab_order([self.list, self.ok, cancel])
        self.list.setFocus()
        self._update()

    def _update(self) -> None:
        self.ok.setEnabled(bool(self.checked()))

    def checked(self) -> list[int]:
        return [
            i
            for i in range(self.list.count())
            if self.list.item(i).checkState() == Qt.CheckState.Checked
        ]


# --- T15: limites --------------------------------------------------------------------------


class _Rolagem(QScrollArea):
    """Rolagem que pede a altura do conteúdo na largura dada; numa tela baixa, encolhe."""

    def __init__(self, content: QWidget) -> None:
        super().__init__()
        self.setObjectName("transparente")
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setWidget(content)

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        content = self.widget()
        if content is None:
            return super().heightForWidth(width)
        frame = 2 * self.frameWidth()
        # mede já descontando a barra de rolagem: assim ela não aparece "por um fio"
        barra = self.verticalScrollBar().sizeHint().width()
        return content.heightForWidth(width - frame - barra) + frame

    def minimumSizeHint(self) -> QSize:
        return QSize(super().minimumSizeHint().width(), 120)


class LimitsDialog(_DialogoCofre):
    """T15 — os limites da proteção, um por linha (ícone de alerta + título + nota)."""

    _clamp_to_screen = True

    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent, 600)
        self._cabecalho(
            "Limites da proteção", "O que o Owl Vault não consegue fazer por você. Leia uma vez."
        )
        conteudo, lay = transparente()
        lay.setSpacing(8)
        self.rows: list[LinhaChecagem] = []
        for t, d in zip(LIMITS_TITLES, LIMITS_TEXT, strict=True):
            row = LinhaChecagem(t, d, "aviso")
            row.icone.setAccessibleName(f"Limite: {t}")
            lay.addWidget(row)
            self.rows.append(row)
        self.scroll_area = _Rolagem(conteudo)
        self.corpo.addWidget(self.scroll_area, 1)
        self.ok = botao_primario("Entendi")
        self.ok.clicked.connect(self.accept)
        self._botoes([self.ok])
        self.ok.setFocus()


def limits_dialog(parent: QWidget | None) -> None:
    LimitsDialog(parent).exec()


def make_label(text: str, name: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName(name)
    return lbl


__all__ = [
    "LIMITS_TEXT",
    "LIMITS_TITLES",
    "ChangePinDialog",
    "ChoiceDialog",
    "ConfirmProtectDialog",
    "LimitsDialog",
    "NewSecretDialog",
    "PickDialog",
    "SecretDialog",
    "ask",
    "inform",
    "limits_dialog",
    "make_label",
    "tab_order",
]
