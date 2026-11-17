"""Telas da janela principal no visual "Cofre" (Estilo 5): assistente (T1/T2), desbloqueio (T3),
perfil ilegível e lista "Pastas protegidas" (T4).

Cada tela é uma ``Pagina``: o corpo (trilha de passos, cartão principal e lateral de 272 px) e
um ``Rodape`` próprio que a janela coloca embaixo, na largura toda (ver ``owl_window``). O
botão primário do rodapé é o padrão da tela: Enter em qualquer campo aciona-o.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from owl_vault import version_label
from owl_vault.application.lockers import (
    ABERTA,
    ABERTURA_INCOMPLETA,
    ABRINDO,
    APAGANDO,
    TRANCADA,
    FolderView,
)
from owl_vault.application.profile import validate_master_password, validate_pin
from owl_vault.domain.errors import OwlVaultError
from owl_vault.domain.limits import MIN_PASSWORD_LENGTH
from owl_vault.storage import winfs
from owl_vault.ui.common import hidpi
from owl_vault.ui.componentes import (
    LARGURA_LATERAL,
    Aviso,
    BotaoMais,
    CampoSenha,
    CartaoLateral,
    Dica,
    MedidorForca,
    Rodape,
    RotuloCortado,
    TrilhaPassos,
    botao,
    botao_discreto,
    cartao,
    erro,
    mostrar_erro,
    nota,
    repintar,
    rotulo,
    subtitulo,
    titulo,
    transparente,
)
from owl_vault.ui.icon import owl_image

#: estados em que há cópias legíveis da pasta no disco (faixa da lista e aviso ao sair, T11)
VISIVEIS = frozenset({ABERTA, ABERTURA_INCOMPLETA, ABRINDO, APAGANDO})


def status_padrao() -> str:
    """Texto do rodapé quando nada está acontecendo (inclui a versão e o build)."""
    return f"Pronto · {version_label()}"


# --- estrutura comum ----------------------------------------------------------------------


class Pagina(QWidget):
    """Corpo de uma tela + o rodapé dela (``self.rodape``, colocado pela janela)."""

    def __init__(self, *, primario: str, voltar: str = "Voltar") -> None:
        super().__init__()
        self.setObjectName("transparente")
        self.rodape = Rodape(voltar=voltar, primario=primario)
        self.rodape.voltar.hide()
        self.status()

    def status(self, texto: str = "", estado: str = "") -> None:
        """Estado à direita do rodapé ("" = pronto, "trabalhando" ou "erro")."""
        self.rodape.definir_estado(texto or status_padrao(), estado)

    def campo_inicial(self) -> QWidget | None:
        """Onde o foco vai ao mostrar a tela."""
        return None

    def enter_aciona_primario(self, *campos: QLineEdit) -> None:
        """Enter nestes campos = o botão primário (o "default" da tela, fora de um QDialog)."""
        for campo in campos:
            campo.returnPressed.connect(self._acionar_primario)

    def _acionar_primario(self) -> None:
        b = self.rodape.primario
        if b.isEnabled() and not b.isHidden():
            b.click()


def _rolavel(conteudo: QWidget) -> QScrollArea:
    """Cartão que rola sozinho quando a janela é baixa (cada passo com a sua rolagem)."""
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setFocusPolicy(Qt.FocusPolicy.NoFocus)  # Tab vai direto aos campos (e rola até eles)
    area.setWidget(conteudo)
    return area


def _palco(principal: QWidget, lateral: Sequence[QWidget]) -> QWidget:
    """[principal (cresce)] + [lateral de 272 px], 20 px entre eles."""
    w, lay = transparente(QHBoxLayout)
    lay.setSpacing(20)
    lay.addWidget(principal, 1)
    if lateral:
        col, cl = transparente()
        cl.setSpacing(20)
        for x in lateral:
            cl.addWidget(x)
        cl.addStretch(1)
        col.setFixedWidth(LARGURA_LATERAL)
        lay.addWidget(col, 0)
    return w


def _centralizado(inner: QWidget, largura: int) -> QWidget:
    w, lay = transparente(QHBoxLayout)
    lay.addStretch(1)
    inner.setMaximumWidth(largura)
    inner.setMinimumWidth(min(largura, 360))
    lay.addWidget(inner, 4)
    lay.addStretch(1)
    return w


def _logo(tamanho: int = 72) -> QLabel:
    lbl = QLabel()
    lbl.setPixmap(hidpi(lambda px: owl_image(px), tamanho))
    lbl.setAlignment(Qt.AlignmentFlag.AlignHCenter)
    lbl.setAccessibleName("Owl Vault")
    return lbl


def _espaco(lay: QVBoxLayout, px: int = 4) -> None:
    """16 entre campos (12 do cartão + 4), 12 entre rótulo e campo."""
    lay.addSpacing(px)


ItemLateral = tuple[str, str, Callable[[], None] | None, bool]


def item(
    chave: str, valor: str, ao_alterar: Callable[[], None] | None = None, *, caminho: bool = False
) -> ItemLateral:
    return (chave, valor, ao_alterar, caminho)


class CartaoResumo(CartaoLateral):
    """``CartaoLateral`` com valores em texto comum (caminhos: monoespaçado, cortado no meio)."""

    def __init__(self, secao: str) -> None:
        super().__init__(secao)
        self._meus: list[QWidget] = []

    def definir(self, itens: Sequence[ItemLateral]) -> None:
        lay = self.layout()
        assert lay is not None
        for w in self._meus:
            w.hide()  # some já (o deleteLater só roda na volta ao laço de eventos)
            lay.removeWidget(w)
            w.deleteLater()
        self._meus = []
        for i, (chave, valor, ao_alterar, caminho) in enumerate(itens):
            if i:
                sep = QFrame()
                sep.setObjectName("ligacao")
                lay.addWidget(sep)
                self._meus.append(sep)
            bloco, bl = transparente()
            bl.setSpacing(2)
            topo, tl = transparente(QHBoxLayout)
            tl.setSpacing(6)
            k = QLabel(chave)
            k.setObjectName("resumoChave")
            tl.addWidget(k)
            if ao_alterar is not None:
                alt = botao_discreto("alterar")
                alt.setAccessibleName(f"Alterar {chave}")
                alt.clicked.connect(ao_alterar)
                tl.addWidget(alt)
            tl.addStretch(1)
            bl.addWidget(topo)
            v: QLabel
            if caminho:
                v = RotuloCortado(valor)
            else:
                v = QLabel(valor)
                v.setObjectName("rotulo")
                v.setWordWrap(True)
                v.setTextFormat(Qt.TextFormat.PlainText)
            bl.addWidget(v)
            lay.addWidget(bloco)
            self._meus.append(bloco)


# --- T1/T2 ------------------------------------------------------------------------------

_AVISO_SM = (
    "Se você esquecer a senha mestra, ninguém consegue recuperar os arquivos — nem o Owl Vault."
)
_TEXTO_RECUPERAR = (
    "Crie o acesso deste computador digitando a MESMA senha mestra que você usava. "
    "Depois do PIN, o Owl Vault pede a pasta para recuperar."
)


class SetupPage(Pagina):
    """Assistente de 2 passos. Emite ``finished(senha_mestra, pin, quer_recuperar)``."""

    finished = Signal(str, str, bool)

    def __init__(self) -> None:
        super().__init__(primario="Continuar para o PIN")
        self.wants_recover = False
        self.trilha = TrilhaPassos(["Senha mestra", "PIN"])
        self.stack = QStackedWidget()
        self.stack.setObjectName("transparente")
        self.stack.addWidget(_rolavel(self._passo1()))
        self.stack.addWidget(_rolavel(self._passo2()))
        self.resumo = CartaoResumo("O que vai acontecer")
        self.dica = Dica()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(20)
        root.addWidget(self.trilha)
        root.addWidget(_palco(self.stack, [self.resumo, self.dica]), 1)

        r = self.rodape
        r.voltar.clicked.connect(lambda: self._ir(0))
        r.primario.clicked.connect(self._avancar)
        self.recover_link = botao_discreto("Já usei o Owl Vault — recuperar minhas pastas")
        self.recover_link.clicked.connect(self._recover_hint)
        r.extra.addWidget(self.recover_link)
        self.enter_aciona_primario(self.sm1, self.sm2, self.pin1, self.pin2)
        self._ir(0)

    def _passo1(self) -> QWidget:
        card, lay = cartao()
        lay.addWidget(titulo("Crie sua senha mestra"))
        lay.addWidget(subtitulo("A senha mestra abre suas pastas em qualquer computador."))
        _espaco(lay)
        lay.addWidget(rotulo("Senha mestra"))
        self.sm1 = CampoSenha(f"Senha mestra (mínimo {MIN_PASSWORD_LENGTH} caracteres)")
        lay.addWidget(self.sm1)
        self.forca = MedidorForca()
        self.sm1.textChanged.connect(self.forca.atualizar)
        lay.addWidget(self.forca)
        _espaco(lay)
        lay.addWidget(rotulo("Confirmação"))
        self.sm2 = CampoSenha("Repita a senha mestra")
        lay.addWidget(self.sm2)
        _espaco(lay)
        self.noted = QCheckBox("Anotei minha senha mestra em um lugar seguro.")
        lay.addWidget(self.noted)
        self.err1 = erro()
        lay.addWidget(self.err1)
        self.recover_note = nota(_TEXTO_RECUPERAR)
        self.recover_note.hide()
        lay.addWidget(self.recover_note)
        self.aviso = Aviso(_AVISO_SM)
        lay.addWidget(self.aviso)
        lay.addStretch(1)
        return card

    def _passo2(self) -> QWidget:
        card, lay = cartao()
        lay.addWidget(titulo("Crie seu PIN"))
        lay.addWidget(
            subtitulo(
                "Use o PIN no dia a dia, só neste computador. Ele é mais fraco que a senha "
                "mestra: não use datas nem sequências como 123456."
            )
        )
        _espaco(lay)
        lay.addWidget(rotulo("PIN"))
        self.pin1 = CampoSenha("PIN (6 a 12 números)", digitos=True)
        lay.addWidget(self.pin1)
        _espaco(lay)
        lay.addWidget(rotulo("Confirmação"))
        self.pin2 = CampoSenha("Repita o PIN", digitos=True)
        lay.addWidget(self.pin2)
        self.err2 = erro()
        lay.addWidget(self.err2)
        lay.addStretch(1)
        return card

    # -- navegação
    def campo_inicial(self) -> QWidget | None:
        return self.sm1 if self.stack.currentIndex() == 0 else self.pin1

    def _ir(self, passo: int) -> None:
        self.stack.setCurrentIndex(passo)
        self.trilha.definir(passo)
        r = self.rodape
        r.voltar.setVisible(passo == 1)
        r.primario.setText("Continuar para o PIN" if passo == 0 else "Concluir")
        self.recover_link.setVisible(passo == 0 and not self.wants_recover)
        self._lateral()
        alvo = self.campo_inicial()
        if alvo is not None:
            alvo.setFocus()

    def _lateral(self) -> None:
        passo = self.stack.currentIndex()
        depois = (
            "Você escolhe a pasta para recuperar."
            if self.wants_recover
            else "Você escolhe as pastas para proteger."
        )
        self.resumo.definir(
            [
                item(
                    "Senha mestra",
                    "Criada." if passo == 1 else "Abre suas pastas em qualquer computador.",
                    (lambda: self._ir(0)) if passo == 1 else None,
                ),
                item("PIN", "O dia a dia, só neste computador."),
                item("Depois", depois),
            ]
        )
        if passo == 1:
            self.dica.definir(
                "Um PIN difícil",
                "Não use datas, números repetidos nem sequências como 123456. Depois de 5 erros, "
                "só a senha mestra abre.",
            )
        elif self.wants_recover:
            self.dica.definir("Recuperar minhas pastas", _TEXTO_RECUPERAR)
        else:
            self.dica.definir(
                "Anote num lugar seguro",
                "Use uma frase longa, fácil de lembrar e difícil de adivinhar. Guarde a anotação "
                "fora do computador.",
            )

    def _avancar(self) -> None:
        if self.stack.currentIndex() == 0:
            self._next()
        else:
            self._finish()

    def start(self, *, recuperar: bool = False) -> None:
        """Volta ao passo 1 com os campos vazios (``recuperar``: veio de "perfil danificado")."""
        for e in (self.sm1, self.sm2, self.pin1, self.pin2):
            e.limpar()
            e.setEnabled(True)
        self.noted.setChecked(False)
        mostrar_erro(self.err1, "")
        mostrar_erro(self.err2, "")
        self.wants_recover = False
        self.recover_note.hide()
        self.set_busy(False)
        if recuperar:
            self._recover_hint()
        self._ir(0)

    def _recover_hint(self) -> None:
        self.wants_recover = True
        self.recover_note.show()
        self.recover_link.hide()
        self._lateral()
        self.sm1.setFocus()

    def _next(self) -> None:
        try:
            validate_master_password(self.sm1.text())
        except OwlVaultError as exc:
            mostrar_erro(self.err1, str(exc))
            return
        if self.sm1.text() != self.sm2.text():
            mostrar_erro(self.err1, "As duas senhas não são iguais.")
            return
        if not self.noted.isChecked():
            mostrar_erro(self.err1, "Marque 'Anotei minha senha mestra em um lugar seguro.'")
            return
        mostrar_erro(self.err1, "")
        self._ir(1)

    def _finish(self) -> None:
        try:
            validate_pin(self.pin1.text())
        except OwlVaultError as exc:
            mostrar_erro(self.err2, str(exc))
            return
        if self.pin1.text() != self.pin2.text():
            mostrar_erro(self.err2, "Os dois PINs não são iguais.")
            return
        mostrar_erro(self.err2, "")
        sm, pin = self.sm1.text(), self.pin1.text()
        for e in (self.sm1, self.sm2, self.pin1, self.pin2):
            e.limpar()
        self.finished.emit(sm, pin, self.wants_recover)

    def set_busy(self, busy: bool, text: str = "") -> None:
        r = self.rodape
        r.primario.setEnabled(not busy)
        r.voltar.setEnabled(not busy)
        self.recover_link.setEnabled(not busy)
        for e in (self.pin1, self.pin2):
            e.setEnabled(not busy)
        self.status(text, "trabalhando" if busy else "")

    def show_failure(self, text: str) -> None:
        self._ir(0)
        mostrar_erro(self.err1, text)


# --- T3 ---------------------------------------------------------------------------------


class UnlockPage(Pagina):
    """Digite seu PIN / senha mestra. Emite ``submitted(segredo, é_senha_mestra)``."""

    submitted = Signal(str, bool)
    new_master_requested = Signal()
    use_pin_once = Signal()

    def __init__(self) -> None:
        super().__init__(primario="Entrar")
        self.master = False
        self.master_failures = 0
        self.practice = False
        self.button_text = "Entrar"
        card, lay = cartao()
        lay.setSpacing(12)
        lay.addWidget(_logo())
        self.title = titulo("Digite seu PIN")
        self.title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.text = subtitulo("")
        self.text.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.edit = CampoSenha("PIN", digitos=True)
        self.err = erro()
        lay.addWidget(self.title)
        lay.addWidget(self.text)
        _espaco(lay)
        lay.addWidget(self.edit)
        lay.addWidget(self.err)
        links, ll = transparente(QHBoxLayout)
        self.switch = botao_discreto("Usar a senha mestra")
        self.switch.clicked.connect(self._toggle)
        self.forgot = botao_discreto("Esqueci o PIN")
        self.forgot.clicked.connect(self._forgot)
        ll.addWidget(self.switch)
        ll.addStretch(1)
        ll.addWidget(self.forgot)
        lay.addWidget(links)
        self.extra, ex = transparente(QHBoxLayout)
        ex.setSpacing(12)
        self.new_master = botao("Criar nova senha mestra")
        self.new_master.clicked.connect(self.new_master_requested.emit)
        self.once = botao("Usar o PIN desta vez")
        self.once.clicked.connect(self.use_pin_once.emit)
        ex.addWidget(self.new_master)
        ex.addWidget(self.once)
        self.extra.hide()
        lay.addWidget(self.extra)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addStretch(1)
        root.addWidget(_centralizado(card, 460))
        root.addStretch(2)
        self.go = self.rodape.primario
        self.go.clicked.connect(self._submit)
        self.enter_aciona_primario(self.edit)

    def campo_inicial(self) -> QWidget | None:
        return self.edit

    def configure(
        self,
        *,
        master: bool,
        title: str = "",
        text: str = "",
        allow_switch: bool = True,
        practice: bool = False,
        error: str = "",
        button: str = "Entrar",
    ) -> None:
        self.master = master
        self.practice = practice
        self.master_failures = 0
        self.button_text = button
        self.extra.hide()
        self.edit.limpar()
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
        mostrar_erro(self.err, error)
        self.set_busy(False)
        self.edit.setFocus()

    def _toggle(self) -> None:
        self.configure(master=not self.master, button=self.button_text)

    def _forgot(self) -> None:
        self.configure(
            master=True,
            text="Digite sua senha mestra. Depois você cria um PIN novo em ☰ > Alterar PIN.",
            button=self.button_text,
        )

    def _submit(self) -> None:
        if not self.go.isEnabled():
            return
        value = self.edit.text()
        if not value:
            mostrar_erro(self.err, "Digite a senha mestra." if self.master else "Digite o PIN.")
            return
        self.edit.limpar()
        self.set_busy(True)
        self.submitted.emit(value, self.master)

    def set_busy(self, busy: bool) -> None:
        """Ocupado: nada desta tela pode disparar outro pedido (nem os links)."""
        for w in (self.go, self.edit, self.switch, self.forgot, self.new_master, self.once):
            w.setEnabled(not busy)
        if busy:
            self.go.setText("Abrindo…" if self.button_text == "Abrir" else "Entrando…")
            self.status(
                "Conferindo a senha mestra…" if self.master else "Conferindo o PIN…",
                "trabalhando",
            )
        else:
            self.go.setText(self.button_text)
            self.status()
            self.edit.setFocus()

    def fail(self, text: str) -> None:
        self.set_busy(False)
        mostrar_erro(self.err, text)
        if self.master and self.practice:
            self.master_failures += 1
            if self.master_failures >= 3:
                mostrar_erro(
                    self.err,
                    text + " Esqueceu? Enquanto o PIN funciona, você pode criar uma nova.",
                )
                self.extra.show()


# --- perfil ilegível (PASTAS_PROTEGIDAS §2) ----------------------------------------------


class ProfileProblemPage(Pagina):
    """O perfil deste computador não pôde ser lido.

    ``corrupt``: danificado → [Recuperar minhas pastas com a senha mestra] (o arquivo danificado
    é guardado ao lado, nunca apagado). Senão (erro de acesso) → [Tentar de novo].
    """

    recover_requested = Signal()
    retry_requested = Signal()

    def __init__(self) -> None:
        super().__init__(primario="Recuperar minhas pastas com a senha mestra")
        self.corrupt = True
        card, lay = cartao()
        lay.addWidget(_logo())
        self.title = titulo("")
        self.title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.text = subtitulo("")
        self.detail = nota("")
        self.aviso = Aviso("")
        self.err = erro()
        for w in (self.title, self.text, self.detail, self.aviso, self.err):
            lay.addWidget(w)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addStretch(1)
        root.addWidget(_centralizado(card, 520))
        root.addStretch(2)
        self.rodape.primario.clicked.connect(self._go)
        self.configure(corrupt=True)

    def configure(self, *, corrupt: bool, detail: str = "") -> None:
        self.corrupt = corrupt
        mostrar_erro(self.err, "")
        self.detail.setText(detail)
        self.detail.setVisible(bool(detail))
        if corrupt:
            self.title.setText("O perfil deste computador está danificado")
            self.text.setText(
                "Suas pastas protegidas continuam guardadas e abrem com a senha mestra. O Owl "
                "Vault cria um acesso novo para este computador e pede as pastas para recuperar."
            )
            self.aviso.definir(
                "O arquivo danificado é guardado ao lado, com outro nome. Nada é apagado."
            )
            self.rodape.primario.setText("Recuperar minhas pastas com a senha mestra")
        else:
            self.title.setText("Não foi possível ler o perfil agora")
            self.text.setText(
                "Outro programa pode estar usando o arquivo do Owl Vault (antivírus, backup ou "
                "sincronização). Feche-o e tente de novo."
            )
            self.aviso.definir("")
            self.rodape.primario.setText("Tentar de novo")
        self.rodape.primario.setEnabled(True)
        self.status()

    def fail(self, text: str) -> None:
        mostrar_erro(self.err, text)
        self.status("Não deu certo.", "erro")

    def _go(self) -> None:
        if self.corrupt:
            self.recover_requested.emit()
        else:
            self.retry_requested.emit()


# --- T4 ---------------------------------------------------------------------------------

_ROTULOS_ACAO = {"abrir": "Abrir", "trancar": "Trancar", "resolver": "Resolver…"}


def estado_da_linha(view: FolderView) -> str:
    """Valor da propriedade ``estado`` de ``QLabel#linhaEstado`` (cor no QSS)."""
    if view.issue == "indisponivel":
        return "indisponivel"
    if view.action == "resolver":
        return "atencao"
    if view.action == "trancar":
        return "aberta"
    return "trancada"


class FolderRow(QFrame):
    """Uma linha da lista: nome, local (cortado no meio), estado, UM botão e o menu ⋯."""

    def __init__(
        self,
        view: FolderView,
        on_action: Callable[[str, str], None],
        menu_items: list[tuple[str, str]],
    ) -> None:
        super().__init__()
        self.setObjectName("linhaPasta")
        rec = view.record
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 12, 12, 12)
        lay.setSpacing(12)
        textos, tl = transparente()
        tl.setSpacing(2)
        name = QLabel(rec.name)
        name.setObjectName("linhaNome")
        name.setTextFormat(Qt.TextFormat.PlainText)
        self.where = RotuloCortado(winfs.strip_extended(winfs.parent_of(rec.path)), "linhaLocal")
        state = QLabel(view.label)
        state.setObjectName("linhaEstado")
        state.setProperty("estado", estado_da_linha(view))
        repintar(state)
        tl.addWidget(name)
        tl.addWidget(self.where)
        tl.addWidget(state)
        if view.attention and view.action == "resolver":
            att = QLabel(view.attention)
            att.setObjectName("linhaDetalhe")
            att.setTextFormat(Qt.TextFormat.PlainText)
            att.setWordWrap(True)
            tl.addWidget(att)
        lay.addWidget(textos, 1)
        self.button = None
        if view.action:
            text = _ROTULOS_ACAO[view.action]
            btn = botao(text)
            if view.action != "resolver":
                btn.setObjectName("primario")
            btn.setAutoDefault(True)  # Enter no botão focado aciona-o
            btn.clicked.connect(lambda: on_action(rec.id, view.action))
            btn.setAccessibleName(f"{text} {rec.name}")
            lay.addWidget(btn, 0, Qt.AlignmentFlag.AlignVCenter)
            self.button = btn
        self.more = None
        if menu_items:
            menu = QMenu(self)
            for label, key in menu_items:
                if key == "-":
                    menu.addSeparator()
                    continue
                act = menu.addAction(label)
                act.triggered.connect(lambda _c=False, k=key: on_action(rec.id, k))
            self.more = BotaoMais(menu, f"Mais opções de {rec.name}")
            lay.addWidget(self.more, 0, Qt.AlignmentFlag.AlignVCenter)


def row_menu(view: FolderView) -> list[tuple[str, str]]:
    """Menu ⋯ por estado (T4)."""
    rec = view.record
    items: list[tuple[str, str]] = []
    if view.issue == "indisponivel":
        return [("Tirar da lista", "forget")]
    if view.action == "resolver" and view.base_action:
        items.append(("Abrir" if view.base_action == "abrir" else "Trancar", view.base_action))
    state = rec.state
    if state == TRANCADA:
        if rec.hidden:
            items.append(("Mostrar no Explorer", "show"))
        else:
            items.append(("Esconder do Explorer", "hide"))
        items.append(("Verificar arquivos", "verify"))
        items.append(("Remover proteção…", "remove"))
    elif state == ABERTA:
        items.append(("Abrir a pasta no Explorer", "explore"))
        items.append(("Trancar e esconder", "lock_hide"))
        items.append(("Remover proteção…", "remove"))
    if view.issue == "nao_encontrada":
        items = [("Procurar a pasta…", "relocate"), ("Tirar da lista", "forget")]
    return items


_RESUMO = [
    ("trancadas", "Trancadas"),
    ("abertas", "Abertas"),
    ("escondidas", "Escondidas"),
    ("atencao", "Precisam de atenção"),
]


def _plural(n: int, um: str, varios: str) -> str:
    return um if n == 1 else varios.format(n=n)


class HomePage(Pagina):
    """Lista "Pastas protegidas" + resumo e dica na lateral."""

    protect_clicked = Signal()
    lock_all_clicked = Signal()

    def __init__(self) -> None:
        super().__init__(primario="+ Proteger uma pasta…")
        self.protect = self.rodape.primario
        self.protect.clicked.connect(self.protect_clicked.emit)

        # faixa "pasta aberta" (Aviso + Trancar agora)
        self.banner = Aviso("")
        self.lock_all = botao("Trancar agora")
        self.lock_all.setAutoDefault(True)
        self.lock_all.clicked.connect(self.lock_all_clicked.emit)
        banner_lay = self.banner.layout()
        assert banner_lay is not None
        banner_lay.addWidget(self.lock_all)

        card, lay = cartao()
        lay.addWidget(titulo("Pastas protegidas"))
        lay.addWidget(
            subtitulo("Os arquivos ficam guardados, criptografados, dentro da própria pasta.")
        )
        self.notice = rotulo("")
        self.notice.setTextFormat(Qt.TextFormat.PlainText)
        self.notice.hide()
        lay.addWidget(self.notice)
        self.list_area = _rolavel(QWidget())
        lay.addWidget(self.list_area, 1)

        coluna, cl = transparente()
        cl.setSpacing(20)
        cl.addWidget(self.banner)
        cl.addWidget(card, 1)

        # resumo: chave à esquerda, número grande à direita (contagens, sem nomes)
        self.resumo = CartaoLateral("Resumo")
        resumo_lay = self.resumo.layout()
        assert resumo_lay is not None
        self._contadores: dict[str, QLabel] = {}
        for key, label in _RESUMO:
            linha, ll = transparente(QHBoxLayout)
            chave = QLabel(label)
            chave.setObjectName("resumoChave")
            valor = QLabel("0")
            valor.setObjectName("linhaNome")
            ll.addWidget(chave)
            ll.addStretch(1)
            ll.addWidget(valor)
            resumo_lay.addWidget(linha)
            self._contadores[key] = valor
        self.dica = Dica()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(_palco(coluna, [self.resumo, self.dica]), 1)
        self.counts: dict[str, int] = {}
        self.set_rows([], lambda _i, _a: None)

    def campo_inicial(self) -> QWidget | None:
        return self.protect

    @property
    def banner_text(self) -> str:
        return self.banner.texto()

    def set_rows(self, views: list[FolderView], on_action: Callable[[str, str], None]) -> None:
        holder, lay = transparente()
        lay.setContentsMargins(0, 0, 4, 0)
        lay.setSpacing(8)
        if not views:
            empty = subtitulo(
                "Nenhuma pasta protegida ainda. Clique em '+ Proteger uma pasta…' e escolha a "
                "pasta que você quer trancar."
            )
            lay.addWidget(empty)
            lay.addWidget(
                nota(
                    "A pasta continua no mesmo lugar. Os arquivos ficam guardados dentro dela, "
                    "criptografados, e abrem com o seu PIN."
                )
            )
        for v in views:
            lay.addWidget(FolderRow(v, on_action, row_menu(v)))
        lay.addStretch(1)
        old = self.list_area.takeWidget()
        if old is not None:
            old.deleteLater()
        self.list_area.setWidget(holder)
        self._resumo(views)
        self._faixa(views)

    def _resumo(self, views: list[FolderView]) -> None:
        c = {"trancadas": 0, "abertas": 0, "escondidas": 0, "atencao": 0}
        for v in views:
            rec = v.record
            if v.action == "resolver":
                c["atencao"] += 1
            elif rec.state == TRANCADA:
                c["escondidas" if rec.hidden else "trancadas"] += 1
            elif rec.state == ABERTA:
                c["abertas"] += 1
        self.counts = c
        for key, label in _RESUMO:
            valor = self._contadores[key]
            valor.setText(str(c[key]))
            valor.setAccessibleName(f"{label}: {c[key]}")
        if not views:
            self.dica.definir(
                "Comece por aqui",
                "Clique em '+ Proteger uma pasta…' e escolha uma pasta sua, como "
                "Documentos\\Particular.",
            )
        elif c["atencao"]:
            self.dica.definir(
                "Precisa de atenção",
                "Clique em 'Resolver…' na linha da pasta. Nenhum arquivo é apagado sem estar "
                "guardado e conferido antes.",
            )
        elif c["abertas"]:
            self.dica.definir(
                "Tranque ao terminar",
                "Uma pasta aberta pode ser lida por qualquer pessoa que use este computador.",
            )
        else:
            self.dica.definir(
                "Seu backup",
                "Copiar a pasta trancada inteira (com os itens ocultos) é o seu backup. Ela "
                "abre com a senha mestra em qualquer computador.",
            )

    def _faixa(self, views: list[FolderView]) -> None:
        visiveis = [v for v in views if v.record.state in VISIVEIS]
        abertas = [v for v in visiveis if v.record.state == ABERTA]
        if not visiveis:
            self.banner.definir("")
            return
        n = len(visiveis)
        text = _plural(
            n,
            "1 pasta está aberta e visível neste computador.",
            "{n} pastas estão abertas e visíveis neste computador.",
        )
        if len(abertas) < n:
            text += " Use 'Resolver…' nas que precisam de atenção."
        self.lock_all.setVisible(bool(abertas))
        self.banner.definir(text)

    def clear(self) -> None:
        """Ao bloquear: nenhum nome de pasta fica na tela, nem em rótulo escondido."""
        self.set_rows([], lambda _i, _a: None)
        self.set_notice("")

    def set_notice(self, text: str) -> None:
        self.notice.setText(text)
        self.notice.setVisible(bool(text))
