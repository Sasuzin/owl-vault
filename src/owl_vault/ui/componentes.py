"""Componentes visuais do tema "Cofre" (Claude Design, Estilo 5).

Cada componente só define estrutura e ``objectName``/propriedades dinâmicas; as cores vêm do
QSS (``ui/tema/owlvault.qss``) e dos tokens (``ui/tema/theme_cofre.py``). Nenhuma cor literal
aqui — a sombra usa o token ``sombra``.

Contrato de nomes (o QSS depende deles; ver visual/ESTILO5-COFRE.md):

==========================  ============================================================
Componente                  objectName / propriedade
==========================  ============================================================
``TrilhaPassos``            passoNumero[estado=feito|atual], passoTexto[estado=atual],
                            ligacao[estado=feito]
``cartao()``                QFrame#cartao (margens 24, espaçamento 12) + sombra
``CartaoLateral``           QFrame#cartaoLateral, secaoLateral, resumoChave, resumoValor,
                            discreto ("alterar")
``Dica`` / ``Aviso``        QFrame#dica / QFrame#aviso
``titulo/subtitulo/...``    QLabel#titulo, #subtitulo, #rotulo, #nota, #erro
``Rodape``                  QFrame#rodape, primario, estadoPonto[estado=erro|trabalhando],
                            estadoTexto
``CampoSenha``              QLineEdit com "Mostrar" (discreto) dentro
``MedidorForca``            4× QFrame#forca[ativo=sim|nao], QLabel#forcaTexto[nivel]
``CampoCaminho``            QLineEdit[caminho=sim] somente leitura + "Escolher" (discreto)
``LinhaChecagem``           checagemIcone[estado=ok|falhou|aviso], checagemTitulo, nota
``BotaoMais``               QToolButton#mais (⋯ e ☰)
==========================  ============================================================

Texto vindo do usuário (nome de pasta, de cofre, caminho) nunca vira HTML: os rótulos daqui
são ``Qt.PlainText`` e as dicas do mouse passam por ``dica_sem_html``. Só o ``Aviso`` aceita
texto rico — quem chama escapa o que veio do usuário (``html.escape``).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import ClassVar

from PySide6 import QtGui
from PySide6.QtCore import QEvent, QObject, QPointF, QRect, QRectF, Qt, Signal
from PySide6.QtGui import (
    QColor,
    QPainter,
    QPainterPath,
    QPaintEvent,
    QPalette,
    QPolygonF,
    QResizeEvent,
)
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QStyle,
    QStyleOptionFrame,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from owl_vault.application.common import password_strength
from owl_vault.ui.common import choose_folder, hidpi
from owl_vault.ui.icon import owl_image
from owl_vault.ui.tema.theme_cofre import LARGURA_LATERAL, repintar
from owl_vault.ui.theme import current_tokens

__all__ = [
    "LARGURA_LATERAL",
    "Aviso",
    "BotaoMais",
    "CampoCaminho",
    "CampoSenha",
    "CartaoLateral",
    "Dica",
    "LinhaChecagem",
    "Marca",
    "MedidorForca",
    "Rodape",
    "RotuloCortado",
    "TrilhaPassos",
    "botao",
    "botao_discreto",
    "botao_perigo",
    "botao_primario",
    "cartao",
    "dica_sem_html",
    "erro",
    "lista_detalhes",
    "nota",
    "repintar",
    "rotulo",
    "sombra",
    "subtitulo",
    "titulo",
    "transparente",
]


# --- textos ------------------------------------------------------------------------------


def dica_sem_html(texto: str) -> str:
    """Texto para ``setToolTip`` que aparece como está, mesmo com "<i>" ou "<b>".

    A dica do mouse do Qt detecta HTML sozinha (não há ``setTextFormat`` para ela): um nome
    "<i>Cofre</i>" sairia "Cofre" em itálico. Quando o texto parece HTML, ele vai escapado.
    """
    if not texto or not QtGui.Qt.mightBeRichText(texto):
        return texto
    return QtGui.Qt.convertFromPlainText(texto, Qt.WhiteSpaceMode.WhiteSpacePre)


def _label(text: str, name: str, *, wrap: bool = True, selectable: bool = False) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName(name)
    # nomes de pastas, cofres e caminhos aparecem como estão ("<i>x</i>" não vira itálico)
    lbl.setTextFormat(Qt.TextFormat.PlainText)
    lbl.setWordWrap(wrap)
    if selectable:
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lbl


def titulo(text: str) -> QLabel:
    return _label(text, "titulo")


def subtitulo(text: str) -> QLabel:
    return _label(text, "subtitulo", selectable=True)


def rotulo(text: str) -> QLabel:
    return _label(text, "rotulo")


def nota(text: str) -> QLabel:
    return _label(text, "nota", selectable=True)


def erro() -> QLabel:
    """Mensagem de validação (escondida até ter texto). Use ``mostrar_erro``."""
    lbl = _label("", "erro")
    lbl.hide()
    return lbl


def mostrar_erro(lbl: QLabel, text: str) -> None:
    lbl.setText(text)
    lbl.setVisible(bool(text))


class RotuloCortado(QLabel):
    """Uma linha que corta o meio com "…" (caminhos longos); o texto inteiro fica na dica.

    Mostra nomes de pastas e cofres: sempre texto puro (nunca HTML), também na dica.
    """

    def __init__(self, text: str, name: str = "resumoValor") -> None:
        super().__init__(text)
        self.setObjectName(name)
        self.setTextFormat(Qt.TextFormat.PlainText)
        self._full = text
        self.setToolTip(dica_sem_html(text))
        self.setMinimumWidth(40)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)

    def set_full_text(self, text: str) -> None:
        self._full = text
        self.setToolTip(dica_sem_html(text))
        self._elide()

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._elide()

    def _elide(self) -> None:
        metrics = self.fontMetrics()
        self.setText(metrics.elidedText(self._full, Qt.TextElideMode.ElideMiddle, self.width()))


# --- botões ------------------------------------------------------------------------------


def botao(text: str) -> QPushButton:
    b = QPushButton(text)
    b.setAutoDefault(False)
    return b


def botao_primario(text: str) -> QPushButton:
    b = QPushButton(text)
    b.setObjectName("primario")
    b.setDefault(True)
    return b


def botao_discreto(text: str) -> QPushButton:
    b = QPushButton(text)
    b.setObjectName("discreto")
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    b.setAutoDefault(False)
    b.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
    return b


def botao_perigo(text: str) -> QPushButton:
    b = QPushButton(text)
    b.setObjectName("perigo")
    b.setAutoDefault(False)
    return b


class BotaoMais(QToolButton):
    """Botão redondo que abre um menu: "⋯" na linha da pasta, "☰" no topo."""

    def __init__(self, menu: QMenu, nome_acessivel: str, texto: str = "⋯") -> None:
        super().__init__()
        self.setObjectName("mais")
        self.setText(texto)
        self.setAccessibleName(nome_acessivel)
        self.setToolTip(dica_sem_html(nome_acessivel))  # leva o nome da pasta
        self.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.setMenu(menu)
        self.setCursor(Qt.CursorShape.PointingHandCursor)


# --- contêineres -------------------------------------------------------------------------


def transparente(
    layout_cls: type[QHBoxLayout] | type[QVBoxLayout] = QVBoxLayout,
) -> tuple[QWidget, QHBoxLayout | QVBoxLayout]:
    """Widget sem fundo próprio (para agrupar dentro de cartões)."""
    w = QWidget()
    w.setObjectName("transparente")
    lay = layout_cls(w)
    lay.setContentsMargins(0, 0, 0, 0)
    return w, lay


class _SombraDoTema(QObject):
    """Acompanha a troca de tema: ``apply_theme`` troca a paleta e a folha do app, e cada
    widget recebe PaletteChange/StyleChange. A cor da sombra não vem do QSS, então é
    refeita aqui com o token ``sombra`` do tema novo."""

    NOME = "owlSombraDoTema"

    def __init__(self, widget: QWidget) -> None:
        super().__init__(widget)
        self.setObjectName(self.NOME)

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if event.type() in (QEvent.Type.StyleChange, QEvent.Type.PaletteChange) and isinstance(
            obj, QWidget
        ):
            efeito = obj.graphicsEffect()
            if isinstance(efeito, QGraphicsDropShadowEffect):
                cor = QColor(current_tokens()["sombra"])
                if efeito.color() != cor:
                    efeito.setColor(cor)
        return False


def sombra(widget: QWidget) -> None:
    """Sombra dos cartões (QSS não tem box-shadow): blur 24, deslocamento (0, 1).

    Pode ser chamada de novo (reaproveita o efeito); a cor segue a troca de tema sozinha.
    """
    efeito = widget.graphicsEffect()
    if not isinstance(efeito, QGraphicsDropShadowEffect):
        efeito = QGraphicsDropShadowEffect(widget)
        efeito.setBlurRadius(24)
        efeito.setOffset(0, 1)
        widget.setGraphicsEffect(efeito)
    efeito.setColor(QColor(current_tokens()["sombra"]))
    achado = widget.findChild(
        QObject, _SombraDoTema.NOME, Qt.FindChildOption.FindDirectChildrenOnly
    )
    if not isinstance(achado, _SombraDoTema):
        widget.installEventFilter(_SombraDoTema(widget))


def cartao(
    *, nome: str = "cartao", margens: int = 24, espacamento: int = 12, com_sombra: bool = True
) -> tuple[QFrame, QVBoxLayout]:
    """``QFrame#cartao`` com ``QVBoxLayout`` (margens 24, espaçamento 12)."""
    frame = QFrame()
    frame.setObjectName(nome)
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(margens, margens, margens, margens)
    lay.setSpacing(espacamento)
    if com_sombra:
        sombra(frame)
    return frame, lay


class Dica(QFrame):
    """Explicação curta do passo atual (``QFrame#dica``): título em negrito + texto."""

    def __init__(self, titulo_texto: str = "", texto: str = "") -> None:
        super().__init__()
        self.setObjectName("dica")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(4)
        self._titulo = _label("", "rotulo")
        self._texto = _label("", "dicaTexto", selectable=True)
        lay.addWidget(self._titulo)
        lay.addWidget(self._texto)
        self.definir(titulo_texto, texto)

    def definir(self, titulo_texto: str, texto: str) -> None:
        self._titulo.setText(titulo_texto)
        self._titulo.setVisible(bool(titulo_texto))
        self._texto.setText(texto)
        self.setVisible(bool(titulo_texto or texto))


_ALERTA = "⚠"
_VARIACOES = chr(0xFE0E) + chr(0xFE0F)  # seletores de variação: texto e emoji


def _triangulo_alerta() -> QPainterPath:
    """O ícone de alerta do design (visual/referencia-estilo5.html), em coordenadas 24×24:
    triângulo cheio com a barra e o ponto da exclamação vazados."""
    triangulo = QPainterPath()
    triangulo.addPolygon(QPolygonF([QPointF(12, 3), QPointF(1.5, 21), QPointF(22.5, 21)]))
    triangulo.closeSubpath()
    barra = QPainterPath()
    barra.addRoundedRect(QRectF(11, 9, 2, 7), 1, 1)
    ponto = QPainterPath()
    ponto.addEllipse(QPointF(12, 17), 1.2, 1.2)
    return triangulo.subtracted(barra.united(ponto))


class _IconeAviso(QLabel):
    """Ícone do ``Aviso`` (``QLabel#avisoIcone``).

    O "⚠" é DESENHADO (18 px, como no design) na cor do QSS (``color: notice-ink``): como
    caractere, o Windows pode trocá-lo pela fonte de emoji colorida, que ignora o tema.
    Outro ícone passado em texto continua sendo um rótulo comum.
    """

    LADO = 18
    DESCIDA = 1  # o design desce o ícone 1 px para alinhar com a 1ª linha do texto

    def __init__(self, icone: str) -> None:
        super().__init__(icone)
        self.setObjectName("avisoIcone")
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setAccessibleName("Aviso")
        self._desenhado = icone.rstrip(_VARIACOES) == _ALERTA
        if self._desenhado:
            self.setFixedSize(self.LADO, self.LADO + self.DESCIDA)
        else:
            self.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)

    def paintEvent(self, event: QPaintEvent) -> None:
        if not self._desenhado:
            super().paintEvent(event)
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        # a cor vem da folha de estilo (token notice-ink) e muda junto com o tema
        p.setBrush(self.palette().color(QPalette.ColorRole.WindowText))
        p.translate(0, self.DESCIDA)
        p.scale(self.LADO / 24, self.LADO / 24)
        p.drawPath(_triangulo_alerta())
        p.end()


class Aviso(QFrame):
    """Caixa de aviso (``QFrame#aviso``) com ícone de alerta. Aceita texto rico (<b>).

    Ícone e texto ficam juntos num bloco alinhado pelo topo (o ícone na altura da 1ª linha).
    Quem acrescenta um botão ao lado (``layout().addWidget``, como a faixa da lista) tem o
    bloco centralizado na altura do botão.
    """

    def __init__(self, texto: str = "", icone: str = _ALERTA) -> None:
        super().__init__()
        self.setObjectName("aviso")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(12)
        corpo, cl = transparente(QHBoxLayout)
        cl.setSpacing(12)
        self._icone = _IconeAviso(icone)
        self._texto = _label("", "avisoTexto", selectable=True)
        self._texto.setTextFormat(Qt.TextFormat.RichText)
        self._texto.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        cl.addWidget(self._icone, 0, Qt.AlignmentFlag.AlignTop)
        cl.addWidget(self._texto, 1)
        lay.addWidget(corpo, 1, Qt.AlignmentFlag.AlignVCenter)
        self.definir(texto)

    def definir(self, texto: str) -> None:
        self._texto.setText(texto)
        self.setVisible(bool(texto))

    def texto(self) -> str:
        return self._texto.text()


class CartaoLateral(QFrame):
    """Resumo das escolhas já feitas (``QFrame#cartaoLateral``)."""

    def __init__(self, secao: str = "") -> None:
        super().__init__()
        self.setObjectName("cartaoLateral")
        sombra(self)
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(20, 20, 20, 20)
        self._lay.setSpacing(12)
        self._secao = _label(secao.upper(), "secaoLateral")
        self._lay.addWidget(self._secao)
        self._itens: list[QWidget] = []

    def definir_secao(self, secao: str) -> None:
        self._secao.setText(secao.upper())

    def definir_itens(self, itens: Sequence[tuple[str, str, Callable[[], None] | None]]) -> None:
        """``[(chave, valor, ao_alterar|None), ...]`` — valores longos são cortados no meio."""
        for w in self._itens:
            self._lay.removeWidget(w)
            w.hide()  # sem isto o item velho fica desenhado sob o novo até o deleteLater rodar
            w.deleteLater()
        self._itens = []
        for i, (chave, valor, ao_alterar) in enumerate(itens):
            if i:
                linha = QFrame()
                linha.setObjectName("ligacao")
                self._lay.addWidget(linha)
                self._itens.append(linha)
            bloco, lay = transparente()
            lay.setSpacing(4)
            topo, tl = transparente(QHBoxLayout)
            tl.setSpacing(6)
            tl.addWidget(_label(chave, "resumoChave", wrap=False))
            if ao_alterar is not None:
                alt = botao_discreto("alterar")
                alt.setAccessibleName(f"Alterar {chave}")
                alt.clicked.connect(ao_alterar)
                tl.addWidget(alt)
            tl.addStretch(1)
            lay.addWidget(topo)
            valor_lbl = RotuloCortado(valor)
            lay.addWidget(valor_lbl)
            self._lay.addWidget(bloco)
            self._itens.append(bloco)


# --- trilha de passos --------------------------------------------------------------------


class TrilhaPassos(QWidget):
    """Cabeçalho "1 Pastas — 2 Senha — 3 Conferência — 4 Criar", sempre visível."""

    def __init__(self, passos: Sequence[str]) -> None:
        super().__init__()
        self.setObjectName("transparente")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)
        self._numeros: list[QLabel] = []
        self._textos: list[QLabel] = []
        self._ligacoes: list[QFrame] = []
        for i, nome in enumerate(passos):
            if i:
                lig = QFrame()
                lig.setObjectName("ligacao")
                lig.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                lay.addWidget(lig, 1, Qt.AlignmentFlag.AlignVCenter)
                self._ligacoes.append(lig)
            num = QLabel(str(i + 1))
            num.setObjectName("passoNumero")
            txt = QLabel(nome)
            txt.setObjectName("passoTexto")
            txt.setTextFormat(Qt.TextFormat.PlainText)
            lay.addWidget(num, 0, Qt.AlignmentFlag.AlignVCenter)
            lay.addWidget(txt, 0, Qt.AlignmentFlag.AlignVCenter)
            self._numeros.append(num)
            self._textos.append(txt)
        self.atual = 0
        self.definir(0)

    def definir(self, atual: int) -> None:
        self.atual = atual
        for i, (num, txt) in enumerate(zip(self._numeros, self._textos, strict=True)):
            estado = "feito" if i < atual else ("atual" if i == atual else "")
            num.setText("✓" if i < atual else str(i + 1))
            num.setProperty("estado", estado)
            txt.setProperty("estado", "atual" if i == atual else "")
            nome = txt.text()
            situacao = "concluído" if i < atual else ("atual" if i == atual else "a fazer")
            num.setAccessibleName(f"Passo {i + 1}, {nome}: {situacao}")
            repintar(num)
            repintar(txt)
        for i, lig in enumerate(self._ligacoes):
            lig.setProperty("estado", "feito" if i < atual else "")
            repintar(lig)


# --- rodapé ------------------------------------------------------------------------------


class Rodape(QFrame):
    """Rodapé fixo: [Voltar] [primário] [extra…] ……… ● estado."""

    def __init__(self, *, voltar: str = "Voltar", primario: str = "Continuar") -> None:
        super().__init__()
        self.setObjectName("rodape")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(32, 20, 32, 20)
        lay.setSpacing(12)
        self.voltar = botao(voltar)
        self.primario = botao_primario(primario)
        lay.addWidget(self.voltar)
        lay.addWidget(self.primario)
        self.extra = QHBoxLayout()
        self.extra.setSpacing(12)
        lay.addLayout(self.extra)
        lay.addStretch(1)
        self.ponto = QLabel()
        self.ponto.setObjectName("estadoPonto")
        self.texto = QLabel("Pronto.")
        self.texto.setObjectName("estadoTexto")
        self.texto.setTextFormat(Qt.TextFormat.PlainText)  # pode citar nomes de pastas
        self.texto.setWordWrap(False)
        lay.addWidget(self.ponto, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addWidget(self.texto, 0, Qt.AlignmentFlag.AlignVCenter)

    def definir_estado(self, texto: str, estado: str = "") -> None:
        """``estado``: "" (ok), "trabalhando" ou "erro"."""
        self.texto.setText(texto)
        self.texto.setToolTip(dica_sem_html(texto))
        self.ponto.setProperty("estado", estado)
        self.ponto.setAccessibleName(
            {"erro": "Erro", "trabalhando": "Trabalhando"}.get(estado, "Pronto")
        )
        repintar(self.ponto)


# --- campos ------------------------------------------------------------------------------


class _Reposiciona(QObject):
    def __init__(self, campo: QLineEdit, botao_: QPushButton) -> None:
        super().__init__(campo)
        self._campo = campo
        self._botao = botao_

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if event.type() == QEvent.Type.Resize:
            hint = self._botao.sizeHint()
            r = self._campo.rect()
            self._botao.setGeometry(
                r.right() - hint.width() - 10,
                (r.height() - hint.height()) // 2,
                hint.width(),
                hint.height(),
            )
        return False


class CampoSenha(QLineEdit):
    """Campo de senha/PIN com o botão "Mostrar" dentro (à direita)."""

    def __init__(self, placeholder: str, *, digitos: bool = False) -> None:
        super().__init__()
        self.setEchoMode(QLineEdit.EchoMode.Password)
        self.setPlaceholderText(placeholder)
        self.setAccessibleName(placeholder)
        if digitos:
            self.setMaxLength(12)
            self.setInputMethodHints(Qt.InputMethodHint.ImhDigitsOnly)
        self.mostrar = botao_discreto("Mostrar")
        self.mostrar.setParent(self)
        self.mostrar.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.mostrar.setAccessibleName("Mostrar o que foi digitado")
        self.mostrar.clicked.connect(self._alternar)
        self.installEventFilter(_Reposiciona(self, self.mostrar))
        self.setTextMargins(0, 0, self.mostrar.sizeHint().width() + 8, 0)

    def _alternar(self) -> None:
        visivel = self.echoMode() == QLineEdit.EchoMode.Password
        self.setEchoMode(QLineEdit.EchoMode.Normal if visivel else QLineEdit.EchoMode.Password)
        self.mostrar.setText("Ocultar" if visivel else "Mostrar")
        self.setFocus()

    def limpar(self) -> None:
        """``setText("")`` também descarta o histórico de desfazer; volta a ocultar."""
        self.setText("")
        self.setEchoMode(QLineEdit.EchoMode.Password)
        self.mostrar.setText("Mostrar")

    def tomar(self) -> str:
        value = self.text()
        self.limpar()
        return value


class MedidorForca(QWidget):
    """4 blocos + "Força da senha" à esquerda e o veredito à direita. Só informa."""

    _ROTULOS: ClassVar[dict[int, str]] = {
        0: "Muito fraca",
        1: "Fraca",
        2: "Razoável",
        3: "Boa",
        4: "Forte",
    }

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("transparente")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        barras, bl = transparente(QHBoxLayout)
        bl.setSpacing(5)
        self._blocos: list[QFrame] = []
        for _ in range(4):
            f = QFrame()
            f.setObjectName("forca")
            f.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            bl.addWidget(f)
            self._blocos.append(f)
        linha, ll = transparente(QHBoxLayout)
        ll.addWidget(_label("Força da senha", "nota", wrap=False))
        ll.addStretch(1)
        self._veredito = _label("", "forcaTexto", wrap=False)
        ll.addWidget(self._veredito)
        lay.addWidget(barras)
        lay.addWidget(linha)
        self.atualizar("")

    def atualizar(self, senha: str) -> None:
        score = password_strength(senha).score if senha else 0
        ativos = min(4, score)
        nivel = "fraca" if score <= 1 else ""
        for i, f in enumerate(self._blocos):
            f.setProperty("ativo", "sim" if i < ativos else "nao")
            f.setProperty("nivel", nivel)
            repintar(f)
        self._veredito.setText(self._ROTULOS.get(score, "") if senha else "")
        self._veredito.setProperty("nivel", nivel)
        repintar(self._veredito)
        self.setAccessibleDescription(f"Força da senha: {self._veredito.text() or 'vazia'}")


class _LinhaCaminho(QLineEdit):
    """O QLineEdit somente leitura do ``CampoCaminho``.

    Sem foco, quando o caminho não cabe, mostra "…" + o FIM do caminho — o nome da pasta
    escolhida fica sempre à vista. Com foco é o QLineEdit normal (cursor no fim; Home vai ao
    começo). ``text()`` é sempre o caminho inteiro, e ele também fica na dica do mouse.
    """

    # margens internas do QLineEdit (QLineEditPrivate::horizontalMargin/verticalMargin)
    _MARGEM_H = 2
    _MARGEM_V = 1

    def _area_texto(self) -> QRect:
        opt = QStyleOptionFrame()
        self.initStyleOption(opt)
        r = self.style().subElementRect(QStyle.SubElement.SE_LineEditContents, opt, self)
        m = self.textMargins()
        return r.adjusted(
            m.left() + self._MARGEM_H,
            m.top() + self._MARGEM_V,
            -(m.right() + self._MARGEM_H),
            -(m.bottom() + self._MARGEM_V),
        )

    def texto_exibido(self) -> str:
        """O que aparece no campo quando ele não tem foco ("…\\Pasta" se não couber)."""
        texto = self.text()
        if not texto or self.hasFocus():
            return texto
        largura = max(0, self._area_texto().width())
        return self.fontMetrics().elidedText(texto, Qt.TextElideMode.ElideLeft, largura)

    def paintEvent(self, event: QPaintEvent) -> None:
        exibido = self.texto_exibido()
        if exibido == self.text():
            super().paintEvent(event)
            return
        opt = QStyleOptionFrame()
        self.initStyleOption(opt)
        p = QPainter(self)
        # fundo e borda pela folha de estilo, como o próprio QLineEdit faz
        self.style().drawPrimitive(QStyle.PrimitiveElement.PE_PanelLineEdit, opt, p, self)
        area = self._area_texto()
        fm = self.fontMetrics()
        topo = area.y() + (area.height() - fm.height() + 1) // 2  # igual ao QLineEdit
        p.setClipRect(area)
        p.setPen(self.palette().color(QPalette.ColorRole.Text))
        p.drawText(QPointF(area.x(), topo + fm.ascent()), exibido)
        p.end()


class CampoCaminho(QWidget):
    """Caminho escolhido no seletor do Windows (somente leitura) + "Escolher" dentro.

    Caminho longo: o campo mostra o fim (o nome da pasta) e a dica mostra o caminho inteiro.
    """

    escolhido = Signal(str)

    def __init__(self, placeholder: str, titulo_seletor: str) -> None:
        super().__init__()
        self.setObjectName("transparente")
        self._titulo_seletor = titulo_seletor
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.campo: QLineEdit = _LinhaCaminho()
        self.campo.setReadOnly(True)
        self.campo.setPlaceholderText(placeholder)
        self.campo.setAccessibleName(placeholder)
        self.campo.setProperty("caminho", "sim")
        self.botao = botao_discreto("Escolher")
        self.botao.setParent(self.campo)
        self.botao.setAccessibleName(f"Escolher: {placeholder}")
        self.botao.clicked.connect(self._escolher)
        self.campo.installEventFilter(_Reposiciona(self.campo, self.botao))
        self.campo.setTextMargins(0, 0, self.botao.sizeHint().width() + 8, 0)
        lay.addWidget(self.campo)

    def _escolher(self) -> None:
        path = choose_folder(self, self._titulo_seletor, self.campo.text())
        if path:
            self.definir(path)
            self.escolhido.emit(path)

    def definir(self, path: str) -> None:
        self.campo.setText(path)
        self.campo.setToolTip(dica_sem_html(path))
        # cursor no FIM: com foco (ou caminho que não cabe) o que aparece é o nome da pasta
        self.campo.setCursorPosition(len(path))

    def texto(self) -> str:
        return self.campo.text().strip()


class LinhaChecagem(QWidget):
    """Uma verificação da conferência: ícone + título + uma linha de detalhe."""

    _ICONES: ClassVar[dict[str, str]] = {"ok": "✓", "falhou": "✕", "aviso": "!", "": "•"}

    def __init__(self, titulo_texto: str, detalhe: str = "", estado: str = "") -> None:
        super().__init__()
        self.setObjectName("transparente")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 4, 0, 4)
        lay.setSpacing(12)
        self.icone = QLabel()
        self.icone.setObjectName("checagemIcone")
        lay.addWidget(self.icone, 0, Qt.AlignmentFlag.AlignTop)
        textos, tl = transparente()
        tl.setSpacing(2)
        self.titulo = _label(titulo_texto, "checagemTitulo")
        self.detalhe = _label("", "nota", selectable=True)
        tl.addWidget(self.titulo)
        tl.addWidget(self.detalhe)
        lay.addWidget(textos, 1)
        self.definir(estado, detalhe)

    def definir(self, estado: str, detalhe: str = "") -> None:
        """``estado``: "ok", "falhou", "aviso" ou "" (ainda não rodou)."""
        self.icone.setText(self._ICONES.get(estado, "•"))
        self.icone.setProperty("estado", estado)
        situacao = {"ok": "passou", "falhou": "falhou", "aviso": "atenção"}.get(estado, "pendente")
        self.icone.setAccessibleName(f"{self.titulo.text()}: {situacao}")
        repintar(self.icone)
        self.detalhe.setText(detalhe)
        self.detalhe.setVisible(bool(detalhe))


class Marca(QWidget):
    """Coruja + "Owl Vault" (Vault em roxo) — topo da janela."""

    def __init__(self, tamanho: int = 32) -> None:
        super().__init__()
        self.setObjectName("transparente")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        owl = QLabel()
        owl.setPixmap(hidpi(lambda px: owl_image(px), tamanho))
        owl.setFixedSize(tamanho, tamanho)
        owl.setAccessibleName("Owl Vault")
        lay.addWidget(owl)
        a = QLabel("Owl")
        a.setObjectName("marca")
        b = QLabel("Vault")
        b.setObjectName("marcaRoxo")
        lay.addWidget(a)
        lay.addWidget(b)
        lay.addStretch(1)


def lista_detalhes(itens: Sequence[str], altura: int = 140) -> QPlainTextEdit:
    """Lista somente leitura (nomes de arquivos etc.)."""
    text = QPlainTextEdit()
    text.setReadOnly(True)
    text.setPlainText("\n".join(f"• {i}" for i in itens))
    text.setMinimumHeight(min(altura, 28 + 20 * max(1, len(itens))))
    text.setMaximumHeight(altura + 80)
    text.setAccessibleName("Detalhes")
    return text
