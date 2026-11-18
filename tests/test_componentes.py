"""Componentes do tema "Cofre" (ui/componentes.py + ui/tema/owlvault.qss) renderizados de verdade.

Plataforma offscreen, nos dois temas, só widgets sintéticos (nenhuma pasta, nenhum perfil).
Cada teste confere pixels ou formatos que a revisão visual apontou como errados.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator

import pytest
from PySide6 import QtGui
from PySide6.QtCore import SIGNAL, QCoreApplication, QEvent, QPoint, QRect, Qt
from PySide6.QtGui import QColor, QImage, QPalette, QTextDocument
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QStyleFactory,
    QVBoxLayout,
    QWidget,
)

from owl_vault.ui import common
from owl_vault.ui import componentes as C
from owl_vault.ui.theme import apply_theme, current_tokens

pytestmark = pytest.mark.gui

CAMINHO_LONGO = (
    "C:\\Users\\Ana Beatriz\\OneDrive - Empresa Exemplo Ltda\\Documentos\\Projetos 2026"
    "\\Clientes\\Contratos assinados"
)
NOME_HTML = "<i>Cofre</i>"


# =========================================================================== utilidades Qt


@pytest.fixture(scope="module")
def qapp() -> Iterator[QApplication]:
    """Uma QApplication por módulo, sem janela real (plataforma offscreen)."""
    anterior = os.environ.get("QT_QPA_PLATFORM")
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")
    app = QApplication.instance() or QApplication(["owl-vault-testes-componentes"])
    assert isinstance(app, QApplication)
    yield app
    _pump()
    if anterior is None:
        os.environ.pop("QT_QPA_PLATFORM", None)
    else:
        os.environ["QT_QPA_PLATFORM"] = anterior


@pytest.fixture(params=["dark", "light"])
def tema(request: pytest.FixtureRequest, qapp: QApplication) -> Iterator[str]:
    """Aplica o tema (QSS + paleta + estilo) e devolve o aplicativo como estava."""
    folha, paleta, estilo = qapp.styleSheet(), qapp.palette(), qapp.style().name()
    anterior = qapp.property("owlTheme")
    apply_theme(qapp, request.param)
    yield str(request.param)
    qapp.setStyleSheet(folha)
    qapp.setStyle(QStyleFactory.create(estilo) or QStyleFactory.create("Fusion"))
    qapp.setPalette(paleta)
    qapp.setProperty("owlTheme", anterior)
    _pump()


@pytest.fixture
def guarda(qapp: QApplication) -> Iterator[Callable[[QWidget], QWidget]]:
    """Registra janelas criadas no teste; no fim, fecha e descarta todas."""
    criadas: list[QWidget] = []

    def guardar(w: QWidget) -> QWidget:
        criadas.append(w)
        return w

    yield guardar
    for w in criadas:
        w.hide()
        w.deleteLater()
    _pump()


def _pump(n: int = 6) -> None:
    for _ in range(n):
        QCoreApplication.processEvents()
        QCoreApplication.sendPostedEvents(None, int(QEvent.Type.DeferredDelete.value))


def _cor(img: QImage, x: int, y: int) -> str:
    return img.pixelColor(x, y).name()


def _perto(a: QColor, b: QColor, tolerancia: int = 10) -> bool:
    return (
        abs(a.red() - b.red()) <= tolerancia
        and abs(a.green() - b.green()) <= tolerancia
        and abs(a.blue() - b.blue()) <= tolerancia
    )


def _faixa_de_tinta(img: QImage, area: QRect, fundo: QColor) -> tuple[int, int]:
    """Primeira e última linha (y) de ``area`` com pixel bem diferente do fundo."""
    ys = []
    for y in range(area.top(), area.bottom() + 1):
        for x in range(area.left(), area.right() + 1):
            c = img.pixelColor(x, y)
            dif = (
                abs(c.red() - fundo.red())
                + abs(c.green() - fundo.green())
                + abs(c.blue() - fundo.blue())
            )
            if dif > 60:
                ys.append(y)
                break
    assert ys, "nenhuma tinta encontrada"
    return min(ys), max(ys)


def _como_aparece_na_dica(dica: str) -> str:
    """O texto que a dica do mouse mostra (o Qt detecta HTML do mesmo jeito)."""
    doc = QTextDocument()
    if QtGui.Qt.mightBeRichText(dica):
        doc.setHtml(dica)
    else:
        doc.setPlainText(dica)
    return doc.toPlainText().replace("\u00a0", " ")


def _janela(
    guarda: Callable[[QWidget], QWidget], largura: int = 640
) -> tuple[QWidget, QVBoxLayout]:
    w = guarda(QWidget())
    w.setObjectName("transparente")
    w.resize(largura, 400)
    lay = QVBoxLayout(w)
    return w, lay


# =========================================================================== visual-1: menus


@pytest.mark.parametrize(
    "conteiner", ["cartao", "cartaoLateral", "dica", "aviso", "rodape", "linhaPasta"]
)
def test_menu_com_pai_dentro_de_conteiner_tem_fundo_do_tema(
    tema: str, guarda: Callable[[QWidget], QWidget], conteiner: str
) -> None:
    """Menu ⋯ da linha e menus de botão direito saíam sem fundo (preto no Windows)."""
    cartao = guarda(QFrame())
    cartao.setObjectName("cartao")
    caixa = QFrame(cartao)
    caixa.setObjectName(conteiner)
    filho = QWidget(caixa)
    menu = QMenu(filho)
    menu.addAction("Verificar arquivos")
    menu.ensurePolished()
    fundo = menu.palette().color(QPalette.ColorRole.Window)
    assert fundo.alpha() == 255, (conteiner, fundo.name(QColor.NameFormat.HexArgb))
    assert fundo.name() == current_tokens()["panel"], conteiner
    assert menu.palette().color(QPalette.ColorRole.WindowText).name() == current_tokens()["ink"]


def test_menu_da_linha_pinta_o_fundo_de_verdade(
    tema: str, guarda: Callable[[QWidget], QWidget]
) -> None:
    """Backing store real da janela popup (RGB32, como no Windows): nada de preto."""
    w, lay = _janela(guarda)
    card, cl = C.cartao()
    linha = QFrame()
    linha.setObjectName("linhaPasta")
    menu = QMenu(linha)
    for texto in ("Esconder do Explorer", "Verificar arquivos", "Remover proteção…"):
        menu.addAction(texto)
    mais = C.BotaoMais(menu, "Mais opções")
    QVBoxLayout(linha).addWidget(mais)
    cl.addWidget(linha)
    lay.addWidget(card)
    w.show()
    _pump()
    menu.popup(mais.mapToGlobal(QPoint(0, mais.height())))
    _pump()
    screen = QApplication.primaryScreen()
    assert screen is not None
    img = screen.grabWindow(menu.winId()).toImage()
    menu.hide()
    painel = current_tokens()["panel"]
    for x, y in ((6, 6), (img.width() - 8, img.height() // 2), (img.width() // 2, 3)):
        assert _cor(img, x, y) == painel, (x, y, _cor(img, x, y))


def test_menu_de_contexto_de_campo_no_cartao_tem_fundo(
    tema: str, guarda: Callable[[QWidget], QWidget]
) -> None:
    w, lay = _janela(guarda)
    card, cl = C.cartao()
    campo = QLineEdit("texto")
    cl.addWidget(campo)
    lay.addWidget(card)
    w.show()
    _pump()
    ctx = campo.createStandardContextMenu()
    assert ctx is not None
    ctx.ensurePolished()
    assert ctx.palette().color(QPalette.ColorRole.Window).name() == current_tokens()["panel"]
    assert ctx.palette().color(QPalette.ColorRole.Window).alpha() == 255
    ctx.deleteLater()


# =========================================================================== visual-7: linha


def _linha_no_cartao(guarda: Callable[[QWidget], QWidget]) -> tuple[QWidget, QFrame, QPushButton]:
    w, lay = _janela(guarda)
    card, cl = C.cartao()
    linha = QFrame()
    linha.setObjectName("linhaPasta")
    ll = QVBoxLayout(linha)
    ll.setContentsMargins(16, 24, 16, 24)
    ll.addWidget(QLabel("Contratos"))
    resolver = C.botao("Resolver…")
    ll.addWidget(resolver)
    ll.addWidget(C.BotaoMais(QMenu(linha), "Mais opções de Contratos"))
    cl.addWidget(linha)
    lay.addWidget(card)
    w.show()
    _pump()
    return w, linha, resolver


def test_linha_da_lista_tem_fundo_panel_alt(
    tema: str, guarda: Callable[[QWidget], QWidget]
) -> None:
    """``QFrame#cartao QWidget`` (transparente) apagava o fundo panel-alt da linha."""
    w, linha, _ = _linha_no_cartao(guarda)
    img = w.grab().toImage()
    p = linha.mapTo(w, QPoint(0, 0))
    dentro = _cor(img, p.x() + linha.width() - 12, p.y() + 10)  # longe dos filhos e da borda
    assert dentro == current_tokens()["panel-alt"]
    assert dentro != current_tokens()["panel"]


def test_hover_de_botao_dentro_da_linha_continua_visivel(
    tema: str, guarda: Callable[[QWidget], QWidget]
) -> None:
    """Com a linha em panel-alt, o hover (antes também panel-alt) sumiria."""
    w, _linha, resolver = _linha_no_cartao(guarda)
    ponto = resolver.mapTo(w, QPoint(10, resolver.height() // 2))  # fundo, longe do texto
    QTest.mouseMove(resolver, QPoint(resolver.width() // 2, resolver.height() // 2))
    _pump()
    assert resolver.underMouse()
    fundo = _cor(w.grab().toImage(), ponto.x(), ponto.y())
    assert fundo != current_tokens()["panel-alt"]
    assert fundo == current_tokens()["border"]
    # o ⋯ da linha: mesmo problema (o hover dele também era panel-alt)
    mais = w.findChild(C.BotaoMais)
    assert mais is not None
    QTest.mouseMove(mais, QPoint(mais.width() // 2, mais.height() // 2))
    _pump()
    assert mais.underMouse()
    ponto = mais.mapTo(w, QPoint(10, mais.height() // 2))  # dentro do círculo, longe do "⋯"
    assert _cor(w.grab().toImage(), ponto.x(), ponto.y()) == current_tokens()["border"]
    QTest.mouseMove(w, QPoint(2, 2))
    _pump()


# =========================================================================== visual-8: aviso


def test_aviso_icone_16px_cor_do_tema_e_alinhado_ao_texto(
    tema: str, guarda: Callable[[QWidget], QWidget]
) -> None:
    """Faixa da lista: o ⚠ ficava 16 px acima do texto (botão de 50 px ao lado) e com 13 px."""
    w, lay = _janela(guarda, 720)
    aviso = C.Aviso("1 pasta está aberta e visível neste computador.")
    botao = C.botao("Trancar agora")
    caixa = aviso.layout()
    assert caixa is not None
    caixa.addWidget(botao)  # como pages.HomePage faz com "Trancar agora"
    lay.addWidget(aviso)
    lay.addStretch(1)
    w.show()
    _pump()
    icone = aviso.findChild(QLabel, "avisoIcone")
    texto = aviso.findChild(QLabel, "avisoTexto")
    assert icone is not None and texto is not None
    assert icone.font().pixelSize() == 16  # "QFrame#aviso QLabel" (13px) não vence mais
    img = w.grab().toImage()
    fundo = QColor(current_tokens()["notice-bg"])
    ri = QRect(icone.mapTo(w, QPoint(0, 0)), icone.size())
    rt = QRect(texto.mapTo(w, QPoint(0, 0)), texto.size())
    rt.setWidth(min(200, rt.width()))
    yi = _faixa_de_tinta(img, ri, fundo)
    yt = _faixa_de_tinta(img, rt, fundo)
    centro_i, centro_t = (yi[0] + yi[1]) / 2, (yt[0] + yt[1]) / 2
    assert abs(centro_i - centro_t) <= 3, (yi, yt)
    # o triângulo é desenhado com o token notice-ink (a fonte de emoji ignoraria o tema)
    ponto = ri.topLeft() + QPoint(6, 15)  # dentro do triângulo, fora da exclamação
    assert _perto(img.pixelColor(ponto), QColor(current_tokens()["notice-ink"]), 8)


def test_aviso_de_varias_linhas_icone_na_primeira_linha(
    tema: str, guarda: Callable[[QWidget], QWidget]
) -> None:
    w, lay = _janela(guarda, 420)
    aviso = C.Aviso(
        "O cofre é uma <b>cópia</b> criptografada. A pasta original continua legível até "
        "você removê-la — e, mesmo removida, podem restar cópias dela na Lixeira."
    )
    lay.addWidget(aviso)
    lay.addStretch(1)
    w.show()
    _pump()
    icone = aviso.findChild(QLabel, "avisoIcone")
    texto = aviso.findChild(QLabel, "avisoTexto")
    assert icone is not None and texto is not None
    assert texto.textFormat() == Qt.TextFormat.RichText  # o Aviso aceita <b> (quem chama escapa)
    img = w.grab().toImage()
    fundo = QColor(current_tokens()["notice-bg"])
    yi = _faixa_de_tinta(img, QRect(icone.mapTo(w, QPoint(0, 0)), icone.size()), fundo)
    rt = QRect(texto.mapTo(w, QPoint(0, 0)), texto.size())
    yt = _faixa_de_tinta(img, rt, fundo)
    assert yt[1] - yt[0] > 30  # o texto quebrou em várias linhas
    assert abs(yi[0] - yt[0]) <= 4, (yi, yt)  # ícone na altura da 1ª linha


# =========================================================================== visual-12: foco


@pytest.mark.parametrize("nome", ["", "log"])
def test_foco_de_teclado_visivel_na_lista_de_detalhes_e_no_registro(
    tema: str, guarda: Callable[[QWidget], QWidget], nome: str
) -> None:
    w, lay = _janela(guarda)
    card, cl = C.cartao()
    if nome:
        lista = QPlainTextEdit()
        lista.setObjectName(nome)
        lista.setReadOnly(True)
        lista.setPlainText("12:00:00  Conferindo…")
    else:
        lista = C.lista_detalhes(["arquivo-1.txt", "arquivo-2.txt", "arquivo-3.txt"])
    outro = C.botao("OK")
    cl.addWidget(lista)
    cl.addWidget(outro)
    lay.addWidget(card)
    w.show()
    w.activateWindow()
    _pump()
    outro.setFocus(Qt.FocusReason.TabFocusReason)
    _pump()
    sem = lista.grab().toImage()
    lista.setFocus(Qt.FocusReason.TabFocusReason)
    _pump()
    assert lista.hasFocus()
    com = lista.grab().toImage()
    y = com.height() // 2
    assert _cor(com, 1, y) == current_tokens()["focus"]  # borda de 2px na cor de foco
    assert _cor(sem, 1, y) != current_tokens()["focus"]


# =========================================================================== visual-13: caminho


def test_campo_caminho_longo_mostra_o_nome_da_pasta(
    tema: str, guarda: Callable[[QWidget], QWidget]
) -> None:
    w, lay = _janela(guarda, 560)
    cc = C.CampoCaminho("Pasta que será copiada", "Escolher a pasta")
    outro = C.botao("OK")
    lay.addWidget(cc)
    lay.addWidget(outro)
    w.show()
    w.activateWindow()
    _pump()
    cc.definir(CAMINHO_LONGO)
    outro.setFocus()
    _pump()
    campo = cc.campo
    assert campo.text() == CAMINHO_LONGO  # a lógica continua com o caminho inteiro
    assert cc.texto() == CAMINHO_LONGO
    assert _como_aparece_na_dica(campo.toolTip()) == CAMINHO_LONGO
    assert campo.cursorPosition() == len(CAMINHO_LONGO)  # antes: 0 (mostrava o começo)
    assert isinstance(campo, C._LinhaCaminho)
    exibido = campo.texto_exibido()
    assert exibido.startswith("…")
    assert exibido.endswith("Clientes\\Contratos assinados")
    assert campo.fontMetrics().horizontalAdvance(exibido) <= campo.width()
    campo.setFocus(Qt.FocusReason.TabFocusReason)
    _pump()
    assert campo.hasFocus()
    assert campo.texto_exibido() == CAMINHO_LONGO  # com foco, o QLineEdit normal
    assert campo.cursorPosition() == len(CAMINHO_LONGO)  # ...rolado até o fim


def test_campo_caminho_curto_e_vazio_aparecem_inteiros(
    tema: str, guarda: Callable[[QWidget], QWidget]
) -> None:
    w, lay = _janela(guarda, 560)
    cc = C.CampoCaminho("Pasta que será copiada", "Escolher a pasta")
    lay.addWidget(cc)
    w.show()
    _pump()
    cc.definir("C:\\Dados\\Fotos")
    _pump()
    assert isinstance(cc.campo, C._LinhaCaminho)
    assert cc.campo.texto_exibido() == "C:\\Dados\\Fotos"
    cc.definir("")
    _pump()
    assert cc.campo.texto_exibido() == ""
    assert cc.campo.toolTip() == ""


# =========================================================================== copia-10: texto puro


def test_rotulos_com_texto_do_usuario_nunca_viram_html(qapp: QApplication) -> None:
    """ "<i>Cofre</i>" digitado como nome aparecia "Cofre" em itálico no resumo lateral."""
    rc = C.RotuloCortado(NOME_HTML)
    assert rc.textFormat() == Qt.TextFormat.PlainText
    assert _como_aparece_na_dica(rc.toolTip()) == NOME_HTML
    rc.set_full_text("<b>A</b>&nbsp;B")
    assert _como_aparece_na_dica(rc.toolTip()) == "<b>A</b>&nbsp;B"

    lateral = C.CartaoLateral("Escolhas do passo 1")
    lateral.definir_itens([("Nome do cofre", NOME_HTML, None)])
    valores = lateral.findChildren(QLabel, "resumoValor")
    assert valores and all(v.textFormat() == Qt.TextFormat.PlainText for v in valores)

    chk = C.LinhaChecagem("<b>Destino</b>", f"Pasta {NOME_HTML}", "falhou")
    assert chk.titulo.textFormat() == Qt.TextFormat.PlainText
    assert chk.detalhe.textFormat() == Qt.TextFormat.PlainText

    e = C.erro()
    C.mostrar_erro(e, f"O nome {NOME_HTML} não serve")
    assert e.textFormat() == Qt.TextFormat.PlainText

    for lbl in (
        C.titulo(NOME_HTML),
        C.subtitulo(NOME_HTML),
        C.rotulo(NOME_HTML),
        C.nota(NOME_HTML),
    ):
        assert lbl.textFormat() == Qt.TextFormat.PlainText, lbl.objectName()

    dica = C.Dica(NOME_HTML, NOME_HTML)
    assert all(lbl.textFormat() == Qt.TextFormat.PlainText for lbl in dica.findChildren(QLabel))

    rod = C.Rodape()
    rod.definir_estado(f"Conferindo {NOME_HTML}…", "trabalhando")
    assert rod.texto.textFormat() == Qt.TextFormat.PlainText
    assert _como_aparece_na_dica(rod.texto.toolTip()) == f"Conferindo {NOME_HTML}…"

    mais = C.BotaoMais(QMenu(), f"Mais opções de {NOME_HTML}")
    assert _como_aparece_na_dica(mais.toolTip()) == f"Mais opções de {NOME_HTML}"
    assert mais.accessibleName() == f"Mais opções de {NOME_HTML}"

    cc = C.CampoCaminho("Pasta", "Escolher")
    cc.definir(f"C:\\{NOME_HTML}")
    assert _como_aparece_na_dica(cc.campo.toolTip()) == f"C:\\{NOME_HTML}"


def test_dica_sem_html_mantem_texto_comum_igual() -> None:
    assert C.dica_sem_html("") == ""
    assert C.dica_sem_html("C:\\Dados\\Fotos") == "C:\\Dados\\Fotos"
    assert C.dica_sem_html("Mais opções de Fotos") == "Mais opções de Fotos"
    assert _como_aparece_na_dica(C.dica_sem_html("a  <i>b</i>\nc")) == "a  <i>b</i>\nc"


# =========================================================================== C6: troca de tema


def test_sombra_do_cartao_acompanha_a_troca_de_tema(
    tema: str, qapp: QApplication, guarda: Callable[[QWidget], QWidget]
) -> None:
    card, _ = C.cartao()
    guarda(card)
    efeito = card.graphicsEffect()
    assert efeito is not None
    assert efeito.color().name(QColor.NameFormat.HexArgb) == current_tokens()["sombra"]
    outro = "light" if tema == "dark" else "dark"
    apply_theme(qapp, outro)  # o fixture devolve o tema anterior no fim
    _pump()
    assert card.graphicsEffect() is efeito
    assert efeito.color().name(QColor.NameFormat.HexArgb) == current_tokens()["sombra"]
    # chamar de novo (como a janela faz ao trocar o tema) reaproveita o efeito e o gancho
    C.sombra(card)
    C.sombra(card)
    assert card.graphicsEffect() is efeito
    ganchos = card.findChildren(
        C._SombraDoTema, C._SombraDoTema.NOME, Qt.FindChildOption.FindDirectChildrenOnly
    )
    assert len(ganchos) == 1


# =========================================================================== v3-visual-2: foco


def _rolagem_baixa(
    guarda: Callable[[QWidget], QWidget], alvo: QWidget, *, antes: int = 300
) -> tuple[QWidget, common.Rolagem, QPushButton]:
    """Janela com uma ``Rolagem`` baixa (120 px) e o botão FORA dela, embaixo, como nos
    diálogos. ``alvo`` fica no conteúdo, ``antes`` px abaixo do topo (fora da vista)."""
    w, lay = _janela(guarda, 480)
    conteudo, cl = C.transparente()
    cl.setSpacing(0)
    cl.setContentsMargins(0, 0, 0, 0)
    calco = QLabel("texto longo do diálogo")
    calco.setFixedHeight(antes)
    cl.addWidget(calco)
    cl.addWidget(alvo)
    cl.addSpacing(200)
    rolagem = common.Rolagem(conteudo)
    rolagem.setFixedHeight(120)
    lay.addWidget(rolagem)
    botao = C.botao("Fechar")
    lay.addWidget(botao)
    lay.addStretch(1)
    QWidget.setTabOrder(botao, alvo)
    w.show()
    w.activateWindow()
    _pump()
    botao.setFocus(Qt.FocusReason.TabFocusReason)
    _pump()
    rolagem.verticalScrollBar().setValue(0)  # o foco inicial (no conteúdo) já pode ter rolado
    _pump()
    return w, rolagem, botao


def _visivel(rolagem: common.Rolagem, alvo: QWidget) -> int:
    """Quantos px de altura de ``alvo`` aparecem no viewport da Rolagem."""
    vista = rolagem.viewport()
    y = alvo.mapTo(vista, QPoint(0, 0)).y()
    return max(0, min(vista.height(), y + alvo.height()) - max(0, y))


@pytest.mark.parametrize("como", ["tab", "setFocus"])
def test_rolagem_traz_para_a_vista_o_campo_focado_vindo_de_fora(
    tema: str, qapp: QApplication, guarda: Callable[[QWidget], QWidget], como: str
) -> None:
    """O Tab que entrava na Rolagem vindo dos botões (fora dela) não rolava: a lista
    "Detalhes" ficava com o foco fora da vista (Resolver "apagando" em 1366x768 a 125%)."""
    lista = C.lista_detalhes([f"arquivo-{i}.txt" for i in range(3)], altura=80)
    _w, rolagem, botao = _rolagem_baixa(guarda, lista)
    assert botao.hasFocus()
    assert rolagem.verticalScrollBar().value() == 0
    assert _visivel(rolagem, lista) == 0  # começa fora da vista
    if como == "tab":
        QTest.keyClick(botao, Qt.Key.Key_Tab)
    else:
        lista.setFocus(Qt.FocusReason.TabFocusReason)
    _pump()
    assert qapp.focusWidget() is lista
    assert _visivel(rolagem, lista) > 0
    assert _visivel(rolagem, lista) == lista.height()  # cabe na vista: aparece inteira


def test_rolagem_campo_mais_alto_que_a_vista_mostra_o_comeco(
    tema: str, qapp: QApplication, guarda: Callable[[QWidget], QWidget]
) -> None:
    """Uma lista mais alta que a vista: o começo dela (onde está o cursor) no alto."""
    lista = C.lista_detalhes([f"arquivo-{i}.txt" for i in range(40)], altura=260)
    _w, rolagem, botao = _rolagem_baixa(guarda, lista)
    assert lista.height() > rolagem.viewport().height()
    assert _visivel(rolagem, lista) == 0
    QTest.keyClick(botao, Qt.Key.Key_Tab)
    _pump()
    assert qapp.focusWidget() is lista
    y = lista.mapTo(rolagem.viewport(), QPoint(0, 0)).y()
    assert 0 <= y <= common.MARGEM_DO_FOCO  # o começo da lista (e o cursor) no alto da vista
    assert _visivel(rolagem, lista) >= rolagem.viewport().height() - common.MARGEM_DO_FOCO


def test_rolagem_nao_pula_no_clique_e_solta_a_conexao_ao_ser_destruida(
    tema: str, qapp: QApplication, guarda: Callable[[QWidget], QWidget]
) -> None:
    """Um clique num botão meio à vista não rola (o botão sairia debaixo do ponteiro e o
    clique se perderia); destruída a Rolagem, o ``focusChanged`` não a chama mais."""
    sinal = SIGNAL("focusChanged(QWidget*,QWidget*)")
    antes = qapp.receivers(sinal)
    dentro = C.botao("Ver detalhes")
    _w, rolagem, botao = _rolagem_baixa(guarda, dentro, antes=100)  # só o alto à vista
    assert qapp.receivers(sinal) == antes + 1
    assert 0 < _visivel(rolagem, dentro) < dentro.height()
    cliques: list[bool] = []
    dentro.clicked.connect(lambda: cliques.append(True))
    # pela janela (como o Windows entrega): o Qt sabe que o botão do mouse está apertado
    janela = dentro.window().windowHandle()
    assert janela is not None
    # perto da borda da vista: se o conteúdo rolasse, o botão sairia de baixo do ponteiro
    ponto = dentro.mapTo(
        dentro.window(), QPoint(dentro.width() // 2, _visivel(rolagem, dentro) - 2)
    )
    QTest.mouseClick(janela, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, ponto)
    _pump()
    assert dentro.hasFocus()
    assert cliques == [True]
    assert rolagem.verticalScrollBar().value() == 0
    rolagem.deleteLater()
    _pump()
    assert qapp.receivers(sinal) == antes
    botao.setFocus(Qt.FocusReason.TabFocusReason)  # nada de "objeto C++ já apagado"
    _pump()
    assert botao.hasFocus()


def test_rolagem_lista_rolada_por_dentro_continua_a_vista_no_tab(
    tema: str, qapp: QApplication, guarda: Callable[[QWidget], QWidget]
) -> None:
    """Lista "Detalhes" rolada por dentro (o cursor fica no começo, FORA da lista): o Tab
    vindo dos botões mostra a lista, e não o retângulo do cursor (que levava o corpo para
    longe dela)."""
    lista = C.lista_detalhes([f"arquivo-{i}.txt" for i in range(60)], altura=80)
    _w, rolagem, botao = _rolagem_baixa(guarda, lista)
    lista.verticalScrollBar().setValue(lista.verticalScrollBar().maximum())
    _pump()
    assert _visivel(rolagem, lista) == 0
    QTest.keyClick(botao, Qt.Key.Key_Tab)
    _pump()
    assert qapp.focusWidget() is lista
    assert _visivel(rolagem, lista) == lista.height()


def test_rolagem_tab_dentro_dela_mostra_a_lista_rolada_por_dentro(
    tema: str, qapp: QApplication, guarda: Callable[[QWidget], QWidget]
) -> None:
    """Tab que anda DENTRO da Rolagem (do botão "Detalhes" para a lista, como em "Versão
    anterior" e "Trancar mesmo assim"): o QScrollArea seguia o cursor da lista rolada por
    dentro (fora dela) e a lista sumia da vista."""
    w, lay = _janela(guarda, 480)
    conteudo, cl = C.transparente()
    cl.setSpacing(0)
    cl.setContentsMargins(0, 0, 0, 0)
    calco = QLabel("texto longo do diálogo")
    calco.setFixedHeight(300)
    cl.addWidget(calco)
    detalhes = C.botao("Detalhes")
    cl.addWidget(detalhes)
    lista = C.lista_detalhes([f"arquivo-{i}.txt" for i in range(60)], altura=80)
    cl.addWidget(lista)
    cl.addSpacing(200)
    rolagem = common.Rolagem(conteudo)
    rolagem.setFixedHeight(120)
    lay.addWidget(rolagem)
    lay.addStretch(1)
    QWidget.setTabOrder(detalhes, lista)
    w.show()
    w.activateWindow()
    _pump()
    detalhes.setFocus(Qt.FocusReason.TabFocusReason)
    _pump()
    lista.verticalScrollBar().setValue(lista.verticalScrollBar().maximum())
    rolagem.verticalScrollBar().setValue(300)  # o botão "Detalhes" no alto da vista
    _pump()
    QTest.keyClick(detalhes, Qt.Key.Key_Tab)
    _pump()
    assert qapp.focusWidget() is lista
    assert _visivel(rolagem, lista) == lista.height()


def test_rolagem_nao_rola_no_foco_inicial_nem_na_volta_a_janela(
    tema: str, qapp: QApplication, guarda: Callable[[QWidget], QWidget]
) -> None:
    """O foco que chega de outra janela (o diálogo acabou de abrir) ou do nada (a janela
    voltou a ficar ativa) não rola: o diálogo abre no topo, com o título e o texto à vista,
    e quem rolou para ler não perde o lugar."""
    lista = C.lista_detalhes([f"arquivo-{i}.txt" for i in range(3)], altura=80)
    _w, rolagem, _botao = _rolagem_baixa(guarda, lista)
    _outra, lay_outra = _janela(guarda, 200)
    de_fora = C.botao("Na janela principal")
    lay_outra.addWidget(de_fora)
    barra = rolagem.verticalScrollBar()
    assert barra.value() == 0 and _visivel(rolagem, lista) == 0
    rolagem._mostra_foco(de_fora, lista)  # foco inicial: veio de outra janela
    assert barra.value() == 0
    rolagem._mostra_foco(None, lista)  # a janela voltou a ficar ativa
    assert barra.value() == 0
