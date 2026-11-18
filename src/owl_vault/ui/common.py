"""Peças compartilhadas da interface: seletor de pasta, formatação, campos e tela de progresso.

Os helpers antigos (``title_label``, ``body``, ``hint``, ``link_button``, ``primary_button``,
``error_label``, ``brand_header``) continuam aqui para quem ainda os usa, mas produzem os
``objectName`` do tema "Cofre" (``titulo``, ``subtitulo``, ``nota``, ``discreto``, ``primario``,
``erro``, ``marca``/``marcaRoxo``) — as cores vêm só do QSS (``ui/tema/owlvault.qss``).
"""

from __future__ import annotations

import html
import math
import os
import time
from collections.abc import Callable, Sequence

from PySide6.QtCore import (
    QEvent,
    QObject,
    QPoint,
    QRect,
    QSettings,
    QSize,
    Qt,
    SignalInstance,
    Slot,
)
from PySide6.QtGui import (
    QCloseEvent,
    QColor,
    QGuiApplication,
    QImage,
    QKeyEvent,
    QPixmap,
    QResizeEvent,
    QShowEvent,
    QTextBlock,
    QTextBlockFormat,
    QTextCharFormat,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
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


#: folga para a moldura do Windows (barra de título e bordas) ao caber na área útil da tela
FOLGA_MOLDURA = 80
FOLGA_LARGURA = 16
#: o mínimo que a barra de título e as bordas ocupam: passar disso tira a janela da tela
FOLGA_TITULO = 40
#: o corpo (``Rolagem``) de um diálogo encolhido para caber na tela fica com pelo menos isto
#: (ou menos, se o conteúdo inteiro for menor)
CORPO_MINIMO = 120
#: numa tela baixa demais até para isso, o corpo encolhe até aqui (e rola): os botões
#: continuam inteiros à vista
CORPO_APERTADO = 64
#: altura máxima de um QWidget no Qt (QWIDGETSIZE_MAX): a Rolagem sem teto
SEM_TETO = 16777215
#: folga em volta do campo focado que a ``Rolagem`` traz para a vista
MARGEM_DO_FOCO = 8


def area_util(window: QWidget) -> QRect | None:
    """Área útil da tela onde a janela está (sem a barra de tarefas), em pixels lógicos."""
    screen = window.screen() or QGuiApplication.primaryScreen()
    return screen.availableGeometry() if screen is not None else None


def fit_to_content(window: QWidget, width: int, *, clamp_to_screen: bool = True) -> None:
    """Tamanho fixo pelo conteúdo, como o QMessageBox: largura ``width`` (ou mais, se o
    conteúdo pedir) e a altura que os textos com quebra de linha precisam NESSA largura.

    Sem isso o Qt mede os textos numa largura menor (sobra um vão) e ainda limita a janela a
    2/3 da tela (corta texto). ``clamp_to_screen`` (padrão): nunca passa da área útil da tela
    (1366x768 a 125%/150%); o corpo dos diálogos fica numa ``Rolagem`` que encolhe e rola, e
    a linha de botões, fora dela, continua à vista.

    Quando a altura fica menor que a natural, o que falta sai SÓ da ``Rolagem`` (ela ganha um
    teto). Sem o teto, o QBoxLayout trata a altura do conteúdo como mínimo da Rolagem e tira a
    diferença de quem for mais alto — a coluna de botões empilhados, que se sobrepunham.
    Piso: a linha de botões inteira mais ``CORPO_MINIMO`` de corpo. Só se nem isso couber na
    tela (descontada só a barra de título, ``FOLGA_TITULO``) o corpo encolhe mais, até
    ``CORPO_APERTADO``.
    """
    lay = window.layout()
    if lay is None:
        return
    rolagens = _rolagens(window)
    minimo = lay.totalMinimumSize()
    w = max(width, minimo.width())
    area = area_util(window) if clamp_to_screen else None
    if area is not None:
        w = max(minimo.width(), min(w, area.width() - FOLGA_LARGURA))
    # medidas SEM o teto que um ajuste anterior pôs na Rolagem (o layout já o aplica)
    naturais = [r.heightForWidth(_largura_para(r, window, w)) for r in rolagens]
    minimos = [r.minimumSizeHint().height() for r in rolagens]
    tetos = [r.maximumHeight() for r in rolagens]
    natural = (
        lay.totalHeightForWidth(w) if lay.hasHeightForWidth() else lay.totalSizeHint().height()
    )
    natural += sum(n - min(n, t) for n, t in zip(naturais, tetos, strict=True))
    piso = minimo.height() + sum(m - min(m, t) for m, t in zip(minimos, tetos, strict=True))
    limite = area.height() - FOLGA_MOLDURA if area is not None else None
    if area is not None and limite is not None and piso > limite:
        # o piso passa da folga confortável: pode ir até perto da barra de título; se nem
        # assim couber, o corpo encolhe mais e os botões continuam inteiros à vista
        apertado = piso - sum(m - min(m, CORPO_APERTADO) for m in minimos)
        piso = max(apertado, min(piso, area.height() - FOLGA_TITULO))
    h = natural if limite is None else min(natural, limite)
    h = max(h, piso)
    falta = max(0, natural - h)
    for i in sorted(range(len(rolagens)), key=lambda k: -naturais[k]):
        tira = min(falta, max(0, naturais[i] - min(minimos[i], CORPO_APERTADO)))
        falta -= tira
        _por_teto(rolagens[i], window, naturais[i] - tira if tira else SEM_TETO)
    if window.minimumSize() != QSize(w, h) or window.maximumSize() != QSize(w, h):
        window.setFixedSize(w, h)


def _rolagens(window: QWidget) -> list[Rolagem]:
    """As ``Rolagem`` visíveis da janela que não estão dentro de outra Rolagem."""
    achadas = []
    for r in window.findChildren(Rolagem):
        if not r.isVisibleTo(window):
            continue
        pai = r.parentWidget()
        while pai is not None and pai is not window and not isinstance(pai, Rolagem):
            pai = pai.parentWidget()
        if not isinstance(pai, Rolagem):
            achadas.append(r)
    return achadas


def _largura_para(alvo: QWidget, janela: QWidget, largura: int) -> int:
    """Largura que ``alvo`` recebe quando ``janela`` tem ``largura``: desconta, de cada nível
    até a janela, as margens do widget (molduras) e as do layout. Vale para quem ocupa a
    largura toda do layout, como a Rolagem dos diálogos (antes de o layout rodar, a largura
    atual dela ainda não é a final)."""
    pai = alvo.parentWidget()
    while pai is not None:
        m = pai.contentsMargins()
        largura -= m.left() + m.right()
        lay = pai.layout()
        if lay is not None:
            lm = lay.contentsMargins()
            largura -= lm.left() + lm.right()
        if pai is janela:
            break
        pai = pai.parentWidget()
    return max(1, largura)


def _por_teto(rolagem: Rolagem, janela: QWidget, teto: int) -> None:
    """Teto de altura da Rolagem. As medidas guardadas pelos layouts até a janela ficam
    velhas: são descartadas, para o próximo ajuste medir certo (e parar de mudar)."""
    teto = max(0, min(teto, SEM_TETO))
    if rolagem.maximumHeight() == teto:
        return
    rolagem.setMaximumHeight(teto)
    w: QWidget | None = rolagem
    while w is not None:
        w.updateGeometry()
        lay = w.layout()
        if lay is not None:
            _invalida(lay)
        if w is janela:
            break
        w = w.parentWidget()


def _invalida(lay: QLayout) -> None:
    lay.invalidate()
    for i in range(lay.count()):
        item = lay.itemAt(i)
        sub = item.layout() if item is not None else None
        if sub is not None:
            _invalida(sub)


class Rolagem(QScrollArea):
    """Rolagem vertical sem moldura que pede a altura do conteúdo na largura dada (como um
    texto com quebra de linha). Numa tela baixa a janela a encolhe (``fit_to_content`` põe um
    teto nela) e o conteúdo rola. O campo do conteúdo que ganha o foco pelo Tab, vindo dos
    botões (``_mostra_foco``) ou de dentro dela (``focusNextPrevChild``), é trazido para a
    vista (``_traz_para_vista``)."""

    def __init__(self, content: QWidget) -> None:
        super().__init__()
        self.setObjectName("transparente")
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)  # o Tab vai direto aos campos
        self.setWidget(content)
        content.installEventFilter(self)
        app = QApplication.instance()
        if isinstance(app, QApplication):
            # método do próprio objeto: o Qt desfaz a conexão quando a Rolagem é destruída
            app.focusChanged.connect(self._mostra_foco)

    @Slot(QWidget, QWidget)
    def _mostra_foco(self, antes: QWidget | None, agora: QWidget | None) -> None:
        """Rola até o widget do conteúdo que ganhou o foco vindo de FORA da Rolagem, na mesma
        janela (o Tab que sai dos botões): inteiro, se cabe na vista; senão, o começo dele.
        O Qt só rola quando o Tab anda DENTRO da QScrollArea (``focusNextPrevChild``); o Tab
        que vinha dos botões deixava o campo focado (a lista "Detalhes") fora da vista, e um
        Enter ali escolhia o botão primário sem a pessoa ver onde estava.

        Não rola: no foco inicial de um diálogo (``antes`` em outra janela: o diálogo abre no
        topo, com o título e o texto à vista), na volta à janela (``antes`` vazio: a pessoa
        pode ter rolado para ler) e com um botão do mouse apertado (o foco veio de um clique:
        o conteúdo pularia debaixo do ponteiro e o clique cairia fora do botão). O cursor de
        um texto não é seguido: numa lista rolada por dentro ele fica fora dela e levaria o
        corpo para longe da lista."""
        if agora is None or antes is None:
            return
        if QGuiApplication.mouseButtons() != Qt.MouseButton.NoButton:
            return
        conteudo = self.widget()
        if conteudo is None or agora is conteudo or not conteudo.isAncestorOf(agora):
            return
        if antes.window() is not agora.window() or conteudo.isAncestorOf(antes):
            return  # outra janela (foco inicial) ou Tab dentro da Rolagem (focusNextPrevChild)
        self._traz_para_vista(agora)

    def focusNextPrevChild(self, next: bool) -> bool:
        """Tab DENTRO da Rolagem: a mesma regra de ``_traz_para_vista``. O do QScrollArea
        (``ensureWidgetVisible``) segue o cursor de um texto, que numa lista rolada por dentro
        fica fora dela, e levava o corpo para longe da lista focada."""
        if not QWidget.focusNextPrevChild(self, next):
            return False
        agora = QApplication.focusWidget()
        if agora is not None:
            self._traz_para_vista(agora)
        return True

    def _traz_para_vista(self, agora: QWidget) -> None:
        """Rola até ``agora`` (se é do conteúdo): inteiro, se cabe na vista; senão, o começo."""
        conteudo = self.widget()
        if conteudo is None or agora is conteudo or not conteudo.isAncestorOf(agora):
            return
        topo = agora.mapTo(conteudo, QPoint(0, 0)).y()
        base = topo + agora.height()
        de = -conteudo.y()  # o trecho do conteúdo à vista: [de, de + vista)
        vista = self.viewport().height()
        if topo >= de and base <= de + vista:
            return  # já está inteiro à vista
        barra = self.verticalScrollBar()
        if agora.height() + 2 * MARGEM_DO_FOCO <= vista and topo >= de:
            barra.setValue(base + MARGEM_DO_FOCO - vista)  # abaixo da vista: inteiro, embaixo
        else:
            barra.setValue(topo - MARGEM_DO_FOCO)  # acima, ou mais alto que a vista: o começo

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        content = self.widget()
        if content is None:
            return super().heightForWidth(width)
        frame = 2 * self.frameWidth()
        h = content.heightForWidth(max(1, width - frame))
        if h < 0:
            h = content.sizeHint().height()
        return h + frame

    def sizeHint(self) -> QSize:
        content = self.widget()
        if content is None:
            return super().sizeHint()
        frame = 2 * self.frameWidth()
        return content.sizeHint() + QSize(frame, frame)

    def minimumSizeHint(self) -> QSize:
        """Altura: ``CORPO_MINIMO``, ou menos se o conteúdo inteiro cabe em menos (o mínimo
        dele é uma linha por texto). Um mínimo maior que o conteúdo esticava os diálogos
        curtos: o título e o texto repartiam a sobra e ficavam longe um do outro."""
        content = self.widget()
        largura = super().minimumSizeHint().width()
        altura = CORPO_MINIMO
        if content is not None:
            barra = self.verticalScrollBar().sizeHint().width()
            largura = max(largura, content.minimumSizeHint().width() + barra)
            frame = 2 * self.frameWidth()
            altura = min(CORPO_MINIMO, max(0, content.minimumSizeHint().height()) + frame)
        return QSize(largura, altura)

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if watched is self.widget() and event.type() == QEvent.Type.LayoutRequest:
            self.updateGeometry()  # um erro ou os detalhes apareceram: a janela acompanha
            self._ajusta_barra()
        return super().eventFilter(watched, event)

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._ajusta_barra()

    def _ajusta_barra(self) -> None:
        """A barra vertical só aparece se o conteúdo NÃO cabe na largura toda. Sem isso, uma
        barra que apareceu num passo intermediário do layout nunca mais sumia: com ela o
        texto quebra numa largura menor, fica mais alto e continua "precisando" dela."""
        content = self.widget()
        if content is None:
            return
        caixa = self.maximumViewportSize()
        altura = content.heightForWidth(caixa.width())
        if altura < 0:
            altura = content.sizeHint().height()
        altura = max(altura, content.minimumSizeHint().height())
        politica = (
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
            if altura <= caixa.height()
            else Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        if self.verticalScrollBarPolicy() != politica:
            self.setVerticalScrollBarPolicy(politica)


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
        inteiro = int(n)
        return "1 byte" if inteiro == 1 else f"{inteiro} bytes"
    units = ["KB", "MB", "GB", "TB"]
    value = n / 1024
    for unit in units:
        text = f"{value:.1f}"
        if float(text) < 1024 or unit == units[-1]:
            return f"{text} {unit}".replace(".", ",")
        value /= 1024
    return f"{n} bytes"  # pragma: no cover - o laço sempre devolve na última unidade


def fmt_int(n: int) -> str:
    """Inteiro com ponto de milhar ("1.234"); um float é arredondado antes."""
    inteiro = _arredonda(n) if isinstance(n, float) else n
    return f"{inteiro:,}".replace(",", ".")


def _arredonda(x: float) -> int:
    """Meio para cima (o ``round`` do Python leva 2,5 a 2: 2h30 viraria "cerca de 2 horas")."""
    return math.floor(x + 0.5)


def fmt_duration(seconds: float) -> str:
    if not math.isfinite(seconds):
        return "tempo incerto"  # nenhuma conta deveria chegar aqui; nunca quebra a tela
    if seconds < 90:
        return "menos de 2 minutos"
    minutes = _arredonda(seconds / 60)
    if minutes < 60:
        return f"cerca de {minutes} minutos"
    hours = seconds / 3600  # das horas exatas (arredondar duas vezes levaria 2h29 a 3 horas)
    if hours < 1.5:
        return "cerca de 1 hora"
    return f"cerca de {_arredonda(hours)} horas"


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


# --- tema: o que é pintado fora do QSS acompanha a troca de tema ------------------------

#: token de cada tipo de linha colorida de um registro; o índice fica em QTextBlock.userState
CORES_DO_REGISTRO = ("", "warn", "danger", "ok")


def assinatura_do_tema() -> tuple[tuple[str, str], ...]:
    """Muda quando o tema muda (para repintar só uma vez por troca)."""
    return tuple(sorted(current_tokens().items()))


def _pintar_bloco(block: QTextBlock, estado: int, tokens: dict[str, str]) -> None:
    if not 0 < estado < len(CORES_DO_REGISTRO):
        return
    fmt = QTextCharFormat()
    fmt.setForeground(QColor(tokens[CORES_DO_REGISTRO[estado]]))
    cur = QTextCursor(block)
    cur.movePosition(QTextCursor.MoveOperation.StartOfBlock)
    cur.movePosition(QTextCursor.MoveOperation.EndOfBlock, QTextCursor.MoveMode.KeepAnchor)
    cur.mergeCharFormat(fmt)


def colorir_linha(block: QTextBlock, cor: str) -> None:
    """Pinta a linha com o token ``cor`` ("warn", "danger", "ok"; "" = cor do QSS) e guarda o
    tipo no bloco, para ``repintar_registro`` refazer a cor quando o tema mudar."""
    estado = CORES_DO_REGISTRO.index(cor) if cor in CORES_DO_REGISTRO else 0
    block.setUserState(estado)
    _pintar_bloco(block, estado, current_tokens())


def repintar_registro(edit: QPlainTextEdit) -> None:
    """Depois de trocar o tema: as linhas coloridas passam para as cores do tema novo."""
    tokens = current_tokens()
    block = edit.document().firstBlock()
    while block.isValid():
        _pintar_bloco(block, block.userState(), tokens)
        block = block.next()


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
        self._tema = assinatura_do_tema()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        self.card, card_lay = comp.cartao()
        outer.addWidget(self.card)
        # tudo menos o Cancelar rola numa tela baixa: o botão fica sempre à vista
        conteudo, lay = comp.transparente()
        lay.setSpacing(12)
        self.rolagem = Rolagem(conteudo)
        card_lay.addWidget(self.rolagem, 1)
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
            box.setUndoRedoEnabled(False)  # o registro não guarda histórico de edição
            box.setTabChangesFocus(True)
            box.setMaximumBlockCount(5000)
            box.setMinimumHeight(160)
            box.setAccessibleName("Etapas")
            lay.addWidget(box, 1)
            self.log_box = box
        self.notice = comp.Aviso(html.escape(note))
        lay.addWidget(self.notice)
        card_lay.addSpacing(8)
        row = QHBoxLayout()
        row.setSpacing(12)
        row.addStretch(1)
        self.cancel_button = comp.botao("Cancelar")
        self.cancel_button.clicked.connect(self._cancel)
        self.cancel_button.setVisible(cancellable)
        row.addWidget(self.cancel_button)
        card_lay.addLayout(row)
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

    def changeEvent(self, event: QEvent) -> None:
        super().changeEvent(event)
        if event.type() in (QEvent.Type.PaletteChange, QEvent.Type.StyleChange):
            tema = assinatura_do_tema()
            # o tema mudou (e o diálogo já foi montado): sombra e linhas coloridas acompanham
            if tema != getattr(self, "_tema", tema):
                self._tema = tema
                from owl_vault.ui.componentes import sombra  # noqa: PLC0415

                sombra(self.card)
                if self.log_box is not None:
                    repintar_registro(self.log_box)

    # ------------------------------------------------------------------ registro
    def _log(self, text: str, cor: str = "") -> None:
        """Uma linha no registro; cor por ``QTextCharFormat`` (nunca HTML)."""
        box = self.log_box
        if box is None:
            return
        cursor = QTextCursor(box.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        if not box.document().isEmpty():
            cursor.insertBlock(QTextBlockFormat(), QTextCharFormat())
        cursor.insertText(f"{time.strftime('%H:%M:%S')}  {text}", QTextCharFormat())
        colorir_linha(box.document().lastBlock(), cor)
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
