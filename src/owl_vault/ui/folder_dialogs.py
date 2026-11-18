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

from PySide6.QtCore import QEvent, Qt, QTimer
from PySide6.QtGui import QShowEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLayout,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from owl_vault.domain.limits import MIN_PASSWORD_LENGTH
from owl_vault.ui.common import (
    CORPO_MINIMO,
    FOLGA_LARGURA,
    FOLGA_MOLDURA,
    Rolagem,
    area_util,
    assinatura_do_tema,
    fit_to_content,
    fmt_duration,
    fmt_int,
    fmt_size,
    show_error,
)
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
    sombra,
    subtitulo,
    titulo,
    transparente,
)

#: largura mínima de um diálogo e margem entre a borda da janela e o cartão
LARGURA = 520
MARGEM = 24
#: até esta largura os botões ficam lado a lado; acima, um embaixo do outro
LARGURA_MAXIMA_BOTOES = 680
#: vão entre os botões (lado a lado, empilhados ou em duas colunas) e espaço antes deles
VAO_BOTOES = 12
ESPACO_ANTES_DOS_BOTOES = 8

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
    """Fundo ``app-bg`` + ``QFrame#cartao``; ``self.corpo`` é o layout do conteúdo do cartão.

    O conteúdo fica numa ``Rolagem`` e a linha de botões, fora dela, embaixo: numa tela baixa
    (1366x768 a 125%/150%) o diálogo nunca passa da área útil, o conteúdo rola e os botões
    continuam à vista.
    """

    def __init__(self, parent: QWidget | None, width: int = LARGURA) -> None:
        super().__init__(parent)
        self.setWindowTitle("Owl Vault")
        self.setMinimumWidth(width)
        self._largura = width
        self._tema = assinatura_do_tema()
        self._erro_visto = ""
        externo = QVBoxLayout(self)
        externo.setContentsMargins(MARGEM, MARGEM, MARGEM, MARGEM)
        self.card, self._cartao = cartao()
        externo.addWidget(self.card)
        conteudo, corpo = transparente()
        corpo.setSpacing(self._cartao.spacing())
        assert isinstance(corpo, QVBoxLayout)
        self.corpo: QVBoxLayout = corpo
        self.rolagem = Rolagem(conteudo)
        self._cartao.addWidget(self.rolagem, 1)
        self.title_label = _puro(titulo(""))
        self.text_label = _puro(subtitulo(""))
        self.corpo.addWidget(self.title_label)
        self.corpo.addWidget(self.text_label)
        #: linha (QHBoxLayout), coluna (QVBoxLayout) ou duas colunas (QGridLayout)
        self.button_box: QLayout | None = None

    def fit(self) -> None:
        """Tamanho fixo pelo conteúdo (largura mínima e a altura que os textos pedem), nunca
        maior que a área útil da tela."""
        fit_to_content(self, self._largura)

    def showEvent(self, event: QShowEvent) -> None:
        self.fit()  # antes de o QDialog centralizar sobre a janela-mãe
        super().showEvent(event)

    def event(self, event: QEvent) -> bool:
        handled = super().event(event)
        if event.type() == QEvent.Type.LayoutRequest and self.isVisible():
            self.fit()  # apareceu um erro ou os detalhes: a altura acompanha
            self._rolar_ate_erro()
        return handled

    def _rolar_ate_erro(self) -> None:
        """Numa tela baixa o corpo rola: um erro NOVO é trazido para a vista (uma vez só,
        para não brigar com quem está rolando)."""
        conteudo = self.rolagem.widget()
        erros = [] if conteudo is None else conteudo.findChildren(QLabel, "erro")
        visiveis = [e for e in erros if e.isVisibleTo(self) and e.text()]
        texto = visiveis[0].text() if visiveis else ""
        if texto and texto != getattr(self, "_erro_visto", ""):
            alvo = visiveis[0]
            QTimer.singleShot(0, self, lambda: self.rolagem.ensureWidgetVisible(alvo, 0, 8))
        self._erro_visto = texto

    def changeEvent(self, event: QEvent) -> None:
        super().changeEvent(event)
        if event.type() in (QEvent.Type.PaletteChange, QEvent.Type.StyleChange):
            tema = assinatura_do_tema()
            # a sombra é um efeito (fora do QSS): refaz com o token (se o cartão já existe)
            if tema != getattr(self, "_tema", tema):
                self._tema = tema
                sombra(self.card)

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
        """Linha de botões à direita (fora da rolagem: sempre à vista); se não cabem, um
        embaixo do outro, na largura toda. Numa tela baixa em que a coluna não cabe junto com
        o corpo mínimo, ficam em duas colunas, na ordem de leitura (os botões nunca saem da
        tela): dois a dois quando cabem lado a lado, e um rótulo longo demais fica sozinho, na
        linha toda (em 731x384, a 175%, a coluna de 4 botões deixava 'Fechar' atrás da barra
        de tarefas)."""
        # a sobra de altura do corpo vai para baixo, nunca para dentro do título e do texto
        self.corpo.addStretch(1)
        self._cartao.addSpacing(ESPACO_ANTES_DOS_BOTOES)
        cabe = max(self.minimumWidth(), LARGURA_MAXIMA_BOTOES) - 2 * MARGEM - 2 * 24
        total = sum(b.sizeHint().width() for b in botoes) + VAO_BOTOES * max(0, len(botoes) - 1)
        box: QLayout
        if total <= cabe or len(botoes) < 2:
            linha = QHBoxLayout()
            linha.addStretch(1)
            for b in botoes:
                linha.addWidget(b)
            linha.setSpacing(VAO_BOTOES)
            box = linha
        elif self._coluna_cabe(botoes) or (linhas := self._linhas_da_grade(botoes)) is None:
            coluna = QVBoxLayout()
            for b in botoes:
                b.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                coluna.addWidget(b)
            coluna.setSpacing(VAO_BOTOES)
            box = coluna
        else:
            grade = QGridLayout()
            grade.setHorizontalSpacing(VAO_BOTOES)
            grade.setVerticalSpacing(VAO_BOTOES)
            for i, botoes_da_linha in enumerate(linhas):
                for j, b in enumerate(botoes_da_linha):
                    b.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                    if len(botoes_da_linha) == 1:
                        grade.addWidget(b, i, 0, 1, 2)  # sozinho, na largura toda
                    else:
                        grade.addWidget(b, i, j)
            if self._grade_cabe(botoes):  # as duas colunas com a mesma largura
                larguras = [max(b.sizeHint().width() for b in botoes)] * 2
            else:  # cada coluna da largura do maior botão que fica nela
                pares = [par for par in linhas if len(par) == 2]
                larguras = [max(par[j].sizeHint().width() for par in pares) for j in (0, 1)]
            for coluna_i, largura in enumerate(larguras):
                grade.setColumnStretch(coluna_i, 1)
                grade.setColumnMinimumWidth(coluna_i, largura)
            box = grade
        self._cartao.addLayout(box)
        self.button_box = box

    def _cromo_vertical(self) -> int:
        """Altura de tudo que não é corpo nem botão: margens, moldura do cartão e vãos."""
        m = self._cartao.contentsMargins()
        f = self.card.contentsMargins()
        return (
            2 * MARGEM
            + m.top()
            + m.bottom()
            + f.top()
            + f.bottom()
            + self._cartao.spacing()
            + ESPACO_ANTES_DOS_BOTOES
        )

    def _coluna_cabe(self, botoes: Sequence[QPushButton]) -> bool:
        """A coluna de botões e ``CORPO_MINIMO`` de corpo cabem na área útil da tela?"""
        area = area_util(self.parentWidget() or self)
        if area is None:
            return True
        coluna = sum(b.sizeHint().height() for b in botoes) + VAO_BOTOES * (len(botoes) - 1)
        return self._cromo_vertical() + CORPO_MINIMO + coluna <= area.height() - FOLGA_MOLDURA

    def _largura_util(self) -> int | None:
        """Largura que os botões podem ocupar sem o diálogo passar da largura da tela."""
        area = area_util(self.parentWidget() or self)
        if area is None:
            return None
        return area.width() - FOLGA_LARGURA - 2 * MARGEM - 2 * 24

    def _grade_cabe(self, botoes: Sequence[QPushButton]) -> bool:
        """Duas colunas iguais (da largura do maior botão) cabem na largura da tela?"""
        util = self._largura_util()
        if util is None:
            return False
        return 2 * max(b.sizeHint().width() for b in botoes) + VAO_BOTOES <= util

    def _linhas_da_grade(self, botoes: Sequence[QPushButton]) -> list[list[QPushButton]] | None:
        """Os botões em linhas de um ou dois, na ordem de leitura (e de Tab).

        Dois vizinhos dividem a linha se as duas colunas, cada uma da largura do maior botão
        que fica nela, ainda cabem na largura da tela; senão o primeiro fica sozinho, na linha
        toda (um rótulo longo não alarga a coluna dos outros). ``None``: nenhum par cabe, e a
        grade seria a própria coluna.
        """
        util = self._largura_util()
        if util is None:
            return None
        larguras = [b.sizeHint().width() for b in botoes]
        linhas: list[list[QPushButton]] = []
        esquerda = direita = 0
        i = 0
        while i < len(botoes):
            if i + 1 < len(botoes):
                nova_esquerda = max(esquerda, larguras[i])
                nova_direita = max(direita, larguras[i + 1])
                if nova_esquerda + VAO_BOTOES + nova_direita <= util:
                    esquerda, direita = nova_esquerda, nova_direita
                    linhas.append([botoes[i], botoes[i + 1]])
                    i += 2
                    continue
            linhas.append([botoes[i]])
            i += 1
        return linhas if len(linhas) < len(botoes) else None


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


#: nome antigo (a rolagem agora é a mesma de todos os diálogos: ``common.Rolagem``)
_Rolagem = Rolagem


class LimitsDialog(_DialogoCofre):
    """T15 — os limites da proteção, um por linha (ícone de alerta + título + nota)."""

    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent, 600)
        self._cabecalho(
            "Limites da proteção", "O que o Owl Vault não consegue fazer por você. Leia uma vez."
        )
        linhas, lay = transparente()
        lay.setSpacing(8)
        self.rows: list[LinhaChecagem] = []
        for t, d in zip(LIMITS_TITLES, LIMITS_TEXT, strict=True):
            row = LinhaChecagem(t, d, "aviso")
            row.icone.setAccessibleName(f"Limite: {t}")
            lay.addWidget(row)
            self.rows.append(row)
        self.corpo.addWidget(linhas)
        #: a rolagem do diálogo (numa tela baixa o texto rola e "Entendi" fica à vista)
        self.scroll_area = self.rolagem
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
