"""Cópia criptografada de uma pasta (modo v1, uso raro — UI_SPEC_V2 T14).

Assistente de 4 passos do visual "Cofre" (visual/ESTILO5-COFRE.md): Pastas → Senha →
Conferência → Criar. "Abrir uma cópia" (restaurar numa pasta nova) e "Conferir uma cópia"
(verificar) ficam no mesmo visual, com cartões próprios. A pasta original nunca é alterada.

A lógica é a de sempre (``preflight_create``, ``create_vault``, ``resume_create``,
``verify_vault``, ``restore_vault``): esta tela só organiza os passos, impede avançar quando
falta algo e roda o trabalho pesado numa QThread (``JobRunner``).
"""

from __future__ import annotations

import datetime as _dt
import itertools
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from PySide6.QtCore import Qt, QTimer, Slot
from PySide6.QtGui import QCloseEvent, QColor, QKeyEvent, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QAbstractButton,
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from owl_vault.application.common import default_vault_name, validate_new_password
from owl_vault.application.create import (
    CreateResult,
    create_vault,
    inspect_vault_dir,
    resume_create,
)
from owl_vault.application.preflight import CreatePlan, default_test_parent, preflight_create
from owl_vault.application.progress import CancelToken, ProgressSink
from owl_vault.application.protection import ProtectedPaths
from owl_vault.application.restore import RestoreReport, inspect_destination, restore_vault
from owl_vault.application.verify import VerifyReport, verify_vault
from owl_vault.crypto.kdf import PRODUCTION_POLICY, KdfPolicy
from owl_vault.domain.errors import CancelledError, OwlVaultError, PreflightError
from owl_vault.domain.limits import MIN_PASSWORD_LENGTH
from owl_vault.domain.models import KdfParams
from owl_vault.storage import winfs
from owl_vault.ui import strings as S
from owl_vault.ui.common import fmt_int, fmt_size, open_in_explorer
from owl_vault.ui.componentes import (
    LARGURA_LATERAL,
    Aviso,
    CampoCaminho,
    CampoSenha,
    CartaoLateral,
    Dica,
    LinhaChecagem,
    Marca,
    MedidorForca,
    Rodape,
    TrilhaPassos,
    botao,
    botao_discreto,
    cartao,
    erro,
    lista_detalhes,
    mostrar_erro,
    nota,
    repintar,
    rotulo,
    subtitulo,
    titulo,
    transparente,
)
from owl_vault.ui.dialogs import CaixaAceite
from owl_vault.ui.folder_dialogs import ask, inform
from owl_vault.ui.icon import owl_icon
from owl_vault.ui.theme import current_tokens
from owl_vault.ui.workers import JobRunner, QtProgress

#: modos da janela (o assistente de criação e as duas ferramentas)
CRIAR, ABRIR, CONFERIR = "criar", "abrir", "conferir"
#: índices das páginas no QStackedWidget (0–3 são os passos do assistente)
_PAGINA_ABRIR, _PAGINA_CONFERIR = 4, 5

TITULOS_CONFERENCIA = (
    "Espaço em disco",
    "Arquivos em uso",
    "Tamanho e contagem da origem",
    "Destino gravável",
)
_NAO_CONFERIDO = "Não conferido: resolva os itens marcados primeiro."
_SEM_LIMITE = 16777215  # QWIDGETSIZE_MAX
_MAX_OUTROS = 8


def _rico(texto: str) -> str:
    """O aviso da cópia com "cópia" em negrito (como no design)."""
    return texto.replace("uma cópia", "uma <b>cópia</b>", 1)


# --- conferência (passo 3): plano da pré-verificação → linhas ---------------------------


@dataclass(frozen=True, slots=True)
class Checagem:
    titulo: str
    estado: str  # "ok" | "falhou" | "aviso" | "" (não rodou)
    detalhe: str = ""


def _divide(texto: str, padrao: str) -> tuple[str, str]:
    """``"Prefixo: resto"`` → (Prefixo, Resto) quando o prefixo é curto; senão (padrao, texto)."""
    cabeca, sep, resto = texto.partition(": ")
    if sep and resto and 0 < len(cabeca) <= 60:
        return cabeca, resto[:1].upper() + resto[1:]
    return padrao, texto


def _resumo(itens: Sequence[str], limite: int = 3) -> str:
    texto = " · ".join(itens[:limite])
    if len(itens) > limite:
        texto += f" · e mais {fmt_int(len(itens) - limite)}"
    return texto


def conferencia(plan: CreatePlan, etapas: Sequence[str], livre: int | None) -> list[Checagem]:
    """Organiza bloqueios e avisos da pré-verificação em linhas (nada é decidido aqui:
    ``plan.blockers`` continua sendo a única regra para criar)."""
    espaco: list[str] = []
    em_uso: list[str] = []
    origem: list[str] = []
    destino: list[str] = []
    outros: list[str] = []
    for b in plan.blockers:
        low = b.lower()
        if "espaço insuficiente" in low or "espaço livre" in low:
            espaco.append(b)
        elif "em uso" in low:
            em_uso.append(b)
        elif b.startswith("Origem:") or "lista de nomes" in low:
            origem.append(b)
        elif b.startswith(("Cofre:", "O cofre", "Teste de restauração:", "A pasta do teste")) or (
            "grande demais para" in low
        ):
            destino.append(b)
        else:
            outros.append(b)
    listou = any("listando a origem" in e for e in etapas)
    abriu = any("abrindo arquivos" in e for e in etapas)

    linhas: list[Checagem] = []
    if espaco:
        linhas.append(Checagem(TITULOS_CONFERENCIA[0], "falhou", _resumo(espaco)))
    elif plan.estimated_vault_bytes:
        detalhe = f"O cofre precisa de cerca de {fmt_size(plan.estimated_vault_bytes)}"
        if livre is not None:
            detalhe += f"; livre: {fmt_size(livre)}"
        linhas.append(Checagem(TITULOS_CONFERENCIA[0], "ok", detalhe + "."))
    else:
        linhas.append(Checagem(TITULOS_CONFERENCIA[0], "", _NAO_CONFERIDO))

    if em_uso:
        nomes = [b.partition(": ")[0] for b in em_uso]
        linhas.append(
            Checagem(
                TITULOS_CONFERENCIA[1],
                "falhou",
                f"Feche estes arquivos e confira de novo: {_resumo(nomes)}",
            )
        )
    elif abriu:
        linhas.append(
            Checagem(
                TITULOS_CONFERENCIA[1],
                "ok",
                f"Nenhum arquivo aberto em outro programa ({fmt_int(len(plan.files))} "
                "conferido(s)).",
            )
        )
    else:
        linhas.append(Checagem(TITULOS_CONFERENCIA[1], "", _NAO_CONFERIDO))

    if origem:
        linhas.append(Checagem(TITULOS_CONFERENCIA[2], "falhou", _resumo(origem)))
    elif listou:
        linhas.append(
            Checagem(
                TITULOS_CONFERENCIA[2],
                "ok",
                f"{fmt_int(len(plan.files))} arquivo(s) · {fmt_int(len(plan.dirs))} pasta(s) · "
                f"{fmt_size(plan.total_bytes)}",
            )
        )
    else:
        linhas.append(Checagem(TITULOS_CONFERENCIA[2], "", _NAO_CONFERIDO))

    if destino:
        linhas.append(Checagem(TITULOS_CONFERENCIA[3], "falhou", _resumo(destino)))
    elif plan.vault_res is not None and plan.test_res is not None:
        fs = plan.vault_fs or "?"
        linhas.append(
            Checagem(
                TITULOS_CONFERENCIA[3],
                "ok",
                f"O local do cofre existe ({fs}). A gravação é testada de novo no início da "
                "criação.",
            )
        )
    else:
        linhas.append(Checagem(TITULOS_CONFERENCIA[3], "", _NAO_CONFERIDO))

    for b in outros[:_MAX_OUTROS]:
        cabeca, resto = _divide(b, "Bloqueio")
        linhas.append(Checagem(cabeca, "falhou", resto))
    if len(outros) > _MAX_OUTROS:
        linhas.append(
            Checagem(
                f"E mais {fmt_int(len(outros) - _MAX_OUTROS)} bloqueio(s)",
                "falhou",
                "Veja a lista completa abaixo.",
            )
        )
    for w in plan.warnings:
        cabeca, resto = _divide(w, "Atenção")
        linhas.append(Checagem(cabeca, "aviso", resto))
    return linhas


class _Registro:
    """Repassa o progresso para a interface e guarda o nome das etapas."""

    def __init__(self, destino: ProgressSink) -> None:
        self._d = destino
        self.etapas: list[str] = []

    def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
        self.etapas.append(name)
        self._d.stage(name, total_bytes, total_items)

    def advance(self, nbytes: int = 0, nitems: int = 0) -> None:
        self._d.advance(nbytes, nitems)

    def info(self, message: str) -> None:
        self._d.info(message)

    def warning(self, message: str) -> None:
        self._d.warning(message)


def mensagem_de_erro(exc: object) -> str:
    if isinstance(exc, CancelledError):
        return S.COPIA_CANCELADA
    if isinstance(exc, OwlVaultError):
        return str(exc)
    return (
        f"Erro inesperado ({type(exc).__name__}): {exc}. Nenhum arquivo da origem foi "
        "alterado. Se for uma criação, você pode tentar 'Retomar criação interrompida'."
    )


# --- peças da tela -------------------------------------------------------------------------


class PainelTrabalho(QWidget):
    """Barra de progresso + etapa em texto + log da sessão (não gravado em disco)."""

    def __init__(self, altura_log: int = 160) -> None:
        super().__init__()
        self.setObjectName("transparente")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        self.etapa = rotulo("Pronto.")
        self.etapa.setObjectName("etapa")
        self.barra = QProgressBar()
        self.barra.setRange(0, 1000)
        self.barra.setValue(0)
        # o percentual vai no texto da etapa (texto sobre a barra fina ficaria ilegível)
        self.barra.setTextVisible(False)
        self.barra.setAccessibleName("Andamento")
        self.log = QPlainTextEdit()
        self.log.setObjectName("log")
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        self.log.setMinimumHeight(altura_log)
        self.log.setPlaceholderText("Mensagens desta sessão (não são gravadas em disco).")
        self.log.setAccessibleName("Mensagens da operação")
        lay.addWidget(self.etapa)
        lay.addWidget(self.barra)
        lay.addWidget(self.log, 1)
        self._nome = "Pronto."
        self._totais = (0, 0)
        self._feito = [0, 0]

    def escrever(self, mensagem: str, tipo: str = "") -> None:
        """Acrescenta uma linha; ``tipo`` "aviso"/"erro"/"ok" pinta com o token do tema."""
        stamp = _dt.datetime.now().strftime("%H:%M:%S")
        self.log.appendPlainText(f"[{stamp}] {mensagem}")
        fmt = QTextCharFormat()
        token = {"aviso": "warn", "erro": "danger", "ok": "ok"}.get(tipo)
        if token is not None:
            fmt.setForeground(QColor(current_tokens()[token]))
        cur = QTextCursor(self.log.document().lastBlock())
        cur.movePosition(QTextCursor.MoveOperation.StartOfBlock)
        cur.movePosition(QTextCursor.MoveOperation.EndOfBlock, QTextCursor.MoveMode.KeepAnchor)
        cur.setCharFormat(fmt)

    def reiniciar(self, texto: str = "Preparando…") -> None:
        self.log.setMaximumHeight(_SEM_LIMITE)
        self._nome = texto
        self.etapa.setText(texto)
        self.barra.setRange(0, 0)  # indeterminado até a primeira etapa com total

    def iniciar_etapa(self, nome: str, total_bytes: int, total_itens: int) -> None:
        self._nome = nome
        self.etapa.setText(nome)
        self._totais = (total_bytes, total_itens)
        self._feito = [0, 0]
        if total_bytes or total_itens:
            self.barra.setRange(0, 1000)
            self.barra.setValue(0)
        else:
            self.barra.setRange(0, 0)

    def avancar(self, nbytes: int, nitens: int) -> None:
        self._feito[0] += nbytes
        self._feito[1] += nitens
        tb, ti = self._totais
        if tb:
            self.barra.setValue(min(1000, int(self._feito[0] * 1000 / tb)))
        elif ti:
            self.barra.setValue(min(1000, int(self._feito[1] * 1000 / ti)))
        else:
            return
        texto = f"{self._nome} — {self.barra.value() // 10}%"
        if ti:
            texto += f" ({fmt_int(min(self._feito[1], ti))} de {fmt_int(ti)})"
        self.etapa.setText(texto)

    def concluir(self, texto: str, ok: bool) -> None:
        # o log encolhe para o resultado caber embaixo (continua rolável)
        self.log.setMaximumHeight(max(self.log.minimumHeight(), 150))
        self.barra.setRange(0, 1000)
        self.barra.setValue(1000 if ok else self.barra.value())
        self.etapa.setText(texto)


class Resultado(QWidget):
    """Resultado de uma operação dentro do cartão: linha de estado, texto e listas."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("transparente")
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(0, 8, 0, 0)
        self._lay.setSpacing(8)
        self.linha: LinhaChecagem | None = None
        self.corpo: QLabel | None = None
        self.hide()

    def limpar(self) -> None:
        while self._lay.count():
            item = self._lay.takeAt(0)
            w = item.widget() if item is not None else None
            if w is not None:
                w.hide()
                w.deleteLater()
        self.linha = None
        self.corpo = None
        self.hide()

    def mostrar(
        self,
        titulo_texto: str,
        estado: str,
        detalhe: str,
        texto: str = "",
        secoes: Sequence[tuple[str, Sequence[str]]] = (),
        extras: Sequence[QWidget] = (),
    ) -> None:
        self.limpar()
        self.linha = LinhaChecagem(titulo_texto, detalhe, estado)
        self._lay.addWidget(self.linha)
        if texto:
            self.corpo = QLabel(texto)
            self.corpo.setObjectName("resultadoTexto")
            self.corpo.setWordWrap(True)
            self.corpo.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self._lay.addWidget(self.corpo)
        for nome, itens in secoes:
            if itens:
                self._lay.addWidget(rotulo(f"{nome} ({fmt_int(len(itens))})"))
                lista = lista_detalhes(itens)
                lista.setMaximumHeight(min(220, 60 + 20 * len(itens)))  # não estica à toa
                self._lay.addWidget(lista)
        for w in extras:
            self._lay.addWidget(w, 0, Qt.AlignmentFlag.AlignLeft)
        self.show()
        # o resultado aparece embaixo dos campos/log: rola o cartão até ele
        QTimer.singleShot(0, self, self._rolar_ate_aqui)

    def _rolar_ate_aqui(self) -> None:
        p = self.parentWidget()
        while p is not None and not isinstance(p, QScrollArea):
            p = p.parentWidget()
        if isinstance(p, QScrollArea) and self.isVisible():
            p.ensureWidgetVisible(self, 0, 24)

    def texto(self) -> str:
        partes: list[str] = []
        if self.linha is not None:
            partes += [self.linha.titulo.text(), self.linha.detalhe.text()]
        if self.corpo is not None:
            partes.append(self.corpo.text())
        return "\n".join(p for p in partes if p)


# --- janela ----------------------------------------------------------------------------------


class CopyWindow(QMainWindow):
    """Assistente "Cópia criptografada" (Pastas → Senha → Conferência → Criar) + ferramentas.

    ``kdf_policy``/``kdf_params``/``protected`` existem para os testes automatizados (perfil
    rápido e pastas temporárias); o aplicativo usa os padrões de produção.
    """

    def __init__(
        self,
        *,
        kdf_policy: KdfPolicy = PRODUCTION_POLICY,
        kdf_params: KdfParams | None = None,
        protected: ProtectedPaths | None = None,
    ) -> None:
        super().__init__()
        self._policy = kdf_policy
        self._params = kdf_params
        self._protected = protected
        self.setWindowTitle(S.COPIA_TITULO_JANELA)
        self.setWindowIcon(owl_icon())
        self.resize(1040, 860)
        self.setMinimumSize(860, 620)
        self.runner = JobRunner(self)
        self.session_sources: list[str] = []
        self._auto_test: str | None = None
        self.modo = CRIAR
        self.passo = 0
        self.retomando = False
        #: "" (ainda não começou) | "rodando" | "ok" | "falhou"
        self.criacao = ""
        self._plan: CreatePlan | None = None
        self._retomada_ok = False
        self._resultado: CreateResult | None = None
        self._painel: PainelTrabalho | None = None
        self._ao_terminar: Callable[[object], None] | None = None
        self._ao_falhar: Callable[[object], None] | None = None
        self._fechar_depois = False
        # etapa, total de itens e itens feitos da pré-verificação (vão para o rodapé)
        self._pf_nome = ""
        self._pf_total = 0
        self._pf_feito = 0
        self._lateral_chave: object = None
        self._lateral_botoes: list[QPushButton] = []

        central = QWidget()
        externo = QVBoxLayout(central)
        externo.setContentsMargins(0, 0, 0, 0)
        externo.setSpacing(0)
        corpo, lay = transparente()
        lay.setContentsMargins(32, 20, 32, 24)
        lay.setSpacing(20)
        lay.addWidget(self._montar_topo())
        self.trilha = TrilhaPassos(S.COPIA_PASSOS)
        lay.addWidget(self.trilha)

        palco = QHBoxLayout()
        palco.setSpacing(20)
        self.paginas = QStackedWidget()
        self.paginas.addWidget(self._pagina_pastas())
        self.paginas.addWidget(self._pagina_senha())
        self.paginas.addWidget(self._pagina_conferencia())
        self.paginas.addWidget(self._pagina_criar())
        self.paginas.addWidget(self._pagina_abrir())
        self.paginas.addWidget(self._pagina_conferir())
        palco.addWidget(self.paginas, 1)
        self.lateral, ll = transparente()
        self.lateral.setFixedWidth(LARGURA_LATERAL)
        ll.setSpacing(20)
        self.resumo = CartaoLateral(S.COPIA_SECAO_LATERAL)
        self.dica = Dica()
        ll.addWidget(self.resumo)
        ll.addWidget(self.dica)
        ll.addStretch(1)
        palco.addWidget(self.lateral, 0)
        lay.addLayout(palco, 1)
        externo.addWidget(corpo, 1)

        self.rodape = Rodape(primario=S.COPIA_PRIMARIO[0])
        self.cancelar = botao("Cancelar")
        self.cancelar.hide()
        self.cancelar.clicked.connect(self._cancelar)
        self.criar_outro = botao_discreto(S.COPIA_CRIAR_OUTRO)
        self.criar_outro.hide()
        self.criar_outro.clicked.connect(self._criar_outro)
        self.rodape.extra.addWidget(self.cancelar)
        self.rodape.extra.addWidget(self.criar_outro)
        self.rodape.voltar.clicked.connect(self._voltar)
        self.rodape.primario.clicked.connect(self._primario)
        externo.addWidget(self.rodape)
        self.setCentralWidget(central)

        b = self.runner.bridge
        b.stage.connect(self._on_stage)
        b.advance.connect(self._on_advance)
        b.info.connect(lambda m: self._escrever(m))
        b.warning.connect(lambda m: self._escrever("AVISO: " + m, "aviso"))
        self.runner.done.connect(self._on_done)
        self.runner.error.connect(self._on_error)
        if winfs.is_elevated():
            self.painel_criar.escrever(
                "AVISO: o Owl Vault está rodando como administrador; isso não é necessário.",
                "aviso",
            )
        self._mostrar()

    # ------------------------------------------------------------------ construção
    def _montar_topo(self) -> QWidget:
        topo, lay = transparente(QHBoxLayout)
        lay.setSpacing(12)
        marca = Marca(28)
        marca.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        lay.addWidget(marca)
        sub = nota("Cópia criptografada de uma pasta")
        sub.setWordWrap(False)
        lay.addWidget(sub, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addStretch(1)
        self.bt_criar = botao_discreto("Criar uma cópia")
        self.bt_abrir = botao_discreto("Abrir uma cópia")
        self.bt_conferir = botao_discreto("Conferir uma cópia")
        self.bt_limites = botao_discreto(S.LIMITS_TITLE)
        self.bt_criar.clicked.connect(lambda: self._ir_modo(CRIAR))
        self.bt_abrir.clicked.connect(lambda: self._ir_modo(ABRIR))
        self.bt_conferir.clicked.connect(lambda: self._ir_modo(CONFERIR))
        self.bt_limites.clicked.connect(self._mostrar_limites)
        for bt in (self.bt_criar, self.bt_abrir, self.bt_conferir, self.bt_limites):
            lay.addWidget(bt, 0, Qt.AlignmentFlag.AlignVCenter)
        return topo

    def _pagina(self) -> tuple[QFrame, QVBoxLayout]:
        """``QFrame#cartao`` com o conteúdo numa área rolável (janelas baixas)."""
        frame, lay = cartao()
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.Shape.NoFrame)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        conteudo, cl = transparente()
        cl.setSpacing(12)
        area.setWidget(conteudo)
        lay.addWidget(area)
        assert isinstance(cl, QVBoxLayout)
        return frame, cl

    @staticmethod
    def _cabecalho(lay: QVBoxLayout, titulo_lbl: QLabel, texto_lbl: QLabel) -> None:
        lay.addWidget(titulo_lbl)
        lay.addWidget(texto_lbl)
        lay.addSpacing(12)

    @staticmethod
    def _campo(
        lay: QVBoxLayout,
        texto: str,
        widget: QWidget,
        foco: QWidget,
        *,
        nota_texto: str = "",
        extra: QWidget | None = None,
    ) -> QWidget:
        """Rótulo (12px acima do campo), campo, extra/nota (8px abaixo); 16px entre campos."""
        grupo, gl = transparente()
        gl.setSpacing(0)
        lbl = rotulo(texto)
        lbl.setBuddy(foco)
        gl.addWidget(lbl)
        gl.addSpacing(12)
        gl.addWidget(widget)
        if extra is not None:
            gl.addSpacing(8)
            gl.addWidget(extra)
        if nota_texto:
            gl.addSpacing(8)
            gl.addWidget(nota(nota_texto))
        if lay.count():
            lay.addSpacing(4)  # 12 do cartão + 4 = 16 entre campos
        lay.addWidget(grupo)
        return grupo

    def _pagina_pastas(self) -> QWidget:
        frame, lay = self._pagina()
        self._cabecalho(lay, titulo(S.COPIA_P1_TITULO), subtitulo(S.COPIA_P1_TEXTO))
        self.c_origem = CampoCaminho("Pasta que será copiada", "Escolher a pasta de origem")
        self.c_local = CampoCaminho(
            "Onde salvar o cofre (ex.: pendrive ou HD externo)", "Escolher onde salvar o cofre"
        )
        self.c_nome = QLineEdit(default_vault_name())
        self.c_nome.setPlaceholderText("Nome da pasta do cofre")
        self.c_nome.setAccessibleName("Nome do cofre")
        self.c_teste = CampoCaminho(
            "Pasta temporária do teste de restauração", "Escolher a pasta do teste de restauração"
        )
        self._campo(lay, "Origem", self.c_origem, self.c_origem.campo)
        self._campo(lay, "Local do cofre", self.c_local, self.c_local.campo)
        self._campo(lay, "Nome do cofre", self.c_nome, self.c_nome)
        self._campo(
            lay, "Teste de restauração", self.c_teste, self.c_teste.campo, nota_texto=S.TESTE_NOTA
        )
        self.erro_pastas = erro()
        lay.addWidget(self.erro_pastas)
        lay.addStretch(1)
        self.c_retomar = botao_discreto(S.COPIA_RETOMAR)
        self.c_retomar.clicked.connect(self._iniciar_retomada)
        lay.addWidget(self.c_retomar, 0, Qt.AlignmentFlag.AlignLeft)
        self.c_origem.campo.textChanged.connect(lambda _t: self._sugerir_teste())
        return frame

    def _pagina_senha(self) -> QWidget:
        frame, lay = self._pagina()
        self.p2_titulo = titulo(S.COPIA_P2_TITULO)
        self.p2_texto = subtitulo(S.SENHA_TEXTO)
        self._cabecalho(lay, self.p2_titulo, self.p2_texto)
        self.c_senha = CampoSenha(f"Senha (mínimo {MIN_PASSWORD_LENGTH} caracteres)")
        self.medidor = MedidorForca()
        self.c_senha.textChanged.connect(self.medidor.atualizar)
        self._campo(lay, "Senha", self.c_senha, self.c_senha, extra=self.medidor)
        self.c_conf = QLineEdit()
        self.c_conf.setEchoMode(QLineEdit.EchoMode.Password)
        self.c_conf.setPlaceholderText("Confirme a senha")
        self.c_conf.setAccessibleName("Confirmação da senha")
        self.g_conf = self._campo(lay, "Confirmação", self.c_conf, self.c_conf)
        self.erro_senha = erro()
        lay.addWidget(self.erro_senha)
        lay.addSpacing(8)
        self.aviso_senha = Aviso(_rico(S.AVISO_COPIA))
        lay.addWidget(self.aviso_senha)
        lay.addStretch(1)
        return frame

    def _pagina_conferencia(self) -> QWidget:
        frame, lay = self._pagina()
        self.p3_titulo = titulo(S.COPIA_P3_TITULO)
        self._cabecalho(lay, self.p3_titulo, subtitulo(S.COPIA_P3_TEXTO))
        caixa, self.lista_checagens = transparente()
        self.lista_checagens.setSpacing(4)
        lay.addWidget(caixa)
        self.linhas: list[LinhaChecagem] = []
        self.bt_de_novo = botao_discreto("Conferir de novo")
        self.bt_de_novo.clicked.connect(self._conferir_de_novo)
        lay.addWidget(self.bt_de_novo, 0, Qt.AlignmentFlag.AlignLeft)
        self.detalhes_titulo = rotulo("Lista completa de bloqueios")
        self.detalhes = lista_detalhes([])
        self.detalhes_titulo.hide()
        self.detalhes.hide()
        lay.addWidget(self.detalhes_titulo)
        lay.addWidget(self.detalhes)
        lay.addSpacing(8)
        lay.addWidget(rotulo(S.LIMITS_TITLE))
        lay.addWidget(nota(S.LIMITS_TEXT))
        self.aceite_limites = CaixaAceite(S.COPIA_ACEITE_LIMITES)
        self.aceite_backup = CaixaAceite(S.BACKUP_TEXT)
        self.aceite_senha = CaixaAceite(S.PASSWORD_LOSS_TEXT)
        self.aceite_fat = CaixaAceite(S.FAT_ACK_TEXT)
        self.aceite_fat.hide()
        for c in self.aceites_todos:
            c.toggled.connect(lambda _v: self._atualizar_primario())
            lay.addWidget(c)
        lay.addStretch(1)
        return frame

    @property
    def aceites_todos(self) -> list[CaixaAceite]:
        return [self.aceite_limites, self.aceite_backup, self.aceite_senha, self.aceite_fat]

    def _pagina_criar(self) -> QWidget:
        frame, lay = self._pagina()
        self.p4_titulo = titulo(S.COPIA_P4_TITULO)
        self.p4_texto = subtitulo(S.COPIA_P4_TEXTO)
        self._cabecalho(lay, self.p4_titulo, self.p4_texto)
        # a última hora de avisar que a pasta original continua legível: fica no topo
        self.aviso_criar = Aviso(_rico(S.AVISO_COPIA))
        lay.addWidget(self.aviso_criar)
        lay.addSpacing(4)
        self.painel_criar = PainelTrabalho(140)
        lay.addWidget(self.painel_criar, 1)
        self.erro_criar = erro()
        lay.addWidget(self.erro_criar)
        self.resultado_criar = Resultado()
        lay.addWidget(self.resultado_criar)
        lay.addStretch(0)  # sobra (log já encolhido no fim) fica embaixo
        return frame

    def _pagina_abrir(self) -> QWidget:
        frame, lay = self._pagina()
        self._cabecalho(lay, titulo("Abrir uma cópia"), subtitulo(S.RESTORE_HINT))
        self.r_copia = CampoCaminho("Pasta da cópia criptografada", "Escolher a cópia")
        self.r_senha = CampoSenha("Senha da cópia")
        self.r_local = CampoCaminho("Onde criar a pasta com os arquivos", "Escolher onde abrir")
        self.r_nome = QLineEdit(self._nome_restaurado())
        self.r_nome.setPlaceholderText("Nome da pasta nova")
        self.r_nome.setAccessibleName("Nome da pasta nova")
        self._campo(lay, "Cópia", self.r_copia, self.r_copia.campo)
        self._campo(lay, "Senha", self.r_senha, self.r_senha)
        self._campo(lay, "Abrir em", self.r_local, self.r_local.campo)
        self._campo(lay, "Nome da pasta nova", self.r_nome, self.r_nome)
        self.erro_abrir = erro()
        lay.addWidget(self.erro_abrir)
        self.painel_abrir = PainelTrabalho(110)
        self.painel_abrir.hide()
        lay.addWidget(self.painel_abrir, 1)
        self.resultado_abrir = Resultado()
        lay.addWidget(self.resultado_abrir)
        lay.addStretch(1)
        return frame

    def _pagina_conferir(self) -> QWidget:
        frame, lay = self._pagina()
        self._cabecalho(lay, titulo("Conferir uma cópia"), subtitulo(S.VERIFY_HINT))
        self.v_copia = CampoCaminho("Pasta da cópia criptografada", "Escolher a cópia")
        self.v_senha = CampoSenha("Senha da cópia")
        self._campo(lay, "Cópia", self.v_copia, self.v_copia.campo)
        self._campo(lay, "Senha", self.v_senha, self.v_senha)
        self.erro_conferir = erro()
        lay.addWidget(self.erro_conferir)
        self.painel_conferir = PainelTrabalho(110)
        self.painel_conferir.hide()
        lay.addWidget(self.painel_conferir, 1)
        self.resultado_conferir = Resultado()
        lay.addWidget(self.resultado_conferir)
        lay.addStretch(1)
        return frame

    @staticmethod
    def _nome_restaurado() -> str:
        return _dt.datetime.now().strftime("Restaurado-%Y%m%d-%H%M")

    # ------------------------------------------------------------------ estado da tela
    def _entradas(self) -> list[QWidget]:
        return [
            self.c_origem,
            self.c_local,
            self.c_nome,
            self.c_teste,
            self.c_retomar,
            self.c_senha,
            self.c_conf,
            self.bt_de_novo,
            *self.aceites_todos,
            self.r_copia,
            self.r_senha,
            self.r_local,
            self.r_nome,
            self.v_copia,
            self.v_senha,
        ]

    def _foco_da_pagina(self) -> list[QWidget]:
        if self.modo == ABRIR:
            return [
                self.r_copia.campo,
                self.r_copia.botao,
                self.r_senha,
                self.r_senha.mostrar,
                self.r_local.campo,
                self.r_local.botao,
                self.r_nome,
            ]
        if self.modo == CONFERIR:
            return [self.v_copia.campo, self.v_copia.botao, self.v_senha, self.v_senha.mostrar]
        por_passo: list[list[QWidget]] = [
            [
                self.c_origem.campo,
                self.c_origem.botao,
                self.c_local.campo,
                self.c_local.botao,
                self.c_nome,
                self.c_teste.campo,
                self.c_teste.botao,
                self.c_retomar,
            ],
            [self.c_senha, self.c_senha.mostrar, self.c_conf],
            [self.bt_de_novo, *(c.caixa for c in self.aceites_todos)],
            [self.painel_criar.log],
        ]
        return por_passo[self.passo]

    def _mostrar(self) -> None:
        """Aplica modo/passo: página, trilha, lateral, rodapé, foco e ordem do Tab."""
        busy = self.runner.busy
        criar = self.modo == CRIAR
        self.trilha.setVisible(criar)
        if criar:
            self.trilha.definir(4 if self.criacao == "ok" else self.passo)
            self.paginas.setCurrentIndex(self.passo)
        else:
            self.paginas.setCurrentIndex(_PAGINA_ABRIR if self.modo == ABRIR else _PAGINA_CONFERIR)
        for bt, m in ((self.bt_criar, CRIAR), (self.bt_abrir, ABRIR), (self.bt_conferir, CONFERIR)):
            bt.setProperty("atual", "sim" if self.modo == m else "")
            bt.setAccessibleDescription("Tela atual" if self.modo == m else "")
            repintar(bt)
            bt.setEnabled(not busy)
        for w in self._entradas():
            w.setEnabled(not busy)

        # retomada: só a senha (sem confirmação nem medidor)
        self.p2_titulo.setText(S.COPIA_P2_RETOMAR_TITULO if self.retomando else S.COPIA_P2_TITULO)
        self.p2_texto.setText(
            f"{S.COPIA_P2_RETOMAR_TEXTO} {S.SENHA_TEXTO}" if self.retomando else S.SENHA_TEXTO
        )
        self.g_conf.setVisible(not self.retomando)
        self.medidor.setVisible(not self.retomando)
        self.p3_titulo.setText(S.COPIA_P3_RETOMAR_TITULO if self.retomando else S.COPIA_P3_TITULO)

        alterar = self._atualizar_lateral(busy)
        self._atualizar_rodape(busy)
        self._ordem_tab(alterar)
        foco = [w for w in self._foco_da_pagina() if w.isEnabled()]
        if foco and not busy:
            foco[0].setFocus(Qt.FocusReason.OtherFocusReason)

    def _atualizar_lateral(self, busy: bool) -> list[QPushButton]:
        """Dica do passo e resumo do passo 1; devolve os botões "alterar" (ordem do Tab)."""
        if self.modo == ABRIR:
            self.resumo.hide()
            self.dica.definir(*S.COPIA_DICA_ABRIR)
            return []
        if self.modo == CONFERIR:
            self.resumo.hide()
            self.dica.definir(*S.COPIA_DICA_CONFERIR)
            return []
        self.dica.definir(
            *(S.COPIA_DICA_FIM if self.criacao == "ok" else S.COPIA_DICAS[self.passo])
        )
        self.p4_texto.setText(S.COPIA_P4_TEXTO_FIM if self.criacao == "ok" else S.COPIA_P4_TEXTO)
        self.resumo.setVisible(self.passo > 0)
        if self.passo == 0:
            return []
        pode = not busy and self.criacao in ("", "falhou")

        def v(texto: str) -> str:
            return texto or "—"

        campos: list[tuple[str, str, QWidget]] = [
            ("Origem", v(self.c_origem.texto()), self.c_origem.campo),
            ("Local do cofre", v(self.c_local.texto()), self.c_local.campo),
            ("Nome do cofre", v(self.c_nome.text().strip()), self.c_nome),
            ("Teste de restauração", v(self.c_teste.texto()), self.c_teste.campo),
        ]
        chave = (tuple((c, val) for c, val, _w in campos), pode)
        if chave == self._lateral_chave:
            return self._lateral_botoes
        self._lateral_chave = chave
        # os itens antigos só são apagados no próximo giro do laço de eventos: some com eles já
        antigos = [
            w
            for w in self.resumo.children()
            if isinstance(w, QWidget) and w.objectName() != "secaoLateral"
        ]
        for w in antigos:
            w.hide()
        antes = set(self.resumo.findChildren(QPushButton))

        def alt(campo: QWidget) -> Callable[[], None] | None:
            return (lambda: self._alterar(campo)) if pode else None

        self.resumo.definir_itens([(c, val, alt(w)) for c, val, w in campos])
        self._lateral_botoes = [b for b in self.resumo.findChildren(QPushButton) if b not in antes]
        return self._lateral_botoes

    def _atualizar_rodape(self, busy: bool) -> None:
        r = self.rodape
        fim_ok = self.modo == CRIAR and self.criacao == "ok"
        self.cancelar.setVisible(busy)
        self.cancelar.setEnabled(busy)
        self.criar_outro.setVisible(fim_ok and not busy)
        r.voltar.setVisible(not fim_ok)
        if self.modo == CRIAR:
            r.voltar.setEnabled(not busy and self.passo > 0 and self.criacao != "rodando")
            if self.passo < 2:
                texto = S.COPIA_PRIMARIO[self.passo]
            elif self.passo == 2:
                texto = S.COPIA_RETOMAR_AGORA if self.retomando else S.COPIA_PRIMARIO[2]
            elif self.criacao == "ok":
                texto = S.COPIA_PRIMARIO_FIM
            elif self.criacao == "falhou":
                texto = S.COPIA_RETOMAR if self._ha_incompleto() else "Voltar às pastas"
            else:
                texto = S.COPIA_PRIMARIO[2]
            r.primario.setText(texto)
            r.primario.setVisible(not (self.passo == 3 and self.criacao == "rodando"))
        else:
            r.voltar.setEnabled(not busy)
            r.primario.setText(
                "Abrir numa pasta nova" if self.modo == ABRIR else "Conferir a cópia"
            )
            r.primario.setVisible(True)
        self._atualizar_primario()

    def _atualizar_primario(self) -> None:
        p = self.rodape.primario
        if self.runner.busy:
            p.setEnabled(False)
            return
        if self.modo == CRIAR and self.passo == 2:
            aceites = all(c.isChecked() for c in self.aceites_todos if not c.isHidden())
            pronto = (
                self._retomada_ok if self.retomando else (self._plan is not None and self._plan.ok)
            )
            p.setEnabled(pronto and aceites)
            return
        p.setEnabled(True)

    def _ordem_tab(self, alterar: Sequence[QWidget]) -> None:
        cadeia: list[QWidget] = [self.bt_criar, self.bt_abrir, self.bt_conferir, self.bt_limites]
        cadeia += self._foco_da_pagina()
        cadeia += list(alterar)
        cadeia += [self.rodape.voltar, self.rodape.primario, self.cancelar, self.criar_outro]
        for a, b in itertools.pairwise(cadeia):
            QWidget.setTabOrder(a, b)

    def _ha_incompleto(self) -> bool:
        vault = self._caminho_cofre()
        if vault is None:
            return False
        try:
            return inspect_vault_dir(vault).kind == "vault-incomplete"
        except OwlVaultError:
            return False

    # ------------------------------------------------------------------ navegação
    def _ir_modo(self, modo: str) -> None:
        if self.runner.busy or modo == self.modo:
            return
        self.modo = modo
        self._mostrar()

    def _alterar(self, campo: QWidget) -> None:
        if self.runner.busy:
            return
        self.passo = 0
        self.criacao = "" if self.criacao == "falhou" else self.criacao
        self._mostrar()
        campo.setFocus(Qt.FocusReason.OtherFocusReason)

    def _ir_passo(self, passo: int) -> None:
        self.passo = passo
        self._mostrar()

    def _voltar(self) -> None:
        if self.runner.busy:
            return
        if self.modo != CRIAR:
            self.modo = CRIAR
            self._mostrar()
            return
        if self.passo == 3:  # depois de uma falha: as pastas (onde fica "Retomar")
            self.criacao = ""
            self._ir_passo(0)
            return
        if self.passo > 0:
            self._ir_passo(self.passo - 1)

    def _primario(self) -> None:
        if self.runner.busy or not self.rodape.primario.isEnabled():
            return
        if self.modo == ABRIR:
            self._abrir_copia()
            return
        if self.modo == CONFERIR:
            self._conferir_copia()
            return
        if self.passo == 0:
            self._avancar_pastas()
        elif self.passo == 1:
            self._avancar_senha()
        elif self.passo == 2:
            self._iniciar_criacao()
        elif self.criacao == "ok" and self._resultado is not None:
            open_in_explorer(self._resultado.vault)
        elif self.criacao == "falhou":
            self.criacao = ""
            if self._ha_incompleto():
                self.passo = 0
                self._iniciar_retomada()
            else:
                self._ir_passo(0)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        """Enter num campo aciona o botão primário (o "default" da página)."""
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            foco = QApplication.focusWidget()
            p = self.rodape.primario
            if not isinstance(foco, (QAbstractButton, QPlainTextEdit)) and p.isVisible():
                if p.isEnabled():
                    p.click()
                event.accept()
                return
        super().keyPressEvent(event)

    def _mostrar_limites(self) -> None:
        inform(self, S.LIMITS_TITLE, S.LIMITS_TEXT + "\n\n" + S.BACKUP_TEXT)

    # ------------------------------------------------------------------ passo 1 — pastas
    def _sugerir_teste(self) -> None:
        """Sugere a pasta do teste no volume da origem; recalcula enquanto o campo ainda
        contém a sugestão automática (uma pasta escolhida pelo usuário é mantida)."""
        src = self.c_origem.texto()
        current = self.c_teste.texto()
        if not src or (current and current != self._auto_test):
            return
        try:
            res = winfs.resolve(src)
            if res.exists and res.is_directory and len(res.parts) > 1:
                suggestion = winfs.strip_extended(default_test_parent(res))
                self._auto_test = suggestion
                self.c_teste.definir(suggestion)
        except (OwlVaultError, OSError):
            pass

    def _caminho_cofre(self) -> str | None:
        parent, name = self.c_local.texto(), self.c_nome.text().strip()
        if not parent or not name:
            return None
        return os.path.join(parent, name)

    def _validar_pastas(self, *, retomada: bool) -> str | None:
        """Mesmas regras de antes (agora antes de avançar). Devolve o caminho do cofre."""
        mostrar_erro(self.erro_pastas, "")
        src = self.c_origem.texto()
        if not src:
            mostrar_erro(
                self.erro_pastas,
                "Informe a mesma pasta de origem usada na criação."
                if retomada
                else "Escolha a pasta de origem.",
            )
            return None
        vault = self._caminho_cofre()
        if vault is None:
            mostrar_erro(self.erro_pastas, "Informe o local e o nome do cofre.")
            return None
        try:
            status = inspect_vault_dir(vault)
        except OwlVaultError as exc:
            mostrar_erro(self.erro_pastas, f"Local do cofre: {exc}")
            return None
        if retomada and status.kind != "vault-incomplete":
            mostrar_erro(self.erro_pastas, "Não há criação interrompida nessa pasta de cofre.")
            return None
        if not retomada and status.kind == "vault-incomplete":
            mostrar_erro(
                self.erro_pastas,
                "Já existe um cofre incompleto com esse nome. Use 'Retomar criação "
                "interrompida' ou escolha outro nome.",
            )
            return None
        return vault

    def _avancar_pastas(self) -> None:
        if self._validar_pastas(retomada=False) is None:
            return
        self.retomando = False
        mostrar_erro(self.erro_senha, "")
        self._ir_passo(1)

    def _iniciar_retomada(self) -> None:
        if self.runner.busy or self._validar_pastas(retomada=True) is None:
            return
        self.retomando = True
        mostrar_erro(self.erro_senha, "")
        self._ir_passo(1)

    # ------------------------------------------------------------------ passo 2 — senha
    def _avancar_senha(self) -> None:
        pw1, pw2 = self.c_senha.text(), self.c_conf.text()
        if self.retomando:
            if not pw1:
                mostrar_erro(self.erro_senha, "Digite a senha do cofre.")
                return
        else:
            if len(pw1) < MIN_PASSWORD_LENGTH:
                mostrar_erro(
                    self.erro_senha,
                    f"A senha deve ter pelo menos {MIN_PASSWORD_LENGTH} caracteres.",
                )
                return
            if pw1 != pw2:
                mostrar_erro(self.erro_senha, "As senhas não conferem.")
                return
            try:
                validate_new_password(pw1)
            except OwlVaultError as exc:
                mostrar_erro(self.erro_senha, str(exc))
                return
        mostrar_erro(self.erro_senha, "")
        self._plan = None
        self._retomada_ok = False
        self._ir_passo(2)
        if self.retomando:
            self._conferir_retomada()
        else:
            self._rodar_conferencia()

    # ------------------------------------------------------------------ passo 3 — conferência
    def _definir_linhas(self, linhas: Sequence[Checagem]) -> None:
        for w in self.linhas:
            self.lista_checagens.removeWidget(w)
            w.hide()
            w.deleteLater()
        self.linhas = []
        for c in linhas:
            w = LinhaChecagem(c.titulo, c.detalhe, c.estado)
            self.lista_checagens.addWidget(w)
            self.linhas.append(w)

    def _definir_detalhes(self, itens: Sequence[str]) -> None:
        mostrar = len(itens) > 3
        self.detalhes.setPlainText("\n".join(f"• {i}" for i in itens) if mostrar else "")
        self.detalhes_titulo.setVisible(mostrar)
        self.detalhes.setVisible(mostrar)

    def _conferir_de_novo(self) -> None:
        if self.runner.busy:
            return
        if self.retomando:
            self._conferir_retomada()
        else:
            self._rodar_conferencia()

    def _rodar_conferencia(self) -> None:
        self._plan = None
        self.aceite_fat.hide()
        self._definir_linhas([Checagem(t, "", "Conferindo…") for t in TITULOS_CONFERENCIA])
        self._definir_detalhes([])
        src = self.c_origem.texto()
        vault = self._caminho_cofre() or ""
        test = self.c_teste.texto() or None
        protected = self._protected

        def job(
            progress: QtProgress, cancel: CancelToken
        ) -> tuple[CreatePlan, list[str], int | None]:
            reg = _Registro(progress)
            plan = preflight_create(
                src, vault, test_parent=test, protected=protected, progress=reg, cancel=cancel
            )
            livre: int | None = None
            if plan.vault_res is not None:
                try:
                    livre = winfs.volume_space(plan.vault_res.existing_ancestor).free_bytes
                except OSError:
                    livre = None
            return plan, reg.etapas, livre

        self._rodar(job, self._depois_conferencia, self._falhou_conferencia, None, "Conferindo…")

    def _depois_conferencia(self, resultado: object) -> None:
        assert isinstance(resultado, tuple)
        plan, etapas, livre = resultado
        assert isinstance(plan, CreatePlan)
        self._plan = plan
        self._definir_linhas(conferencia(plan, etapas, livre))
        self._definir_detalhes(plan.blockers)
        self.aceite_fat.setVisible(plan.needs_fat_ack)
        if plan.blockers:
            self.rodape.definir_estado("Corrija os itens marcados e confira de novo.", "erro")
        else:
            self.rodape.definir_estado("Conferência concluída. Marque os avisos para continuar.")

    def _falhou_conferencia(self, exc: object) -> None:
        self._plan = None
        msg = mensagem_de_erro(exc)
        self._definir_linhas(
            [Checagem(t, "", "Não conferido.") for t in TITULOS_CONFERENCIA]
            + [Checagem("A conferência parou", "falhou", msg)]
        )
        self.rodape.definir_estado(msg, "erro")

    def _conferir_retomada(self) -> None:
        """Retomada: a pré-verificação roda dentro de ``resume_create``; aqui só o que a
        tela antiga perguntava (aceites e, se for o caso, o aviso de FAT/exFAT)."""
        self._retomada_ok = False
        self._definir_detalhes([])
        self.aceite_fat.hide()
        vault = self._caminho_cofre()
        linhas: list[Checagem] = []
        try:
            if vault is None:
                raise OwlVaultError("Informe o local e o nome do cofre.")
            status = inspect_vault_dir(vault)
            if status.kind != "vault-incomplete":
                linhas.append(
                    Checagem("Criação interrompida", "falhou", "Não há criação interrompida aqui.")
                )
            else:
                if isinstance(status.files_total, int) and isinstance(status.files_done, int):
                    detalhe = (
                        f"{fmt_int(status.files_done)} de {fmt_int(status.files_total)} "
                        "arquivo(s) já criptografado(s). A criação continua de onde parou."
                    )
                else:
                    detalhe = "A criação continua de onde parou."
                linhas.append(Checagem("Criação interrompida encontrada", "ok", detalhe))
                res = winfs.resolve(vault)
                self.aceite_fat.setVisible(winfs.is_fat(res.fs_name))
                self._retomada_ok = True
        except OwlVaultError as exc:
            linhas.append(Checagem("Local do cofre", "falhou", str(exc)))
        linhas.append(
            Checagem(
                "Origem",
                "",  # conferida dentro da retomada (resume_create), não aqui
                "A origem é conferida de novo ao retomar: arquivos que mudaram são "
                "criptografados outra vez.",
            )
        )
        self._definir_linhas(linhas)
        self.rodape.definir_estado("Pronto.")
        self._atualizar_primario()

    # ------------------------------------------------------------------ passo 4 — criar
    def _iniciar_criacao(self) -> None:
        if self.retomando:
            self._iniciar_retomada_job()
            return
        plan = self._plan
        if plan is None or plan.blockers:
            return
        password = self.c_senha.tomar()
        self.c_conf.setText("")  # setText também descarta o histórico de desfazer
        self.session_sources.append(plan.source_ext)
        fat_ack = plan.needs_fat_ack and self.aceite_fat.isChecked()
        params, policy, protected = self._params, self._policy, self._protected

        def job(progress: QtProgress, cancel: CancelToken) -> CreateResult:
            return create_vault(
                plan.source_ext,
                plan.vault_ext,
                password,
                plan=plan,
                kdf_params=params,
                kdf_policy=policy,
                protected=protected,
                fat_acknowledged=fat_ack,
                progress=progress,
                cancel=cancel,
            )

        self._comecar_passo4(job)

    def _iniciar_retomada_job(self) -> None:
        vault = self._caminho_cofre()
        src = self.c_origem.texto()
        if vault is None or not self._retomada_ok:
            return
        password = self.c_senha.tomar()
        self.c_conf.setText("")
        self.session_sources.append(src)
        fat_ack = not self.aceite_fat.isHidden() and self.aceite_fat.isChecked()
        policy, protected = self._policy, self._protected

        def job(progress: QtProgress, cancel: CancelToken) -> CreateResult:
            return resume_create(
                vault,
                src,
                password,
                kdf_policy=policy,
                protected=protected,
                fat_acknowledged=fat_ack,
                progress=progress,
                cancel=cancel,
            )

        self._comecar_passo4(job)

    def _comecar_passo4(self, job: Callable[[QtProgress, CancelToken], CreateResult]) -> None:
        self.criacao = "rodando"
        self._resultado = None
        self.p4_titulo.setText(S.COPIA_P4_TITULO)
        mostrar_erro(self.erro_criar, "")
        self.resultado_criar.limpar()
        self.passo = 3
        self._rodar(job, self._depois_criar, self._falhou_criar, self.painel_criar, "Criando…")

    def _depois_criar(self, result: object) -> None:
        assert isinstance(result, CreateResult)
        self._resultado = result
        self.criacao = "ok"
        self._plan = None
        ok = result.status == "success"
        self.p4_titulo.setText(S.COPIA_P4_TITULO_OK if ok else S.COPIA_P4_TITULO_DIVERGENCIAS)
        data, _sep, hora = result.snapshot_label.partition(" ")
        if ok:
            texto = S.FIM_TEXTO.format(data=data, hora=hora)
            if result.removable_media:
                texto += " " + S.COPIA_MIDIA_REMOVIVEL
        else:
            texto = result.message
        self.painel_criar.concluir("Concluído.", ok=True)
        self.painel_criar.escrever(result.message, "ok" if ok else "aviso")
        self.resultado_criar.mostrar(
            "Cópia criada e verificada" if ok else "Cópia criada, com divergências",
            "ok" if ok else "aviso",
            f"{fmt_int(result.files)} arquivo(s) · {fmt_int(result.dirs)} pasta(s) · "
            f"{fmt_size(result.total_bytes)} · cofre em {winfs.strip_extended(result.vault)}",
            texto,
            [
                ("Divergências", result.divergences),
                ("Avisos", result.warnings),
                ("Notas", result.notes),
            ],
        )
        hora_agora = _dt.datetime.now().strftime("%H:%M")
        self.rodape.definir_estado(f"Pronto. Último cofre verificado às {hora_agora}.")

    def _falhou_criar(self, exc: object) -> None:
        self.criacao = "falhou"
        msg = mensagem_de_erro(exc)
        self.p4_titulo.setText(S.COPIA_P4_TITULO_PAROU)
        self.painel_criar.concluir("A criação parou.", ok=False)
        self.painel_criar.escrever(
            "Operação cancelada." if isinstance(exc, CancelledError) else f"Erro: {msg}", "erro"
        )
        mostrar_erro(self.erro_criar, msg)
        if isinstance(exc, PreflightError) and exc.blockers:
            self.resultado_criar.mostrar(
                "Bloqueios", "falhou", str(exc), secoes=[("Bloqueios", exc.blockers)]
            )
        self.rodape.definir_estado("A criação parou. Veja o motivo no cartão.", "erro")

    def _criar_outro(self) -> None:
        if self.runner.busy:
            return
        self.criacao = ""
        self.retomando = False
        self._resultado = None
        self._plan = None
        self.c_nome.setText(default_vault_name())
        for c in self.aceites_todos:
            c.setChecked(False)
        self.resultado_criar.limpar()
        mostrar_erro(self.erro_criar, "")
        self.p4_titulo.setText(S.COPIA_P4_TITULO)
        self.painel_criar.concluir("Pronto.", ok=False)
        self.painel_criar.barra.setValue(0)
        self.rodape.definir_estado("Pronto.")
        self._ir_passo(0)

    # ------------------------------------------------------------------ conferir uma cópia
    def _conferir_copia(self) -> None:
        mostrar_erro(self.erro_conferir, "")
        vault, password = self.v_copia.texto(), self.v_senha.text()
        if not vault or not password:
            mostrar_erro(self.erro_conferir, "Informe o cofre e a senha.")
            return
        self.v_senha.limpar()
        self.resultado_conferir.limpar()
        self.painel_conferir.show()
        policy = self._policy

        def job(progress: QtProgress, cancel: CancelToken) -> VerifyReport:
            return verify_vault(vault, password, policy=policy, progress=progress, cancel=cancel)

        self._rodar(
            job, self._depois_conferir, self._falhou_conferir, self.painel_conferir, "Conferindo…"
        )

    def _depois_conferir(self, report: object) -> None:
        assert isinstance(report, VerifyReport)
        if report.fully_ok:
            titulo_r, estado = "Cofre íntegro", "ok"
            headline = (
                f"Cofre íntegro: {report.files_ok}/{report.total_files} arquivos conferidos.\n"
                f"{report.creation_status}"
            )
        elif report.ok:
            titulo_r, estado = "Todos os arquivos conferem, com observações", "aviso"
            headline = (
                f"Todos os {report.files_ok} arquivos conferem, mas há observações"
                + (
                    " — uma cópia de segurança do cabeçalho/manifesto está danificada "
                    "(veja docs/RECOVERY.md §2)"
                    if report.redundancy
                    else ""
                )
                + f".\n{report.creation_status}"
            )
        else:
            titulo_r, estado = "Problemas encontrados", "falhou"
            headline = (
                f"PROBLEMAS ENCONTRADOS: {len(report.bad)} arquivo(s) com falha de integridade "
                f"({report.files_ok}/{report.total_files} íntegros).\n{report.creation_status}"
            )
        if report.lock_note:
            headline += "\n" + report.lock_note
        self.painel_conferir.concluir("Concluído.", ok=True)
        self.painel_conferir.escrever(
            headline.replace("\n", " "), {"ok": "ok", "aviso": "aviso"}.get(estado, "erro")
        )
        self.resultado_conferir.mostrar(
            titulo_r,
            estado,
            f"{fmt_int(report.files_ok)} de {fmt_int(report.total_files)} arquivo(s) íntegro(s)",
            headline,
            [
                ("Problemas", report.bad),
                ("Cópias redundantes danificadas", report.redundancy),
                ("Anomalias", report.anomalies),
                ("Notas", report.notes),
            ],
        )
        self.rodape.definir_estado(
            "Pronto." if estado == "ok" else "Conferência concluída com observações.",
            "" if estado != "falhou" else "erro",
        )

    def _falhou_conferir(self, exc: object) -> None:
        msg = mensagem_de_erro(exc)
        self.painel_conferir.concluir("A conferência parou.", ok=False)
        self.painel_conferir.escrever(f"Erro: {msg}", "erro")
        mostrar_erro(self.erro_conferir, msg)
        self.rodape.definir_estado("A conferência parou.", "erro")

    # ------------------------------------------------------------------ abrir uma cópia
    def _abrir_copia(self) -> None:
        mostrar_erro(self.erro_abrir, "")
        vault, password = self.r_copia.texto(), self.r_senha.text()
        parent, name = self.r_local.texto(), self.r_nome.text().strip()
        if not vault or not password or not parent or not name:
            mostrar_erro(
                self.erro_abrir, "Informe o cofre, a senha, o destino e o nome da pasta nova."
            )
            return
        dest = os.path.join(parent, name)
        allow_resume = False
        try:
            state = inspect_destination(dest)
        except OwlVaultError as exc:
            mostrar_erro(self.erro_abrir, str(exc))
            return
        if state == "nonempty":
            mostrar_erro(
                self.erro_abrir,
                "A pasta de destino já existe e não está vazia. Escolha outro nome.",
            )
            return
        if state == "resumable":
            escolha = ask(
                self,
                "Continuar a restauração?",
                "Esta pasta contém uma restauração interrompida deste Owl Vault. Continuar de "
                "onde parou? (arquivos existentes são conferidos pelo hash e nunca sobrescritos)",
                [("Continuar de onde parou", "sim"), ("Cancelar", "nao")],
            )
            if escolha != "sim":
                return
            allow_resume = True
        password = self.r_senha.tomar()
        sources = list(self.session_sources)
        policy, protected = self._policy, self._protected
        self.resultado_abrir.limpar()
        self.painel_abrir.show()

        def job(progress: QtProgress, cancel: CancelToken) -> RestoreReport:
            return restore_vault(
                vault,
                password,
                dest,
                policy=policy,
                protected=protected,
                session_sources=sources,
                allow_resume=allow_resume,
                progress=progress,
                cancel=cancel,
            )

        self._rodar(job, self._depois_abrir, self._falhou_abrir, self.painel_abrir, "Abrindo…")

    def _depois_abrir(self, report: object) -> None:
        assert isinstance(report, RestoreReport)
        destino = winfs.strip_extended(report.destination)
        if report.ok:
            titulo_r, estado = "Cópia aberta numa pasta nova", "ok"
            headline = (
                f"Restauração concluída em {destino}: {report.restored} arquivo(s) "
                f"restaurado(s), {report.skipped_existing} já existente(s) conferido(s).\n"
                f"{report.creation_status}"
            )
        else:
            titulo_r, estado = "Restauração parcial", "falhou"
            headline = (
                f"Restauração PARCIAL em {destino}: {report.restored} arquivo(s) "
                f"restaurado(s); {len(report.failed)} falha(s), {len(report.conflicts)} "
                f"conflito(s).\n{report.creation_status}"
            )
        mostrar_pasta = botao_discreto("Mostrar a pasta")
        mostrar_pasta.clicked.connect(lambda: open_in_explorer(report.destination))
        self.painel_abrir.concluir("Concluído.", ok=report.ok)
        self.painel_abrir.escrever(headline.replace("\n", " "), "ok" if report.ok else "erro")
        self.resultado_abrir.mostrar(
            titulo_r,
            estado,
            destino,
            headline,
            [
                ("Falhas", report.failed),
                ("Conflitos", report.conflicts),
                ("Avisos", report.warnings),
                ("Notas", report.notes),
            ],
            [mostrar_pasta],
        )
        self.r_nome.setText(self._nome_restaurado())
        self.rodape.definir_estado(
            "Pronto." if report.ok else "Restauração parcial.", "" if report.ok else "erro"
        )

    def _falhou_abrir(self, exc: object) -> None:
        msg = mensagem_de_erro(exc)
        self.painel_abrir.concluir("A restauração parou.", ok=False)
        self.painel_abrir.escrever(f"Erro: {msg}", "erro")
        mostrar_erro(self.erro_abrir, msg)
        self.rodape.definir_estado("A restauração parou.", "erro")

    # ------------------------------------------------------------------ trabalho em QThread
    def _rodar(
        self,
        job: Callable[[QtProgress, CancelToken], object],
        ao_terminar: Callable[[object], None],
        ao_falhar: Callable[[object], None],
        painel: PainelTrabalho | None,
        texto: str,
    ) -> None:
        self._ao_terminar = ao_terminar
        self._ao_falhar = ao_falhar
        self._painel = painel
        self._pf_nome, self._pf_total, self._pf_feito = "", 0, 0
        if painel is not None:
            painel.reiniciar()
        self.rodape.definir_estado(texto, "trabalhando")
        self.runner.start(job)
        self._mostrar()

    def _escrever(self, mensagem: str, tipo: str = "") -> None:
        (self._painel or self.painel_criar).escrever(mensagem, tipo)

    @Slot(str, object, object)
    def _on_stage(self, name: str, total_bytes: object, total_items: object) -> None:
        tb = total_bytes if isinstance(total_bytes, int) else 0
        ti = total_items if isinstance(total_items, int) else 0
        if self._painel is not None:
            self._painel.iniciar_etapa(name, tb, ti)
            self._painel.escrever(name)
        self._pf_nome, self._pf_total, self._pf_feito = name, ti, 0
        self.rodape.definir_estado(name, "trabalhando")

    @Slot(object, object)
    def _on_advance(self, nbytes: object, nitems: object) -> None:
        nb = nbytes if isinstance(nbytes, int) else 0
        ni = nitems if isinstance(nitems, int) else 0
        if self._painel is not None:
            self._painel.avancar(nb, ni)
            self.rodape.definir_estado(self._painel.etapa.text(), "trabalhando")
            return
        self._pf_feito += ni
        if self._pf_total:
            feito = min(self._pf_feito, self._pf_total)
            self.rodape.definir_estado(
                f"{self._pf_nome} ({fmt_int(feito)} de {fmt_int(self._pf_total)})", "trabalhando"
            )

    def _cancelar(self) -> None:
        if not self.runner.busy:
            return
        self.runner.cancel()
        self._escrever("Cancelamento solicitado: a operação vai parar no próximo ponto seguro.")
        self.cancelar.setEnabled(False)
        self.rodape.definir_estado("Parando num ponto seguro…", "trabalhando")

    @Slot(object)
    def _on_done(self, result: object) -> None:
        handler = self._ao_terminar
        self._ao_terminar = self._ao_falhar = None
        self._painel = None
        if handler is not None:
            handler(result)
        self._depois_do_trabalho()

    @Slot(object)
    def _on_error(self, exc: object) -> None:
        handler = self._ao_falhar
        self._ao_terminar = self._ao_falhar = None
        self._painel = None
        if handler is not None:
            handler(exc)
        else:
            self.rodape.definir_estado(mensagem_de_erro(exc), "erro")
        self._depois_do_trabalho()

    def _depois_do_trabalho(self) -> None:
        self._mostrar()
        if self._fechar_depois:
            self._fechar_depois = False
            QTimer.singleShot(0, self.close)

    # ------------------------------------------------------------------ fechar
    def closeEvent(self, event: QCloseEvent) -> None:
        if self.runner.busy:
            escolha = ask(
                self,
                "Há uma operação em andamento",
                S.COPIA_FECHAR_TEXTO,
                [("Parar e fechar", "stop"), ("Continuar trabalhando", "keep")],
                primary="keep",
            )
            if escolha == "stop" and self.runner.busy:
                self._fechar_depois = True
                self._cancelar()
            event.ignore()
            return
        event.accept()
