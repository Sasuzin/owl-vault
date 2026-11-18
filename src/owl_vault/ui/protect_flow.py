"""Assistente "Proteger uma pasta" na própria janela (UI_SPEC_V2 T5 + T6, visual "Cofre").

Passos: 1 Pasta (seletor do Windows) → 2 Conferência (pré-verificação: uma linha por checagem,
aviso com todos os pontos da confirmação T5d e "Entendi" na 1ª proteção) → 3 Trancar (barra,
etapa 1/4…4/4, tempo restante e um registro só com as etapas — nunca nomes de arquivos).

A tela só mostra e pede: quem roda a conferência e o trancamento (numa QThread, pelo
``JobRunner``) é a janela, que escuta ``check_requested``/``lock_requested``.
"""

from __future__ import annotations

import html
import time
from collections.abc import Sequence

from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtWidgets import (
    QCheckBox,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from owl_vault.application.lockers import LockOutcome, ProtectCheck
from owl_vault.domain.errors import CancelledError, OwlVaultError, PreflightError
from owl_vault.storage import winfs
from owl_vault.ui.common import _map_stage, fmt_duration, fmt_int, fmt_size
from owl_vault.ui.componentes import (
    Aviso,
    CampoCaminho,
    Dica,
    LinhaChecagem,
    TrilhaPassos,
    botao_discreto,
    cartao,
    erro,
    lista_detalhes,
    mostrar_erro,
    nota,
    rotulo,
    subtitulo,
    titulo,
)
from owl_vault.ui.pages import CartaoResumo, Pagina, _palco, _rolavel, item
from owl_vault.ui.workers import JobRunner

#: (chave, título) das linhas da conferência, na ordem em que aparecem
CHECAGENS: list[tuple[str, str]] = [
    ("permitida", "Pasta permitida"),
    ("arquivos", "Arquivos"),
    ("espaco", "Espaço em disco"),
    ("em_uso", "Arquivos em uso"),
    ("permissao", "Permissão para apagar"),
]

_OK = {
    "permitida": "A pasta pode ser protegida.",
    "espaco": "Há espaço para guardar os arquivos criptografados.",
    "em_uso": "Nenhum arquivo está aberto em outro programa.",
    "permissao": "O Windows deixa o Owl Vault apagar as cópias legíveis.",
}

#: os cinco pontos da confirmação T5d (nenhum some: só mudaram de lugar)
PONTOS_T5D = [
    "Os arquivos ficam guardados, criptografados, dentro da própria pasta. As cópias legíveis "
    "são apagadas (não vão para a Lixeira).",
    "Para abrir, use o atalho dentro da pasta ou o Owl Vault, com o seu PIN.",
    "Cópias que já existem em outros lugares (Lixeira, OneDrive, backups, versões anteriores) "
    "não são apagadas. Recomendamos ativar o BitLocker.",
    "Ao abrir, os arquivos voltam com nome, conteúdo e data de modificação; data de criação, "
    "atributos e permissões não voltam.",
    "Enquanto aberta, a pasta ocupa o dobro do espaço.",
]

_NAO_CONFERIDO = "Não conferido: resolva os itens marcados e confira de novo."


def classificar(motivo: str) -> str:
    """Em qual linha da conferência entra um bloqueio da ``PreflightError``."""
    low = motivo.lower()
    if "em uso" in low:
        return "em_uso"
    if any(k in low for k in ("espaço insuficiente", "espaço livre", "falta espaço")):
        return "espaco"
    if "segurança do windows" in low or "apagar arquivos" in low:
        return "permissao"
    return "permitida"


def _definir(lbl: QLabel, text: str) -> None:
    """Texto + visibilidade (rótulo vazio não ocupa espaço)."""
    lbl.setText(text)
    lbl.setVisible(bool(text))


def estimativa(files: int, total: int) -> float:
    """Segundos estimados para trancar (~60 MB/s, 3 passadas), como na confirmação T5d."""
    return total / (60 * 1024 * 1024) * 2.2 + files * 0.01


def resumo_arquivos(files: int, total: int) -> str:
    text = f"{fmt_int(files)} arquivo(s) · {fmt_size(total)}"
    seconds = estimativa(files, total)
    if seconds > 120:
        text += f" · pode levar {fmt_duration(seconds)}"
    return text


class ProtectPage(Pagina):
    """Os três passos do assistente. A janela conecta os sinais e roda os trabalhos."""

    back_to_list = Signal()
    check_requested = Signal(str)
    lock_requested = Signal()

    def __init__(self, runner: JobRunner) -> None:
        super().__init__(primario="Continuar para a conferência")
        self._runner = runner
        self.check: ProtectCheck | None = None
        self.first_time = False
        self.checking_now = False
        self.locking_now = False
        self.done = False
        self.locked_ok = False
        self.stopping = False
        self.failures: dict[str, list[str]] = {}
        self._path = ""
        self._stage_text = ""
        self._totals = (0, 0)
        self._done_counts = [0, 0]
        self._t0 = time.monotonic()
        self._connected = False
        #: o app bloqueou (``clear``): um caminho que o seletor de pastas devolver depois (ele
        #: não fecha com o bloqueio) é descartado; ``start`` desliga a marca
        self._bloqueada = False

        self.trilha = TrilhaPassos(["Pasta", "Conferência", "Trancar"])
        self.stack = QStackedWidget()
        self.stack.setObjectName("transparente")
        self.stack.addWidget(_rolavel(self._passo_pasta()))
        self.stack.addWidget(_rolavel(self._passo_conferencia()))
        self.stack.addWidget(_rolavel(self._passo_trancar()))
        self.resumo = CartaoResumo("O que vai acontecer")
        self.dica = Dica()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(20)
        root.addWidget(self.trilha)
        root.addWidget(_palco(self.stack, [self.resumo, self.dica]), 1)

        r = self.rodape
        r.voltar.clicked.connect(self._voltar)
        r.primario.clicked.connect(self._primario)
        self.again = botao_discreto("Conferir de novo")
        self.again.clicked.connect(self._conferir)
        self.another = botao_discreto("Proteger outra pasta")
        self.another.clicked.connect(lambda: self.start(first_time=False))
        r.extra.addWidget(self.again)
        r.extra.addWidget(self.another)
        self.start(first_time=False)

    # ------------------------------------------------------------------ montagem
    def _passo_pasta(self) -> QWidget:
        card, lay = cartao()
        lay.addWidget(titulo("Escolha a pasta"))
        lay.addWidget(
            subtitulo(
                "A pasta continua no mesmo lugar. Os arquivos ficam guardados dentro dela, "
                "criptografados, e só abrem com o seu PIN."
            )
        )
        lay.addSpacing(4)
        lay.addWidget(rotulo("Pasta"))
        self.campo = CampoCaminho(
            "Nenhuma pasta escolhida", "Escolha a pasta que você quer proteger"
        )
        self.campo.escolhido.connect(self.set_path)
        lay.addWidget(self.campo)
        lay.addWidget(
            nota(
                "Escolha uma pasta sua, como Documentos\\Particular. Pastas do Windows "
                "(Documentos, Downloads, Área de Trabalho) não podem ser protegidas inteiras."
            )
        )
        self.err1 = erro()
        lay.addWidget(self.err1)
        lay.addStretch(1)
        return card

    def _passo_conferencia(self) -> QWidget:
        card, lay = cartao()
        self.t2 = titulo("Conferência")
        self.t2.setTextFormat(Qt.TextFormat.PlainText)
        self.s2 = subtitulo("")
        self.s2.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self.t2)
        lay.addWidget(self.s2)
        self.bar2 = QProgressBar()
        self.bar2.setTextVisible(False)
        self.bar2.setRange(0, 0)
        lay.addWidget(self.bar2)
        self.linhas: dict[str, LinhaChecagem] = {}
        for key, label in CHECAGENS:
            linha = LinhaChecagem(label)
            self.linhas[key] = linha
            lay.addWidget(linha)
        self.details = lista_detalhes([])
        self.details.hide()
        self.show_details = botao_discreto("Detalhes")
        self.show_details.clicked.connect(self._alternar_detalhes)
        lay.addWidget(self.show_details, 0, Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(self.details)
        self.aviso2 = Aviso("<br>".join(f"•&nbsp; {html.escape(p)}" for p in PONTOS_T5D))
        lay.addWidget(self.aviso2)
        self.entendi = QCheckBox("Entendi")
        self.entendi.toggled.connect(self._atualizar_rodape)
        lay.addWidget(self.entendi)
        lay.addStretch(1)
        return card

    def _passo_trancar(self) -> QWidget:
        card, lay = cartao()
        self.t3 = titulo("Trancando")
        self.t3.setTextFormat(Qt.TextFormat.PlainText)
        self.s3 = subtitulo("")
        self.s3.setTextFormat(Qt.TextFormat.PlainText)
        self.s3.hide()
        lay.addWidget(self.t3)
        lay.addWidget(self.s3)
        self.bar3 = QProgressBar()
        self.bar3.setTextVisible(False)
        self.bar3.setRange(0, 0)
        lay.addWidget(self.bar3)
        self.etapa = rotulo("Preparando…")
        lay.addWidget(self.etapa)
        self.eta = nota("")
        lay.addWidget(self.eta)
        self.log = QPlainTextEdit()
        self.log.setObjectName("log")
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        self.log.setAccessibleName("Registro das etapas")
        self.log.setMinimumHeight(120)
        lay.addWidget(self.log, 1)
        self.aviso3 = Aviso("Não use esta pasta até terminar.")
        lay.addWidget(self.aviso3)
        return card

    def _alternar_detalhes(self) -> None:
        self.details.setVisible(self.details.isHidden())

    # ------------------------------------------------------------------ estado
    @property
    def step(self) -> int:
        return self.stack.currentIndex()

    def campo_inicial(self) -> QWidget | None:
        if self.step == 0:
            return self.campo.botao if not self._path else self.rodape.primario
        if self.step == 1:
            return self.rodape.primario if self.rodape.primario.isEnabled() else self.entendi
        return None

    def _nome(self) -> str:
        if self.check is not None:
            return self.check.name
        return winfs.name_of(self._path) if self._path else ""

    def _topo(self, passo: int) -> None:
        area = self.stack.widget(passo)
        if isinstance(area, QScrollArea):
            area.verticalScrollBar().setValue(0)

    def _ir(self, passo: int) -> None:
        self.stack.setCurrentIndex(passo)
        self.trilha.definir(passo)
        self._lateral()
        self._atualizar_rodape()

    def _lateral(self) -> None:
        passo = self.step
        if passo == 0:
            self.resumo.definir_secao("O que vai acontecer")
            self.resumo.definir(
                [
                    item("1. Conferência", "Nada na pasta é alterado."),
                    item("2. Guardar", "Os arquivos são criptografados, conferidos e testados."),
                    item("3. Apagar", "Só depois, as cópias legíveis são apagadas."),
                ]
            )
            self.dica.definir(
                "Antes de começar",
                "Feche os arquivos desta pasta. Enquanto o Owl Vault tranca, não use a pasta.",
            )
            return
        self.resumo.definir_secao("Sua escolha")
        local = winfs.strip_extended(winfs.parent_of(self._path)) if self._path else ""
        arquivos = (
            f"{fmt_int(self.check.files)} · {fmt_size(self.check.total_bytes)}"
            if self.check is not None
            else "—"
        )
        alterar = (lambda: self._ir(0)) if passo == 1 and not self.checking_now else None
        self.resumo.definir(
            [
                item("Pasta", self._nome(), alterar),
                item("Local", local, caminho=True),
                item("Arquivos", arquivos),
            ]
        )
        if passo == 1:
            self.dica.definir(
                "Confira antes de trancar",
                "Nada é apagado antes de os arquivos estarem guardados, conferidos e testados.",
            )
        elif self.done and self.locked_ok:
            self.dica.definir(
                "Seu backup",
                "Copiar a pasta trancada inteira (com os itens ocultos) é o seu backup. Ela abre "
                "com a senha mestra em qualquer computador.",
            )
        elif self.done:
            self.dica.definir(
                "Nada se perde",
                "Nenhum arquivo é apagado sem estar guardado, conferido e testado antes.",
            )
        else:
            self.dica.definir(
                "Pode cancelar",
                "Nas etapas 1 a 3, cancelar não apaga nada. Na etapa 4, o Owl Vault para depois "
                "do arquivo atual e a pasta fica em 'Precisa de atenção'.",
            )

    def _atualizar_rodape(self) -> None:
        r = self.rodape
        passo = self.step
        self.again.hide()
        self.another.hide()
        r.primario.show()
        r.voltar.show()
        r.voltar.setEnabled(True)
        if passo == 0:
            r.voltar.setText("Voltar")
            r.primario.setText("Continuar para a conferência")
            r.primario.setEnabled(bool(self._path))
        elif passo == 1:
            r.primario.setText("Trancar agora")
            if self.checking_now:
                r.voltar.setText("Cancelar")
                r.voltar.setEnabled(not self.stopping)
                r.primario.setEnabled(False)
            else:
                r.voltar.setText("Voltar")
                ack_ok = not self.first_time or self.entendi.isChecked()
                r.primario.setEnabled(self.check is not None and not self.failures and ack_ok)
                self.again.setVisible(bool(self.failures))
                if self.check is not None and not self.failures:
                    # a caixa pode estar abaixo da dobra: o rodapé diz por que o botão não liga
                    self.status("" if ack_ok else "Leia os avisos e marque 'Entendi'.")
        elif self.locking_now:
            r.primario.hide()
            r.voltar.setEnabled(not self.stopping)
            r.voltar.setText(
                "Parar depois do arquivo atual"
                if self._stage_text.startswith("4/4")
                else "Cancelar"
            )
        else:
            r.voltar.hide()
            r.primario.setText("Voltar para a lista")
            r.primario.setEnabled(True)
            self.another.show()

    # ------------------------------------------------------------------ ações do rodapé
    def _voltar(self) -> None:
        passo = self.step
        if passo == 0:
            self.back_to_list.emit()
        elif passo == 1 and self.checking_now:
            self._cancelar()
        elif passo == 1:
            self._ir(0)
        elif self.locking_now:
            self._cancelar()

    def _primario(self) -> None:
        passo = self.step
        if passo == 0:
            self._conferir()
        elif passo == 1:
            if self.rodape.primario.isEnabled():
                self.lock_requested.emit()
        else:
            self.back_to_list.emit()

    def _conferir(self) -> None:
        if not self._path:
            mostrar_erro(self.err1, "Escolha a pasta que você quer proteger.")
            return
        mostrar_erro(self.err1, "")
        self.check_requested.emit(self._path)

    def _cancelar(self) -> None:
        self._runner.cancel()
        self.stopping = True
        self.rodape.voltar.setEnabled(False)
        if self.locking_now:
            self.etapa.setText("Parando num ponto seguro…")
        self.status("Parando num ponto seguro…", "trabalhando")

    # ------------------------------------------------------------------ chamado pela janela
    def start(self, *, first_time: bool) -> None:
        """Volta ao passo 1 sem nada escolhido (também usado ao bloquear: limpa os nomes)."""
        self._desconectar()
        self._bloqueada = False
        self.first_time = first_time
        self.check = None
        self.failures = {}
        self.checking_now = False
        self.locking_now = False
        self.done = False
        self.locked_ok = False
        self.stopping = False
        self._path = ""
        self._stage_text = ""
        self.campo.definir("")
        mostrar_erro(self.err1, "")
        self.t2.setText("Conferência")
        self.s2.setText("")
        self.t3.setText("Trancando")
        self.s3.setText("")
        self.s3.hide()
        self.etapa.setText("Preparando…")
        _definir(self.eta, "")
        self.log.setPlainText("")
        self.details.setPlainText("")
        self.details.hide()
        self.show_details.hide()
        self.entendi.setChecked(False)
        self.entendi.setVisible(first_time)
        self.aviso3.definir("Não use esta pasta até terminar.")
        for linha in self.linhas.values():
            linha.definir("", "")
        self.status()
        self._ir(0)

    def clear(self) -> None:
        """Ao bloquear: limpa os nomes e passa a recusar caminhos até o próximo ``start``."""
        self.start(first_time=False)
        self._bloqueada = True

    @Slot(str)
    def set_path(self, path: str) -> None:
        if self._bloqueada:
            # o seletor de pastas voltou depois do bloqueio: o caminho (com o nome da pasta)
            # não fica nem no campo, nem na dica, nem aqui
            self._path = ""
            self.campo.definir("")
            self._atualizar_rodape()
            return
        self._path = path
        self.check = None
        self.failures = {}
        self.campo.definir(path)
        mostrar_erro(self.err1, "")
        self._atualizar_rodape()

    def checking(self) -> None:
        """Passo 2 enquanto a pré-verificação roda (nada é alterado na pasta)."""
        self.checking_now = True
        self.stopping = False
        self.check = None
        self.failures = {}
        nome = self._nome()
        self.t2.setText(f"Proteger '{nome}'?" if nome else "Conferência")
        self.s2.setText("Conferindo a pasta…")
        self.bar2.show()
        self.show_details.hide()
        self.details.hide()
        for linha in self.linhas.values():
            linha.definir("", "Conferindo…")
        self._topo(1)
        self._ir(1)
        self.status("Conferindo a pasta…", "trabalhando")

    def show_check(self, check: ProtectCheck) -> None:
        """Pré-verificação sem bloqueios: tudo em ok e "Trancar agora" liberado."""
        self.checking_now = False
        self.check = check
        self.failures = {}
        self.bar2.hide()
        self.show_details.hide()
        self.details.hide()
        self.details.setPlainText("")
        self.t2.setText(f"Proteger '{check.name}'?")
        self.s2.setText(winfs.strip_extended(winfs.parent_of(check.path)))
        for key, linha in self.linhas.items():
            if key == "arquivos":
                linha.definir("ok", resumo_arquivos(check.files, check.total_bytes))
            else:
                linha.definir("ok", _OK[key])
        self.status()
        self._ir(1)

    def show_blockers(self, blockers: Sequence[str]) -> None:
        """Pré-verificação recusada: cada bloqueio vai para a sua linha, com o motivo."""
        self.checking_now = False
        self.check = None
        self.bar2.hide()
        nome = self._nome()
        self.t2.setText(f"Não é possível proteger '{nome}'" if nome else "Não é possível proteger")
        self.s2.setText("Resolva os itens marcados e clique em Conferir de novo.")
        grupos: dict[str, list[str]] = {}
        for motivo in blockers:
            grupos.setdefault(classificar(motivo), []).append(motivo)
        self.failures = grupos
        for key, linha in self.linhas.items():
            if key in grupos:
                itens = grupos[key]
                extra = f" (e mais {len(itens) - 1})" if len(itens) > 1 else ""
                linha.definir("falhou", itens[0] + extra)
            elif key == "permitida" or (key == "espaco" and "permitida" not in grupos):
                # as regras da pasta sempre rodam; o espaço, sempre que a pasta passou
                linha.definir("ok", _OK[key])
            else:
                # a pré-verificação parou antes (ou no meio) desta checagem — sem contagem de
                # arquivos e sem a sonda de exclusão completa, não dá para dizer que passou
                linha.definir("", _NAO_CONFERIDO)
        lista = list(blockers[:5])
        if len(blockers) > 5:
            lista.append(f"e mais {len(blockers) - 5}")
        self.details.setPlainText("\n".join(f"• {i}" for i in lista))
        self.details.hide()
        self.show_details.setText(f"Detalhes ({fmt_int(len(blockers))})")
        self.show_details.setVisible(len(blockers) > 1)
        self.status("A pasta não pode ser protegida agora.", "erro")
        self._ir(1)

    def check_cancelled(self) -> None:
        self.checking_now = False
        self.bar2.hide()
        self._ir(0)
        mostrar_erro(self.err1, "A conferência foi cancelada. Nada foi alterado.")
        self.status()

    def locking(self) -> None:
        """Passo 3: trancando (a janela já iniciou o trabalho no ``JobRunner``)."""
        self.locking_now = True
        self.stopping = False
        self.done = False
        nome = self._nome()
        self.t3.setText(f"Trancando '{nome}'")
        self.s3.hide()
        self.bar3.setRange(0, 0)
        self.etapa.setText("Preparando…")
        _definir(self.eta, "")
        self.log.setPlainText("")
        self._stage_text = ""
        self._log("Começou.")
        self.aviso3.definir("Não use esta pasta até terminar.")
        self._conectar()
        self._topo(2)
        self._ir(2)
        self.status("Trancando…", "trabalhando")

    def finish(self, out: LockOutcome) -> None:
        self._desconectar()
        self.locking_now = False
        self.done = True
        self.locked_ok = out.complete
        name = out.record.name
        self.bar3.setRange(0, 1000)
        if out.complete:
            self.bar3.setValue(1000)
            self.t3.setText(f"'{name}' está trancada.")
            extras = []
            if out.removable:
                extras.append("Use 'Remover hardware com segurança' antes de tirar a unidade.")
            if out.kept_previous:
                extras.append(
                    "Uma versão anterior com arquivos que não estão na pasta foi mantida."
                )
            extras.append("Para abrir, use 'Abrir' na lista ou o atalho dentro da pasta.")
            self.s3.setText(" ".join(extras))
            self.etapa.setText("Pronto.")
            self._log("Pronto: a pasta está trancada.")
            self.status(f"'{name}' está trancada.")
        else:
            n = len(out.pending)
            self.t3.setText(f"O trancamento de '{name}' parou antes do fim")
            # o motivo é o do gerente: "item novo colocado durante o trancamento" NÃO está
            # guardado, então não dá para dizer sempre "seus arquivos já estão guardados"
            self.s3.setText(
                f"{n} item(ns) ainda estão na pasta. Na lista, clique em 'Resolver…' para ver o "
                "que fazer."
            )
            self.etapa.setText("Parou num ponto seguro.")
            self._log("Parou num ponto seguro.")
            self.status("O trancamento parou antes do fim.", "erro")
        self.s3.show()
        _definir(self.eta, "")
        self.aviso3.definir("")
        self._ir(2)

    def fail(self, exc: BaseException) -> None:
        self._desconectar()
        self.locking_now = False
        self.done = True
        self.locked_ok = False
        name = self._nome()
        self.bar3.setRange(0, 1000)
        self.bar3.setValue(0)
        if isinstance(exc, CancelledError) and self._stage_text.startswith("4/4"):
            # parou na etapa 4: os arquivos já estão guardados, parte das cópias legíveis não
            self.t3.setText(f"O trancamento de '{name}' parou antes do fim")
            text = (
                "Seus arquivos já estão guardados, mas parte das cópias legíveis ainda está na "
                "pasta. Na lista, clique em 'Resolver…' para continuar trancando ou desfazer."
            )
            self._log("Parou depois do arquivo atual.")
        elif isinstance(exc, CancelledError):
            self.t3.setText("O trancamento foi cancelado")
            text = f"'{name}' continua aberta, como antes. Nada foi apagado."
            self._log("Cancelado num ponto seguro.")
        else:
            self.t3.setText(f"Não foi possível trancar '{name}'")
            if isinstance(exc, PreflightError) and exc.blockers:
                text = exc.blockers[0]
            elif isinstance(exc, OwlVaultError):
                text = str(exc)
            else:
                text = f"{type(exc).__name__}: {exc}"
            text += " Nenhum arquivo foi apagado sem estar guardado e conferido antes."
            self._log("Parou com erro.")
        self.s3.setText(text)
        self.s3.show()
        self.etapa.setText("")
        _definir(self.eta, "")
        self.aviso3.definir("")
        self.status("O trancamento não terminou.", "erro")
        self._ir(2)

    # ------------------------------------------------------------------ progresso
    def _conectar(self) -> None:
        if not self._connected:
            b = self._runner.bridge
            b.stage.connect(self._on_stage)
            b.advance.connect(self._on_advance)
            self._connected = True

    def _desconectar(self) -> None:
        if self._connected:
            b = self._runner.bridge
            for sig, slot in ((b.stage, self._on_stage), (b.advance, self._on_advance)):
                try:
                    sig.disconnect(slot)
                except (RuntimeError, TypeError):
                    pass
            self._connected = False

    def _log(self, text: str) -> None:
        self.log.appendPlainText(f"{time.strftime('%H:%M:%S')}  {text}")

    @Slot(str, object, object)
    def _on_stage(self, name: str, total_bytes: object, total_items: object) -> None:
        text = _map_stage("lock", name)
        tb = int(total_bytes) if isinstance(total_bytes, int) else 0
        ti = int(total_items) if isinstance(total_items, int) else 0
        self._totals = (tb, ti)
        self._done_counts = [0, 0]
        self._t0 = time.monotonic()
        _definir(self.eta, "")
        if tb or ti:
            self.bar3.setRange(0, 1000)
            self.bar3.setValue(0)
        else:
            self.bar3.setRange(0, 0)
        if text != self._stage_text:
            self._log(text)
        self._stage_text = text
        if self.stopping:
            self.etapa.setText("Parando num ponto seguro…")
        else:
            self.etapa.setText(f"{text} (0 de {fmt_int(ti)})" if text.startswith("1/4") else text)
        self._atualizar_rodape()

    @Slot(object, object)
    def _on_advance(self, nbytes: object, nitems: object) -> None:
        self._done_counts[0] += int(nbytes) if isinstance(nbytes, int) else 0
        self._done_counts[1] += int(nitems) if isinstance(nitems, int) else 0
        tb, ti = self._totals
        done_b, done_i = self._done_counts
        frac = done_b / tb if tb else (done_i / ti if ti else 0.0)
        self.bar3.setValue(min(1000, int(frac * 1000)))
        if ti and not self.stopping:
            self.etapa.setText(f"{self._stage_text} ({fmt_int(min(done_i, ti))} de {fmt_int(ti)})")
        elapsed = time.monotonic() - self._t0
        if frac > 0.03 and elapsed > 3:
            remaining = elapsed * (1 - frac) / frac
            _definir(self.eta, f"Tempo restante: {fmt_duration(remaining)}")
