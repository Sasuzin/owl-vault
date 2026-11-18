"""Aceites obrigatórios e relatórios da cópia criptografada (visual "Cofre").

``CaixaAceite`` é a caixa de seleção com texto longo (quebra linha e alterna ao clicar no
texto) usada no passo "Conferência" do assistente. ``PreflightDialog`` e ``ReportDialog``
continuam disponíveis com o mesmo contrato, agora com os componentes do tema.
"""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import QEvent, Qt, Signal
from PySide6.QtGui import QMouseEvent, QShowEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from owl_vault.application.preflight import CreatePlan
from owl_vault.ui import strings as S
from owl_vault.ui.common import Rolagem, fit_to_content
from owl_vault.ui.componentes import (
    botao,
    botao_primario,
    lista_detalhes,
    nota,
    rotulo,
    subtitulo,
    titulo,
    transparente,
)


class _ClickLabel(QLabel):
    """Rótulo com quebra de linha que alterna a caixa associada ao ser clicado."""

    def __init__(self, text: str, box: QCheckBox) -> None:
        super().__init__(text)
        self.setWordWrap(True)
        self.setObjectName("aceiteTexto")
        self._box = box

    def mousePressEvent(self, ev: QMouseEvent) -> None:
        if self._box.isEnabled():
            self._box.toggle()
        super().mousePressEvent(ev)


class CaixaAceite(QWidget):
    """Aceite obrigatório: caixa de seleção + texto que quebra linha (clicável)."""

    toggled = Signal(bool)

    def __init__(self, texto: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("transparente")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 2, 0, 2)
        lay.setSpacing(10)
        self.caixa = QCheckBox()
        self.caixa.setAccessibleName(texto)
        self.caixa.toggled.connect(self.toggled.emit)
        self.texto = _ClickLabel(texto, self.caixa)
        lay.addWidget(self.caixa, 0, Qt.AlignmentFlag.AlignTop)
        lay.addWidget(self.texto, 1)

    def isChecked(self) -> bool:
        return self.caixa.isChecked()

    def setChecked(self, value: bool) -> None:
        self.caixa.setChecked(value)

    def text(self) -> str:
        return self.texto.text()


def _secao(lay: QVBoxLayout, title: str, items: Sequence[str]) -> None:
    lay.addWidget(rotulo(f"{title} ({len(items)})"))
    lay.addWidget(lista_detalhes(items))


class _DialogoRolavel(QDialog):
    """Conteúdo numa ``Rolagem`` e a linha de botões embaixo, fora dela: o diálogo nunca
    passa da área útil da tela e os botões ficam sempre à vista."""

    def __init__(self, parent: QWidget | None, largura: int) -> None:
        super().__init__(parent)
        self.setMinimumWidth(largura)
        self._largura = largura
        self._externo = QVBoxLayout(self)
        self._externo.setContentsMargins(24, 24, 24, 24)
        self._externo.setSpacing(12)
        conteudo, corpo = transparente()
        corpo.setSpacing(12)
        assert isinstance(corpo, QVBoxLayout)
        self.corpo: QVBoxLayout = corpo
        self.rolagem = Rolagem(conteudo)
        self._externo.addWidget(self.rolagem, 1)

    def _rodape(self, linha: QWidget) -> None:
        self._externo.addWidget(linha)

    def showEvent(self, event: QShowEvent) -> None:
        fit_to_content(self, self._largura)
        super().showEvent(event)

    def event(self, event: QEvent) -> bool:
        handled = super().event(event)
        if event.type() == QEvent.Type.LayoutRequest and self.isVisible():
            fit_to_content(self, self._largura)
        return handled


class PreflightDialog(_DialogoRolavel):
    """Mostra o plano; só habilita "Criar cofre" com todos os aceites marcados."""

    def __init__(self, plan: CreatePlan, parent: QWidget | None = None) -> None:
        super().__init__(parent, 640)
        self.setWindowTitle(f"{S.APP_TITLE} — pré-verificação")
        lay = self.corpo
        lay.addWidget(titulo("Conferência antes de criar"))
        lay.addWidget(nota("\n".join(plan.summary_lines())))
        if plan.blockers:
            lay.addWidget(subtitulo("Não é possível criar o cofre. Corrija os bloqueios abaixo:"))
            _secao(lay, "Bloqueios", plan.blockers)
        if plan.warnings:
            _secao(lay, "Avisos", plan.warnings)
        self.aceites: list[CaixaAceite] = []
        if not plan.blockers:
            lay.addWidget(rotulo(S.LIMITS_TITLE))
            lay.addWidget(nota(S.LIMITS_TEXT))
            textos = [S.COPIA_ACEITE_LIMITES, S.BACKUP_TEXT, S.PASSWORD_LOSS_TEXT]
            if plan.needs_fat_ack:
                textos.append(S.FAT_ACK_TEXT)
            for t in textos:
                caixa = CaixaAceite(t)
                caixa.toggled.connect(self._update)
                lay.addWidget(caixa)
                self.aceites.append(caixa)
        linha, ll = transparente(QHBoxLayout)
        ll.addStretch(1)
        self._ok: QPushButton | None = None
        if not plan.blockers:
            self._ok = botao_primario("Criar cofre")
            self._ok.setEnabled(False)
            self._ok.clicked.connect(self.accept)
            ll.addWidget(self._ok)
        fechar = botao("Fechar" if plan.blockers else "Cancelar")
        fechar.clicked.connect(self.reject)
        ll.addWidget(fechar)
        self._rodape(linha)

    def _update(self) -> None:
        if self._ok is not None:
            self._ok.setEnabled(all(c.isChecked() for c in self.aceites))


class ReportDialog(_DialogoRolavel):
    def __init__(
        self,
        title: str,
        headline: str,
        sections: Sequence[tuple[str, Sequence[str]]],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent, 620)
        self.setWindowTitle(f"{S.APP_TITLE} — {title}")
        lay = self.corpo
        lay.addWidget(subtitulo(headline))
        for name, items in sections:
            if items:
                _secao(lay, name, items)
        linha, ll = transparente(QHBoxLayout)
        ll.addStretch(1)
        ok = botao_primario("OK")
        ok.clicked.connect(self.accept)
        ll.addWidget(ok)
        self._rodape(linha)
