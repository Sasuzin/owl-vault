"""Diálogos: relatório de pré-verificação com aceites obrigatórios e relatórios finais."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from owl_vault.application.preflight import CreatePlan
from owl_vault.ui import strings as S


class _ClickLabel(QLabel):
    """Rótulo com quebra de linha que alterna a caixa associada ao ser clicado."""

    def __init__(self, text: str, box: QCheckBox) -> None:
        super().__init__(text)
        self.setWordWrap(True)
        self._box = box

    def mousePressEvent(self, ev: QMouseEvent) -> None:
        self._box.toggle()
        super().mousePressEvent(ev)


def _list_box(title: str, items: Sequence[str]) -> QGroupBox:
    box = QGroupBox(f"{title} ({len(items)})")
    lay = QVBoxLayout(box)
    text = QPlainTextEdit()
    text.setReadOnly(True)
    text.setPlainText("\n".join(f"• {i}" for i in items))
    text.setMinimumHeight(90)
    lay.addWidget(text)
    return box


class PreflightDialog(QDialog):
    """Mostra o plano; só habilita "Criar cofre" com todos os aceites marcados."""

    def __init__(self, plan: CreatePlan, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{S.APP_TITLE} — pré-verificação")
        self.setMinimumWidth(640)
        lay = QVBoxLayout(self)
        summary = QLabel("\n".join(plan.summary_lines()))
        summary.setWordWrap(True)
        lay.addWidget(summary)
        if plan.blockers:
            lay.addWidget(
                QLabel("<b>Não é possível criar o cofre.</b> Corrija os bloqueios abaixo:")
            )
            lay.addWidget(_list_box("Bloqueios", plan.blockers))
        if plan.warnings:
            lay.addWidget(_list_box("Avisos", plan.warnings))
        self._checks: list[QCheckBox] = []
        if not plan.blockers:
            limits = QGroupBox(S.LIMITS_TITLE)
            ll = QVBoxLayout(limits)
            lbl = QLabel(S.LIMITS_TEXT)
            lbl.setWordWrap(True)
            ll.addWidget(lbl)
            lay.addWidget(limits)
            self._add_check(lay, "Li e entendi os limites da proteção.")
            self._add_check(lay, S.BACKUP_TEXT)
            self._add_check(lay, S.PASSWORD_LOSS_TEXT)
            if plan.needs_fat_ack:
                self._add_check(lay, S.FAT_ACK_TEXT)
        buttons = QDialogButtonBox()
        self._ok: QPushButton | None = None
        if not plan.blockers:
            self._ok = buttons.addButton("Criar cofre", QDialogButtonBox.ButtonRole.AcceptRole)
            self._ok.setObjectName("primary")
            self._ok.setEnabled(False)
        buttons.addButton(
            "Fechar" if plan.blockers else "Cancelar", QDialogButtonBox.ButtonRole.RejectRole
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def _add_check(self, lay: QVBoxLayout, text: str) -> None:
        row = QHBoxLayout()
        cb = QCheckBox()
        cb.setAccessibleName(text)
        cb.toggled.connect(self._update)
        label = _ClickLabel(text, cb)
        row.addWidget(cb, 0, Qt.AlignmentFlag.AlignTop)
        row.addWidget(label, 1)
        lay.addLayout(row)
        self._checks.append(cb)

    def _update(self) -> None:
        if self._ok is not None:
            self._ok.setEnabled(all(c.isChecked() for c in self._checks))


class ReportDialog(QDialog):
    def __init__(
        self,
        title: str,
        headline: str,
        sections: Sequence[tuple[str, Sequence[str]]],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{S.APP_TITLE} — {title}")
        self.setMinimumWidth(620)
        lay = QVBoxLayout(self)
        lbl = QLabel(headline)
        lbl.setWordWrap(True)
        lay.addWidget(lbl)
        for name, items in sections:
            if items:
                lay.addWidget(_list_box(name, items))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        lay.addWidget(buttons)
