"""Janela principal: abas Criar / Verificar / Restaurar, progresso, cancelamento e log em memória."""

from __future__ import annotations

import datetime as _dt
import os
from typing import Any

from PySide6.QtCore import QSettings, Qt, Slot
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from owl_vault import __version__
from owl_vault.application.common import default_vault_name, password_strength
from owl_vault.application.create import (
    CreateResult,
    create_vault,
    inspect_vault_dir,
    resume_create,
)
from owl_vault.application.preflight import CreatePlan, default_test_parent, preflight_create
from owl_vault.application.progress import CancelToken
from owl_vault.application.restore import RestoreReport, inspect_destination, restore_vault
from owl_vault.application.verify import VerifyReport, verify_vault
from owl_vault.crypto.kdf import PRODUCTION_POLICY
from owl_vault.domain.errors import CancelledError, OwlVaultError, PreflightError
from owl_vault.domain.limits import MIB, MIN_PASSWORD_LENGTH
from owl_vault.storage import winfs
from owl_vault.ui import strings as S
from owl_vault.ui.dialogs import PreflightDialog, ReportDialog
from owl_vault.ui.icon import owl_icon
from owl_vault.ui.theme import apply_theme, save_theme, saved_theme
from owl_vault.ui.workers import JobRunner, QtProgress


def _clear_qt_dialog_history() -> None:
    """Melhor esforço: o Qt guarda a última pasta usada no registro (THREAT_MODEL §4)."""
    s = QSettings(QSettings.Scope.UserScope, "QtProject")
    s.beginGroup("FileDialog")
    for key in ("lastVisited", "history"):
        s.remove(key)
    s.endGroup()
    s.sync()


class PathRow(QWidget):
    def __init__(self, placeholder: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.edit = QLineEdit()
        self.edit.setPlaceholderText(placeholder)
        self.button = QPushButton("Escolher...")
        self.button.clicked.connect(self._choose)
        lay.addWidget(self.edit, 1)
        lay.addWidget(self.button)

    def _choose(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Escolher pasta", self.edit.text())
        _clear_qt_dialog_history()
        if path:
            self.edit.setText(os.path.normpath(path))

    def text(self) -> str:
        return self.edit.text().strip()

    def setText(self, value: str) -> None:
        self.edit.setText(value)


def _wipe(edit: QLineEdit) -> None:
    """``setText("")`` também descarta o histórico de desfazer (``clear()`` o manteria)."""
    edit.setText("")


def _password_edit(placeholder: str) -> QLineEdit:
    e = QLineEdit()
    e.setEchoMode(QLineEdit.EchoMode.Password)
    e.setPlaceholderText(placeholder)
    return e


def _hint(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("hint")
    lbl.setWordWrap(True)
    return lbl


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(S.APP_TITLE)
        self.setWindowIcon(owl_icon())
        self.resize(860, 720)
        self.runner = JobRunner(self)
        self.session_sources: list[str] = []
        self._totals = (0, 0)
        self._auto_test: str | None = None
        self._done = [0, 0]

        central = QWidget()
        root = QVBoxLayout(central)
        banner = QLabel(S.BANNER)
        banner.setObjectName("banner")
        banner.setWordWrap(True)
        root.addWidget(banner)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_create_tab(), "Criar cofre")
        self.tabs.addTab(self._build_verify_tab(), "Verificar cofre")
        self.tabs.addTab(self._build_restore_tab(), "Restaurar")
        root.addWidget(self.tabs)

        status = QHBoxLayout()
        self.stage_label = QLabel("Pronto.")
        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        self.cancel_button = QPushButton("Cancelar")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel)
        status.addWidget(self.stage_label, 2)
        status.addWidget(self.progress, 3)
        status.addWidget(self.cancel_button)
        root.addLayout(status)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        self.log.setPlaceholderText("Mensagens desta sessão (não são gravadas em disco).")
        root.addWidget(self.log, 1)
        self.setCentralWidget(central)

        self._build_menu()
        b = self.runner.bridge
        b.stage.connect(self._on_stage)
        b.advance.connect(self._on_advance)
        b.info.connect(lambda m: self._log(m))
        b.warning.connect(lambda m: self._log("AVISO: " + m))
        self.runner.done.connect(self._on_done)
        self.runner.error.connect(self._on_error)
        self._on_done_handler: Any = None
        if winfs.is_elevated():
            self._log("AVISO: o Owl Vault está rodando como administrador; isso não é necessário.")

    # ------------------------------------------------------------------ construção
    def _build_menu(self) -> None:
        view = self.menuBar().addMenu("&Exibir")
        self.dark_action = QAction("Tema escuro", self, checkable=True)
        self.dark_action.setChecked(saved_theme() == "dark")
        self.dark_action.toggled.connect(self._toggle_theme)
        view.addAction(self.dark_action)
        help_menu = self.menuBar().addMenu("&Ajuda")
        limits = QAction(S.LIMITS_TITLE, self)
        limits.triggered.connect(
            lambda: QMessageBox.information(
                self, S.LIMITS_TITLE, S.LIMITS_TEXT + "\n\n" + S.BACKUP_TEXT
            )
        )
        help_menu.addAction(limits)
        about = QAction("Sobre o Owl Vault", self)
        about.triggered.connect(
            lambda: QMessageBox.about(
                self,
                "Sobre o Owl Vault",
                f"<b>Owl Vault</b> {__version__}<br>Cópias criptografadas e verificáveis de pastas."
                "<br>AES-256-GCM, Argon2id. Sem nuvem, sem telemetria.<br>"
                "Não houve auditoria independente.",
            )
        )
        help_menu.addAction(about)

    def _build_create_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.addWidget(_hint(S.CREATE_HINT))
        form = QFormLayout()
        self.c_source = PathRow("Pasta que será copiada (não será alterada)")
        self.c_source.edit.editingFinished.connect(self._suggest_test_dir)
        self.c_source.edit.textChanged.connect(lambda _t: self._suggest_test_dir())
        self.c_parent = PathRow("Onde criar o cofre (ex.: pendrive ou HD externo)")
        self.c_name = QLineEdit(default_vault_name())
        self.c_test = PathRow("Pasta temporária do teste de restauração")
        self.c_pw1 = _password_edit(f"Senha (mínimo {MIN_PASSWORD_LENGTH} caracteres)")
        self.c_pw2 = _password_edit("Confirme a senha")
        self.c_strength = QLabel("")
        self.c_pw1.textChanged.connect(self._update_strength)
        form.addRow("Origem:", self.c_source)
        form.addRow("Local do cofre:", self.c_parent)
        form.addRow("Nome do cofre:", self.c_name)
        form.addRow("Teste de restauração:", self.c_test)
        form.addRow("Senha:", self.c_pw1)
        form.addRow("Confirmação:", self.c_pw2)
        form.addRow("", self.c_strength)
        lay.addLayout(form)
        lay.addWidget(_hint(S.TEST_DIR_HINT))
        row = QHBoxLayout()
        self.c_go = QPushButton("Pré-verificar e criar cofre...")
        self.c_go.setObjectName("primary")
        self.c_go.clicked.connect(self._start_preflight)
        self.c_resume = QPushButton("Retomar criação interrompida")
        self.c_resume.clicked.connect(self._start_resume)
        row.addWidget(self.c_go)
        row.addWidget(self.c_resume)
        row.addStretch(1)
        lay.addLayout(row)
        lay.addStretch(1)
        self._inputs_create = [
            self.c_source,
            self.c_parent,
            self.c_name,
            self.c_test,
            self.c_pw1,
            self.c_pw2,
            self.c_go,
            self.c_resume,
        ]
        return w

    def _build_verify_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.addWidget(_hint(S.VERIFY_HINT))
        form = QFormLayout()
        self.v_vault = PathRow("Pasta do cofre")
        self.v_pw = _password_edit("Senha do cofre")
        form.addRow("Cofre:", self.v_vault)
        form.addRow("Senha:", self.v_pw)
        lay.addLayout(form)
        self.v_go = QPushButton("Verificar cofre")
        self.v_go.setObjectName("primary")
        self.v_go.clicked.connect(self._start_verify)
        lay.addWidget(self.v_go, 0, Qt.AlignmentFlag.AlignLeft)
        lay.addStretch(1)
        self._inputs_verify = [self.v_vault, self.v_pw, self.v_go]
        return w

    def _build_restore_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.addWidget(_hint(S.RESTORE_HINT))
        form = QFormLayout()
        self.r_vault = PathRow("Pasta do cofre")
        self.r_pw = _password_edit("Senha do cofre")
        self.r_parent = PathRow("Onde criar a pasta restaurada")
        self.r_name = QLineEdit(_dt.datetime.now().strftime("Restaurado-%Y%m%d-%H%M"))
        form.addRow("Cofre:", self.r_vault)
        form.addRow("Senha:", self.r_pw)
        form.addRow("Destino (pasta pai):", self.r_parent)
        form.addRow("Nome da pasta nova:", self.r_name)
        lay.addLayout(form)
        self.r_go = QPushButton("Restaurar para pasta nova")
        self.r_go.setObjectName("primary")
        self.r_go.clicked.connect(self._start_restore)
        lay.addWidget(self.r_go, 0, Qt.AlignmentFlag.AlignLeft)
        lay.addStretch(1)
        self._inputs_restore = [self.r_vault, self.r_pw, self.r_parent, self.r_name, self.r_go]
        return w

    # ------------------------------------------------------------------ utilidades
    def _log(self, message: str) -> None:
        stamp = _dt.datetime.now().strftime("%H:%M:%S")
        self.log.appendPlainText(f"[{stamp}] {message}")

    def _set_busy(self, busy: bool) -> None:
        for wdg in self._inputs_create + self._inputs_verify + self._inputs_restore:
            wdg.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        if not busy:
            self.stage_label.setText("Pronto.")
            self.progress.setRange(0, 1000)

    def _warn(self, text: str) -> None:
        QMessageBox.warning(self, S.APP_TITLE, text)

    def _toggle_theme(self, dark: bool) -> None:
        theme = "dark" if dark else "light"
        save_theme(theme)
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_theme(app, theme)

    def _update_strength(self) -> None:
        st = password_strength(self.c_pw1.text())
        self.c_strength.setText(f"Força estimada: {st.label}" if self.c_pw1.text() else "")

    def _suggest_test_dir(self) -> None:
        """Sugere a pasta do teste no volume da origem; recalcula enquanto o campo ainda
        contém a sugestão automática (um valor digitado pelo usuário é mantido)."""
        src = self.c_source.text()
        current = self.c_test.text()
        if not src or (current and current != self._auto_test):
            return
        try:
            res = winfs.resolve(src)
            if res.exists and res.is_directory and len(res.parts) > 1:
                suggestion = winfs.strip_extended(default_test_parent(res))
                self._auto_test = suggestion
                self.c_test.setText(suggestion)
        except (OwlVaultError, OSError):
            pass

    def _vault_path(self) -> str | None:
        parent, name = self.c_parent.text(), self.c_name.text().strip()
        if not parent or not name:
            self._warn("Informe o local e o nome do cofre.")
            return None
        return os.path.join(parent, name)

    def _run(self, job: Any, on_done: Any) -> None:
        self._on_done_handler = on_done
        self._set_busy(True)
        self.runner.start(job)

    # ------------------------------------------------------------------ progresso
    @Slot(str, object, object)
    def _on_stage(self, name: str, total_bytes: object, total_items: object) -> None:
        self.stage_label.setText(name)
        self._log(name)
        tb = int(total_bytes) if isinstance(total_bytes, int) else 0
        ti = int(total_items) if isinstance(total_items, int) else 0
        self._totals = (tb, ti)
        self._done = [0, 0]
        if tb or ti:
            self.progress.setRange(0, 1000)
            self.progress.setValue(0)
        else:
            self.progress.setRange(0, 0)  # indeterminado

    @Slot(object, object)
    def _on_advance(self, nbytes: object, nitems: object) -> None:
        self._done[0] += int(nbytes) if isinstance(nbytes, int) else 0
        self._done[1] += int(nitems) if isinstance(nitems, int) else 0
        tb, ti = self._totals
        if tb:
            self.progress.setValue(min(1000, int(self._done[0] * 1000 / tb)))
        elif ti:
            self.progress.setValue(min(1000, int(self._done[1] * 1000 / ti)))

    def _cancel(self) -> None:
        self.runner.cancel()
        self._log("Cancelamento solicitado: a operação vai parar no próximo ponto seguro.")
        self.cancel_button.setEnabled(False)

    @Slot(object)
    def _on_done(self, result: object) -> None:
        self._set_busy(False)
        handler, self._on_done_handler = self._on_done_handler, None
        if handler is not None:
            handler(result)

    @Slot(object)
    def _on_error(self, exc: object) -> None:
        self._set_busy(False)
        self._on_done_handler = None
        if isinstance(exc, CancelledError):
            self._log("Operação cancelada.")
            QMessageBox.information(
                self,
                S.APP_TITLE,
                "Operação cancelada em um ponto seguro. Na criação, use 'Retomar criação "
                "interrompida' para continuar depois.",
            )
        elif isinstance(exc, PreflightError):
            self._log(f"Bloqueado: {exc}")
            ReportDialog("bloqueios", str(exc), [("Bloqueios", exc.blockers)], self).exec()
        elif isinstance(exc, OwlVaultError):
            self._log(f"Erro: {exc}")
            self._warn(str(exc))
        else:
            self._log(f"Erro inesperado: {type(exc).__name__}: {exc}")
            QMessageBox.critical(
                self,
                S.APP_TITLE,
                f"Erro inesperado ({type(exc).__name__}): {exc}\n\nNenhum arquivo da origem foi "
                "alterado. Se for uma criação, você pode tentar 'Retomar'.",
            )

    # ------------------------------------------------------------------ criar
    def _start_preflight(self) -> None:
        src = self.c_source.text()
        vault = self._vault_path()
        if not src or vault is None:
            if not src:
                self._warn("Escolha a pasta de origem.")
            return
        pw1, pw2 = self.c_pw1.text(), self.c_pw2.text()
        if len(pw1) < MIN_PASSWORD_LENGTH:
            self._warn(f"A senha deve ter pelo menos {MIN_PASSWORD_LENGTH} caracteres.")
            return
        if pw1 != pw2:
            self._warn("As senhas não conferem.")
            return
        try:
            status = inspect_vault_dir(vault)
        except OwlVaultError as exc:
            self._warn(f"Local do cofre: {exc}")
            return
        if status.kind == "vault-incomplete":
            self._warn(
                "Já existe um cofre incompleto com esse nome. Use 'Retomar criação interrompida' "
                "ou escolha outro nome."
            )
            return
        test = self.c_test.text() or None

        def job(progress: QtProgress, cancel: CancelToken) -> CreatePlan:
            return preflight_create(src, vault, test_parent=test, progress=progress, cancel=cancel)

        self._run(job, self._after_preflight)

    def _after_preflight(self, plan: object) -> None:
        assert isinstance(plan, CreatePlan)
        dlg = PreflightDialog(plan, self)
        if dlg.exec() != PreflightDialog.DialogCode.Accepted or plan.blockers:
            self._log("Criação não iniciada.")
            return
        password = self.c_pw1.text()
        _wipe(self.c_pw1)
        _wipe(self.c_pw2)
        self.session_sources.append(plan.source_ext)
        fat_ack = plan.needs_fat_ack  # o diálogo só aceita com a caixa marcada

        def job(progress: QtProgress, cancel: CancelToken) -> CreateResult:
            return create_vault(
                plan.source_ext,
                plan.vault_ext,
                password,
                plan=plan,
                fat_acknowledged=fat_ack,
                progress=progress,
                cancel=cancel,
            )

        self._run(job, self._after_create)

    def _start_resume(self) -> None:
        src = self.c_source.text()
        vault = self._vault_path()
        if not src or vault is None:
            if not src:
                self._warn("Informe a mesma pasta de origem usada na criação.")
            return
        try:
            status = inspect_vault_dir(vault)
        except OwlVaultError as exc:
            self._warn(f"Local do cofre: {exc}")
            return
        if status.kind != "vault-incomplete":
            self._warn("Não há criação interrompida nessa pasta de cofre.")
            return
        password = self.c_pw1.text()
        if not password:
            self._warn("Digite a senha do cofre (campo Senha).")
            return
        answer = QMessageBox.question(
            self,
            S.LIMITS_TITLE,
            S.LIMITS_TEXT
            + "\n\n"
            + S.BACKUP_TEXT
            + "\n\n"
            + S.PASSWORD_LOSS_TEXT
            + "\n\nLi e entendi estes avisos. Continuar a retomada?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        fat_ack = False
        try:
            res = winfs.resolve(vault)
            if winfs.is_fat(res.fs_name):
                answer = QMessageBox.question(self, S.APP_TITLE, S.FAT_ACK_TEXT)
                if answer != QMessageBox.StandardButton.Yes:
                    return
                fat_ack = True
        except OwlVaultError as exc:
            self._warn(str(exc))
            return
        _wipe(self.c_pw1)
        _wipe(self.c_pw2)
        self.session_sources.append(src)

        def job(progress: QtProgress, cancel: CancelToken) -> CreateResult:
            return resume_create(
                vault, src, password, fat_acknowledged=fat_ack, progress=progress, cancel=cancel
            )

        self._run(job, self._after_create)

    def _after_create(self, result: object) -> None:
        assert isinstance(result, CreateResult)
        self._log(result.message)
        headline = (
            f"{result.message}\n\nArquivos: {result.files} | Pastas: {result.dirs} | "
            f"{result.total_bytes / MIB:.1f} MiB\nCofre: {result.vault}"
        )
        ReportDialog(
            "cofre criado" if result.status == "success" else "cofre criado com divergências",
            headline,
            [
                ("Divergências", result.divergences),
                ("Avisos", result.warnings),
                ("Notas", result.notes),
            ],
            self,
        ).exec()
        self.c_name.setText(default_vault_name())

    # ------------------------------------------------------------------ verificar
    def _start_verify(self) -> None:
        vault, password = self.v_vault.text(), self.v_pw.text()
        if not vault or not password:
            self._warn("Informe o cofre e a senha.")
            return
        _wipe(self.v_pw)

        def job(progress: QtProgress, cancel: CancelToken) -> VerifyReport:
            return verify_vault(
                vault, password, policy=PRODUCTION_POLICY, progress=progress, cancel=cancel
            )

        self._run(job, self._after_verify)

    def _after_verify(self, report: object) -> None:
        assert isinstance(report, VerifyReport)
        if report.fully_ok:
            headline = f"Cofre íntegro: {report.files_ok}/{report.total_files} arquivos conferidos.\n{report.creation_status}"
        elif report.ok:
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
            headline = (
                f"PROBLEMAS ENCONTRADOS: {len(report.bad)} arquivo(s) com falha de integridade "
                f"({report.files_ok}/{report.total_files} íntegros).\n{report.creation_status}"
            )
        if report.lock_note:
            headline += "\n" + report.lock_note
        self._log(headline.replace("\n", " "))
        ReportDialog(
            "verificação",
            headline,
            [
                ("Problemas", report.bad),
                ("Cópias redundantes danificadas", report.redundancy),
                ("Anomalias", report.anomalies),
                ("Notas", report.notes),
            ],
            self,
        ).exec()

    # ------------------------------------------------------------------ restaurar
    def _start_restore(self) -> None:
        vault, password = self.r_vault.text(), self.r_pw.text()
        parent, name = self.r_parent.text(), self.r_name.text().strip()
        if not vault or not password or not parent or not name:
            self._warn("Informe o cofre, a senha, o destino e o nome da pasta nova.")
            return
        dest = os.path.join(parent, name)
        allow_resume = False
        try:
            state = inspect_destination(dest)
        except OwlVaultError as exc:
            self._warn(str(exc))
            return
        if state == "nonempty":
            self._warn("A pasta de destino já existe e não está vazia. Escolha outro nome.")
            return
        if state == "resumable":
            answer = QMessageBox.question(
                self,
                S.APP_TITLE,
                "Esta pasta contém uma restauração interrompida deste Owl Vault. Continuar de "
                "onde parou? (arquivos existentes são conferidos pelo hash e nunca sobrescritos)",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            allow_resume = True
        _wipe(self.r_pw)
        sources = list(self.session_sources)

        def job(progress: QtProgress, cancel: CancelToken) -> RestoreReport:
            return restore_vault(
                vault,
                password,
                dest,
                policy=PRODUCTION_POLICY,
                session_sources=sources,
                allow_resume=allow_resume,
                progress=progress,
                cancel=cancel,
            )

        self._run(job, self._after_restore)

    def _after_restore(self, report: object) -> None:
        assert isinstance(report, RestoreReport)
        if report.ok:
            headline = (
                f"Restauração concluída em {report.destination}: {report.restored} arquivo(s) "
                f"restaurado(s), {report.skipped_existing} já existente(s) conferido(s).\n"
                f"{report.creation_status}"
            )
        else:
            headline = (
                f"Restauração PARCIAL em {report.destination}: {report.restored} arquivo(s) "
                f"restaurado(s); {len(report.failed)} falha(s), {len(report.conflicts)} conflito(s).\n"
                f"{report.creation_status}"
            )
        self._log(headline.replace("\n", " "))
        ReportDialog(
            "restauração",
            headline,
            [
                ("Falhas", report.failed),
                ("Conflitos", report.conflicts),
                ("Avisos", report.warnings),
                ("Notas", report.notes),
            ],
            self,
        ).exec()
        self.r_name.setText(_dt.datetime.now().strftime("Restaurado-%Y%m%d-%H%M"))

    # ------------------------------------------------------------------ fechar
    def closeEvent(self, event: QCloseEvent) -> None:
        if self.runner.busy:
            answer = QMessageBox.question(
                self,
                S.APP_TITLE,
                "Há uma operação em andamento. Cancelar? (a janela fecha quando ela parar num "
                "ponto seguro)",
            )
            if answer == QMessageBox.StandardButton.Yes:
                self._cancel()
                self.runner.done.connect(lambda _r: self.close())
                self.runner.error.connect(lambda _e: self.close())
            event.ignore()
            return
        event.accept()
