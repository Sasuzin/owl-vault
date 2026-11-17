"""Janela principal da v2: pastas protegidas (UI_SPEC_V2).

Fluxo: assistente (1ª vez) → PIN → lista "Pastas protegidas". Operações longas rodam numa
thread (``JobRunner``) com a tela de progresso modal; o perfil destravado fica só em memória e
é descartado ao bloquear (5 min sem uso, Win+L, suspensão ou ☰ > Bloquear agora).
"""

from __future__ import annotations

import ctypes
import re
import sys
import time
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path
from typing import Any

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Slot
from PySide6.QtGui import QAction, QActionGroup, QCloseEvent, QShowEvent
from PySide6.QtWidgets import QApplication, QDialog, QMainWindow, QMenu, QStackedWidget, QWidget

from owl_vault import __version__
from owl_vault.application.lockers import (
    ABERTA,
    TRANCADA,
    VAULT_DIR,
    LockerManager,
    LockOutcome,
    ProtectCheck,
    UnlockOutcome,
)
from owl_vault.application.profile import (
    DpapiUnavailableError,
    PinError,
    PinUnavailableError,
    ProfileSession,
    ProfileStore,
)
from owl_vault.application.progress import CancelToken
from owl_vault.application.restore import RestoreReport
from owl_vault.application.verify import VerifyReport, verify_vault
from owl_vault.crypto.kdf import PRODUCTION_POLICY, KdfPolicy
from owl_vault.domain.errors import (
    AuthenticationError,
    CancelledError,
    OwlVaultError,
    PreflightError,
)
from owl_vault.storage import winfs
from owl_vault.ui.common import (
    ProgressDialog,
    choose_folder,
    fmt_duration,
    hidpi,
    open_in_explorer,
    short_list,
)
from owl_vault.ui.folder_dialogs import (
    ChangePinDialog,
    ConfirmProtectDialog,
    NewSecretDialog,
    PickDialog,
    SecretDialog,
    ask,
    inform,
    limits_dialog,
)
from owl_vault.ui.icon import WORD_PURPLE, ico_bytes, logo_image, owl_icon
from owl_vault.ui.pages import HomePage, SetupPage, UnlockPage
from owl_vault.ui.theme import apply_theme, save_theme, saved_theme
from owl_vault.ui.workers import JobRunner, QtProgress

IDLE_LOCK_SECONDS = 5 * 60
WM_WTSSESSION_CHANGE = 0x02B1
WTS_SESSION_LOCK = 0x7
WM_POWERBROADCAST = 0x0218
PBT_APMSUSPEND = 0x4
FOLDER_ID_RE = re.compile(r"[0-9a-f]{32}")

ErrorHandler = Callable[[BaseException], bool]


class _InputWatcher(QObject):
    """Registra o último uso (teclado/mouse) para o travamento automático."""

    def __init__(self) -> None:
        super().__init__()
        self.last = time.monotonic()

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if event.type() in (
            QEvent.Type.KeyPress,
            QEvent.Type.MouseButtonPress,
            QEvent.Type.MouseMove,
            QEvent.Type.Wheel,
        ):
            self.last = time.monotonic()
        return False


class OwlWindow(QMainWindow):
    def __init__(
        self,
        launcher: tuple[str, str],
        *,
        open_request: str | None = None,
        policy: KdfPolicy = PRODUCTION_POLICY,
        profile_dir: Path | None = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle("Owl Vault")
        self.setWindowIcon(owl_icon())
        self.resize(820, 640)
        self.setMinimumSize(560, 460)
        self.launcher = launcher
        self.policy = policy
        self.store = ProfileStore(profile_dir, policy)
        self.session: ProfileSession | None = None
        self.mgr: LockerManager | None = None
        self.pending_open = (
            open_request if open_request and FOLDER_ID_RE.fullmatch(open_request) else None
        )
        self._icon = ico_bytes()
        self._job: (
            tuple[ProgressDialog | None, Callable[[Any], None], ErrorHandler | None] | None
        ) = None
        self._lock_after_job = False
        self._skip_practice = False
        self._needs_new_pin = False
        self._wants_new_master = False
        self._wants_recover = False
        self._quitting = False
        self._wts_registered = False
        self._copy_window: QWidget | None = None

        self.runner = JobRunner(self)
        self.runner.done.connect(self._job_done)
        self.runner.error.connect(self._job_failed)

        self.pages = QStackedWidget()
        self.setup_page = SetupPage()
        self.setup_page.finished.connect(self._create_profile)
        self.unlock_page = UnlockPage()
        self.unlock_page.submitted.connect(self._submit_unlock)
        self.unlock_page.new_master_requested.connect(self._request_new_master)
        self.unlock_page.use_pin_once.connect(self._use_pin_once)
        self.home = HomePage(self._build_menu())
        self.home.protect_clicked.connect(self._protect)
        self.home.lock_all_clicked.connect(self._lock_all)
        for p in (self.setup_page, self.unlock_page, self.home):
            self.pages.addWidget(p)
        self.setCentralWidget(self.pages)

        self._watcher = _InputWatcher()
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self._watcher)
        self._idle = QTimer(self)
        self._idle.setInterval(15_000)
        self._idle.timeout.connect(self._idle_check)
        self._idle.start()
        self._start()

    # ------------------------------------------------------------------ menu ☰
    def _build_menu(self) -> QMenu:
        menu = QMenu(self)
        menu.addAction("Recuperar uma pasta protegida…", self._recover)
        menu.addAction("Cópia criptografada de uma pasta…", self._open_copy_tool)
        menu.addSeparator()
        menu.addAction("Alterar PIN…", self._change_pin)
        menu.addAction("Bloquear agora", self.lock_now)
        menu.addSeparator()
        menu.addAction("Limites da proteção", lambda: limits_dialog(self))
        theme = menu.addMenu("Tema")
        group = QActionGroup(self)
        for label, key in (("Escuro", "dark"), ("Claro", "light")):
            act = QAction(label, self, checkable=True)
            act.setChecked(saved_theme() == key)
            act.triggered.connect(lambda _c=False, k=key: self._set_theme(k))
            group.addAction(act)
            theme.addAction(act)
        menu.addAction("Sobre o Owl Vault", self._about)
        return menu

    def _set_theme(self, key: str) -> None:
        save_theme(key)
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_theme(app, key)

    def _about(self) -> None:
        from PySide6.QtWidgets import QMessageBox  # noqa: PLC0415

        box = QMessageBox(self)
        box.setWindowTitle("Sobre o Owl Vault")
        box.setIconPixmap(hidpi(lambda px: logo_image(px), 132))
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(
            f'<b>Owl <span style="color:{WORD_PURPLE.name()}">Vault</span></b> {__version__}'
            "<br>Pastas protegidas por criptografia no seu computador.<br>"
            "AES-256-GCM e Argon2id. Sem nuvem, sem telemetria.<br>"
            "Não houve auditoria independente."
        )
        box.exec()

    # ------------------------------------------------------------------ início / desbloqueio
    def _start(self) -> None:
        if not self.store.exists():
            self.pages.setCurrentWidget(self.setup_page)
        else:
            self._show_unlock()

    def _show_unlock(self, error: str = "") -> None:
        try:
            pin_ok = self.store.pin_available()
            practice = self.store.practice_due() and not self._skip_practice
        except (OwlVaultError, OSError, ValueError, KeyError) as exc:
            pin_ok, practice = False, False
            error = error or f"O perfil do Owl Vault está danificado: {exc}"
        opening = self.pending_open is not None
        if self._wants_new_master:
            self.unlock_page.configure(
                master=False,
                title="Digite seu PIN",
                text="Para criar uma nova senha mestra, confirme com o seu PIN.",
                allow_switch=False,
                error=error,
            )
        elif practice and pin_ok and not opening:
            self.unlock_page.configure(
                master=True,
                title="Digite sua senha mestra",
                text="Pedimos de vez em quando para você não esquecê-la.",
                practice=True,
                error=error,
            )
        elif not pin_ok:
            self.unlock_page.configure(
                master=True,
                title="Abrir pasta protegida" if opening else "Digite sua senha mestra",
                text="O PIN está desativado. Use a senha mestra.",
                allow_switch=False,
                error=error,
            )
        else:
            self.unlock_page.configure(
                master=False,
                title="Abrir pasta protegida" if opening else "Digite seu PIN",
                error=error,
            )
        self.pages.setCurrentWidget(self.unlock_page)

    @Slot(str, str, bool)
    def _create_profile(self, master: str, pin: str, wants_recover: bool) -> None:
        self._wants_recover = wants_recover
        self.setup_page.set_busy(True, "Preparando a proteção (alguns segundos)…")

        def job(_p: QtProgress, _c: CancelToken) -> ProfileSession:
            return self.store.create(master, pin)

        def failed(exc: BaseException) -> bool:
            self.setup_page.set_busy(False)
            self.setup_page.show_failure(str(exc))
            return True

        self._run(job, self._unlocked, on_error=failed)

    @Slot(str, bool)
    def _submit_unlock(self, secret: str, master: bool) -> None:
        def job(_p: QtProgress, _c: CancelToken) -> ProfileSession:
            if master:
                return self.store.unlock_with_master(secret)
            return self.store.unlock_with_pin(secret)

        self._run(job, self._unlocked, on_error=self._unlock_failed)

    def _unlock_failed(self, exc: BaseException) -> bool:
        if isinstance(exc, PinError):
            if exc.remaining > 0:
                self.unlock_page.fail(
                    f"PIN incorreto. Restam {exc.remaining} tentativa(s); depois disso, só a "
                    "senha mestra."
                )
            else:
                self._show_unlock("PIN incorreto muitas vezes. O PIN foi desativado.")
            return True
        if isinstance(exc, DpapiUnavailableError):
            self._needs_new_pin = True
            self.unlock_page.configure(master=True, text=str(exc), allow_switch=False)
            return True
        if isinstance(exc, PinUnavailableError):
            self._show_unlock(str(exc))
            return True
        if isinstance(exc, AuthenticationError):
            self.unlock_page.fail(
                "Senha mestra incorreta." if self.unlock_page.master else str(exc)
            )
            return True
        self.unlock_page.fail(str(exc))
        return True

    def _use_pin_once(self) -> None:
        self._skip_practice = True
        self._show_unlock()

    def _request_new_master(self) -> None:
        self._wants_new_master = True
        self._show_unlock()

    def _unlocked(self, session: object) -> None:
        assert isinstance(session, ProfileSession)
        self.session = session
        self.mgr = LockerManager(
            session, icon_bytes=self._icon, launcher=self.launcher, policy=self.policy
        )
        self._skip_practice = False
        self._watcher.last = time.monotonic()
        notes = list(session.notes)
        try:
            notes += self.mgr.reconcile_on_start()
        except (OwlVaultError, OSError) as exc:
            notes.append(str(exc))
        self._refresh()
        self.home.set_notice(" ".join(notes))
        self.pages.setCurrentWidget(self.home)
        QTimer.singleShot(0, self._after_unlock)

    def _after_unlock(self) -> None:
        if self.session is None:
            return
        if self._needs_new_pin:
            self._needs_new_pin = False
            self._new_pin_after_master()
        if self._wants_new_master:
            self._wants_new_master = False
            self._new_master()
        if self._wants_recover:
            self._wants_recover = False
            self._recover()
        if self.pending_open:
            fid, self.pending_open = self.pending_open, None
            self._open_folder(fid)

    def _replace_session(self, new: ProfileSession) -> None:
        old = self.session
        self.session = new
        if self.mgr is not None:
            self.mgr.session = new
        if old is not None and old is not new:
            old.close()

    # ------------------------------------------------------------------ bloqueio
    def lock_now(self) -> None:
        if self.runner.busy:
            self._lock_after_job = True
            return
        self._lock_after_job = False
        for _ in range(8):
            modal = QApplication.activeModalWidget()
            if modal is None or modal is self:
                break
            if isinstance(modal, QDialog):
                modal.reject()
            else:
                modal.close()
        if self.session is not None:
            self.session.close()
        self.session = None
        self.mgr = None
        self.home.clear()
        if self.store.exists():
            self._show_unlock()

    def _idle_check(self) -> None:
        if self.session is None or self.runner.busy:
            return
        if time.monotonic() - self._watcher.last >= IDLE_LOCK_SECONDS:
            self.lock_now()

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        if not self._wts_registered and sys.platform == "win32":
            try:
                ctypes.windll.wtsapi32.WTSRegisterSessionNotification(
                    wintypes.HWND(int(self.winId())), 0
                )
                self._wts_registered = True
            except (OSError, AttributeError):
                pass

    def nativeEvent(self, event_type: Any, message: Any) -> Any:
        if sys.platform == "win32" and bytes(event_type) == b"windows_generic_MSG":
            try:
                msg = wintypes.MSG.from_address(int(message))
                if (msg.message == WM_WTSSESSION_CHANGE and msg.wParam == WTS_SESSION_LOCK) or (
                    msg.message == WM_POWERBROADCAST and msg.wParam == PBT_APMSUSPEND
                ):
                    QTimer.singleShot(0, self.lock_now)
            except (ValueError, OSError):
                pass
        return super().nativeEvent(event_type, message)

    def _block_shutdown(self, active: bool) -> None:
        if sys.platform != "win32":
            return
        try:
            hwnd = wintypes.HWND(int(self.winId()))
            user32 = ctypes.windll.user32
            if active:
                user32.ShutdownBlockReasonCreate(
                    hwnd, ctypes.c_wchar_p("O Owl Vault está trabalhando numa pasta protegida.")
                )
            else:
                user32.ShutdownBlockReasonDestroy(hwnd)
        except (OSError, AttributeError):
            pass

    # ------------------------------------------------------------------ pedidos externos
    @Slot(str)
    def handle_message(self, text: str) -> None:
        """``abrir <id>`` (atalho da pasta) ou ``mostrar``."""
        self.showNormal()
        self.raise_()
        self.activateWindow()
        parts = text.split()
        if len(parts) == 2 and parts[0] == "abrir" and FOLDER_ID_RE.fullmatch(parts[1]):
            self.request_open(parts[1])

    def request_open(self, folder_id: str) -> None:
        if self.runner.busy:
            inform(self, "Aguarde", "Espere a operação atual terminar e use o atalho de novo.")
            return
        if self.session is None or self.mgr is None:
            self.pending_open = folder_id
            if self.store.exists():
                self._show_unlock()
            return
        rec = self.session.index.folder(folder_id)
        name = rec.name if rec else "pasta protegida"
        self._confirm_identity(f"Abrir '{name}'", "", "Abrir", lambda: self._open_folder(folder_id))

    def _confirm_identity(
        self, title: str, text: str, button: str, then: Callable[[], None], error: str = ""
    ) -> None:
        """Pede o PIN (ou a senha mestra) de novo e troca a sessão pela nova."""
        try:
            pin_ok = self.store.pin_available()
        except (OwlVaultError, OSError, ValueError, KeyError):
            pin_ok = False
        dlg = SecretDialog(
            self, title, text, button, master=not pin_ok, allow_master=pin_ok, error=error
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        secret, master = dlg.take(), dlg.master

        def job(_p: QtProgress, _c: CancelToken) -> ProfileSession:
            if master:
                return self.store.unlock_with_master(secret)
            return self.store.unlock_with_pin(secret)

        def done(new: object) -> None:
            assert isinstance(new, ProfileSession)
            self._replace_session(new)
            then()

        def failed(exc: BaseException) -> bool:
            if isinstance(exc, PinError):
                msg = (
                    f"PIN incorreto. Restam {exc.remaining} tentativa(s)."
                    if exc.remaining
                    else "PIN incorreto muitas vezes. Use a senha mestra."
                )
            elif isinstance(exc, AuthenticationError):
                msg = "Senha mestra incorreta." if master else str(exc)
            else:
                return False
            QTimer.singleShot(0, lambda: self._confirm_identity(title, text, button, then, msg))
            return True

        self._run(job, done, on_error=failed, title="Conferindo…", cancellable=False)

    # ------------------------------------------------------------------ execução de trabalhos
    def _run(
        self,
        job: Callable[[QtProgress, CancelToken], Any],
        on_done: Callable[[Any], None],
        *,
        on_error: ErrorHandler | None = None,
        title: str | None = None,
        mode: str = "generic",
        note: str = "",
        cancellable: bool = True,
    ) -> None:
        dlg = None
        if title is not None:
            dlg = ProgressDialog(
                self, title, self.runner, mode=mode, note=note, cancellable=cancellable
            )
        self._job = (dlg, on_done, on_error)
        self._block_shutdown(True)
        self.runner.start(job)
        if dlg is not None:
            dlg.open()

    @Slot(object)
    def _job_done(self, result: object) -> None:
        assert self._job is not None
        dlg, on_done, _ = self._job
        self._job = None
        self._block_shutdown(False)
        if dlg is not None:
            dlg.finish()
        on_done(result)
        self._after_job()

    @Slot(object)
    def _job_failed(self, exc: object) -> None:
        assert self._job is not None
        dlg, _, on_error = self._job
        self._job = None
        self._block_shutdown(False)
        if dlg is not None:
            dlg.finish()
        assert isinstance(exc, BaseException)
        if on_error is None or not on_error(exc):
            self._default_error(exc)
        self._after_job()

    def _after_job(self) -> None:
        if self._lock_after_job and not self.runner.busy:
            QTimer.singleShot(0, self.lock_now)

    def _default_error(self, exc: BaseException) -> None:
        if isinstance(exc, CancelledError):
            self._refresh()
            self.home.set_notice("A operação parou num ponto seguro.")
            return
        if isinstance(exc, PreflightError):
            items = exc.blockers or [str(exc)]
            ask(
                self,
                str(exc) if exc.blockers else "Não foi possível continuar",
                items[0],
                [("Fechar", "close")],
                details=items[1:],
            )
        elif isinstance(exc, OwlVaultError):
            inform(self, "Não foi possível concluir", str(exc))
        else:
            inform(
                self,
                "Erro inesperado",
                f"{type(exc).__name__}: {exc}\n\nNenhum arquivo foi apagado sem estar guardado "
                "e conferido antes.",
            )
        self._refresh()

    # ------------------------------------------------------------------ lista
    def _refresh(self) -> None:
        if self.mgr is None:
            return
        try:
            views = self.mgr.views()
        except (OwlVaultError, OSError) as exc:
            self.home.set_notice(str(exc))
            return
        self.home.set_rows(views, self._on_row_action)

    def _refresh_with(self, notice: str) -> None:
        self._refresh()
        self.home.set_notice(notice)

    def _rec_name(self, folder_id: str) -> str:
        if self.session is None:
            return "pasta"
        rec = self.session.index.folder(folder_id)
        return rec.name if rec else "pasta"

    def _on_row_action(self, folder_id: str, action: str) -> None:
        if self.mgr is None or self.runner.busy:
            return
        handlers: dict[str, Callable[[str], None]] = {
            "abrir": self._open_folder,
            "trancar": self._lock_folder,
            "resolver": self._resolve,
            "hide": self._hide,
            "show": self._show_folder,
            "verify": self._verify,
            "remove": self._remove,
            "explore": self._explore,
            "lock_hide": lambda fid: self._lock_folder(fid, hide_after=True),
            "forget": self._forget,
            "relocate": self._relocate,
        }
        fn = handlers.get(action)
        if fn is not None:
            fn(folder_id)

    # ------------------------------------------------------------------ proteger (T5)
    def _protect(self, path: str | None = None) -> None:
        if self.mgr is None or self.runner.busy:
            return
        if path is None:
            path = choose_folder(self, "Escolha a pasta que você quer proteger")
            if not path:
                return
        mgr = self.mgr
        chosen = path

        def job(p: QtProgress, c: CancelToken) -> ProtectCheck:
            return mgr.check_protect(chosen, p, c)

        def failed(exc: BaseException) -> bool:
            if isinstance(exc, PreflightError):
                items = exc.blockers or [str(exc)]
                choice = ask(
                    self,
                    "Não é possível proteger esta pasta",
                    items[0],
                    [("Tentar de novo", "retry"), ("Fechar", "close")],
                    details=items[1:6] + ([f"e mais {len(items) - 6}"] if len(items) > 6 else []),
                )
                if choice == "retry":
                    QTimer.singleShot(0, lambda: self._protect(chosen))
                return True
            return False

        self._run(job, self._confirm_protect, on_error=failed, title="Conferindo a pasta…")

    def _confirm_protect(self, check: object) -> None:
        assert isinstance(check, ProtectCheck)
        if self.mgr is None:
            return
        dlg = ConfirmProtectDialog(
            self, check.name, check.files, check.total_bytes, first_time=not self.mgr.folders
        )
        if dlg.exec() != QDialog.DialogCode.Accepted or self.mgr is None:
            return
        mgr = self.mgr

        def job(p: QtProgress, c: CancelToken) -> LockOutcome:
            return mgr.protect(check, p, c)

        self._run(
            job,
            self._lock_done,
            title=f"Trancando '{check.name}'",
            mode="lock",
            note="Não use esta pasta até terminar.",
        )

    # ------------------------------------------------------------------ trancar (T7)
    def _lock_folder(
        self,
        folder_id: str,
        *,
        hide_after: bool = False,
        then: Callable[[], None] | None = None,
        on_error: ErrorHandler | None = None,
    ) -> None:
        if self.mgr is None:
            return
        mgr = self.mgr
        name = self._rec_name(folder_id)
        try:
            missing = mgr.missing_since_open(folder_id)
        except (OwlVaultError, OSError):
            missing = []
        if missing:
            n = len(missing)
            choice = ask(
                self,
                f"Trancar '{name}'?",
                f"Desde que você abriu '{name}', {n} arquivo(s) foram apagados ou movidos: "
                f"{short_list(missing)}. Eles não ficarão na pasta trancada.",
                [("Trancar mesmo assim", "go"), ("Cancelar", "cancel")],
                details=missing if n > 5 else (),
            )
            if choice != "go" or self.mgr is None:
                return

        def job(p: QtProgress, c: CancelToken) -> LockOutcome:
            return mgr.lock(folder_id, p, c, accept_missing=missing)

        def done(out: object) -> None:
            assert isinstance(out, LockOutcome)
            if out.complete and hide_after and self.mgr is not None:
                try:
                    self.mgr.hide(folder_id)
                except (OwlVaultError, OSError):
                    pass
            self._lock_done(out)
            if out.complete and then is not None:
                then()

        self._run(
            job,
            done,
            on_error=on_error,
            title=f"Trancando '{name}'",
            mode="lock",
            note="Não use esta pasta até terminar.",
        )

    def _lock_done(self, out: object) -> None:
        assert isinstance(out, LockOutcome)
        self._refresh()
        name = out.record.name
        if out.complete:
            msg = f"'{name}' está trancada."
            if out.removable:
                msg += " Use 'Remover hardware com segurança' antes de tirar a unidade."
            if out.kept_previous:
                msg += " Uma versão anterior com arquivos que não estão na pasta foi mantida."
            self.home.set_notice(msg)
        else:
            QTimer.singleShot(0, lambda: self._resolve(out.record.id))

    def _lock_all(self) -> None:
        if self.mgr is None:
            return
        ids = [r.id for r in self.mgr.folders if r.state == ABERTA]
        self._lock_sequence(ids, None)

    def _lock_sequence(
        self, ids: list[str], then: Callable[[], None] | None, on_error: ErrorHandler | None = None
    ) -> None:
        if not ids:
            if then is not None:
                then()
            return
        first, rest = ids[0], ids[1:]
        self._lock_folder(
            first,
            then=lambda: QTimer.singleShot(0, lambda: self._lock_sequence(rest, then, on_error)),
            on_error=on_error,
        )

    # ------------------------------------------------------------------ abrir (T6)
    def _open_folder(self, folder_id: str) -> None:
        if self.mgr is None or self.session is None:
            return
        rec = self.session.index.folder(folder_id)
        if rec is None:
            inform(self, "Pasta não encontrada", "Esta pasta não está na lista do Owl Vault.")
            return
        view = self.mgr.view(rec)
        if rec.state == ABERTA and view.issue in ("", "versao_anterior"):
            open_in_explorer(rec.path)
            return
        if view.issue in (
            "nao_encontrada",
            "itens_extras",
            "sem_dados",
            "indisponivel",
            "apagando",
        ):
            self._resolve(folder_id)
            return
        mgr = self.mgr

        def job(p: QtProgress, c: CancelToken) -> UnlockOutcome:
            return mgr.unlock(folder_id, p, c)

        def done(out: object) -> None:
            assert isinstance(out, UnlockOutcome)
            self._refresh()
            if out.complete:
                open_in_explorer(out.path)
                self.home.set_notice(
                    f"'{out.record.name}' está aberta. Tranque de novo quando terminar."
                )
            else:
                QTimer.singleShot(0, lambda: self._resolve(folder_id))

        self._run(
            job,
            done,
            title=f"Abrindo '{rec.name}'",
            mode="unlock",
            note="Se cancelar, dá para continuar depois.",
        )

    def _explore(self, folder_id: str) -> None:
        if self.session is not None:
            rec = self.session.index.folder(folder_id)
            if rec is not None:
                open_in_explorer(rec.path)

    # ------------------------------------------------------------------ resolver (T8)
    def _resolve(self, folder_id: str) -> None:
        if self.mgr is None or self.session is None:
            return
        mgr = self.mgr
        rec = self.session.index.folder(folder_id)
        if rec is None:
            return
        view = mgr.view(rec)
        name = rec.name
        issue = view.issue
        if issue == "apagando":
            n = len(rec.pending)
            text = (
                f"Seus arquivos já estão guardados. {n} item(ns) ainda não foram apagados da "
                f"pasta porque estavam abertos ou foram alterados: {short_list(rec.pending, 3)} "
                "Feche-os e clique em Continuar trancando."
                if n
                else view.attention
            )
            choice = ask(
                self,
                f"Trancamento de '{name}' interrompido",
                text,
                [
                    ("Continuar trancando", "cont"),
                    ("Desfazer (deixar a pasta aberta)", "undo"),
                    ("Fechar", "close"),
                ],
                details=rec.pending if n > 3 else (),
            )
            if choice == "cont":
                self._run(
                    lambda p, c: mgr.continue_lock(folder_id, p, c),
                    self._lock_done,
                    title=f"Trancando '{name}'",
                    mode="lock",
                )
            elif choice == "undo":
                self._run(
                    lambda p, c: mgr.undo_lock(folder_id, p, c),
                    lambda _o: self._refresh_with(f"'{name}' continua aberta."),
                    title=f"Devolvendo os arquivos de '{name}'",
                    mode="unlock",
                )
        elif issue == "abertura_incompleta":
            n = len(rec.pending)
            choice = ask(
                self,
                f"'{name}' não abriu por completo",
                f"{n} arquivo(s) não puderam ser abertos: {short_list(rec.pending, 3)} A cópia "
                "protegida deles continua guardada.",
                [("Tentar de novo", "retry"), ("Continuar sem eles", "skip")],
                details=rec.pending if n > 3 else (),
            )
            if choice == "retry":
                self._open_folder(folder_id)
            elif choice == "skip":
                mgr.accept_incomplete_unlock(folder_id)
                self._refresh()
                open_in_explorer(rec.path)
        elif issue == "abrindo":
            if (
                ask(
                    self,
                    f"Abertura de '{name}' interrompida",
                    view.attention,
                    [("Continuar abrindo", "go"), ("Fechar", "close")],
                )
                == "go"
            ):
                self._open_folder(folder_id)
        elif issue == "trancando":
            mgr.reconcile_on_start()
            self._refresh()
        elif issue == "itens_extras":
            choice = ask(
                self,
                f"Há itens novos em '{name}'",
                view.attention,
                [("Mostrar no Explorer", "show"), ("Tentar de novo", "retry")],
            )
            if choice == "show":
                open_in_explorer(rec.path)
            self._refresh()
        elif issue == "sem_dados":
            choice = ask(
                self,
                f"Dados de '{name}' não encontrados",
                view.attention + " Se você moveu ou apagou a pasta oculta '.owlvault', coloque-a "
                "de volta. Tirar da lista não apaga nada.",
                [("Fechar", "close"), ("Tirar da lista", "forget")],
            )
            if choice == "forget":
                self._forget(folder_id)
        elif issue == "nao_encontrada":
            choice = ask(
                self,
                f"'{name}' não foi encontrada",
                view.attention,
                [("Procurar a pasta…", "find"), ("Tirar da lista", "forget")],
            )
            if choice == "find":
                self._relocate(folder_id)
            elif choice == "forget":
                self._forget(folder_id)
        elif issue == "versao_anterior":
            files = mgr.kept_only_files(folder_id)
            choice = ask(
                self,
                f"Versão anterior de '{name}'",
                view.attention,
                [
                    ("Recuperar esses arquivos em outra pasta…", "restore"),
                    ("Apagar a versão anterior…", "delete"),
                    ("Fechar", "close"),
                ],
                details=files,
                primary="restore",
            )
            if choice == "restore":
                self._restore_kept(folder_id)
            elif choice == "delete":
                text = (
                    f"Estes {len(files)} arquivo(s) existem só na versão anterior e serão apagados "
                    "para sempre:"
                    if files
                    else "A versão anterior não tem arquivos que faltem na pasta. Apagar?"
                )
                if (
                    ask(
                        self,
                        "Apagar a versão anterior?",
                        text,
                        [("Apagar", "delete"), ("Cancelar", "cancel")],
                        details=files,
                        details_open=True,
                        primary="cancel",
                    )
                    == "delete"
                ):
                    try:
                        mgr.delete_kept(folder_id, files)
                    except (OwlVaultError, OSError) as exc:
                        inform(self, "Não foi possível apagar", str(exc))
                    self._refresh()
        elif issue == "senha_antiga":
            if (
                ask(
                    self,
                    f"Atualizar '{name}'",
                    view.attention,
                    [("Abrir", "open"), ("Fechar", "close")],
                )
                == "open"
            ):
                self._open_folder(folder_id)
        else:
            self._refresh()

    def _restore_kept(self, folder_id: str) -> None:
        if self.mgr is None:
            return
        mgr = self.mgr
        parent = choose_folder(self, "Escolha onde criar a pasta com a versão anterior")
        if not parent:
            return

        def done(reports: object) -> None:
            assert isinstance(reports, list)
            lines: list[str] = []
            for r in reports:
                assert isinstance(r, RestoreReport)
                lines.append(f"{r.destination}: {r.restored} arquivo(s)")
            inform(self, "Versão anterior recuperada", "Os arquivos foram recuperados em:", lines)
            for r in reports:
                open_in_explorer(r.destination)
            self._refresh()

        self._run(
            lambda p, c: mgr.restore_kept(folder_id, parent, p, c),
            done,
            title="Recuperando a versão anterior",
        )

    def _relocate(self, folder_id: str) -> None:
        if self.mgr is None:
            return
        path = choose_folder(self, f"Onde está a pasta '{self._rec_name(folder_id)}'?")
        if not path:
            return
        try:
            self.mgr.relocate(folder_id, path)
        except (OwlVaultError, OSError) as exc:
            inform(self, "Não é esta pasta", str(exc))
        self._refresh()

    def _forget(self, folder_id: str) -> None:
        if self.mgr is None:
            return
        name = self._rec_name(folder_id)
        if (
            ask(
                self,
                f"Tirar '{name}' da lista?",
                "Nada será apagado. Para voltar a usar a pasta, "
                "use ☰ > Recuperar uma pasta protegida.",
                [("Tirar da lista", "go"), ("Cancelar", "cancel")],
                primary="cancel",
            )
            == "go"
        ):
            self.mgr.forget(folder_id)
            self._refresh()

    # ------------------------------------------------------------------ esconder (T9)
    def _hide(self, folder_id: str) -> None:
        if self.mgr is None:
            return
        name = self._rec_name(folder_id)
        if (
            ask(
                self,
                f"Esconder '{name}'?",
                "A pasta some do Explorer e só volta pelo Owl Vault. Quem souber mostrar arquivos "
                "protegidos do sistema ainda pode ver que ela existe, mas não o conteúdo.",
                [("Esconder", "hide"), ("Cancelar", "cancel")],
            )
            != "hide"
            or self.mgr is None
        ):
            return
        try:
            self.mgr.hide(folder_id)
        except (OwlVaultError, OSError) as exc:
            inform(self, "Não foi possível esconder", str(exc))
        self._refresh()

    def _show_folder(self, folder_id: str) -> None:
        if self.mgr is None:
            return
        try:
            self.mgr.show(folder_id)
        except (OwlVaultError, OSError) as exc:
            inform(self, "Não foi possível mostrar", str(exc))
        self._refresh()

    # ------------------------------------------------------------------ verificar
    def _verify(self, folder_id: str) -> None:
        if self.mgr is None or self.session is None:
            return
        mgr = self.mgr
        rec = self.session.index.folder(folder_id)
        if rec is None:
            return
        vault_dir = winfs.join(rec.path, VAULT_DIR)
        policy = self.policy

        def job(p: QtProgress, c: CancelToken) -> VerifyReport:
            return verify_vault(
                vault_dir, mgr.keys_for_vault(vault_dir), policy=policy, progress=p, cancel=c
            )

        def done(report: object) -> None:
            assert isinstance(report, VerifyReport)
            if report.fully_ok:
                inform(
                    self,
                    "Tudo certo",
                    f"Os {report.files_ok} arquivo(s) de '{rec.name}' estão íntegros.",
                )
            elif report.ok:
                inform(
                    self,
                    "Arquivos íntegros, com observações",
                    f"Os {report.files_ok} arquivo(s) conferem, mas uma cópia de segurança "
                    "interna está danificada.",
                    report.redundancy + report.anomalies,
                )
            else:
                inform(
                    self,
                    "Problemas encontrados",
                    f"{len(report.bad)} arquivo(s) de '{rec.name}' estão danificados. Se você "
                    "tem uma cópia da pasta trancada (backup), use-a.",
                    report.bad,
                )

        self._run(job, done, title=f"Verificando '{rec.name}'")

    # ------------------------------------------------------------------ remover proteção (T10)
    def _remove(self, folder_id: str) -> None:
        if self.session is None:
            return
        name = self._rec_name(folder_id)
        self._confirm_identity(
            f"Remover a proteção de '{name}'?",
            "A pasta volta a ser comum e qualquer pessoa que use este computador poderá ver os "
            "arquivos.",
            "Remover proteção",
            lambda: self._remove_confirmed(folder_id),
        )

    def _remove_confirmed(self, folder_id: str) -> None:
        if self.mgr is None or self.session is None:
            return
        rec = self.session.index.folder(folder_id)
        if rec is None:
            return
        if rec.state == TRANCADA:
            mgr = self.mgr

            def done(out: object) -> None:
                assert isinstance(out, UnlockOutcome)
                if out.complete:
                    QTimer.singleShot(0, lambda: self._remove_finish(folder_id))
                else:
                    self._refresh()
                    QTimer.singleShot(0, lambda: self._resolve(folder_id))

            self._run(
                lambda p, c: mgr.unlock(folder_id, p, c),
                done,
                title=f"Abrindo '{rec.name}'",
                mode="unlock",
            )
        else:
            self._remove_finish(folder_id)

    def _remove_finish(self, folder_id: str) -> None:
        if self.mgr is None:
            return
        name = self._rec_name(folder_id)
        try:
            missing = self.mgr.removal_missing(folder_id)
        except (OwlVaultError, OSError) as exc:
            inform(self, "Não foi possível remover a proteção", str(exc))
            return
        if (
            missing
            and ask(
                self,
                "Há arquivos protegidos fora da pasta",
                f"{len(missing)} arquivo(s) guardados não estão na pasta '{name}' e serão apagados "
                "para sempre:",
                [("Remover mesmo assim", "go"), ("Cancelar", "cancel")],
                details=missing,
                details_open=True,
                primary="cancel",
            )
            != "go"
        ):
            return
        try:
            self.mgr.remove_protection(folder_id, confirmed_missing=missing)
        except (OwlVaultError, OSError) as exc:
            inform(self, "Não foi possível remover a proteção", str(exc))
            self._refresh()
            return
        self._refresh()
        self.home.set_notice(f"A proteção de '{name}' foi removida. A pasta agora é comum.")

    # ------------------------------------------------------------------ recuperar (T12)
    def _recover(self) -> None:
        if self.mgr is None or self.runner.busy:
            return
        if (
            ask(
                self,
                "Recuperar uma pasta protegida",
                "Escolha a pasta com o ícone do Owl Vault. Se ela estava escondida, escolha a pasta "
                "onde ela ficava.",
                [("Escolher a pasta…", "go"), ("Cancelar", "cancel")],
            )
            != "go"
        ):
            return
        path = choose_folder(self, "Escolha a pasta protegida (ou onde ela ficava)")
        if not path or self.mgr is None:
            return
        mgr = self.mgr
        try:
            found = mgr.find_recoverable(path)
        except (OwlVaultError, OSError) as exc:
            inform(self, "Não foi possível procurar", str(exc))
            return
        if not found:
            inform(self, "Nada encontrado", "Não há pasta protegida pelo Owl Vault aqui.")
            return
        if len(found) > 1:
            pick = PickDialog(
                self,
                "Pastas encontradas",
                "Marque as pastas que você quer recuperar.",
                [winfs.name_of(f) for f in found],
            )
            if pick.exec() != QDialog.DialogCode.Accepted:
                return
            found = [found[i] for i in pick.checked()]
            if not found:
                return
        dlg = SecretDialog(
            self,
            "Senha mestra",
            "Digite a senha mestra usada quando a pasta foi protegida.",
            "Recuperar",
            master=True,
            allow_master=False,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        secret = dlg.take()

        def job(_p: QtProgress, _c: CancelToken) -> tuple[list[str], list[str]]:
            ok: list[str] = []
            bad: list[str] = []
            for f in found:
                try:
                    ok.append(mgr.recover(f, secret).name)
                except AuthenticationError:
                    bad.append(f"{winfs.name_of(f)}: senha mestra incorreta para esta pasta")
                except (OwlVaultError, OSError) as exc:
                    bad.append(f"{winfs.name_of(f)}: {exc}")
            return ok, bad

        def done(result: object) -> None:
            assert isinstance(result, tuple)
            ok, bad = result
            self._refresh()
            if ok:
                inform(
                    self,
                    "Pasta(s) recuperada(s)",
                    "Agora elas abrem com o seu PIN: " + ", ".join(ok),
                    bad,
                )
            else:
                inform(self, "Nenhuma pasta recuperada", "Confira a senha mestra.", bad)

        self._run(job, done, title="Recuperando…", cancellable=False)

    # ------------------------------------------------------------------ PIN e senha mestra
    def _change_pin(self) -> None:
        if self.session is None or self.runner.busy:
            return
        dlg = ChangePinDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        current, new, master = dlg.take()

        def job(_p: QtProgress, _c: CancelToken) -> ProfileSession:
            s = (
                self.store.unlock_with_master(current)
                if master
                else self.store.unlock_with_pin(current)
            )
            s.set_pin(new)
            return s

        def done(s: object) -> None:
            assert isinstance(s, ProfileSession)
            self._replace_session(s)
            self.home.set_notice("PIN alterado.")

        def failed(exc: BaseException) -> bool:
            if isinstance(exc, PinError):
                inform(
                    self,
                    "PIN incorreto",
                    f"Restam {exc.remaining} tentativa(s)."
                    if exc.remaining
                    else "O PIN foi desativado. Use 'Esqueci o PIN' com a senha mestra.",
                )
                return True
            if isinstance(exc, AuthenticationError):
                inform(self, "Não conferiu", "Senha mestra incorreta." if master else str(exc))
                return True
            return False

        self._run(job, done, on_error=failed, title="Salvando o PIN…", cancellable=False)

    def _new_pin_after_master(self) -> None:
        session = self.session
        if session is None:
            return
        dlg = NewSecretDialog(
            self,
            master=False,
            title="Crie um PIN novo",
            text="O PIN antigo não funciona mais neste computador.",
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        pin = dlg.take()
        self._run(
            lambda _p, _c: session.set_pin(pin),
            lambda _r: self.home.set_notice("PIN criado."),
            title="Salvando o PIN…",
            cancellable=False,
        )

    def _new_master(self) -> None:
        session = self.session
        if session is None:
            return
        dlg = NewSecretDialog(
            self,
            master=True,
            title="Criar nova senha mestra",
            text="As pastas trancadas continuam abrindo normalmente com o PIN. Para que elas também "
            "abram com a senha nova em outro computador, abra e tranque cada uma de novo.",
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        sm = dlg.take()
        self._run(
            lambda _p, _c: session.change_master(sm),
            lambda _r: self._refresh_with("Nova senha mestra criada."),
            title="Salvando a senha mestra…",
            cancellable=False,
        )

    # ------------------------------------------------------------------ cópia (T14)
    def _open_copy_tool(self) -> None:
        from owl_vault.ui.copy_window import CopyWindow  # noqa: PLC0415

        if self._copy_window is None:
            self._copy_window = CopyWindow()
        self._copy_window.show()
        self._copy_window.raise_()
        self._copy_window.activateWindow()

    # ------------------------------------------------------------------ sair (T11)
    def closeEvent(self, event: QCloseEvent) -> None:
        if self._quitting:
            if self._copy_window is not None:
                self._copy_window.close()
            event.accept()
            return
        if self.runner.busy:
            if (
                ask(
                    self,
                    "Há uma operação em andamento",
                    "Parar num ponto seguro e fechar? Você pode continuar depois.",
                    [("Parar e fechar", "stop"), ("Continuar trabalhando", "keep")],
                    primary="keep",
                )
                == "stop"
            ):
                self.runner.cancel()
                self.runner.done.connect(lambda _r: self._quit_now())
                self.runner.error.connect(lambda _e: self._quit_now())
            event.ignore()
            return
        opened = [r for r in self.mgr.folders if r.state == ABERTA] if self.mgr else []
        if not opened:
            self._quit()
            event.accept()
            return
        lines = [f"{r.name}" for r in opened]
        choice = ask(
            self,
            "Sair do Owl Vault?",
            "Estas pastas estão abertas e visíveis:",
            [("Trancar e sair", "lock"), ("Sair sem trancar", "quit"), ("Cancelar", "cancel")],
            details=lines,
            details_open=True,
        )
        if choice == "quit":
            self._quit()
            event.accept()
            return
        event.ignore()
        if choice == "lock":

            def failed(exc: BaseException) -> bool:
                again = ask(
                    self,
                    "Não deu para trancar",
                    str(exc),
                    [("Tentar de novo", "retry"), ("Sair sem trancar", "quit")],
                )
                if again == "retry":
                    QTimer.singleShot(0, self.close)
                else:
                    QTimer.singleShot(0, self._quit_now)
                return True

            self._lock_sequence([r.id for r in opened], self._quit_now, failed)

    def _quit(self) -> None:
        self._quitting = True
        if self.session is not None:
            self.session.close()
            self.session = None
        self.mgr = None

    def _quit_now(self) -> None:
        self._quit()
        self.close()


_ = fmt_duration
