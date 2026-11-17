"""Janela principal da v2 no visual "Cofre": pastas protegidas (UI_SPEC_V2, ESTILO5-COFRE).

Estrutura: QWidget central sem margens = conteúdo (margens 32/20/32/24: marca e ☰ no topo, as
telas num QStackedWidget) + rodapé na largura toda (cada tela tem o seu ``Rodape``; os dois
QStackedWidget trocam juntos). Fluxo: assistente (1ª vez) → PIN → lista "Pastas protegidas";
"Proteger uma pasta" é um assistente na própria janela (``protect_flow``). As demais operações
longas mostram a ``ProgressDialog``. Todo trabalho pesado roda numa thread (``JobRunner``), um
por vez; o perfil destravado fica só em memória e é descartado ao bloquear (5 min sem uso,
Win+L, suspensão ou ☰ > Bloquear agora).
"""

from __future__ import annotations

import ctypes
import os
import re
import sys
import time
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Slot
from PySide6.QtGui import QAction, QActionGroup, QCloseEvent, QShowEvent
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QMainWindow,
    QMenu,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from owl_vault import version_label
from owl_vault.application.lockers import (
    ABERTA,
    MANTIDO,
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
    ProfileCorruptError,
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
    StateError,
)
from owl_vault.storage import winfs
from owl_vault.ui.common import (
    ProgressDialog,
    choose_folder,
    hidpi,
    open_in_explorer,
    short_list,
)
from owl_vault.ui.componentes import BotaoMais, Marca, sombra, transparente
from owl_vault.ui.folder_dialogs import (
    ChangePinDialog,
    NewSecretDialog,
    PickDialog,
    SecretDialog,
    ask,
    inform,
    limits_dialog,
)
from owl_vault.ui.icon import ico_bytes, logo_image, owl_icon
from owl_vault.ui.pages import (
    VISIVEIS,
    HomePage,
    Pagina,
    ProfileProblemPage,
    SetupPage,
    UnlockPage,
)
from owl_vault.ui.protect_flow import ProtectPage
from owl_vault.ui.theme import apply_theme, current_tokens, save_theme, saved_theme
from owl_vault.ui.workers import JobRunner, QtProgress

IDLE_LOCK_SECONDS = 5 * 60
WM_WTSSESSION_CHANGE = 0x02B1
WTS_SESSION_LOCK = 0x7
WM_POWERBROADCAST = 0x0218
PBT_APMSUSPEND = 0x4
FOLDER_ID_RE = re.compile(r"[0-9a-f]{32}")
#: origem de um pedido "abrir <id>": a linha de comando (o atalho iniciou o app) ou uma
#: mensagem da instância única (o app já estava rodando) — esta pede confirmação com o nome
ORIGEM_LINHA = "linha"
ORIGEM_MENSAGEM = "mensagem"
BUSY_TEXT = "Espere a operação atual terminar."
#: avisos de versão anterior mantida: a pasta aberta continua utilizável
KEPT_ISSUES = ("versao_anterior", "versao_anterior_ilegivel")

ErrorHandler = Callable[[BaseException], bool]


@dataclass
class _Job:
    dialog: ProgressDialog | None
    on_done: Callable[[Any], None]
    on_error: ErrorHandler | None
    after: Callable[[], None] | None


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
        self.setWindowTitle(f"Owl Vault {version_label()}")
        self.setWindowIcon(owl_icon())
        self.resize(980, 760)
        self.setMinimumSize(760, 580)
        self.launcher = launcher
        self.policy = policy
        self.store = ProfileStore(profile_dir, policy)
        self.session: ProfileSession | None = None
        self.mgr: LockerManager | None = None
        self.pending_open = (
            open_request if open_request and FOLDER_ID_RE.fullmatch(open_request) else None
        )
        self._pending_source = ORIGEM_LINHA
        self._icon = ico_bytes()
        self._job: _Job | None = None
        self._lock_after_job = False
        self._quit_after_job = False
        self._quit_sequence = False
        self._after_unlock_pending = False
        self._recovering = False
        self._skip_practice = False
        self._needs_new_pin = False
        self._wants_new_master = False
        self._wants_recover = False
        self._quitting = False
        self._visible_count = 0
        self._wts_registered = False
        self._copy_window: QWidget | None = None

        self.runner = JobRunner(self)
        self.runner.done.connect(self._job_done)
        self.runner.error.connect(self._job_failed)

        self.setup_page = SetupPage()
        self.setup_page.finished.connect(self._create_profile)
        self.unlock_page = UnlockPage()
        self.unlock_page.submitted.connect(self._submit_unlock)
        self.unlock_page.new_master_requested.connect(self._request_new_master)
        self.unlock_page.use_pin_once.connect(self._use_pin_once)
        self.problem_page = ProfileProblemPage()
        self.problem_page.recover_requested.connect(self._recover_corrupt_profile)
        self.problem_page.retry_requested.connect(self._start)
        self.home = HomePage()
        self.home.protect_clicked.connect(lambda: self._protect())
        self.home.lock_all_clicked.connect(self._lock_all)
        self.protect_page = ProtectPage(self.runner)
        self.protect_page.back_to_list.connect(self._back_to_list)
        self.protect_page.check_requested.connect(self._protect_check)
        self.protect_page.lock_requested.connect(self._protect_lock)
        self._all_pages: list[Pagina] = [
            self.setup_page,
            self.unlock_page,
            self.problem_page,
            self.home,
            self.protect_page,
        ]

        self.menu = self._build_menu()
        self._build_layout()

        self._watcher = _InputWatcher()
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self._watcher)
        self._idle = QTimer(self)
        self._idle.setInterval(15_000)
        self._idle.timeout.connect(self._idle_check)
        self._idle.start()
        self._start()

    # ------------------------------------------------------------------ estrutura
    def _build_layout(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        conteudo = QWidget()
        cl = QVBoxLayout(conteudo)
        cl.setContentsMargins(32, 20, 32, 24)
        cl.setSpacing(20)
        topo, tl = transparente(QHBoxLayout)
        tl.addWidget(Marca())
        tl.addStretch(1)
        self.menu_button = BotaoMais(self.menu, "Menu", "☰")
        tl.addWidget(self.menu_button)
        cl.addWidget(topo)
        self.pages = QStackedWidget()
        self.pages.setObjectName("transparente")
        for p in self._all_pages:
            self.pages.addWidget(p)
        cl.addWidget(self.pages, 1)
        root.addWidget(conteudo, 1)
        self.rodapes = QStackedWidget()
        self.rodapes.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        for p in self._all_pages:
            self.rodapes.addWidget(p.rodape)
        root.addWidget(self.rodapes)
        self.setCentralWidget(central)

    def _show_page(self, page: Pagina) -> None:
        self.pages.setCurrentWidget(page)
        self.rodapes.setCurrentWidget(page.rodape)
        self._update_menu()
        alvo = page.campo_inicial()
        if alvo is not None:
            alvo.setFocus()

    def _current_page(self) -> Pagina | None:
        page = self.pages.currentWidget()
        return page if isinstance(page, Pagina) else None

    def _status(self, text: str = "", estado: str = "") -> None:
        page = self._current_page()
        if page is not None:
            page.status(text, estado)

    # ------------------------------------------------------------------ menu ☰
    def _build_menu(self) -> QMenu:
        menu = QMenu(self)
        self._session_actions: list[QAction] = []

        def only_unlocked(action: QAction) -> None:
            self._session_actions.append(action)

        only_unlocked(menu.addAction("Recuperar uma pasta protegida…", lambda: self._recover()))
        only_unlocked(menu.addAction("Cópia criptografada de uma pasta…", self._open_copy_tool))
        only_unlocked(menu.addSeparator())
        only_unlocked(menu.addAction("Alterar PIN…", self._change_pin))
        only_unlocked(menu.addAction("Bloquear agora", self.lock_now))
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
        menu.aboutToShow.connect(self._update_menu)
        return menu

    def _update_menu(self) -> None:
        unlocked = self.session is not None
        for act in self._session_actions:
            act.setVisible(unlocked)

    def _set_theme(self, key: str) -> None:
        save_theme(key)
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_theme(app, key)
        # a sombra dos cartões é um efeito (QSS não tem box-shadow): refaz com o token novo
        for w in self.findChildren(QFrame):
            if w.objectName() in ("cartao", "cartaoLateral"):
                sombra(w)

    def _about(self) -> None:
        from PySide6.QtWidgets import QMessageBox  # noqa: PLC0415

        box = QMessageBox(self)
        box.setWindowTitle("Sobre o Owl Vault")
        box.setIconPixmap(hidpi(lambda px: logo_image(px), 132))
        box.setTextFormat(Qt.TextFormat.RichText)
        roxo = current_tokens()["accent-text"]
        box.setText(
            f'<b>Owl <span style="color:{roxo}">Vault</span></b> {version_label()}'
            "<br>Pastas protegidas por criptografia no seu computador.<br>"
            "AES-256-GCM e Argon2id. Sem nuvem, sem telemetria.<br>"
            "Não houve auditoria independente."
        )
        box.exec()

    # ------------------------------------------------------------------ início / desbloqueio
    def _start(self) -> None:
        if not self.store.exists():
            self.setup_page.start()
            self._show_page(self.setup_page)
        else:
            self._show_unlock()

    def _show_profile_problem(self, *, corrupt: bool, detail: str = "") -> None:
        self.problem_page.configure(corrupt=corrupt, detail=detail)
        self._show_page(self.problem_page)

    def _show_unlock(self, error: str = "") -> None:
        try:
            pin_ok = self.store.pin_available()
            practice = self.store.practice_due() and not self._skip_practice
        except OSError as exc:  # antivírus/backup segurando o arquivo: não é perfil danificado
            self._show_profile_problem(corrupt=False, detail=str(exc.strerror or exc))
            return
        except (OwlVaultError, ValueError, KeyError, TypeError):  # ProfileCorruptError & cia.
            self._show_profile_problem(corrupt=True)
            return
        opening = self.pending_open is not None
        button = "Abrir" if opening else "Entrar"
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
                button=button,
            )
        else:
            self.unlock_page.configure(
                master=False,
                title="Abrir pasta protegida" if opening else "Digite seu PIN",
                error=error,
                button=button,
            )
        self._show_page(self.unlock_page)

    def _recover_corrupt_profile(self) -> None:
        """Perfil ilegível: guarda os arquivos danificados ao lado e recria com recuperação."""
        try:
            self._set_aside_profile()
        except OSError as exc:
            self.problem_page.fail(
                f"Não foi possível guardar o arquivo danificado: {exc.strerror or exc}. Feche "
                "outros programas e tente de novo."
            )
            return
        self.setup_page.start(recuperar=True)
        self._show_page(self.setup_page)

    def _set_aside_profile(self) -> list[Path]:
        """Renomeia ``perfil.owlp``/``.bak`` para ``*.danificado-<data>`` (nunca apaga)."""
        stamp = time.strftime("%Y%m%d-%H%M%S")
        moved: list[Path] = []
        for p in (self.store.path, self.store.bak):
            if not p.exists():
                continue
            target = p.with_name(f"{p.name}.danificado-{stamp}")
            n = 2
            while target.exists():
                target = p.with_name(f"{p.name}.danificado-{stamp}-{n}")
                n += 1
            os.rename(p, target)
            moved.append(target)
        return moved

    @Slot(str, str, bool)
    def _create_profile(self, master: str, pin: str, wants_recover: bool) -> None:
        self._wants_recover = wants_recover

        def job(_p: QtProgress, _c: CancelToken) -> ProfileSession:
            return self.store.create(master, pin)

        def failed(exc: BaseException) -> bool:
            self.setup_page.set_busy(False)
            self.setup_page.show_failure(str(exc))
            return True

        if not self._run(job, self._unlocked, on_error=failed, status=None):
            self.setup_page.show_failure(BUSY_TEXT)
            return
        self.setup_page.set_busy(True, "Preparando a proteção (alguns segundos)…")

    @Slot(str, bool)
    def _submit_unlock(self, secret: str, master: bool) -> None:
        def job(_p: QtProgress, _c: CancelToken) -> ProfileSession:
            if master:
                return self.store.unlock_with_master(secret)
            return self.store.unlock_with_pin(secret)

        if not self._run(job, self._unlocked, on_error=self._unlock_failed, status=None):
            self.unlock_page.fail(BUSY_TEXT)

    def _unlock_failed(self, exc: BaseException) -> bool:
        if isinstance(exc, ProfileCorruptError):
            self._show_profile_problem(corrupt=True)
            return True
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
            self.unlock_page.configure(
                master=True,
                text=str(exc),
                allow_switch=False,
                button=self.unlock_page.button_text,
            )
            return True
        if isinstance(exc, PinUnavailableError):
            self._show_unlock(str(exc))
            return True
        if isinstance(exc, AuthenticationError):
            self.unlock_page.fail(
                "Senha mestra incorreta." if self.unlock_page.master else str(exc)
            )
            return True
        if isinstance(exc, OSError):
            self.unlock_page.fail(
                f"Não foi possível ler o perfil agora ({exc.strerror or exc}). Feche outros "
                "programas e tente de novo."
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
        self._quitting = False
        self._visible_count = 0  # destravado, quem sabe das pastas é o índice
        self._watcher.last = time.monotonic()
        notes = list(session.notes)
        try:
            notes += self.mgr.reconcile_on_start()
        except (OwlVaultError, OSError) as exc:
            notes.append(str(exc))
        self._refresh()
        self.home.set_notice(" ".join(notes))
        self._show_page(self.home)
        QTimer.singleShot(0, self._after_unlock)

    def _after_unlock(self) -> None:
        """Pendências do desbloqueio, UMA por vez: cada etapa chama a próxima quando o próprio
        trabalho (ou o diálogo dela) termina — nunca duas operações ao mesmo tempo."""
        if self.session is None or self.mgr is None or self._quitting:
            self._after_unlock_pending = False
            return
        if self.runner.busy:
            self._after_unlock_pending = True  # _after_job retoma
            return
        self._after_unlock_pending = False
        nxt = self._continue_after_unlock
        if self._needs_new_pin:
            self._needs_new_pin = False
            self._new_pin_after_master(then=nxt)
            return
        if self._wants_new_master:
            self._wants_new_master = False
            self._new_master(then=nxt)
            return
        if self._wants_recover:
            self._wants_recover = False
            self._recovering = True  # o pedido do atalho espera a recuperação terminar
            self._recover(then=nxt)
            return
        recovered, self._recovering = self._recovering, False
        if self.pending_open:
            fid, self.pending_open = self.pending_open, None
            source, self._pending_source = self._pending_source, ORIGEM_LINHA
            self._open_pending(fid, source, recovered=recovered)

    def _continue_after_unlock(self) -> None:
        QTimer.singleShot(0, self._after_unlock)

    def _open_pending(self, folder_id: str, source: str, *, recovered: bool = False) -> None:
        if self.session is None:
            return
        rec = self.session.index.folder(folder_id)
        if rec is None:
            if recovered:  # o atalho antigo aponta para o registro de antes da recuperação
                self.home.set_notice(
                    "As pastas recuperadas estão na lista. Use 'Abrir' na pasta que você quer."
                )
                return
            self._not_in_list()
            return
        self._check_shortcut(folder_id)
        # o PIN digitado na tela de desbloqueio não vale como "sim" para um pedido que chegou por
        # mensagem (outro processo): confirma com o nome da pasta antes de abrir
        if (
            source == ORIGEM_MENSAGEM
            and ask(
                self,
                f"Abrir '{rec.name}'?",
                "O atalho 'Abrir com Owl Vault' desta pasta foi usado. Se não foi você, clique "
                "em Cancelar.",
                [("Abrir", "open"), ("Cancelar", "cancel")],
            )
            != "open"
        ):
            return
        self._open_folder(folder_id)

    def _replace_session(self, new: ProfileSession) -> None:
        old = self.session
        self.session = new
        if self.mgr is not None:
            self.mgr.session = new
        if old is not None and old is not new:
            old.close()

    def _sync_pin_state(self) -> None:
        """Depois de um PIN errado com o app destravado: o disco tem o contador (e talvez o PIN
        desativado) mais novo que a sessão em memória; sem isto, o próximo ``save()`` gravaria
        o PIN de volta com o contador zerado."""
        s = self.session
        if s is None:
            return
        try:
            obj, other = self.store.read_raw()
        except (OwlVaultError, OSError, ValueError):
            return
        if obj.get("profile_id") != s.obj.get("profile_id"):
            return

        def failures(o: dict[str, Any] | None) -> int:
            try:
                return int((o or {}).get("pin_failures", 0) or 0)
            except (TypeError, ValueError):
                return 0

        s.obj["pin"] = obj.get("pin")
        s.obj["pin_failures"] = max(failures(obj), failures(other), failures(s.obj))

    # ------------------------------------------------------------------ bloqueio
    def lock_now(self) -> None:
        if self.runner.busy:
            self._lock_after_job = True
            return
        self._lock_after_job = False
        self._quit_sequence = False
        self._after_unlock_pending = False
        popup = QApplication.activePopupWidget()
        if popup is not None:
            popup.close()
        for _ in range(8):
            modal = QApplication.activeModalWidget()
            if modal is None or modal is self:
                break
            if isinstance(modal, QDialog):
                modal.reject()
            else:
                modal.close()
        if self.mgr is not None:
            # só a CONTAGEM (sem nomes) fica em memória, para o aviso ao sair (T11)
            try:
                self._visible_count = sum(1 for r in self.mgr.folders if r.state in VISIVEIS)
            except OwlVaultError:
                self._visible_count = 0
        if self.session is not None:
            self.session.close()
        self.session = None
        self.mgr = None
        self.home.clear()
        self.protect_page.clear()
        if self.store.exists():
            self._show_unlock()
        else:
            self._update_menu()

    def _idle_check(self) -> None:
        if self.session is None or self.runner.busy or self._quit_sequence:
            return
        if time.monotonic() - self._watcher.last >= IDLE_LOCK_SECONDS:
            self.lock_now()

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        if self._quitting and self.session is None:
            self._quitting = False  # nunca reaparece "meio encerrada" (sem sessão, com a lista)
            self._start()
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
        if self._quitting:
            self._quitting = False
            self._start()
        self.showNormal()
        self.raise_()
        self.activateWindow()
        parts = text.split()
        if len(parts) == 2 and parts[0] == "abrir" and FOLDER_ID_RE.fullmatch(parts[1]):
            self.request_open(parts[1])

    def request_open(self, folder_id: str, source: str = ORIGEM_MENSAGEM) -> None:
        if self.runner.busy:
            inform(self, "Aguarde", "Espere a operação atual terminar e use o atalho de novo.")
            return
        if self.session is None or self.mgr is None:
            self.pending_open = folder_id
            self._pending_source = source
            if self.store.exists():
                self._show_unlock()
            return
        rec = self.session.index.folder(folder_id)
        if rec is None:
            self._not_in_list()  # nada a proteger aqui: explica sem pedir o PIN
            return
        self._confirm_identity(
            f"Abrir '{rec.name}'", "", "Abrir", lambda: self._open_from_shortcut(folder_id)
        )

    def _open_from_shortcut(self, folder_id: str) -> None:
        self._check_shortcut(folder_id)
        self._open_folder(folder_id)

    def _check_shortcut(self, folder_id: str) -> None:
        """Pedido vindo do atalho 'Abrir com Owl Vault': confere o espaço reservado da pasta
        trancada (o atalho é refeito se estiver diferente do esperado) e avisa."""
        if self.mgr is None:
            return
        try:
            notes = self.mgr.repair_placeholders(folder_id)
        except (OwlVaultError, OSError):
            return  # pasta fora do lugar ou sem dados: o próprio 'Abrir' explica
        if notes:
            inform(self, "O atalho desta pasta foi refeito", " ".join(notes))

    def _not_in_list(self) -> None:
        choice = ask(
            self,
            "Esta pasta não está na lista",
            "Esta pasta não está na lista deste computador. Se você reinstalou o Windows ou o "
            "Owl Vault, recupere-a com a mesma senha mestra.",
            [("Recuperar uma pasta protegida…", "recover"), ("Fechar", "close")],
        )
        if choice == "recover":
            self._recover()

    def _confirm_identity(
        self,
        title: str,
        text: str,
        button: str,
        then: Callable[[], None],
        error: str = "",
        *,
        perigo: bool = False,
    ) -> None:
        """Pede o PIN (ou a senha mestra) de novo e troca a sessão pela nova. ``perigo``: o
        botão de ação é destrutivo (ex.: 'Remover proteção')."""
        if self.runner.busy:
            self._status(BUSY_TEXT, "erro")
            return
        try:
            pin_ok = self.store.pin_available()
        except (OwlVaultError, OSError, ValueError, KeyError):
            pin_ok = False
        dlg = SecretDialog(
            self,
            title,
            text,
            button,
            master=not pin_ok,
            allow_master=pin_ok,
            error=error,
            perigo=perigo,
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
            if isinstance(exc, AuthenticationError):  # inclui PinError e PIN desativado
                self._sync_pin_state()
            if isinstance(exc, PinError):
                msg = (
                    f"PIN incorreto. Restam {exc.remaining} tentativa(s)."
                    if exc.remaining
                    else "PIN incorreto muitas vezes. Use a senha mestra."
                )
            elif isinstance(exc, PinUnavailableError):
                msg = str(exc)
            elif isinstance(exc, AuthenticationError):
                msg = "Senha mestra incorreta." if master else str(exc)
            else:
                return False
            QTimer.singleShot(
                0,
                lambda: self._confirm_identity(title, text, button, then, msg, perigo=perigo),
            )
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
        after: Callable[[], None] | None = None,
        status: str | None = "Trabalhando…",
    ) -> bool:
        """Inicia ``job`` na thread. Recusa (devolve False, sem tocar no trabalho em curso) se
        já houver outro rodando. ``after`` roda depois de ``on_done``/``on_error``; ``status``
        vai para o rodapé da tela atual (None: a própria tela já mostra o que está fazendo)."""
        if self.runner.busy:
            self._status(BUSY_TEXT, "erro")
            return False
        dlg = None
        if title is not None:
            dlg = ProgressDialog(
                self, title, self.runner, mode=mode, note=note, cancellable=cancellable
            )
        self._block_shutdown(True)
        try:
            self.runner.start(job)
        except RuntimeError:
            self._block_shutdown(False)
            if dlg is not None:
                dlg.deleteLater()
            self._status(BUSY_TEXT, "erro")
            return False
        self._job = _Job(dlg, on_done, on_error, after)
        if status is not None:
            self._status(status, "trabalhando")
        if dlg is not None:
            dlg.open()
        return True

    def _take_job(self) -> _Job | None:
        job, self._job = self._job, None
        self._block_shutdown(False)
        # o fim de uma operação longa conta como uso: o resultado não some logo em seguida
        self._watcher.last = time.monotonic()
        self._status()
        if job is not None and job.dialog is not None:
            job.dialog.finish()
        return job

    @Slot(object)
    def _job_done(self, result: object) -> None:
        job = self._take_job()
        try:
            if job is not None:
                job.on_done(result)
                if job.after is not None:
                    job.after()
        finally:
            self._after_job()

    @Slot(object)
    def _job_failed(self, exc: object) -> None:
        job = self._take_job()
        try:
            assert isinstance(exc, BaseException)
            if job is None or job.on_error is None or not job.on_error(exc):
                self._default_error(exc)
            if job is not None and job.after is not None:
                job.after()
        finally:
            self._after_job()

    def _after_job(self) -> None:
        if self._quit_after_job:
            if self.runner.busy:  # on_done encadeou outro trabalho: pede para parar também
                self.runner.cancel()
                return
            self._quit_after_job = False
            self.close()  # caminho normal (T11 se ainda houver pasta aberta)
            return
        if self.runner.busy:
            return
        if self._lock_after_job:
            QTimer.singleShot(0, self.lock_now)
        elif self._after_unlock_pending:
            QTimer.singleShot(0, self._after_unlock)

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
        handlers: dict[str, Callable[[str], object]] = {
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

    def _back_to_list(self) -> None:
        if self.session is None:
            return
        self._refresh()
        self._show_page(self.home)

    # ------------------------------------------------------------------ proteger (T5)
    def _protect(self, path: str | None = None) -> None:
        """Abre o assistente "Proteger uma pasta" (passo 1; com ``path``, já confere)."""
        if self.mgr is None or self.runner.busy:
            return
        self.protect_page.start(first_time=not self.mgr.folders)
        self._show_page(self.protect_page)
        if path:
            self.protect_page.set_path(path)
            self._protect_check(path)

    @Slot(str)
    def _protect_check(self, path: str) -> None:
        if self.mgr is None:
            return
        mgr = self.mgr
        page = self.protect_page

        def job(p: QtProgress, c: CancelToken) -> ProtectCheck:
            return mgr.check_protect(path, p, c)

        def done(check: object) -> None:
            assert isinstance(check, ProtectCheck)
            page.show_check(check)

        def failed(exc: BaseException) -> bool:
            if isinstance(exc, CancelledError):
                page.check_cancelled()
            elif isinstance(exc, PreflightError):
                page.show_blockers(exc.blockers or [str(exc)])
            elif isinstance(exc, (OwlVaultError, OSError)):
                page.show_blockers([str(exc)])
            else:
                page.show_blockers([f"{type(exc).__name__}: {exc}"])
            return True

        page.checking()
        if not self._run(job, done, on_error=failed, status=None):
            page.show_blockers([BUSY_TEXT])

    def _protect_lock(self) -> None:
        page = self.protect_page
        check = page.check
        if check is None or self.mgr is None:
            return
        mgr = self.mgr

        def job(p: QtProgress, c: CancelToken) -> LockOutcome:
            return mgr.protect(check, p, c)

        def done(out: object) -> None:
            assert isinstance(out, LockOutcome)
            page.finish(out)
            self._lock_done(out, resolve=False)

        def failed(exc: BaseException) -> bool:
            page.fail(exc)
            self._refresh()
            return True

        page.locking()
        if not self._run(job, done, on_error=failed, status=None):
            page.fail(OwlVaultError(BUSY_TEXT))

    # ------------------------------------------------------------------ trancar (T7)
    def _lock_folder(
        self,
        folder_id: str,
        *,
        hide_after: bool = False,
        then: Callable[[], None] | None = None,
        on_error: ErrorHandler | None = None,
        on_abort: Callable[[], None] | None = None,
    ) -> bool:
        """Tranca uma pasta aberta. Devolve False se nada foi iniciado (``on_abort`` também
        roda se o trancamento parar antes do fim)."""
        if self.mgr is None or self.runner.busy:
            return False
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
                return False

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
            elif not out.complete and on_abort is not None:
                on_abort()

        return self._run(
            job,
            done,
            on_error=on_error,
            title=f"Trancando '{name}'",
            mode="lock",
            note="Não use esta pasta até terminar.",
        )

    def _lock_done(self, out: object, *, resolve: bool = True) -> None:
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
        elif resolve:
            QTimer.singleShot(0, lambda: self._resolve(out.record.id))

    def _lock_all(self) -> None:
        if self.mgr is None:
            return
        ids = [r.id for r in self.mgr.folders if r.state == ABERTA]
        self._lock_sequence(ids, None)

    def _lock_sequence(
        self,
        ids: list[str],
        then: Callable[[], None] | None,
        on_error: Callable[[str, BaseException], bool] | None = None,
        on_abort: Callable[[], None] | None = None,
    ) -> None:
        if not ids:
            if then is not None:
                then()
            return
        first, rest = ids[0], ids[1:]
        err = self._bind_error(on_error, first) if on_error is not None else None
        started = self._lock_folder(
            first,
            then=lambda: QTimer.singleShot(
                0, lambda: self._lock_sequence(rest, then, on_error, on_abort)
            ),
            on_error=err,
            on_abort=on_abort,
        )
        if not started and on_abort is not None:
            on_abort()

    @staticmethod
    def _bind_error(handler: Callable[[str, BaseException], bool], folder_id: str) -> ErrorHandler:
        def err(exc: BaseException) -> bool:
            return handler(folder_id, exc)

        return err

    # ------------------------------------------------------------------ abrir (T6)
    def _open_folder(self, folder_id: str) -> None:
        if self.mgr is None or self.session is None:
            return
        if self.runner.busy:
            self._status(BUSY_TEXT, "erro")
            return
        rec = self.session.index.folder(folder_id)
        if rec is None:
            self._not_in_list()
            return
        view = self.mgr.view(rec)
        if rec.state == ABERTA and view.issue in ("", *KEPT_ISSUES):
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
        if self.mgr is None or self.session is None or self.runner.busy:
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
                    lambda out: self._undo_done(out, name),
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
            try:
                notes = mgr.reconcile_on_start()
            except (OwlVaultError, OSError) as exc:
                notes = [str(exc)]
            self._refresh()
            if notes:
                self.home.set_notice(" ".join(notes))
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
            text = view.attention
            if rec.state != TRANCADA:
                text += (
                    " Se você renomeou ou moveu a pasta aberta, clique em 'Procurar a pasta…' e "
                    "escolha-a no lugar novo (precisa ser a mesma pasta, na mesma unidade)."
                )
            choice = ask(
                self,
                f"'{name}' não foi encontrada",
                text,
                [("Procurar a pasta…", "find"), ("Tirar da lista", "forget")],
            )
            if choice == "find":
                self._relocate(folder_id)
            elif choice == "forget":
                self._forget(folder_id)
        elif issue == "versao_anterior_ilegivel":
            self._resolve_unreadable_kept(folder_id)
        elif issue == "versao_anterior":
            try:
                files = mgr.kept_only_files(folder_id)
            except StateError:  # ficou ilegível ou sumiu depois da lista: nunca conta como vazia
                self._refresh()
                self._resolve_unreadable_kept(folder_id)
                return
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
                perigo="delete",
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
                        perigo="delete",
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

    def _undo_done(self, out: object, name: str) -> None:
        """Fim do 'Desfazer': mostra o que não voltou (falhas) e os conflitos em caminhos que
        o Owl Vault tinha apagado (a versão guardada deles foi MANTIDA)."""
        assert isinstance(out, UnlockOutcome)
        self._refresh()
        report = out.report
        if not out.complete:
            inform(
                self,
                f"Nem todos os arquivos voltaram para '{name}'",
                out.record.attention
                or "Alguns arquivos não puderam ser devolvidos. A cópia protegida deles continua "
                "guardada.",
                report.failed if report is not None else (),
            )
            return
        if out.record.attention and any(v.role == MANTIDO for v in out.record.vaults):
            inform(
                self,
                f"'{name}' continua aberta",
                out.record.attention,
                report.conflicts if report is not None else (),
            )
            return
        self.home.set_notice(f"'{name}' continua aberta.")

    def _resolve_unreadable_kept(self, folder_id: str) -> None:
        """Versão anterior MANTIDA ilegível ou ausente: nunca é apagada nem tratada como vazia.
        Só dá para tentar recuperá-la (ou o salvamento de emergência) ou, se a pasta dela sumiu,
        esquecê-la."""
        if self.mgr is None or self.session is None:
            return
        mgr = self.mgr
        rec = self.session.index.folder(folder_id)
        if rec is None:
            return
        name = rec.name
        gone = [v for v in rec.vaults if v.role == MANTIDO and not os.path.lexists(v.location)]
        view = mgr.view(rec)
        text = view.attention or (
            f"A versão anterior de '{name}' que foi mantida não pôde ser lida. Nada foi apagado."
        )
        buttons: list[tuple[str, str]] = []
        if len(gone) < sum(1 for v in rec.vaults if v.role == MANTIDO):
            buttons.append(("Tentar recuperar em outra pasta…", "restore"))
        if gone:
            text += (
                f" {len(gone)} versão(ões) anterior(es) não existe(m) mais no disco (a pasta "
                "oculta foi apagada fora do Owl Vault)."
            )
            buttons.append(("Esquecer a versão que sumiu", "forget_kept"))
        buttons.append(("Fechar", "close"))
        choice = ask(self, f"Versão anterior de '{name}'", text, buttons)
        if choice == "restore":
            self._restore_kept(folder_id)
        elif choice == "forget_kept":
            try:
                n = mgr.forget_missing_kept(folder_id)
            except (OwlVaultError, OSError) as exc:
                inform(self, "Não foi possível esquecer a versão anterior", str(exc))
                n = 0
            self._refresh()
            if n:
                self.home.set_notice(
                    f"{n} versão(ões) anterior(es) de '{name}' que não existia(m) mais saiu(íram) "
                    "da lista. Nada foi apagado."
                )

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
        if not path or self.mgr is None:
            return
        try:
            self.mgr.relocate(folder_id, path)
        except (OwlVaultError, OSError) as exc:
            inform(self, "Não é esta pasta", str(exc))
        self._refresh()

    def _forget_text(self, folder_id: str) -> str:
        rec = self.session.index.folder(folder_id) if self.session is not None else None
        if rec is None or rec.state == TRANCADA:
            warning = ""
            if rec is not None and self.mgr is not None:
                try:  # cofre fora da pasta (área temporária): 'Recuperar' não o acharia
                    warning = self.mgr.forget_warning(folder_id)
                except (OwlVaultError, OSError):
                    warning = ""
            if warning:
                return f"Nada será apagado. {warning}"
            return (
                "Nada será apagado. Para voltar a usar a pasta, use ☰ > Recuperar uma pasta "
                "protegida."
            )
        where = winfs.strip_extended(winfs.parent_of(rec.path))
        text = (
            "Nada será apagado. Os arquivos legíveis continuam na pasta; para trancá-la de novo, "
            "use '+ Proteger uma pasta…'. A cópia criptografada anterior fica na pasta oculta "
            f"'.owlvault-{rec.id}', em {where}."
        )
        if any(v.role == MANTIDO for v in rec.vaults):
            text += (
                " Atenção: os arquivos da versão anterior mantida só existem nessa cópia oculta."
            )
        return text

    def _forget(self, folder_id: str) -> None:
        if self.mgr is None:
            return
        name = self._rec_name(folder_id)
        if (
            ask(
                self,
                f"Tirar '{name}' da lista?",
                self._forget_text(folder_id),
                [("Tirar da lista", "go"), ("Cancelar", "cancel")],
                primary="cancel",
            )
            == "go"
            and self.mgr is not None
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
        name = rec.name

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
                    f"Os {report.files_ok} arquivo(s) de '{name}' estão íntegros.",
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
                    f"{len(report.bad)} arquivo(s) de '{name}' estão danificados. Se você "
                    "tem uma cópia da pasta trancada (backup), use-a.",
                    report.bad,
                )

        self._run(job, done, title=f"Verificando '{name}'")

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
            perigo=True,
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
                perigo="go",
            )
            != "go"
        ):
            return
        if self.mgr is None:
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
    def _recover(self, then: Callable[[], None] | None = None) -> None:
        started = False
        try:
            started = self._recover_steps(then)
        finally:
            if not started and then is not None:
                then()

    def _recover_steps(self, then: Callable[[], None] | None) -> bool:
        if self.mgr is None or self.runner.busy:
            return False
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
            return False
        path = choose_folder(self, "Escolha a pasta protegida (ou onde ela ficava)")
        if not path or self.mgr is None:
            return False
        mgr = self.mgr
        try:
            found = mgr.find_recoverable(path)
        except (OwlVaultError, OSError) as exc:
            inform(self, "Não foi possível procurar", str(exc))
            return False
        if not found:
            inform(self, "Nada encontrado", "Não há pasta protegida pelo Owl Vault aqui.")
            return False
        if len(found) > 1:
            pick = PickDialog(
                self,
                "Pastas encontradas",
                "Marque as pastas que você quer recuperar.",
                [winfs.name_of(f) for f in found],
            )
            if pick.exec() != QDialog.DialogCode.Accepted:
                return False
            found = [found[i] for i in pick.checked()]
            if not found:
                return False
        dlg = SecretDialog(
            self,
            "Senha mestra",
            "Digite a senha mestra usada quando a pasta foi protegida.",
            "Recuperar",
            master=True,
            allow_master=False,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return False
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

        return self._run(job, done, title="Recuperando…", cancellable=False, after=then)

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
            if isinstance(exc, AuthenticationError):
                self._sync_pin_state()
            if isinstance(exc, PinError):
                inform(
                    self,
                    "PIN incorreto",
                    f"Restam {exc.remaining} tentativa(s)."
                    if exc.remaining
                    else "O PIN foi desativado. Use 'Esqueci o PIN' com a senha mestra.",
                )
                return True
            if isinstance(exc, PinUnavailableError):
                inform(self, "PIN desativado", str(exc))
                return True
            if isinstance(exc, AuthenticationError):
                inform(self, "Não conferiu", "Senha mestra incorreta." if master else str(exc))
                return True
            return False

        self._run(job, done, on_error=failed, title="Salvando o PIN…", cancellable=False)

    def _new_pin_after_master(self, then: Callable[[], None] | None = None) -> None:
        started = False
        try:
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
            started = self._run(
                lambda _p, _c: session.set_pin(pin),
                lambda _r: self.home.set_notice("PIN criado."),
                title="Salvando o PIN…",
                cancellable=False,
                after=then,
            )
        finally:
            if not started and then is not None:
                then()

    def _new_master(self, then: Callable[[], None] | None = None) -> None:
        started = False
        try:
            session = self.session
            if session is None:
                return
            dlg = NewSecretDialog(
                self,
                master=True,
                title="Criar nova senha mestra",
                text="As pastas trancadas continuam abrindo normalmente com o PIN. Para que elas "
                "também abram com a senha nova em outro computador, abra e tranque cada uma de "
                "novo.",
            )
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            sm = dlg.take()
            started = self._run(
                lambda _p, _c: session.change_master(sm),
                lambda _r: self._refresh_with("Nova senha mestra criada."),
                title="Salvando a senha mestra…",
                cancellable=False,
                after=then,
            )
        finally:
            if not started and then is not None:
                then()

    # ------------------------------------------------------------------ cópia (T14)
    def _open_copy_tool(self) -> None:
        from owl_vault.ui.copy_window import CopyWindow  # noqa: PLC0415

        if self._copy_window is None:
            self._copy_window = CopyWindow()
        self._copy_window.show()
        self._copy_window.raise_()
        self._copy_window.activateWindow()

    def _close_copy_window(self) -> bool:
        """Fecha a Cópia criptografada junto com a janela principal (False = ela recusou, por
        estar trabalhando: aí a principal também continua aberta)."""
        w = self._copy_window
        if w is None:
            return True
        if w.isVisible() and not w.close():
            return False
        self._copy_window = None
        w.deleteLater()
        return True

    # ------------------------------------------------------------------ sair (T11)
    def closeEvent(self, event: QCloseEvent) -> None:
        if self._quitting:
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
                if self.runner.busy:
                    self.runner.cancel()
                    self._quit_after_job = True  # _after_job fecha (uma vez só)
                else:  # terminou enquanto a pergunta estava aberta: fluxo normal
                    QTimer.singleShot(0, self.close)
            event.ignore()
            return
        if self.mgr is None:
            n = self._visible_count
            if n and self.store.exists():
                choice = ask(
                    self,
                    "Sair do Owl Vault?",
                    (
                        "Há 1 pasta aberta e visível."
                        if n == 1
                        else f"Há {n} pastas abertas e visíveis."
                    )
                    + " Digite o PIN para trancar.",
                    [("Sair sem trancar", "quit"), ("Cancelar", "cancel")],
                    primary="cancel",
                )
                if choice != "quit":
                    event.ignore()
                    return
            self._accept_close(event)
            return
        folders = self.mgr.folders
        opened = [r for r in folders if r.state == ABERTA]
        attention = [r for r in folders if r.state in VISIVEIS and r.state != ABERTA]
        if not opened and not attention:
            self._accept_close(event)
            return
        lines = [r.name for r in opened] + [
            f"{r.name} — precisa de atenção; não dá para trancar automaticamente" for r in attention
        ]
        buttons = [("Trancar e sair", "lock")] if opened else []
        buttons += [("Sair sem trancar", "quit"), ("Cancelar", "cancel")]
        choice = ask(
            self,
            "Sair do Owl Vault?",
            "Estas pastas estão abertas e visíveis:",
            buttons,
            details=lines,
            details_open=True,
            primary="lock" if opened else "cancel",
        )
        if choice == "quit":
            self._accept_close(event)
            return
        event.ignore()
        if choice == "lock":
            self._quit_sequence = True
            self._lock_sequence(
                [r.id for r in opened],
                self._quit_now,
                on_error=self._quit_lock_failed,
                on_abort=self._end_quit_sequence,
            )

    def _accept_close(self, event: QCloseEvent) -> None:
        if not self._close_copy_window():
            event.ignore()
            return
        self._quit()
        event.accept()

    def _end_quit_sequence(self) -> None:
        self._quit_sequence = False

    def _quit_lock_failed(self, folder_id: str, exc: BaseException) -> bool:
        """Erro no "Trancar e sair": mostra o motivo; só sai com "Sair sem trancar"."""
        self._quit_sequence = False
        name = self._rec_name(folder_id)
        details: list[str] = []
        if isinstance(exc, PreflightError):
            items = exc.blockers or [str(exc)]
            text = f"{items[0]} Depois, clique em Tentar de novo."
            details = items[1:6] + ([f"e mais {len(items) - 6}"] if len(items) > 6 else [])
        elif isinstance(exc, CancelledError):
            text = "O trancamento parou num ponto seguro. A pasta continua aberta."
        else:
            text = str(exc) or type(exc).__name__
        again = ask(
            self,
            f"Não deu para trancar '{name}'",
            text,
            [("Tentar de novo", "retry"), ("Sair sem trancar", "quit")],
            details=details,
            primary="retry",
        )
        if again == "retry":
            QTimer.singleShot(0, self.close)
        elif again == "quit":
            QTimer.singleShot(0, self._quit_now)
        else:  # Esc/X no aviso: NÃO sai — volta ao app com as pastas como estão
            self._refresh()
            self.home.set_notice("As pastas continuam abertas. Tranque-as antes de sair.")
        return True

    def _quit(self) -> None:
        self._quitting = True
        self._quit_after_job = False
        self._quit_sequence = False
        if self.session is not None:
            self.session.close()
            self.session = None
        self.mgr = None
        self.home.clear()
        self.protect_page.clear()
        self.unlock_page.configure(master=False)
        self._show_page(self.unlock_page)

    def _quit_now(self) -> None:
        self._quit_sequence = False
        if not self._close_copy_window():
            self._refresh()
            self.home.set_notice("Feche a janela da Cópia criptografada para sair.")
            return
        self._quit()
        self.close()
