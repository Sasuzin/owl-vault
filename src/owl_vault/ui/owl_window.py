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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from PySide6.QtCore import QEvent, QObject, QPoint, Qt, QTimer, Slot
from PySide6.QtGui import QAction, QActionGroup, QCloseEvent, QColor, QGuiApplication, QShowEvent
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QGraphicsDropShadowEffect,
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
    ABERTURA_INCOMPLETA,
    ABRINDO,
    APAGANDO,
    COFRE_DIFERENTE,
    MANTIDO,
    RESTAURANDO,
    TRANCADA,
    TRANCANDO,
    VAULT_DIR,
    FolderView,
    LockerManager,
    LockOutcome,
    ProtectCheck,
    UnlockOutcome,
)
from owl_vault.application.profile import (
    NOTE_BACKUP_PENDING,
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
from owl_vault.ui.componentes import BotaoMais, Marca, transparente
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
    ISSUES_CONHECIDAS,
    VISIVEIS,
    HomePage,
    Pagina,
    ProfileProblemPage,
    SetupPage,
    UnlockPage,
    pode_trancar,
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
#: tamanho preferido da janela principal (encolhe para caber na área útil da tela)
LARGURA_PADRAO = 980
ALTURA_PADRAO = 760
#: o que a moldura do Windows (barra de título e bordas) soma ao tamanho do conteúdo, com
#: folga: a janela inteira, com a moldura, tem de caber na área útil (sem a barra de tarefas)
MOLDURA_LARGURA = 40
MOLDURA_ALTURA = 60

ErrorHandler = Callable[[BaseException], bool]


@dataclass
class _Job:
    dialog: ProgressDialog | None
    on_done: Callable[[Any], None]
    on_error: ErrorHandler | None
    after: Callable[[], None] | None
    #: (título, texto) mostrado se o app bloqueou durante o trabalho e ele deu certo — só
    #: para mudanças no perfil que a pessoa precisa saber (ex.: o PIN novo); nunca com nomes
    locked_note: tuple[str, str] | None = None


class _Segredo:
    """Senha ou PIN entregue UMA vez ao trabalho da thread.

    A função do trabalho guarda só esta caixa, não o texto: o ``JobRunner`` mantém o trabalho
    vivo depois do fim e, sem isto, a senha continuaria alcançável depois de bloquear. Ao ser
    tomado, o valor sai daqui."""

    __slots__ = ("_valor",)

    def __init__(self, valor: str) -> None:
        self._valor = valor

    def tomar(self) -> str:
        valor, self._valor = self._valor, ""
        return valor


@dataclass
class _Falha:
    """Uma pasta que ficou de fora de uma fila de trancamento, e por quê."""

    folder_id: str
    motivo: str
    detalhes: list[str] = field(default_factory=list)


@dataclass
class _Sequencia:
    """Pastas trancadas em fila ("Trancar agora" da faixa ou "Trancar e sair" do T11).

    Uma falha não para a fila: as outras pastas são trancadas e, no fim, um resumo diz quais
    ficaram de fora e por quê. Só o cancelamento pelo usuário (ou o bloqueio) para a fila.
    ``conhecidas``: pastas que o usuário viu na pergunta de saída (as que aparecerem depois
    fazem a pergunta voltar antes de sair)."""

    pendentes: list[str]
    sair: bool
    conhecidas: set[str] = field(default_factory=set)
    falhas: list[_Falha] = field(default_factory=list)
    trancadas: int = 0
    parou: bool = False  # o usuário cancelou o trancamento em andamento
    desistiu: bool = False  # o usuário respondeu "Cancelar" à pergunta do T7


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
        #: a Cópia criptografada foi bloqueada no meio de um trabalho (ainda está parando)
        self._copy_blocked = False
        #: pastas com "Trancar e esconder" pedido: escondidas quando o trancamento terminar,
        #: mesmo que termine depois de "Continuar trancando" (só ids, nunca nomes)
        self._hide_after: set[str] = set()
        self._effects_pending = False

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
        self._initial_size()

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

    def _initial_size(self) -> None:
        """Tamanho inicial que cabe na área útil da tela (sem a barra de tarefas), com a moldura.

        O mínimo é o que o layout precisa (o conteúdo de cada tela rola; o rodapé, com o botão
        principal, fica sempre à vista). Se nem o mínimo couber, ``show_initial`` maximiza."""
        minimo = self.minimumSizeHint()
        self.setMinimumSize(minimo)
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is None:
            self.resize(LARGURA_PADRAO, ALTURA_PADRAO)
            return
        area = screen.availableGeometry()
        w = max(minimo.width(), min(LARGURA_PADRAO, area.width() - MOLDURA_LARGURA))
        h = max(minimo.height(), min(ALTURA_PADRAO, area.height() - MOLDURA_ALTURA))
        self.resize(w, h)
        x = area.x() + max(0, (area.width() - w - MOLDURA_LARGURA) // 2)
        y = area.y() + max(0, (area.height() - h - MOLDURA_ALTURA) // 2)
        self.move(QPoint(x, y))

    def fits_screen(self) -> bool:
        """O tamanho mínimo (com a moldura) cabe na área útil da tela?"""
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is None:
            return True
        area = screen.availableGeometry()
        minimo = self.minimumSize()
        return (
            minimo.width() + MOLDURA_LARGURA <= area.width()
            and minimo.height() + MOLDURA_ALTURA <= area.height()
        )

    def show_initial(self) -> None:
        """Primeira exibição: normal se couber; maximizada numa tela menor que o mínimo."""
        if self.fits_screen():
            self.show()
        else:
            self.showMaximized()

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
        # a folha do app esconde o indicador dos menus (QMenu::indicator { width: 0 }): neste
        # submenu ele volta, para a marca mostrar qual tema está em uso
        theme.setStyleSheet("QMenu::indicator { width: 16px; height: 16px; }")
        group = QActionGroup(self)
        group.setExclusive(True)
        self._theme_actions: dict[str, QAction] = {}
        for label, key in (("Escuro", "dark"), ("Claro", "light")):
            act = QAction(label, self, checkable=True)
            act.triggered.connect(lambda _c=False, k=key: self._set_theme(k))
            group.addAction(act)
            theme.addAction(act)
            self._theme_actions[key] = act
        self.theme_menu = theme
        theme.aboutToShow.connect(self._sync_theme_menu)
        self._sync_theme_menu()
        menu.addAction("Sobre o Owl Vault", self._about)
        menu.aboutToShow.connect(self._update_menu)
        return menu

    def _update_menu(self) -> None:
        unlocked = self.session is not None
        for act in self._session_actions:
            act.setVisible(unlocked)

    @staticmethod
    def _current_theme() -> str:
        app = QApplication.instance()
        tema = app.property("owlTheme") if app is not None else None
        return tema if tema in ("dark", "light") else saved_theme()

    def _sync_theme_menu(self) -> None:
        """☰ > Tema: a marca fica no tema em uso."""
        atual = self._current_theme()
        for key, act in self._theme_actions.items():
            act.setChecked(key == atual)

    def _set_theme(self, key: str) -> None:
        save_theme(key)
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_theme(app, key)
        self._repaint_effects()
        self._sync_theme_menu()

    def _repaint_effects(self) -> None:
        """Cores pintadas fora do QSS (sombra dos cartões, inclusive nos diálogos abertos)
        seguem o tema atual (contrato C6)."""
        self._effects_pending = False
        cor = QColor(current_tokens()["sombra"])
        janelas: list[QWidget] = [self]
        if self._copy_window is not None:  # janela sem pai: findChildren daqui não a alcança
            janelas.append(self._copy_window)
        for janela in janelas:
            for w in [janela, *janela.findChildren(QWidget)]:
                efeito = w.graphicsEffect()
                if isinstance(efeito, QGraphicsDropShadowEffect) and efeito.color() != cor:
                    efeito.setColor(cor)

    def changeEvent(self, event: QEvent) -> None:
        super().changeEvent(event)
        if event.type() in (QEvent.Type.PaletteChange, QEvent.Type.StyleChange) and not getattr(
            self, "_effects_pending", True
        ):
            # apply_theme troca a paleta e a folha do app: repinta uma vez, depois da troca
            self._effects_pending = True
            QTimer.singleShot(0, self, self._repaint_effects)
            QTimer.singleShot(0, self, self._sync_theme_menu)

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
        new_master_lost = self._wants_new_master and not pin_ok
        if new_master_lost:
            # o PIN foi desativado enquanto confirmava "Criar nova senha mestra": esse caminho
            # acabou (sem o PIN, só a senha mestra atual abre o app)
            self._wants_new_master = False
        if self._wants_new_master:
            self.unlock_page.configure(
                master=False,
                title="Digite seu PIN",
                text="Para criar uma nova senha mestra, confirme com o seu PIN.",
                allow_switch=False,
                error=error,
            )
        elif new_master_lost:
            self.unlock_page.configure(
                master=True,
                title="Abrir pasta protegida" if opening else "Digite sua senha mestra",
                text="O PIN foi desativado. Agora só a senha mestra abre o Owl Vault; sem ela, "
                "não dá para criar uma nova.",
                allow_switch=False,
                error=error,
                button=button,
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
        sm, codigo = _Segredo(master), _Segredo(pin)

        def job(_p: QtProgress, _c: CancelToken) -> ProfileSession:
            return self.store.create(sm.tomar(), codigo.tomar())

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
        caixa = _Segredo(secret)

        def job(_p: QtProgress, _c: CancelToken) -> ProfileSession:
            if master:
                return self.store.unlock_with_master(caixa.tomar())
            return self.store.unlock_with_pin(caixa.tomar())

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
        """Bloqueia (☰ > Bloquear agora, 5 min sem uso, Win+L, suspensão).

        A Cópia criptografada é bloqueada JÁ, mesmo com um trabalho desta janela rodando (a
        senha digitada lá não espera). O resto espera o trabalho em andamento terminar."""
        self._block_copy_window()
        if self.runner.busy:
            self._lock_after_job = True
            return
        self._lock_after_job = False
        self._quit_sequence = False
        self._after_unlock_pending = False
        self._wants_new_master = False
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
        self._discard_dialogs()
        if self.store.exists():
            self._show_unlock()
        else:
            self._update_menu()

    def _discard_dialogs(self) -> None:
        """Destrói os diálogos já fechados (progresso, perguntas, PIN): eles guardam nomes de
        pastas e de arquivos e, sem isto, se acumulariam a cada operação."""
        for dlg in self.findChildren(QDialog):
            if not dlg.isVisible():
                dlg.deleteLater()

    @staticmethod
    def _copy_busy(w: QWidget) -> bool:
        runner = getattr(w, "runner", None)
        return bool(getattr(runner, "busy", False))

    def _block_copy_window(self) -> None:
        """Contrato C1: a Cópia criptografada limpa as senhas e se fecha (se estiver trabalhando,
        pede o cancelamento e se fecha quando parar). A referência fica até ela fechar."""
        w = self._copy_window
        if w is None:
            return
        bloquear = getattr(w, "bloquear", None)
        if callable(bloquear):
            bloquear()
        else:
            w.close()
        if self._copy_busy(w):
            self._copy_blocked = True
        else:
            self._copy_window = None
            self._copy_blocked = False
            w.deleteLater()

    @staticmethod
    def _pergunta_na_tela() -> bool:
        """Há uma pergunta (diálogo modal que não é a tela de progresso) esperando a pessoa."""
        modal = QApplication.activeModalWidget()
        return modal is not None and not isinstance(modal, ProgressDialog)

    def _idle_check(self) -> None:
        if self.session is None or self.runner.busy:
            return
        if self._quit_sequence and not self._pergunta_na_tela():
            # "Trancar e sair" entre um trancamento e o próximo: não trava no meio da fila. Com
            # uma pergunta na tela (o T7 ou o resumo do fim), ninguém está mexendo: trava sim
            return
        copia = self._copy_window
        if copia is not None and not self._copy_blocked and self._copy_busy(copia):
            # a Cópia criptografada trabalhando conta como uso (como um trabalho desta janela):
            # o travamento automático não a interrompe no meio
            self._watcher.last = time.monotonic()
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
        if self._quit_sequence:
            # "Trancar e sair" em andamento: abrir uma pasta agora a deixaria aberta ao sair
            inform(
                self,
                "Aguarde",
                "O Owl Vault está trancando as pastas para fechar. Use o atalho de novo depois.",
            )
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
        if dlg.exec() != QDialog.DialogCode.Accepted or self.session is None:
            return
        caixa, master = _Segredo(dlg.take()), dlg.master

        def job(_p: QtProgress, _c: CancelToken) -> ProfileSession:
            if master:
                return self.store.unlock_with_master(caixa.tomar())
            return self.store.unlock_with_pin(caixa.tomar())

        def done(new: object) -> None:
            assert isinstance(new, ProfileSession)
            self._replace_session(new)
            then()

        def failed(exc: BaseException) -> bool:
            if self.session is None:
                return True  # bloqueou durante a conferência: nada de pedir o PIN de novo
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
        locked_note: tuple[str, str] | None = None,
    ) -> bool:
        """Inicia ``job`` na thread. Recusa (devolve False, sem tocar no trabalho em curso) se
        já houver outro rodando. ``after`` roda depois de ``on_done``/``on_error``; ``status``
        vai para o rodapé da tela atual (None: a própria tela já mostra o que está fazendo).
        Se o bloqueio for pedido durante o trabalho, o app bloqueia ANTES de ``on_done`` /
        ``on_error`` (ver ``_lock_if_requested``); ``locked_note`` é o aviso, sem nomes, que
        aparece então se o trabalho deu certo."""
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
        self._job = _Job(dlg, on_done, on_error, after, locked_note)
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
            job.dialog.deleteLater()  # o título dela tem o nome da pasta: não fica oculta
        return job

    @Slot(object)
    def _job_done(self, result: object) -> None:
        job = self._take_job()
        try:
            bloqueou = self._lock_if_requested(result)
            if job is not None:
                if bloqueou and isinstance(result, ProfileSession):
                    # o bloqueio pedido vale mais que a sessão nova (desbloqueio, PIN
                    # conferido, PIN trocado): ela é descartada, nada fica destravado
                    if result is not self.session:
                        result.close()
                    if job.locked_note is not None:
                        inform(self, *job.locked_note)
                else:
                    job.on_done(result)  # cada fim confere self.session antes de mostrar algo
                if job.after is not None:
                    job.after()
        finally:
            self._after_job()

    @Slot(object)
    def _job_failed(self, exc: object) -> None:
        job = self._take_job()
        try:
            assert isinstance(exc, BaseException)
            bloqueou = self._lock_if_requested()
            handled = job is not None and job.on_error is not None and job.on_error(exc)
            if not handled and not bloqueou:
                # bloqueado: o erro (que pode citar pastas e arquivos) não vai para a tela
                # travada; o estado da pasta aparece na lista depois de desbloquear
                self._default_error(exc)
            if job is not None and job.after is not None:
                job.after()
        finally:
            self._after_job()

    def _lock_if_requested(self, result: object = None) -> bool:
        """Bloqueio pedido durante o trabalho (Win+L, suspensão): bloqueia ANTES de mostrar o
        resultado, que poderia trazer nomes e caminhos ou abrir o Explorer numa pasta legível
        com o app ainda destravado. Antes, faz o que o trabalho prometeu e não mostra nada
        ("Trancar e esconder"). Devolve True se bloqueou agora."""
        if not self._lock_after_job or self.runner.busy:
            return False
        if isinstance(result, LockOutcome):
            self._hide_after_lock(result)
        self.lock_now()
        return True

    def _after_job(self) -> None:
        if self._quit_after_job:
            if self.runner.busy:  # on_done encadeou outro trabalho: pede para parar também
                self.runner.cancel()
                return
            self._quit_after_job = False
            if self._lock_after_job:
                # Win+L/suspensão depois de "Parar e fechar": bloqueia antes da pergunta de
                # sair, que então só mostra a contagem e não volta ao app destravado
                self.lock_now()
            self.close()  # caminho normal (T11 se ainda houver pasta aberta)
            return
        if self.runner.busy:
            return
        self._discard_dialogs()
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
            if self.session is not None:  # bloqueado: a tela Proteger já foi limpa
                page.show_check(check)

        def failed(exc: BaseException) -> bool:
            if self.session is None:
                return True  # bloqueado: os motivos (com nomes) não voltam à tela limpa
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
            if self.session is None:
                return  # bloqueado: a tela Proteger já foi limpa (nada de nome nela)
            page.finish(out)
            self._lock_done(out, resolve=False)

        def failed(exc: BaseException) -> bool:
            if self.session is not None:
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
        seq: _Sequencia | None = None,
    ) -> bool:
        """Tranca uma pasta aberta. Devolve False se nada foi iniciado (o usuário respondeu
        "Cancelar" à pergunta do T7, ou outro trabalho está rodando). ``seq``: faz parte de
        uma fila — o fim (ou a falha) segue para a próxima pasta da fila."""
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
            # Enter nunca escolhe a ação que apaga: o padrão é Cancelar (botão de perigo no "go")
            choice = ask(
                self,
                f"Trancar '{name}'?",
                f"Desde que você abriu '{name}', {n} arquivo(s) foram apagados ou movidos: "
                f"{short_list(missing)}. Se você trancar, eles não ficarão na pasta trancada e "
                "a cópia protegida deles será apagada para sempre.",
                [("Trancar mesmo assim", "go"), ("Cancelar", "cancel")],
                details=missing if n > 5 else (),
                primary="cancel",
                perigo="go",
            )
            if choice != "go" or self.mgr is None:
                return False
        if hide_after:
            self._hide_after.add(folder_id)

        def job(p: QtProgress, c: CancelToken) -> LockOutcome:
            return mgr.lock(folder_id, p, c, accept_missing=missing)

        def done(out: object) -> None:
            assert isinstance(out, LockOutcome)
            self._lock_done(out, resolve=seq is None)
            if seq is not None:
                if out.complete:
                    seq.trancadas += 1
                else:
                    seq.falhas.append(self._incomplete_failure(out))
                QTimer.singleShot(0, lambda: self._sequence_next(seq))

        def failed(exc: BaseException) -> bool:
            if seq is None:
                return False  # _default_error mostra o erro
            seq.falhas.append(self._lock_failure(folder_id, exc))
            if isinstance(exc, CancelledError):
                seq.parou = True  # o usuário pediu para parar: a fila acaba aqui
            self._refresh()
            QTimer.singleShot(0, lambda: self._sequence_next(seq))
            return True

        return self._run(
            job,
            done,
            on_error=failed,
            title=f"Trancando '{name}'",
            mode="lock",
            note="Não use esta pasta até terminar.",
        )

    def _hide_after_lock(self, out: LockOutcome) -> str | None:
        """Esconde a pasta que acabou de ser trancada, se foi pedido "Trancar e esconder".
        Devolve o motivo, se não deu para esconder (None: escondeu, ou não havia pedido)."""
        fid = out.record.id
        if not out.complete or fid not in self._hide_after or self.mgr is None:
            return None
        self._hide_after.discard(fid)
        try:
            self.mgr.hide(fid)
        except (OwlVaultError, OSError) as exc:
            return str(exc) or type(exc).__name__
        return None

    def _lock_done(self, out: object, *, resolve: bool = True) -> None:
        assert isinstance(out, LockOutcome)
        if self.mgr is None or self.session is None:
            return  # bloqueou: nada de nome de pasta na tela travada (o esconder já foi feito)
        fid = out.record.id
        name = out.record.name
        hide_problem = self._hide_after_lock(out)
        self._refresh()
        if out.complete:
            if hide_problem is not None:
                msg = f"'{name}' está trancada, mas não foi possível escondê-la: {hide_problem}"
            else:
                msg = f"'{name}' está trancada."
            if out.removable:
                msg += " Use 'Remover hardware com segurança' antes de tirar a unidade."
            if out.kept_previous:
                msg += " Uma versão anterior com arquivos que não estão na pasta foi mantida."
            self.home.set_notice(msg)
        elif resolve:
            QTimer.singleShot(0, lambda: self._resolve(fid))

    # ------------------------------------------------------------------ filas de trancamento
    def _lock_all(self) -> None:
        """Faixa "Trancar agora": tranca todas as pastas abertas que podem ser trancadas; as
        visíveis que não podem (sumiram, unidade fora, abrindo, restaurando, trancamento
        interrompido) entram no resumo do fim, como no "Trancar e sair"."""
        if self.mgr is None or self.runner.busy:
            return
        seq = _Sequencia([], sair=False)
        for v in self._views():
            if pode_trancar(v):
                seq.pendentes.append(v.record.id)
            elif v.record.state in VISIVEIS:
                seq.falhas.append(_Falha(v.record.id, v.attention or v.label))
        self._sequence_next(seq)

    def _views(self) -> list[FolderView]:
        if self.mgr is None:
            return []
        try:
            return self.mgr.views()
        except (OwlVaultError, OSError):
            return []

    def _sequence_next(self, seq: _Sequencia) -> None:
        if self.mgr is None or self.session is None:  # bloqueou no meio: a fila acaba aqui
            self._quit_sequence = False
            return
        while seq.pendentes and not seq.parou:
            fid = seq.pendentes.pop(0)
            rec = self.session.index.folder(fid)
            if rec is None:
                continue
            try:
                view = self.mgr.view(rec)
            except (OwlVaultError, OSError) as exc:
                seq.falhas.append(_Falha(fid, str(exc)))
                continue
            if not pode_trancar(view):
                if rec.state in VISIVEIS:  # mudou desde a pergunta: fica no resumo
                    seq.falhas.append(_Falha(fid, view.attention or view.label))
                continue
            if self._lock_folder(fid, seq=seq):
                return  # o fim deste trancamento chama _sequence_next de novo
            if self.runner.busy:
                seq.falhas.append(_Falha(fid, BUSY_TEXT))
            else:
                seq.desistiu = True  # "Cancelar" no T7: a fila para sem trancar o resto
            seq.parou = True
        if self.mgr is None or self.session is None:
            # bloqueou com a pergunta do T7 na tela: nenhum resumo (com nomes) na tela travada
            self._quit_sequence = False
            return
        if seq.parou and not seq.desistiu:
            for fid in seq.pendentes:
                seq.falhas.append(_Falha(fid, "Não chegou a ser trancada: o trancamento parou."))
            seq.pendentes.clear()
        if seq.sair:
            self._quit_sequence_end(seq)
        else:
            self._lock_all_end(seq)

    def _lock_failure(self, folder_id: str, exc: BaseException) -> _Falha:
        """Motivo verdadeiro de uma pasta não ter sido trancada (pelo estado de agora)."""
        rec = self.session.index.folder(folder_id) if self.session is not None else None
        state = rec.state if rec is not None else ""
        if isinstance(exc, CancelledError):
            if state == APAGANDO:
                return _Falha(
                    folder_id,
                    "O trancamento parou antes do fim. Os arquivos já estão guardados, mas parte "
                    "das cópias legíveis ainda está na pasta. Na lista, use 'Resolver…' para "
                    "continuar trancando ou desfazer.",
                )
            if state == ABERTA:
                return _Falha(
                    folder_id, "O trancamento foi cancelado. A pasta continua aberta, como antes."
                )
            return _Falha(
                folder_id, "O trancamento parou num ponto seguro. Na lista, use 'Resolver…'."
            )
        if isinstance(exc, PreflightError):
            items = exc.blockers or [str(exc)]
            extra = items[1:6] + ([f"e mais {len(items) - 6}"] if len(items) > 6 else [])
            return _Falha(folder_id, items[0], extra)
        return _Falha(folder_id, str(exc) or type(exc).__name__)

    @staticmethod
    def _incomplete_failure(out: LockOutcome) -> _Falha:
        n = len(out.pending)
        motivo = out.record.attention or (
            f"O trancamento parou antes do fim: {n} item(ns) ainda estão na pasta. Na lista, "
            "use 'Resolver…' para ver o que fazer."
        )
        return _Falha(out.record.id, motivo, list(out.pending[:5]))

    def _failure_summary(self, seq: _Sequencia) -> tuple[str, str, list[str]]:
        """(título, texto, detalhes) do resumo das pastas que ficaram de fora."""
        if len(seq.falhas) == 1:
            f = seq.falhas[0]
            return f"Não deu para trancar '{self._rec_name(f.folder_id)}'", f.motivo, f.detalhes
        linhas = [f"{self._rec_name(f.folder_id)}: {f.motivo}" for f in seq.falhas]
        return (
            f"{len(seq.falhas)} pastas não foram trancadas",
            "Estas pastas não foram trancadas:",
            linhas,
        )

    def _lock_all_end(self, seq: _Sequencia) -> None:
        if self.mgr is None or self.session is None:
            return  # bloqueado: nada de resumo com nomes de pastas na tela travada
        self._refresh()
        if seq.falhas:
            title, text, details = self._failure_summary(seq)
            if seq.trancadas:
                text = f"{seq.trancadas} pasta(s) foram trancadas. " + text
            ask(self, title, text, [("Fechar", "close")], details=details, details_open=True)
        elif seq.trancadas > 1:
            self.home.set_notice(f"{seq.trancadas} pastas foram trancadas.")

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
            "trancando",
        ) or (view.issue not in ISSUES_CONHECIDAS and view.base_action != "abrir"):
            self._resolve(folder_id)  # abrir não resolveria: o Resolver explica e dá a saída
            return
        mgr = self.mgr

        def job(p: QtProgress, c: CancelToken) -> UnlockOutcome:
            return mgr.unlock(folder_id, p, c)

        def done(out: object) -> None:
            assert isinstance(out, UnlockOutcome)
            if self.session is None:
                return  # bloqueou durante a abertura: o Explorer não abre a pasta legível
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
            self._resolve_deleting(folder_id, view)
        elif issue == "abertura_incompleta":
            n = len(rec.pending)
            choice = ask(
                self,
                f"'{name}' não abriu por completo",
                view.attention,
                [
                    ("Tentar de novo", "retry"),
                    ("Continuar sem eles", "skip"),
                    ("Tirar da lista", "forget"),
                ],
                details=rec.pending,
                details_open=0 < n <= 5,
            )
            if choice == "retry":
                self._open_folder(folder_id)
            elif choice == "skip":
                try:
                    mgr.accept_incomplete_unlock(folder_id)
                except (OwlVaultError, OSError) as exc:
                    inform(self, "Não foi possível concluir", str(exc))
                    self._refresh()
                    return
                self._refresh()
                open_in_explorer(rec.path)
            elif choice == "forget":
                self._forget(folder_id)
        elif issue == "abrindo":
            choice = ask(
                self,
                f"Abertura de '{name}' interrompida",
                view.attention,
                [("Continuar abrindo", "go"), ("Tirar da lista", "forget"), ("Fechar", "close")],
            )
            if choice == "go":
                self._open_folder(folder_id)
            elif choice == "forget":
                self._forget(folder_id)
        elif issue == "trancando":
            self._resolve_locking(folder_id)
        elif issue == "itens_extras":
            choice = ask(
                self,
                f"Há itens novos em '{name}'",
                view.attention,
                [
                    ("Mostrar no Explorer", "show"),
                    ("Tentar de novo", "retry"),
                    ("Tirar da lista", "forget"),
                ],
            )
            if choice == "show":
                open_in_explorer(rec.path)
            if choice == "forget":
                self._forget(folder_id)
            else:
                self._refresh()
        elif issue == "indisponivel":
            text = view.attention or view.label
            if "Procurar" not in text:
                text += (
                    " Conecte a unidade. Se ela voltou com outra letra, clique em 'Procurar a "
                    "pasta…' e escolha a pasta no lugar novo."
                )
            choice = ask(
                self,
                f"'{name}' está indisponível",
                text,
                [("Procurar a pasta…", "find"), ("Tirar da lista", "forget"), ("Fechar", "close")],
                primary="close",
            )
            if choice == "find":
                self._relocate(folder_id)
            elif choice == "forget":
                self._forget(folder_id)
            else:
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
                    ("Tirar da lista", "forget"),
                    ("Fechar", "close"),
                ],
                details=files,
                primary="restore",
                perigo="delete",
            )
            if choice == "restore":
                self._restore_kept(folder_id)
            elif choice == "forget":
                self._forget(folder_id)
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
            choice = ask(
                self,
                f"Atualizar '{name}'",
                view.attention,
                [("Abrir", "open"), ("Tirar da lista", "forget"), ("Fechar", "close")],
            )
            if choice == "open":
                self._open_folder(folder_id)
            elif choice == "forget":
                self._forget(folder_id)
        elif issue or view.action == "resolver":
            self._resolve_generic(folder_id, view)
        else:
            self._refresh()

    def _resolve_deleting(self, folder_id: str, view: FolderView) -> None:
        """Trancamento parado na etapa 4 (apagando). O texto é o do gerente (``attention``),
        específico do problema: arquivo em uso ≠ item novo colocado durante o trancamento (que
        NÃO está guardado) ≠ cofre da área temporária que sumiu. A lista vai nos detalhes."""
        if self.mgr is None:
            return
        mgr = self.mgr
        rec = view.record
        name = rec.name
        pending = list(rec.pending)
        text = view.attention
        novos = [p for p in pending if "item novo" in p]
        if novos and "durante o trancamento" not in text:
            # só se o gerente ainda não disse (o texto dele já cita os itens novos)
            text += (
                f" Atenção: {len(novos)} item(ns) foram colocados na pasta durante o trancamento "
                "e NÃO estão guardados. Mova-os para outro lugar antes de continuar."
            )
        buttons = [("Continuar trancando", "cont"), ("Desfazer (deixar a pasta aberta)", "undo")]
        if pending:
            buttons.append(("Mostrar no Explorer", "show"))
        buttons += [("Tirar da lista", "forget"), ("Fechar", "close")]
        choice = ask(
            self,
            f"Trancamento de '{name}' interrompido",
            text,
            buttons,
            details=pending,
            details_open=bool(pending),
        )
        if choice == "cont":
            self._run(
                lambda p, c: mgr.continue_lock(folder_id, p, c),
                self._lock_done,
                title=f"Trancando '{name}'",
                mode="lock",
            )
        elif choice == "undo":
            self._hide_after.discard(folder_id)
            self._run(
                lambda p, c: mgr.undo_lock(folder_id, p, c),
                lambda out: self._undo_done(out, name),
                title=f"Devolvendo os arquivos de '{name}'",
                mode="unlock",
            )
        elif choice == "show":
            open_in_explorer(rec.path)
        elif choice == "forget":
            self._forget(folder_id)

    def _resolve_locking(self, folder_id: str) -> None:
        """Trancamento interrompido sem confirmação ('trancando'): o Owl Vault confere a pasta e
        mostra o resultado na lista. Se ela continuar presa (a conferência não decide), mostra
        o problema e as saídas — nunca repete o erro sem oferecer nada."""
        if self.mgr is None or self.session is None:
            return
        mgr = self.mgr
        try:
            notes = mgr.reconcile_on_start()
        except (OwlVaultError, OSError) as exc:
            notes = [str(exc)]
        self._refresh()
        if notes:
            self.home.set_notice(" ".join(notes))
        rec = self.session.index.folder(folder_id) if self.session is not None else None
        if rec is None or self.mgr is None or rec.state != TRANCANDO:
            return
        view = self.mgr.view(rec)
        name = rec.name
        choice = ask(
            self,
            f"Trancamento de '{name}' interrompido",
            view.attention or " ".join(notes),
            [
                ("Deixar a pasta aberta", "open"),
                ("Procurar a pasta…", "find"),
                ("Tirar da lista", "forget"),
                ("Fechar", "close"),
            ],
            primary="close",
        )
        if choice == "open":
            self._leave_open(folder_id, name)
        elif choice == "find":
            self._relocate(folder_id)
        elif choice == "forget":
            self._forget(folder_id)

    def _leave_open(self, folder_id: str, name: str) -> None:
        """'Deixar a pasta aberta' (trancamento interrompido que a conferência não decide): a
        pasta volta a ficar aberta e a cópia em dúvida é guardada como versão anterior. Nada é
        apagado. Se a conferência agora decidir que a exclusão já tinha começado, mostra o
        Resolver da etapa 4 (Desfazer / Continuar trancando)."""
        if self.mgr is None:
            return
        try:
            state = self.mgr.leave_open(folder_id)
        except (OwlVaultError, OSError) as exc:
            inform(self, "Não foi possível deixar a pasta aberta", str(exc))
            self._refresh()
            return
        self._hide_after.discard(folder_id)
        self._refresh()
        if state == APAGANDO:
            QTimer.singleShot(0, lambda: self._resolve(folder_id))
        elif state == ABERTA:
            self.home.set_notice(f"'{name}' continua aberta.")

    def _resolve_generic(self, folder_id: str, view: FolderView) -> None:
        """Problema que esta janela não conhece (contrato C4): mostra o texto do gerente e as
        saídas que valem em qualquer estado. Nenhuma linha fica sem saída."""
        rec = view.record
        text = view.attention or (
            "Esta pasta precisa de atenção. Se ela mudou de lugar, use 'Procurar a pasta…'."
        )
        buttons: list[tuple[str, str]] = []
        if view.base_action in ("abrir", "trancar"):
            buttons.append(("Abrir" if view.base_action == "abrir" else "Trancar", "base"))
        buttons += [
            ("Procurar a pasta…", "find"),
            ("Tirar da lista", "forget"),
            ("Cancelar", "cancel"),
        ]
        choice = ask(self, f"'{rec.name}' precisa de atenção", text, buttons, primary="cancel")
        if choice == "base":
            if view.base_action == "abrir":
                self._open_folder(folder_id)
            else:
                self._lock_folder(folder_id)
        elif choice == "find":
            self._relocate(folder_id)
        elif choice == "forget":
            self._forget(folder_id)
        else:
            self._refresh()

    def _undo_done(self, out: object, name: str) -> None:
        """Fim do 'Desfazer': mostra o que não voltou (falhas) e os conflitos em caminhos que
        o Owl Vault tinha apagado (a versão guardada deles foi MANTIDA)."""
        assert isinstance(out, UnlockOutcome)
        if self.session is None:
            return  # bloqueou durante o Desfazer: nenhum nome na tela travada
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
        buttons += [("Tirar da lista", "forget"), ("Fechar", "close")]
        choice = ask(self, f"Versão anterior de '{name}'", text, buttons)
        if choice == "restore":
            self._restore_kept(folder_id)
        elif choice == "forget":
            self._forget(folder_id)
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
        if not parent or self.mgr is not mgr or self.session is None:
            return  # desistiu, ou o app bloqueou com o seletor aberto: nada começa

        def done(reports: object) -> None:
            assert isinstance(reports, list)
            if self.session is None:
                return  # bloqueou durante o trabalho: nem aviso com caminhos nem Explorer
            lines: list[str] = []
            failures: list[str] = []
            for r in reports:
                assert isinstance(r, RestoreReport)
                lines.append(f"{winfs.strip_extended(r.destination)}: {r.restored} arquivo(s)")
                failures += r.failed
                failures += [f"{c}: já havia outro item com o mesmo nome" for c in r.conflicts]
            self._refresh()
            if failures:
                ok = sum(r.restored for r in reports if isinstance(r, RestoreReport))
                text = f"{len(failures)} arquivo(s) não puderam ser recuperados (lista abaixo)."
                if ok:
                    dests = "; ".join(
                        winfs.strip_extended(r.destination)
                        for r in reports
                        if isinstance(r, RestoreReport) and r.restored
                    )
                    text += f" Os outros {ok} arquivo(s) estão em: {dests}."
                else:
                    text += " Nenhum arquivo foi recuperado."
                inform(self, "Nem todos os arquivos foram recuperados", text, failures)
            else:
                inform(
                    self, "Versão anterior recuperada", "Os arquivos foram recuperados em:", lines
                )
            if self.session is None:
                return  # bloqueou com o aviso na tela: nada de abrir pasta legível agora
            for r in reports:
                if r.restored:
                    open_in_explorer(r.destination)

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
        """Texto da confirmação de "Tirar da lista" (contrato C2): o do gerente, verdadeiro
        para o estado atual (onde ficam os arquivos legíveis e as cópias fora da pasta, que
        'Recuperar' não acha). "Use ☰ > Recuperar" só quando ele não avisa nada (pasta
        trancada com tudo dentro dela)."""
        rec = self.session.index.folder(folder_id) if self.session is not None else None
        if rec is None:
            return "Nada será apagado."
        warning = ""
        if self.mgr is not None:
            try:
                warning = self.mgr.forget_warning(folder_id).strip()
            except (OwlVaultError, OSError):
                warning = ""
        if not warning:
            if rec.state == TRANCADA:
                return (
                    "Nada será apagado. Para voltar a usar a pasta, use ☰ > Recuperar uma pasta "
                    "protegida."
                )
            warning = self._forget_fallback(rec.state, rec.id, rec.path, rec.vaults)
        text = (
            warning if warning.startswith("Nada será apagado") else f"Nada será apagado. {warning}"
        )
        if rec.state == ABERTA and "Proteger uma pasta" not in text:
            text += " Para trancá-la de novo depois, use '+ Proteger uma pasta…'."
        return text

    @staticmethod
    def _forget_fallback(state: str, folder_id: str, path: str, vaults: list[Any]) -> str:
        """Só se o gerente não disser nada para um estado que não é 'trancada': nunca afirma
        que os arquivos legíveis estão na pasta quando parte deles pode estar só na cópia."""
        where = winfs.strip_extended(winfs.parent_of(path))
        oculta = f"na pasta oculta '.owlvault-{folder_id}', em {where}"
        if state == ABERTA:
            text = f"Os arquivos legíveis continuam na pasta. A cópia criptografada fica {oculta}."
        elif state == APAGANDO:
            text = (
                "O trancamento não terminou: parte das cópias legíveis já foi apagada, e esses "
                f"arquivos só existem na cópia criptografada que fica {oculta}."
            )
        elif state in (ABRINDO, RESTAURANDO):
            text = (
                "A abertura não terminou: todos os arquivos, ou parte deles, só existem na cópia "
                f"criptografada que fica {oculta}."
            )
        elif state == ABERTURA_INCOMPLETA:
            text = (
                "Parte dos arquivos não voltou para a pasta e só existe na cópia criptografada "
                f"que fica {oculta}."
            )
        elif state == TRANCANDO:
            text = (
                "O trancamento não terminou: os arquivos legíveis continuam na pasta, e pode "
                f"haver uma cópia criptografada {oculta}."
            )
        else:
            text = f"Pode haver arquivos na pasta e numa cópia criptografada {oculta}."
        if any(getattr(v, "role", "") == MANTIDO for v in vaults):
            text += " Os arquivos da versão anterior mantida só existem nessa cópia oculta."
        return (
            text + " Depois de tirar da lista, 'Recuperar uma pasta protegida' NÃO encontra essa "
            "cópia. Prefira 'Procurar a pasta…' ou resolver a pasta antes."
        )

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
            != "go"
            or self.mgr is None
        ):
            return
        try:
            self.mgr.forget(folder_id)
        except (OwlVaultError, OSError) as exc:
            inform(self, "Não foi possível tirar da lista", str(exc))
            self._refresh()
            return
        self._hide_after.discard(folder_id)
        self._refresh()
        self.home.set_notice(f"'{name}' saiu da lista. Nada foi apagado.")

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
        view = mgr.view(rec)
        if view.issue == COFRE_DIFERENTE:
            # outro cofre no lugar (ex.: backup antigo copiado por cima): conferir este diria
            # "tudo certo" sobre dados que não são os desta pasta
            inform(
                self,
                "Os dados não são os registrados",
                f"{view.attention} Nada foi verificado nem alterado.",
            )
            self._refresh()
            return

        def job(p: QtProgress, c: CancelToken) -> VerifyReport:
            return verify_vault(
                vault_dir, mgr.keys_for_vault(vault_dir), policy=policy, progress=p, cancel=c
            )

        def done(report: object) -> None:
            assert isinstance(report, VerifyReport)
            if self.session is None:
                return  # bloqueou durante a verificação: o resultado (com o nome) não aparece
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
                if self.session is None:
                    return  # bloqueou: a proteção não é removida sem a pessoa na frente
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
        if dlg.exec() != QDialog.DialogCode.Accepted or self.mgr is not mgr:
            return False
        caixa = _Segredo(dlg.take())

        def job(_p: QtProgress, _c: CancelToken) -> tuple[list[str], list[str]]:
            ok: list[str] = []
            bad: list[str] = []
            secret = caixa.tomar()
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
            if self.session is None:
                return  # bloqueou durante a recuperação: as pastas aparecem na lista depois
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
        if dlg.exec() != QDialog.DialogCode.Accepted or self.session is None:
            return
        current, new, master = dlg.take()
        atual, novo = _Segredo(current), _Segredo(new)

        def job(_p: QtProgress, _c: CancelToken) -> ProfileSession:
            # os dois saem das caixas já no começo: um PIN atual errado não deixa o novo nelas
            cur, nov = atual.tomar(), novo.tomar()
            s = self.store.unlock_with_master(cur) if master else self.store.unlock_with_pin(cur)
            s.set_pin(nov)
            return s

        def done(s: object) -> None:
            assert isinstance(s, ProfileSession)
            self._replace_session(s)
            self.home.set_notice(self._profile_saved("PIN alterado.", s))

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

        self._run(
            job,
            done,
            on_error=failed,
            title="Salvando o PIN…",
            cancellable=False,
            locked_note=("PIN alterado", "Para entrar, use o PIN novo."),
        )

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
            if dlg.exec() != QDialog.DialogCode.Accepted or self.session is not session:
                return
            pin = _Segredo(dlg.take())
            started = self._run(
                lambda _p, _c: session.set_pin(pin.tomar()),
                lambda _r: self.home.set_notice(self._profile_saved("PIN criado.", session)),
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
            if dlg.exec() != QDialog.DialogCode.Accepted or self.session is not session:
                return
            sm = _Segredo(dlg.take())
            started = self._run(
                lambda _p, _c: session.change_master(sm.tomar()),
                lambda _r: self._refresh_with(
                    self._profile_saved("Nova senha mestra criada.", session)
                ),
                title="Salvando a senha mestra…",
                cancellable=False,
                after=then,
            )
        finally:
            if not started and then is not None:
                then()

    @staticmethod
    def _profile_saved(text: str, session: ProfileSession | None) -> str:
        """Aviso de uma mudança no perfil que valeu. Se a cópia de segurança do perfil não pôde
        ser trocada junto (``NOTE_BACKUP_PENDING``), diz isso também."""
        if session is not None and NOTE_BACKUP_PENDING in session.notes:
            return f"{text} {NOTE_BACKUP_PENDING}"
        return text

    # ------------------------------------------------------------------ cópia (T14)
    def _open_copy_tool(self) -> None:
        from owl_vault.ui.copy_window import CopyWindow  # noqa: PLC0415

        w = self._copy_window
        if w is not None and self._copy_blocked:
            if self._copy_busy(w):  # bloqueada no meio de um trabalho: ainda está parando
                inform(
                    self,
                    "Aguarde",
                    "A Cópia criptografada está parando num ponto seguro. Tente de novo em "
                    "alguns segundos.",
                )
                return
            # parou e se fechou: começa do zero (nada do que foi digitado antes do bloqueio)
            self._copy_window = None
            self._copy_blocked = False
            w.deleteLater()
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
        if self._copy_busy(w):
            # escondida (bloqueada) ainda parando: destruí-la agora derrubaria o trabalho dela
            return False
        self._copy_window = None
        self._copy_blocked = False
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
        if self._quit_sequence:  # "Trancar e sair" já em andamento: o X espera ele terminar
            event.ignore()
            return
        lockable, attention = self._visible_folders()
        if not lockable and not attention:
            self._accept_close(event)
            return
        while True:
            shown = {v.record.id for v in (*lockable, *attention)}
            offered = [v.record.id for v in lockable]  # "Trancar e sair" prometeu trancar estas
            lines = [v.record.name for v in lockable] + [
                f"{v.record.name} — precisa de atenção; não dá para trancar automaticamente"
                for v in attention
            ]
            buttons = [("Trancar e sair", "lock")] if lockable else []
            buttons += [("Sair sem trancar", "quit"), ("Cancelar", "cancel")]
            choice = ask(
                self,
                "Sair do Owl Vault?",
                "Estas pastas estão abertas e visíveis:",
                buttons,
                details=lines,
                details_open=True,
                primary="lock" if lockable else "cancel",
            )
            if choice not in ("lock", "quit") or self.mgr is None:
                event.ignore()  # Cancelar/Esc, ou o app bloqueou com a pergunta na tela
                return
            # a decisão vale para a lista de AGORA: com a pergunta na tela, o atalho de uma
            # pasta pode tê-la aberto. Pasta nova na lista ⇒ pergunta de novo, com ela.
            lockable, attention = self._visible_folders()
            if not {v.record.id for v in (*lockable, *attention)} - shown:
                break
        if choice == "quit":
            self._accept_close(event)
            return
        event.ignore()
        self._quit_sequence = True
        ids = [v.record.id for v in lockable]
        # uma pasta oferecida na pergunta que deixou de poder ser trancada (renomeada, unidade
        # fora) entra na fila assim mesmo: _sequence_next a põe no resumo, com o motivo
        ids += [fid for fid in offered if fid not in ids]
        seq = _Sequencia(ids, sair=True, conhecidas=shown)
        # as que precisam de atenção não entram na fila, mas entram no resumo do fim: o app só
        # sai deixando-as com cópias legíveis se a pessoa escolher "Sair sem trancar"
        seq.falhas += [self._attention_failure(v) for v in attention if v.record.id not in ids]
        self._sequence_next(seq)

    @staticmethod
    def _attention_failure(view: FolderView) -> _Falha:
        """Pasta que precisa de atenção no resumo do "Trancar e sair": o texto do gerente e onde
        estão as saídas que ele cita (o Resolver da lista, não o resumo)."""
        motivo = (view.attention or view.label).strip()
        if "Resolver" not in motivo:
            if motivo and not motivo.endswith((".", "!", "?", "…")):
                motivo += "."
            motivo = f"{motivo} Volte ao Owl Vault e use 'Resolver…' nesta pasta.".strip()
        return _Falha(view.record.id, motivo)

    def _visible_folders(self) -> tuple[list[FolderView], list[FolderView]]:
        """Pastas que podem ter cópias legíveis (``VISIVEIS``), separadas em (dá para trancar
        já, precisa de atenção). Uma pasta aberta que sumiu ou com a unidade fora não é
        "trancável": aparece como "precisa de atenção"."""
        if self.mgr is None:
            return [], []
        lockable: list[FolderView] = []
        attention: list[FolderView] = []
        for rec in list(self.mgr.folders):
            if rec.state not in VISIVEIS:
                continue
            try:
                view = self.mgr.view(rec)
            except (OwlVaultError, OSError) as exc:
                view = FolderView(rec, "Precisa de atenção", "resolver", str(exc), issue="erro")
            (lockable if pode_trancar(view) else attention).append(view)
        return lockable, attention

    def _visible_ids(self) -> set[str]:
        lockable, attention = self._visible_folders()
        return {v.record.id for v in (*lockable, *attention)}

    def _accept_close(self, event: QCloseEvent) -> None:
        if not self._close_copy_window():
            event.ignore()
            return
        self._quit()
        event.accept()

    def _quit_sequence_end(self, seq: _Sequencia) -> None:
        """Fim do "Trancar e sair". Tudo trancado: sai. Senão, um resumo de quais pastas
        ficaram de fora e por quê; o app só sai sem trancar se o usuário escolher isso."""
        if self.mgr is None:
            self._quit_sequence = False
            return
        self._refresh()
        if seq.desistiu and not seq.falhas:  # "Cancelar" no T7: volta ao app, sem sair
            self._quit_sequence = False
            self.home.set_notice("Nem todas as pastas foram trancadas. Tranque-as antes de sair.")
            return
        if not seq.falhas:
            self._quit_now(seq.conhecidas)
            return
        title, text, details = self._failure_summary(seq)
        lockable_now = {v.record.id for v in self._visible_folders()[0]}
        retry = any(f.folder_id in lockable_now for f in seq.falhas)
        if retry and len(seq.falhas) == 1:
            text += " Depois, clique em Tentar de novo."
        if seq.trancadas:
            text = f"{seq.trancadas} pasta(s) foram trancadas. " + text
        buttons = (
            [("Tentar de novo", "retry"), ("Sair sem trancar", "quit")]
            if retry
            else [("Voltar ao Owl Vault", "cancel"), ("Sair sem trancar", "quit")]
        )
        choice = ask(
            self,
            title,
            text,
            buttons,
            details=details,
            details_open=True,
            primary="retry" if retry else "cancel",
        )
        self._quit_sequence = False
        if self.mgr is None:
            return  # bloqueou com o resumo na tela (inatividade, Win+L): fica bloqueado
        if choice == "retry":
            QTimer.singleShot(0, self.close)
        elif choice == "quit":
            conhecidas = set(seq.conhecidas)
            QTimer.singleShot(0, lambda: self._quit_now(conhecidas))
        else:  # Esc/X ou "Voltar": NÃO sai — volta ao app com as pastas como estão
            self._refresh()
            if all(self._rec_state(f.folder_id) == ABERTA for f in seq.falhas):
                self.home.set_notice("As pastas continuam abertas. Tranque-as antes de sair.")
            else:
                self.home.set_notice(
                    "Nem todas as pastas foram trancadas. Use 'Resolver…' nas que precisam de "
                    "atenção antes de sair."
                )

    def _rec_state(self, folder_id: str) -> str:
        rec = self.session.index.folder(folder_id) if self.session is not None else None
        return rec.state if rec is not None else ""

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
        self._discard_dialogs()
        self.unlock_page.configure(master=False)
        self._show_page(self.unlock_page)

    def _quit_now(self, conhecidas: set[str] | None = None) -> None:
        """Sai depois do "Trancar e sair". ``conhecidas``: as pastas que o usuário viu na
        pergunta de saída — se apareceu outra pasta aberta desde então, pergunta de novo."""
        self._quit_sequence = False
        if conhecidas is not None and self.mgr is not None and self._visible_ids() - conhecidas:
            QTimer.singleShot(0, self.close)  # T11 de novo, com a lista de agora
            return
        if not self._close_copy_window():
            self._refresh()
            self.home.set_notice("Feche a janela da Cópia criptografada para sair.")
            return
        self._quit()
        self.close()
