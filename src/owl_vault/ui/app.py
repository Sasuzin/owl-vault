"""Ponto de entrada da interface gráfica (``OwlVault.exe``).

``OwlVault.exe``                 abre o Owl Vault (pastas protegidas)
``OwlVault.exe --abrir <id>``    usado pelo atalho dentro de uma pasta trancada
``OwlVault.exe --selftest``      autoteste do executável (sem janela)
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from PySide6.QtCore import QLibraryInfo, QLocale, QTranslator
from PySide6.QtWidgets import QApplication, QWidget

from owl_vault import APP_NAME, __version__
from owl_vault.ui.icon import owl_icon, owl_image
from owl_vault.ui.theme import apply_theme, saved_theme


def _install_pt_br_translations(app: QApplication) -> None:
    """Botões e menus do próprio Qt em português ("Sim"/"Não", "Copiar", "Colar"...)."""
    translator = QTranslator(app)
    path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    if translator.load(QLocale("pt_BR"), "qtbase", "_", path):
        app.installTranslator(translator)


def _open_request(argv: list[str]) -> str | None:
    if "--abrir" in argv:
        i = argv.index("--abrir")
        if i + 1 < len(argv):
            value = argv[i + 1].strip().lower()
            if len(value) == 32 and all(c in "0123456789abcdef" for c in value):
                return value
    return None


DEV_APP_USER_MODEL_ID = "OwlVault.App"


def explicit_app_user_model_id() -> str | None:
    """ID de aplicativo próprio (AppUserModelID) para a barra de tarefas — só no
    desenvolvimento.

    Rodando pelo ``pythonw``, sem ID próprio a barra de tarefas mostra o ícone do Python. No
    ``OwlVault.exe``, NÃO: com ID próprio e sem atalho que o declare, a barra pede o ícone à
    janela assim que ela aparece e, se o programa ainda está ocupado abrindo, cai no ícone da
    classe de janela do Qt — o genérico do Windows (visto no Windows 11 25H2: às vezes coruja,
    às vezes genérico, com o mesmo exe). Sem ID próprio, a barra usa o ícone embutido no exe
    (a coruja) e o atalho do Menu Iniciar, sem depender de tempo."""
    if sys.platform != "win32" or getattr(sys, "frozen", False):
        return None
    return DEV_APP_USER_MODEL_ID


def use_owl_class_icon(window: QWidget) -> bool:
    """Coruja também no ícone da CLASSE de janela, antes de a janela aparecer.

    Sem atalho que leve a barra de tarefas ao exe (a 1ª execução, do arquivo baixado), ela pede
    o ícone à janela; se o Owl Vault ainda está ocupado abrindo, o pedido expira e ela usa o
    ícone da classe — que o Qt registra como o genérico do Windows (visto no 0.4.0: a cópia
    baixada sempre com o ícone genérico, a instalada sempre com a coruja). Devolve se trocou."""
    if sys.platform != "win32":
        return False
    try:
        from owl_vault.storage import shell  # noqa: PLC0415 - só no Windows

        big, small = shell.class_icon_sizes()
        hwnd = int(window.winId())  # cria a janela nativa (ainda escondida)
        shell.set_window_class_icons(hwnd, owl_image(big).toHICON(), owl_image(small).toHICON())
    except Exception:  # apenas cosmético (ícone na barra de tarefas): nunca impede de abrir
        return False
    return True


#: mutex nomeado que existe enquanto o Owl Vault está aberto. O instalador e o desinstalador
#: (``AppMutex`` em ``packaging/owl_vault.iss``) o procuram e pedem para fechar o programa antes
#: de trocar o exe — em vez de fechá-lo à força: no teste da 0.6.0, o fechamento automático do
#: Windows (Restart Manager) fechou a janela, mas o lançador do PyInstaller (processo sem
#: janela) ficou preso segurando o OwlVault.exe e o instalador parou num erro.
APP_MUTEX = "OwlVaultApp"
_HELD_MUTEXES: list[int] = []


def hold_app_mutex(name: str = APP_MUTEX) -> int | None:
    """Cria (ou abre) o mutex ``name`` e o mantém até o processo terminar (o Windows o solta
    sozinho quando o programa fecha). Devolve o handle, ou ``None`` se não deu."""
    if sys.platform != "win32":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    handle = kernel32.CreateMutexW(None, False, name)
    if not handle:
        return None
    _HELD_MUTEXES.append(int(handle))
    return int(handle)


def configure_app(app: QApplication) -> None:
    """Nome, versão e ícone do app.

    Sem ``setApplicationDisplayName``: com ele, o Qt acrescenta " - Owl Vault" ao título de
    toda janela que não termina com o nome, e os títulos do app já começam com "Owl Vault"
    (ficava "Owl Vault v0.3.2 · build 10 · 843d2dd - Owl Vault" e "Owl Vault — Cópia
    criptografada - Owl Vault")."""
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setWindowIcon(owl_icon())


def main() -> int:
    argv = sys.argv[1:]
    if "--selftest" in argv:
        from owl_vault.selftest import run  # noqa: PLC0415 - só no modo de autoteste

        return run()
    hold_app_mutex()  # "o Owl Vault está aberto", para o instalador pedir que feche
    app_id = explicit_app_user_model_id()
    if app_id is not None:
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
        except Exception:  # noqa: S110 - apenas cosmético (ícone na barra de tarefas)
            pass
    app = QApplication(sys.argv)
    configure_app(app)

    from owl_vault.ui.single_instance import SingleInstance  # noqa: PLC0415

    request = _open_request(argv)
    single = SingleInstance()
    if not single.primary:
        single.send(f"abrir {request}" if request else "mostrar")
        return 0

    _install_pt_br_translations(app)
    apply_theme(app, saved_theme())

    from owl_vault.application.install import ensure_installed  # noqa: PLC0415
    from owl_vault.ui.owl_window import OwlWindow  # noqa: PLC0415

    launcher = ensure_installed()
    window = OwlWindow(launcher, open_request=request)
    use_owl_class_icon(window)
    single.message.connect(window.handle_message)
    window.show_initial()  # cabe na área útil da tela; numa tela pequena demais, maximizada
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
