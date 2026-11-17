"""Ponto de entrada da interface gráfica (``OwlVault.exe``).

``OwlVault.exe``                 abre o Owl Vault (pastas protegidas)
``OwlVault.exe --abrir <id>``    usado pelo atalho dentro de uma pasta trancada
``OwlVault.exe --selftest``      autoteste do executável (sem janela)
"""

from __future__ import annotations

import ctypes
import sys

from PySide6.QtCore import QLibraryInfo, QLocale, QTranslator
from PySide6.QtWidgets import QApplication

from owl_vault import APP_NAME, __version__
from owl_vault.ui.icon import owl_icon
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


def main() -> int:
    argv = sys.argv[1:]
    if "--selftest" in argv:
        from owl_vault.selftest import run  # noqa: PLC0415 - só no modo de autoteste

        return run()
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("OwlVault.App")
        except Exception:  # noqa: S110 - apenas cosmético (ícone na barra de tarefas)
            pass
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setWindowIcon(owl_icon())

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
    single.message.connect(window.handle_message)
    window.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
