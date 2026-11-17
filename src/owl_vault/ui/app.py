"""Ponto de entrada da interface gráfica (``OwlVault.exe``)."""

from __future__ import annotations

import ctypes
import sys

from PySide6.QtWidgets import QApplication

from owl_vault import APP_NAME, __version__
from owl_vault.ui.icon import owl_icon
from owl_vault.ui.main_window import MainWindow
from owl_vault.ui.theme import apply_theme, saved_theme


def main() -> int:
    if "--selftest" in sys.argv[1:]:
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
    apply_theme(app, saved_theme())
    window = MainWindow()
    window.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
