"""Uma única janela do Owl Vault por usuário.

O atalho "Abrir com Owl Vault" de uma pasta roda ``OwlVault.exe --abrir <id>``. Se o programa
já estiver aberto, essa segunda execução só repassa o pedido (pelo canal local do usuário) e
termina; a janela existente pede o PIN e abre a pasta.
"""

from __future__ import annotations

import ctypes
import getpass
import hashlib
import os
import sys
from ctypes import wintypes

from PySide6.QtCore import QByteArray, QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket

ERROR_ALREADY_EXISTS = 183
ASFW_ANY = 0xFFFFFFFF


def _key() -> str:
    who = f"{os.environ.get('USERDOMAIN', '')}\\{getpass.getuser()}|{os.environ.get('LOCALAPPDATA', '')}"
    return "OwlVault-" + hashlib.sha256(who.encode("utf-8")).hexdigest()[:24]


class SingleInstance(QObject):
    message = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.name = _key()
        self.primary = True
        self._mutex = None
        self._server: QLocalServer | None = None
        if sys.platform == "win32":
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
            k32.CreateMutexW.restype = wintypes.HANDLE
            self._mutex = k32.CreateMutexW(None, False, "Local\\" + self.name)
            if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
                self.primary = False
        if self.primary:
            QLocalServer.removeServer(self.name)
            server = QLocalServer(self)
            server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
            server.newConnection.connect(self._on_connection)
            server.listen(self.name)
            self._server = server

    def send(self, text: str) -> bool:
        """Repassa ``text`` à instância principal (e permite que ela venha para a frente)."""
        if sys.platform == "win32":
            try:
                ctypes.windll.user32.AllowSetForegroundWindow(ASFW_ANY)
            except OSError:
                pass
        sock = QLocalSocket()
        sock.connectToServer(self.name)
        if not sock.waitForConnected(3000):
            return False
        sock.write(QByteArray(text.encode("utf-8")[:512] + b"\n"))
        sock.waitForBytesWritten(3000)
        sock.disconnectFromServer()
        return True

    def _on_connection(self) -> None:
        assert self._server is not None
        sock = self._server.nextPendingConnection()
        if sock is None:
            return

        def read() -> None:
            if not sock.canReadLine():
                return
            line = bytes(sock.readLine().data()).decode("utf-8", "replace").strip()
            sock.disconnectFromServer()
            if line:
                self.message.emit(line[:512])

        sock.readyRead.connect(read)
        sock.disconnected.connect(sock.deleteLater)
