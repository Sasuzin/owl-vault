"""Uma única janela do Owl Vault por usuário.

O atalho "Abrir com Owl Vault" de uma pasta roda ``OwlVault.exe --abrir <id>``. Se o programa
já estiver aberto, essa segunda execução só repassa o pedido (pelo canal local do usuário) e
termina; a janela existente pede o PIN e abre a pasta.

Segurança (revisão): os nomes de pipe do Windows são globais. Por isso:

* o servidor só escuta se conseguir ser o PRIMEIRO dono do nome (FILE_FLAG_FIRST_PIPE_INSTANCE);
  se outra conta já criou um pipe com esse nome, o app roda sem instância única;
* cada lado confere que o processo do outro lado é da MESMA conta do Windows (SID do token);
  mensagens de outra conta são descartadas e nada é enviado a um servidor de outra conta;
* uma mensagem é uma linha curta (no máximo 512 bytes); o resto é descartado.

Mesmo vinda da mesma conta, uma mensagem nunca abre uma pasta sozinha: a janela sempre pede
o PIN (e mostra o nome da pasta) antes de abrir.
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
ERROR_ACCESS_DENIED = 5
ASFW_ANY = 0xFFFFFFFF
MAX_MESSAGE = 512
_PIPE_ACCESS_DUPLEX = 0x3
_FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_TOKEN_QUERY = 0x0008


def _key() -> str:
    who = f"{os.environ.get('USERDOMAIN', '')}\\{getpass.getuser()}|{os.environ.get('LOCALAPPDATA', '')}"
    return "OwlVault-" + hashlib.sha256(who.encode("utf-8")).hexdigest()[:24]


if sys.platform == "win32":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _k32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    _k32.CreateMutexW.restype = wintypes.HANDLE
    _k32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    _k32.CreateNamedPipeW.restype = wintypes.HANDLE
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    _k32.GetNamedPipeClientProcessId.restype = wintypes.BOOL
    _k32.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    _k32.GetNamedPipeServerProcessId.restype = wintypes.BOOL
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = wintypes.HANDLE
    _adv.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _adv.OpenProcessToken.restype = wintypes.BOOL


def _invalid(handle: object) -> bool:
    return handle is None or handle in (0, ctypes.c_void_p(-1).value)


def claim_pipe_name(name: str) -> bool:
    """True se o nome do pipe está livre (este processo pode ser o primeiro dono)."""
    if sys.platform != "win32":
        return True
    h = _k32.CreateNamedPipeW(
        "\\\\.\\pipe\\" + name,
        _PIPE_ACCESS_DUPLEX | _FILE_FLAG_FIRST_PIPE_INSTANCE,
        0,
        1,
        MAX_MESSAGE,
        MAX_MESSAGE,
        0,
        None,
    )
    if _invalid(h):
        return False
    _k32.CloseHandle(h)
    return True


def _process_sid(pid: int) -> str | None:
    from owl_vault.storage import acl  # noqa: PLC0415

    proc = _k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if _invalid(proc):
        return None
    try:
        token = wintypes.HANDLE()
        if not _adv.OpenProcessToken(proc, _TOKEN_QUERY, ctypes.byref(token)):
            return None
        try:
            return acl.token_user_sid(int(token.value or 0))
        finally:
            _k32.CloseHandle(token)
    finally:
        _k32.CloseHandle(proc)


def peer_is_same_user(sock: QLocalSocket, *, peer_is_server: bool) -> bool:
    """O processo do outro lado do pipe é da mesma conta do Windows?"""
    if sys.platform != "win32":
        return True
    from owl_vault.storage import acl  # noqa: PLC0415

    handle = wintypes.HANDLE(int(sock.socketDescriptor()))
    pid = wintypes.ULONG()
    fn = _k32.GetNamedPipeServerProcessId if peer_is_server else _k32.GetNamedPipeClientProcessId
    if not fn(handle, ctypes.byref(pid)):
        return False
    mine = acl.current_user_sid()
    theirs = _process_sid(int(pid.value))
    return bool(mine) and mine == theirs


class SingleInstance(QObject):
    message = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.name = _key()
        self.primary = True
        self._mutex = None
        self._server: QLocalServer | None = None
        if sys.platform == "win32":
            self._mutex = _k32.CreateMutexW(None, False, "Local\\" + self.name)
            if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
                self.primary = False
        if self.primary and claim_pipe_name(self.name):
            server = QLocalServer(self)
            server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
            server.newConnection.connect(self._on_connection)
            if server.listen(self.name):
                self._server = server

    @property
    def listening(self) -> bool:
        return self._server is not None

    def send(self, text: str) -> bool:
        """Repassa ``text`` à instância principal (e permite que ela venha para a frente)."""
        sock = QLocalSocket()
        sock.connectToServer(self.name)
        if not sock.waitForConnected(3000):
            return False
        if not peer_is_same_user(sock, peer_is_server=True):
            sock.abort()
            return False
        if sys.platform == "win32":
            try:
                ctypes.windll.user32.AllowSetForegroundWindow(ASFW_ANY)
            except OSError:
                pass
        sock.write(QByteArray(text.encode("utf-8")[: MAX_MESSAGE - 1] + b"\n"))
        sock.waitForBytesWritten(3000)
        sock.disconnectFromServer()
        return True

    def _on_connection(self) -> None:
        assert self._server is not None
        sock = self._server.nextPendingConnection()
        if sock is None:
            return
        sock.disconnected.connect(sock.deleteLater)
        if not peer_is_same_user(sock, peer_is_server=False):
            sock.abort()
            return

        def read() -> None:
            if not sock.canReadLine():
                if sock.bytesAvailable() > MAX_MESSAGE:
                    sock.abort()
                return
            line = bytes(sock.readLine(MAX_MESSAGE).data()).decode("utf-8", "replace").strip()
            sock.disconnectFromServer()
            if line:
                self.message.emit(line[:MAX_MESSAGE])

        sock.readyRead.connect(read)
        if sock.bytesAvailable():  # o cliente pode ter escrito antes desta conexão ser tratada
            read()
