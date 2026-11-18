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

Entrega confirmada (revisão): a janela principal responde ``ok`` depois de ler o pedido. A 2ª
execução espera essa resposta por até ``SEND_PATIENCE`` segundos (a janela pode estar ocupada) e,
se o canal cair antes de o pedido ser lido, tenta de novo. Sem confirmação, avisa o usuário em
vez de sair calada — um clique em "Abrir com Owl Vault" nunca se perde em silêncio.
"""

from __future__ import annotations

import ctypes
import getpass
import hashlib
import os
import sys
import time
from ctypes import wintypes

from PySide6.QtCore import QByteArray, QCoreApplication, QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import QApplication, QMessageBox

from owl_vault import APP_NAME

ERROR_ALREADY_EXISTS = 183
ERROR_ACCESS_DENIED = 5
ASFW_ANY = 0xFFFFFFFF
MAX_MESSAGE = 512
#: resposta da janela principal depois de ler um pedido
ACK = b"ok"
#: quanto tempo (s) a 2ª execução espera a janela principal confirmar o pedido
SEND_PATIENCE = 10.0

# resultado de uma tentativa de entrega
_DELIVERED = "entregue"  # a janela principal confirmou (ou, versão anterior, leu e fechou)
_NOT_READ = "nao_lido"  # o pedido não foi lido (sem conexão, ou o canal caiu antes): tenta de novo
_NO_REPLY = "sem_resposta"  # o pedido foi lido, mas a janela não confirmou a tempo
_REFUSED = "recusado"  # o canal é de outra conta do Windows: nada foi enviado

_WARNINGS = {
    _NOT_READ: "O Owl Vault já está aberto, mas não respondeu. Tente de novo em alguns segundos.",
    _NO_REPLY: "O Owl Vault está ocupado e ainda não confirmou o pedido. Se a janela dele não "
    "aparecer logo, tente de novo em alguns segundos.",
    _REFUSED: "Não foi possível passar o pedido para o Owl Vault que já está aberto. Use a "
    "janela dele.",
}
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


def _ms_left(deadline: float, cap: int | None = None) -> int:
    left = max(0, int((deadline - time.monotonic()) * 1000))
    return left if cap is None else min(cap, left)


def _warn_user(text: str) -> None:
    """Caixa de aviso simples. Sem interface gráfica (testes, QCoreApplication) não mostra nada:
    quem chamou fica só com o retorno False."""
    if not isinstance(QCoreApplication.instance(), QApplication):
        return
    box = QMessageBox(QMessageBox.Icon.Warning, APP_NAME, text, QMessageBox.StandardButton.Ok)
    box.exec()


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

    def send(self, text: str, *, patience: float = SEND_PATIENCE, warn: bool = True) -> bool:
        """Repassa ``text`` à instância principal (e permite que ela venha para a frente).

        True só quando a principal confirma que leu o pedido. Ela pode estar ocupada: espera
        até ``patience`` segundos e, se o pedido não chegou a ser lido (canal caiu, sem
        conexão), tenta de novo. Sem confirmação devolve False e, com ``warn``, avisa o usuário
        numa caixa de mensagem (só quando há interface gráfica)."""
        payload = QByteArray(text.encode("utf-8")[: MAX_MESSAGE - 1] + b"\n")
        deadline = time.monotonic() + max(0.0, patience)
        while True:
            outcome = self._send_once(payload, deadline)
            # lido sem confirmação: NÃO reenviar (a janela abriria o pedido duas vezes)
            if outcome in (_DELIVERED, _NO_REPLY, _REFUSED) or time.monotonic() >= deadline:
                break
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
        if outcome == _DELIVERED:
            return True
        if warn:
            _warn_user(_WARNINGS[outcome])
        return False

    def _send_once(self, payload: QByteArray, deadline: float) -> str:
        sock = QLocalSocket()
        try:
            sock.connectToServer(self.name)
            if not sock.waitForConnected(_ms_left(deadline, cap=3000)):
                return _NOT_READ
            if not peer_is_same_user(sock, peer_is_server=True):
                return _REFUSED
            if sys.platform == "win32":
                try:
                    ctypes.windll.user32.AllowSetForegroundWindow(ASFW_ANY)
                except OSError:
                    pass
            written: list[int] = []
            sock.bytesWritten.connect(written.append)
            sock.write(payload)
            # o canal do Qt no Windows só conclui a escrita quando a principal lê
            while sum(written) < payload.size():
                if sock.state() != QLocalSocket.LocalSocketState.ConnectedState:
                    return _NOT_READ  # caiu antes de a principal ler
                left = _ms_left(deadline)
                if left <= 0:
                    return _NOT_READ  # a principal não leu a tempo (ocupada)
                sock.waitForBytesWritten(left)
            while not sock.canReadLine():
                if sock.state() != QLocalSocket.LocalSocketState.ConnectedState:
                    # leu e fechou sem responder: versão anterior, que não confirma
                    return _DELIVERED
                left = _ms_left(deadline)
                if left <= 0:
                    return _NO_REPLY
                sock.waitForReadyRead(left)
            reply = bytes(sock.readLine(64).data()).strip()
            return _DELIVERED if reply == ACK else _NO_REPLY
        finally:
            sock.abort()

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
            # confirma ANTES de tratar o pedido (que pode abrir um diálogo e demorar); o canal
            # só fecha depois que a 2ª execução ler a confirmação
            sock.write(QByteArray(ACK + b"\n"))
            sock.disconnectFromServer()
            if line:
                self.message.emit(line[:MAX_MESSAGE])

        sock.readyRead.connect(read)
        if sock.bytesAvailable():  # o cliente pode ter escrito antes desta conexão ser tratada
            read()
