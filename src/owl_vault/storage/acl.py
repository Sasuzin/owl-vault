"""Permissões NTFS dos itens que o Owl Vault cria (defesa em profundidade).

Problema (revisão de segurança): numa pasta herdando "Usuários autenticados: Modificar" (o
padrão das pastas criadas na raiz de C:\\ ou de um disco D:\\), outra conta deste computador
poderia trocar o atalho "Abrir com Owl Vault" por um programa dela, ou ler as cópias
temporárias do teste de restauração.

Solução: DACL **protegida** (sem herança) só com a conta atual, SYSTEM e Administradores nos
itens que o Owl Vault cria: espaço reservado, ``P\\.owlvault`` e a área temporária
``.owlvault-<id>``. "Modificar" na pasta-mãe não dá FILE_DELETE_CHILD, então a outra conta não
consegue apagar nem renomear esses itens. É melhor esforço: se falhar (FAT, rede, política),
nada quebra — a proteção dos dados continua sendo a criptografia.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("owl_vault.storage.acl requer Windows")

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

TOKEN_QUERY = 0x0008
TokenUser = 1
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
SDDL_REVISION_1 = 1

_GetCurrentProcess = _kernel32.GetCurrentProcess
_GetCurrentProcess.restype = wintypes.HANDLE
_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_LocalFree = _kernel32.LocalFree
_LocalFree.argtypes = [wintypes.HLOCAL]
_LocalFree.restype = wintypes.HLOCAL

_OpenProcessToken = _advapi32.OpenProcessToken
_OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
_OpenProcessToken.restype = wintypes.BOOL
_GetTokenInformation = _advapi32.GetTokenInformation
_GetTokenInformation.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
_GetTokenInformation.restype = wintypes.BOOL
_ConvertSidToStringSidW = _advapi32.ConvertSidToStringSidW
_ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
_ConvertSidToStringSidW.restype = wintypes.BOOL
_ConvertSDDL = _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
_ConvertSDDL.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.ULONG),
]
_ConvertSDDL.restype = wintypes.BOOL
_SetFileSecurityW = _advapi32.SetFileSecurityW
_SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID]
_SetFileSecurityW.restype = wintypes.BOOL


def token_user_sid(token: int | None = None) -> str | None:
    """SID (texto) do usuário de um token; do processo atual se ``token`` for None."""
    own = token is None
    handle = wintypes.HANDLE()
    if own:
        if not _OpenProcessToken(_GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(handle)):
            return None
    else:
        handle = wintypes.HANDLE(token)
    try:
        needed = wintypes.DWORD()
        _GetTokenInformation(handle, TokenUser, None, 0, ctypes.byref(needed))
        if not needed.value:
            return None
        buf = ctypes.create_string_buffer(needed.value)
        if not _GetTokenInformation(handle, TokenUser, buf, needed, ctypes.byref(needed)):
            return None
        psid = ctypes.cast(buf, ctypes.POINTER(wintypes.LPVOID))[0]  # TOKEN_USER.User.Sid
        text = wintypes.LPWSTR()
        if not _ConvertSidToStringSidW(psid, ctypes.byref(text)):
            return None
        try:
            return text.value
        finally:
            _LocalFree(ctypes.cast(text, wintypes.HLOCAL))
    finally:
        if own:
            _CloseHandle(handle)


def current_user_sid() -> str | None:
    return token_user_sid(None)


def restrict_to_owner(path: str, *, directory: bool) -> bool:
    """DACL protegida: só a conta atual, SYSTEM e Administradores (controle total).

    Em pastas, as entradas são herdáveis (OI/CI): o que for criado dentro herda a mesma
    restrição. Devolve False se não conseguiu (sem exceção).
    """
    sid = current_user_sid()
    if not sid:
        return False
    inherit = "OICI" if directory else ""
    sddl = f"D:P(A;{inherit};FA;;;{sid})(A;{inherit};FA;;;SY)(A;{inherit};FA;;;BA)"
    sd = wintypes.LPVOID()
    if not _ConvertSDDL(sddl, SDDL_REVISION_1, ctypes.byref(sd), None):
        return False
    try:
        return bool(
            _SetFileSecurityW(
                path, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd
            )
        )
    finally:
        _LocalFree(ctypes.cast(sd, wintypes.HLOCAL))
