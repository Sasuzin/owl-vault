"""Integração com o Explorer: ícone da pasta (desktop.ini), atalho, atributos e avisos ao
shell, pastas conhecidas do Windows.

Nada aqui protege dados — é só a "aparência" da pasta trancada. A proteção é a criptografia.
"""

from __future__ import annotations

import ctypes
import os
import sys
import uuid
from ctypes import wintypes

from owl_vault.domain.errors import OwlVaultError

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("owl_vault.storage.shell requer Windows")

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_shell32 = ctypes.WinDLL("shell32", use_last_error=True)
_ole32 = ctypes.WinDLL("ole32", use_last_error=True)

FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

SHCNE_UPDATEDIR = 0x00001000
SHCNE_UPDATEITEM = 0x00002000
SHCNF_PATHW = 0x0005
SHCNF_FLUSHNOWAIT = 0x3000


_GetFileAttributesW = _kernel32.GetFileAttributesW
_GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
_GetFileAttributesW.restype = wintypes.DWORD
_SetFileAttributesW = _kernel32.SetFileAttributesW
_SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
_SetFileAttributesW.restype = wintypes.BOOL
_SHChangeNotify = _shell32.SHChangeNotify
_SHChangeNotify.argtypes = [wintypes.LONG, wintypes.UINT, wintypes.LPCVOID, wintypes.LPCVOID]
_SHChangeNotify.restype = None


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def parse(cls, text: str) -> _GUID:
        u = uuid.UUID(text)
        g = cls()
        g.Data1, g.Data2, g.Data3 = u.fields[0], u.fields[1], u.fields[2]
        rest = u.bytes[8:]
        for i in range(8):
            g.Data4[i] = rest[i]
        return g


_SHGetKnownFolderPath = _shell32.SHGetKnownFolderPath
_SHGetKnownFolderPath.argtypes = [
    ctypes.POINTER(_GUID),
    wintypes.DWORD,
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.LPWSTR),
]
_SHGetKnownFolderPath.restype = ctypes.c_long
_CoTaskMemFree = _ole32.CoTaskMemFree
_CoTaskMemFree.argtypes = [wintypes.LPVOID]
_CoTaskMemFree.restype = None

#: Pastas conhecidas que NÃO podem ser trancadas inteiras (o Windows depende delas).
KNOWN_FOLDERS = {
    "Área de Trabalho": "B4BFCC3A-DB2C-424C-B029-7FE99A87C641",
    "Documentos": "FDD39AD0-238F-46AF-ADB4-6C85480369C7",
    "Downloads": "374DE290-123F-4565-9164-39C4925E467B",
    "Imagens": "33E28130-4E1E-4676-835A-98395C3BC3BB",
    "Músicas": "4BD8D571-6D19-48D3-BE97-422220080E43",
    "Vídeos": "18989B1D-99B5-455B-841C-AB7C74E4DDFC",
    "Perfil do usuário": "5E6C858F-0E22-4760-9AFE-EA3317B67173",
}


def known_folder(guid: str) -> str | None:
    g = _GUID.parse(guid)
    out = wintypes.LPWSTR()
    if _SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(out)) != 0:
        return None
    try:
        return out.value
    finally:
        _CoTaskMemFree(out)


def known_folders() -> dict[str, str]:
    result: dict[str, str] = {}
    for name, guid in KNOWN_FOLDERS.items():
        path = known_folder(guid)
        if path:
            result[name] = path
    return result


def get_attributes(path: str) -> int:
    value = _GetFileAttributesW(path)
    if value == INVALID_FILE_ATTRIBUTES:
        raise OSError(None, "atributos indisponíveis", path, ctypes.get_last_error())
    return int(value)


def change_attributes(path: str, add: int = 0, remove: int = 0) -> None:
    current = get_attributes(path)
    new = (current | add) & ~remove
    if new == current:
        return
    if not _SetFileAttributesW(path, new or 0x80):  # 0x80 = NORMAL
        raise OSError(None, "não foi possível alterar atributos", path, ctypes.get_last_error())


def notify_changed(path: str) -> None:
    """Pede ao Explorer para reler a pasta (ícone/atalhos)."""
    plain = _plain(path)
    buf = ctypes.create_unicode_buffer(plain)
    _SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW | SHCNF_FLUSHNOWAIT, buf, None)
    _SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW | SHCNF_FLUSHNOWAIT, buf, None)


def desktop_ini_bytes(icon_name: str, tip: str) -> bytes:
    """desktop.ini em UTF-16LE com BOM (aceita acentos), ícone RELATIVO à própria pasta
    (funciona em qualquer conta ou computador)."""
    crlf = "\r\n"
    text = (
        "[.ShellClassInfo]"
        + crlf
        + f"IconResource={icon_name},0"
        + crlf
        + f"InfoTip={tip}"
        + crlf
        + "ConfirmFileOp=0"
        + crlf
    )
    return b"\xff\xfe" + text.encode("utf-16-le")


_shlwapi = ctypes.WinDLL("shlwapi", use_last_error=True)
_PathMakeSystemFolderW = _shlwapi.PathMakeSystemFolderW
_PathMakeSystemFolderW.argtypes = [wintypes.LPCWSTR]
_PathMakeSystemFolderW.restype = wintypes.BOOL
_PathUnmakeSystemFolderW = _shlwapi.PathUnmakeSystemFolderW
_PathUnmakeSystemFolderW.argtypes = [wintypes.LPCWSTR]
_PathUnmakeSystemFolderW.restype = wintypes.BOOL


_EXT = "\\\\?\\"


def _plain(p: str) -> str:
    return p[len(_EXT) :] if p.startswith(_EXT) else p


def make_system_folder(path: str) -> None:
    """Marca a pasta para o Explorer ler o desktop.ini (ícone personalizado)."""
    if not _PathMakeSystemFolderW(_plain(path)):
        change_attributes(path, add=FILE_ATTRIBUTE_READONLY)


def unmake_system_folder(path: str) -> None:
    _PathUnmakeSystemFolderW(_plain(path))
    change_attributes(path, remove=FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM)


# --- atalho .lnk via IShellLinkW + IPersistFile (COM, sem PowerShell) ---------------------

_CLSID_ShellLink = "00021401-0000-0000-C000-000000000046"
_IID_IShellLinkW = "000214F9-0000-0000-C000-000000000046"
_IID_IPersistFile = "0000010B-0000-0000-C000-000000000046"
_CoInitializeEx = _ole32.CoInitializeEx
_CoInitializeEx.argtypes = [wintypes.LPVOID, wintypes.DWORD]
_CoInitializeEx.restype = ctypes.c_long
_CoUninitialize = _ole32.CoUninitialize
_CoUninitialize.argtypes = []
_CoUninitialize.restype = None
_CoCreateInstance = _ole32.CoCreateInstance
_CoCreateInstance.argtypes = [
    ctypes.POINTER(_GUID),
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(_GUID),
    ctypes.POINTER(ctypes.c_void_p),
]
_CoCreateInstance.restype = ctypes.c_long
_CLSCTX_INPROC_SERVER = 0x1
_COINIT_APARTMENTTHREADED = 0x2
_RPC_E_CHANGED_MODE = -2147417850  # 0x80010106


def _vcall(obj: ctypes.c_void_p, index: int, *args: object, argtypes: tuple[object, ...]) -> int:
    vtbl = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
    proto = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *argtypes)  # type: ignore[arg-type]
    fn = proto(vtbl[index])
    return int(fn(obj, *args))


def _check(hr: int, what: str) -> None:
    if hr < 0:
        raise OwlVaultError(
            f"não foi possível criar o atalho da pasta ({what}: 0x{hr & 0xFFFFFFFF:08X})"
        )


def create_shortcut(
    lnk_path: str, target: str, arguments: str, icon: str, description: str, workdir: str
) -> None:
    """Cria um atalho .lnk pela API do Windows (IShellLinkW). Nada é passado por linha de
    comando: não há risco de injeção por nomes de pasta."""
    hr_init = _CoInitializeEx(None, _COINIT_APARTMENTTHREADED)
    initialized = hr_init in (0, 1)
    if hr_init < 0 and hr_init != _RPC_E_CHANGED_MODE:
        _check(hr_init, "COM")
    link = ctypes.c_void_p()
    persist = ctypes.c_void_p()
    try:
        clsid = _GUID.parse(_CLSID_ShellLink)
        iid = _GUID.parse(_IID_IShellLinkW)
        _check(
            _CoCreateInstance(
                ctypes.byref(clsid),
                None,
                _CLSCTX_INPROC_SERVER,
                ctypes.byref(iid),
                ctypes.byref(link),
            ),
            "CoCreateInstance",
        )
        w = wintypes.LPCWSTR
        _check(_vcall(link, 20, _plain(target), argtypes=(w,)), "SetPath")
        _check(_vcall(link, 11, arguments, argtypes=(w,)), "SetArguments")
        _check(_vcall(link, 9, _plain(workdir), argtypes=(w,)), "SetWorkingDirectory")
        _check(_vcall(link, 7, description, argtypes=(w,)), "SetDescription")
        _check(_vcall(link, 17, _plain(icon), 0, argtypes=(w, ctypes.c_int)), "SetIconLocation")
        iid_pf = _GUID.parse(_IID_IPersistFile)
        _check(
            _vcall(
                link,
                0,
                ctypes.byref(iid_pf),
                ctypes.byref(persist),
                argtypes=(ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p)),
            ),
            "QueryInterface",
        )
        _check(_vcall(persist, 6, _plain(lnk_path), 1, argtypes=(w, wintypes.BOOL)), "Save")
    finally:
        if persist:
            _vcall(persist, 2, argtypes=())
        if link:
            _vcall(link, 2, argtypes=())
        if initialized:
            _CoUninitialize()
    if not os.path.exists(lnk_path):
        raise OwlVaultError("não foi possível criar o atalho da pasta")


def current_executable() -> tuple[str, str]:
    """(programa, argumentos-base) para relançar o Owl Vault a partir de um atalho."""
    if getattr(sys, "frozen", False):
        return sys.executable, ""
    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    exe = pythonw if os.path.exists(pythonw) else sys.executable
    return exe, "-m owl_vault"
