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
_IID_IShellLinkDataList = "45E2B4AE-B1C3-11D0-B92F-00A0C90312E1"
#: sem LinkInfo (série do volume, caminho-base) e sem TrackerDataBlock (nome da máquina, MAC):
#: o atalho copiado junto com a pasta (backup) não carrega esses rastros.
SLDF_FORCE_NO_LINKINFO = 0x100
SLDF_FORCE_NO_LINKTRACK = 0x40000
_STGM_READ = 0
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


class _Com:
    """CoInitializeEx/CoUninitialize + IShellLinkW e IPersistFile (liberados ao sair)."""

    def __enter__(self) -> _Com:
        hr = _CoInitializeEx(None, _COINIT_APARTMENTTHREADED)
        self._initialized = hr in (0, 1)
        if hr < 0 and hr != _RPC_E_CHANGED_MODE:
            _check(hr, "COM")
        self.link = ctypes.c_void_p()
        self.persist = ctypes.c_void_p()
        clsid = _GUID.parse(_CLSID_ShellLink)
        iid = _GUID.parse(_IID_IShellLinkW)
        try:
            _check(
                _CoCreateInstance(
                    ctypes.byref(clsid),
                    None,
                    _CLSCTX_INPROC_SERVER,
                    ctypes.byref(iid),
                    ctypes.byref(self.link),
                ),
                "CoCreateInstance",
            )
            self.persist = self.query(_IID_IPersistFile)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def query(self, iid_text: str) -> ctypes.c_void_p:
        out = ctypes.c_void_p()
        iid = _GUID.parse(iid_text)
        _check(
            _vcall(
                self.link,
                0,
                ctypes.byref(iid),
                ctypes.byref(out),
                argtypes=(ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p)),
            ),
            "QueryInterface",
        )
        return out

    def __exit__(self, *_exc: object) -> None:
        if self.persist:
            _vcall(self.persist, 2, argtypes=())
            self.persist = ctypes.c_void_p()
        if self.link:
            _vcall(self.link, 2, argtypes=())
            self.link = ctypes.c_void_p()
        if self._initialized:
            _CoUninitialize()
            self._initialized = False


def create_shortcut(
    lnk_path: str, target: str, arguments: str, icon: str, description: str, workdir: str
) -> None:
    """Cria um atalho .lnk pela API do Windows (IShellLinkW). Nada é passado por linha de
    comando: não há risco de injeção por nomes de pasta. O atalho sai sem LinkInfo e sem
    TrackerDataBlock (não leva série do volume, nome da máquina nem MAC)."""
    w = wintypes.LPCWSTR
    with _Com() as com:
        link = com.link
        _check(_vcall(link, 20, _plain(target), argtypes=(w,)), "SetPath")
        _check(_vcall(link, 11, arguments, argtypes=(w,)), "SetArguments")
        _check(_vcall(link, 9, _plain(workdir), argtypes=(w,)), "SetWorkingDirectory")
        _check(_vcall(link, 7, description, argtypes=(w,)), "SetDescription")
        _check(_vcall(link, 17, _plain(icon), 0, argtypes=(w, ctypes.c_int)), "SetIconLocation")
        data = com.query(_IID_IShellLinkDataList)
        try:
            flags = wintypes.DWORD()
            _check(
                _vcall(data, 6, ctypes.byref(flags), argtypes=(ctypes.POINTER(wintypes.DWORD),)),
                "GetFlags",
            )
            new = flags.value | SLDF_FORCE_NO_LINKINFO | SLDF_FORCE_NO_LINKTRACK
            _check(_vcall(data, 7, new, argtypes=(wintypes.DWORD,)), "SetFlags")
        finally:
            _vcall(data, 2, argtypes=())
        _check(_vcall(com.persist, 6, _plain(lnk_path), 1, argtypes=(w, wintypes.BOOL)), "Save")
    if not os.path.exists(lnk_path):
        raise OwlVaultError("não foi possível criar o atalho da pasta")
    _scrub_lnk(lnk_path, target, arguments)


# --- limpeza do .lnk (MS-SHLLINK) -----------------------------------------------------------
_HAS_ID_LIST = 0x1
_HAS_LINK_INFO = 0x2
_STRING_FLAGS = (0x4, 0x8, 0x10, 0x20, 0x40)  # nome, caminho relativo, pasta, argumentos, ícone
_IS_UNICODE = 0x80
_TRACKER_SIG = 0xA0000003  # nome NetBIOS + droids (podem conter o MAC)
_PROPERTY_STORE_SIG = 0xA0000009  # propriedades do alvo (pode repetir dados da máquina)


def _scrubbed_lnk(data: bytes) -> bytes | None:
    """Remove LinkInfo (série do volume, caminho-base) e os blocos de rastreio do .lnk.

    Devolve ``None`` se o arquivo não tiver o formato esperado (aí ele fica como está).
    """
    import struct  # noqa: PLC0415

    if len(data) < 0x4C or struct.unpack_from("<I", data, 0)[0] != 0x4C:
        return None
    flags = struct.unpack_from("<I", data, 0x14)[0]
    pos = 0x4C
    if flags & _HAS_ID_LIST:
        pos += 2 + struct.unpack_from("<H", data, pos)[0]
    id_end = pos
    link_info_end = pos
    if flags & _HAS_LINK_INFO:
        link_info_end = pos + struct.unpack_from("<I", data, pos)[0]
    pos = link_info_end
    unit = 2 if flags & _IS_UNICODE else 1
    for bit in _STRING_FLAGS:
        if flags & bit:
            pos += 2 + unit * struct.unpack_from("<H", data, pos)[0]
    strings = data[link_info_end:pos]
    blocks = b""
    while pos + 4 <= len(data):
        size = struct.unpack_from("<I", data, pos)[0]
        if size < 4:
            break
        if size < 8 or pos + size > len(data):
            return None
        sig = struct.unpack_from("<I", data, pos + 4)[0]
        if sig not in (_TRACKER_SIG, _PROPERTY_STORE_SIG):
            blocks += data[pos : pos + size]
        pos += size
    header = bytearray(data[:0x4C])
    struct.pack_into("<I", header, 0x14, flags & ~_HAS_LINK_INFO)
    return bytes(header) + data[0x4C:id_end] + strings + blocks + b"\x00\x00\x00\x00"


def _scrub_lnk(lnk_path: str, target: str, arguments: str) -> None:
    """Melhor esforço: grava a versão limpa e confere que o atalho continua igual."""
    try:
        with open(lnk_path, "rb") as fh:
            original = fh.read()
        clean = _scrubbed_lnk(original)
        if clean is None or clean == original:
            return
        with open(lnk_path, "wb") as fh:
            fh.write(clean)
        if not shortcut_matches(lnk_path, target, arguments):
            with open(lnk_path, "wb") as fh:
                fh.write(original)
    except OSError:
        return


def read_shortcut(lnk_path: str) -> tuple[str, str]:
    """``(alvo, argumentos)`` de um .lnk, lidos pela API do Windows (sem resolver o alvo)."""
    w = wintypes
    with _Com() as com:
        _check(
            _vcall(com.persist, 5, _plain(lnk_path), _STGM_READ, argtypes=(w.LPCWSTR, w.DWORD)),
            "Load",
        )
        buf = ctypes.create_unicode_buffer(4096)
        _check(
            _vcall(
                com.link,
                3,  # GetPath, SLGP_RAWPATH
                buf,
                len(buf),
                None,
                0x4,
                argtypes=(w.LPWSTR, ctypes.c_int, ctypes.c_void_p, w.DWORD),
            ),
            "GetPath",
        )
        target = buf.value
        args = ctypes.create_unicode_buffer(4096)
        _check(
            _vcall(com.link, 10, args, len(args), argtypes=(w.LPWSTR, ctypes.c_int)), "GetArguments"
        )
        return target, args.value


def shortcut_matches(lnk_path: str, target: str, arguments: str) -> bool:
    """O atalho existe e aponta exatamente para ``target`` com ``arguments``?"""
    try:
        got_target, got_args = read_shortcut(lnk_path)
    except (OSError, OwlVaultError):
        return False
    return (
        os.path.normcase(got_target) == os.path.normcase(_plain(target)) and got_args == arguments
    )


def current_executable() -> tuple[str, str]:
    """(programa, argumentos-base) para relançar o Owl Vault a partir de um atalho."""
    if getattr(sys, "frozen", False):
        return sys.executable, ""
    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    exe = pythonw if os.path.exists(pythonw) else sys.executable
    return exe, "-m owl_vault"
