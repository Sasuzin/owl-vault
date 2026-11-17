"""E/S Win32 via ctypes (ARCHITECTURE §6).

Tudo que depende de semântica específica do Windows/NTFS fica aqui:

* ``to_extended``: caminhos absolutos com prefixo ``\\\\?\\`` (suporta > 260 caracteres);
* ``resolve``: caminho final resolvido (GUID do volume) para comparações de "dentro de",
  imunes a nomes 8.3, ``subst``, junctions e pontos de montagem;
* ``Win32File``: handle com leitura/escrita, flush, informações (FileId, datas, atributos),
  renomeação e exclusão **pelo handle** (sem corrida por caminho);
* ``open_source``: abre a origem negando escrita a outros processos, sem seguir reparse
  points e sem disparar download de arquivos de nuvem;
* ``UnbufferedReader``: leitura sem cache do sistema (bytes vêm do dispositivo);
* ``ExclusiveLock``: trava de escritor único com DELETE_ON_CLOSE.
"""

from __future__ import annotations

import ctypes
import mmap
import os
import stat as stat_mod
import sys
import time
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Self

from owl_vault.domain.errors import (
    AntivirusBlockedError,
    FileInUseError,
    FileTooLargeForFsError,
    InsufficientSpaceError,
    OwlVaultError,
    SourceChangedError,
    UnsafePathError,
    VaultLockedError,
)
from owl_vault.domain.models import FileIdentity, Fingerprint
from owl_vault.domain.names import fold

if sys.platform != "win32":  # pragma: no cover - o produto é exclusivo para Windows
    raise ImportError("owl_vault.storage.winfs requer Windows")

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# --- constantes Win32 -------------------------------------------------------------------
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
FILE_READ_ATTRIBUTES = 0x0080
FILE_WRITE_ATTRIBUTES = 0x0100
SYNCHRONIZE = 0x00100000

FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
FILE_SHARE_DELETE = 0x4

CREATE_NEW = 1
CREATE_ALWAYS = 2
OPEN_EXISTING = 3
OPEN_ALWAYS = 4

FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_OPEN_NO_RECALL = 0x00100000
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
FILE_FLAG_NO_BUFFERING = 0x20000000
FILE_FLAG_DELETE_ON_CLOSE = 0x04000000

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
RECALL_ATTRIBUTES = (
    FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)

IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
IO_REPARSE_TAG_SYMLINK = 0xA000000C

VOLUME_NAME_DOS = 0x0
VOLUME_NAME_GUID = 0x1

FileBasicInfo = 0
FileStandardInfo = 1
FileRenameInfo = 3
FileDispositionInfo = 4
FileAttributeTagInfo = 9
FileIdInfo = 18
FileDispositionInfoEx = 21
FILE_DISPOSITION_FLAG_DELETE = 0x1
FILE_DISPOSITION_FLAG_POSIX_SEMANTICS = 0x2
FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE = 0x10
ERROR_DIR_NOT_EMPTY = 145

DRIVE_REMOTE = 4

# --- erros Win32 relevantes -------------------------------------------------------------
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_ACCESS_DENIED = 5
ERROR_SHARING_VIOLATION = 32
ERROR_LOCK_VIOLATION = 33
ERROR_HANDLE_DISK_FULL = 39
ERROR_FILE_EXISTS = 80
ERROR_DISK_FULL = 112
ERROR_ALREADY_EXISTS = 183
ERROR_FILE_TOO_LARGE = 223
ERROR_VIRUS_INFECTED = 225
ERROR_VIRUS_DELETED = 226
ERROR_CANT_ACCESS_FILE = 1920
ERROR_INVALID_FUNCTION = 1
ERROR_NOT_SUPPORTED = 50
ERROR_INVALID_PARAMETER = 87

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_EXTENDED_PREFIX = "\\\\?\\"
_UNC_EXTENDED_PREFIX = "\\\\?\\UNC\\"
_EPOCH_AS_FILETIME = 116_444_736_000_000_000

# --- protótipos -------------------------------------------------------------------------
_CreateFileW = _kernel32.CreateFileW
_CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
_CreateFileW.restype = wintypes.HANDLE

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL
_DeviceIoControl = _kernel32.DeviceIoControl
_DeviceIoControl.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
_DeviceIoControl.restype = wintypes.BOOL

_ReadFile = _kernel32.ReadFile
_ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
_ReadFile.restype = wintypes.BOOL

_WriteFile = _kernel32.WriteFile
_WriteFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
_WriteFile.restype = wintypes.BOOL

_FlushFileBuffers = _kernel32.FlushFileBuffers
_FlushFileBuffers.argtypes = [wintypes.HANDLE]
_FlushFileBuffers.restype = wintypes.BOOL

_GetFinalPathNameByHandleW = _kernel32.GetFinalPathNameByHandleW
_GetFinalPathNameByHandleW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
]
_GetFinalPathNameByHandleW.restype = wintypes.DWORD

_GetFileInformationByHandleEx = _kernel32.GetFileInformationByHandleEx
_GetFileInformationByHandleEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.LPVOID,
    wintypes.DWORD,
]
_GetFileInformationByHandleEx.restype = wintypes.BOOL

_SetFileInformationByHandle = _kernel32.SetFileInformationByHandle
_SetFileInformationByHandle.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.LPVOID,
    wintypes.DWORD,
]
_SetFileInformationByHandle.restype = wintypes.BOOL

_GetVolumeInformationByHandleW = _kernel32.GetVolumeInformationByHandleW
_GetVolumeInformationByHandleW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPWSTR,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPWSTR,
    wintypes.DWORD,
]
_GetVolumeInformationByHandleW.restype = wintypes.BOOL

_GetDiskFreeSpaceW = _kernel32.GetDiskFreeSpaceW
_GetDiskFreeSpaceW.argtypes = [
    wintypes.LPCWSTR,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
]
_GetDiskFreeSpaceW.restype = wintypes.BOOL

_GetDiskFreeSpaceExW = _kernel32.GetDiskFreeSpaceExW
_GetDiskFreeSpaceExW.argtypes = [
    wintypes.LPCWSTR,
    ctypes.POINTER(ctypes.c_ulonglong),
    ctypes.POINTER(ctypes.c_ulonglong),
    ctypes.POINTER(ctypes.c_ulonglong),
]
_GetDiskFreeSpaceExW.restype = wintypes.BOOL

_GetVolumePathNameW = _kernel32.GetVolumePathNameW
_GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
_GetVolumePathNameW.restype = wintypes.BOOL

_GetDriveTypeW = _kernel32.GetDriveTypeW
_GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
_GetDriveTypeW.restype = wintypes.UINT


class _FILE_BASIC_INFO(ctypes.Structure):
    _fields_ = [
        ("CreationTime", ctypes.c_longlong),
        ("LastAccessTime", ctypes.c_longlong),
        ("LastWriteTime", ctypes.c_longlong),
        ("ChangeTime", ctypes.c_longlong),
        ("FileAttributes", wintypes.DWORD),
    ]


class _FILE_STANDARD_INFO(ctypes.Structure):
    _fields_ = [
        ("AllocationSize", ctypes.c_longlong),
        ("EndOfFile", ctypes.c_longlong),
        ("NumberOfLinks", wintypes.DWORD),
        ("DeletePending", ctypes.c_ubyte),
        ("Directory", ctypes.c_ubyte),
    ]


class _FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
    _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]


class _FILE_ID_INFO(ctypes.Structure):
    _fields_ = [("VolumeSerialNumber", ctypes.c_ulonglong), ("FileId", ctypes.c_ubyte * 16)]


class _FILE_DISPOSITION_INFO_EX(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD)]


class _FILE_DISPOSITION_INFO(ctypes.Structure):
    _fields_ = [("DeleteFile", ctypes.c_ubyte)]


class _FILE_RENAME_INFO(ctypes.Structure):
    _fields_ = [
        ("ReplaceIfExists", wintypes.DWORD),  # união BOOLEAN/Flags; byte baixo = BOOLEAN
        ("RootDirectory", wintypes.HANDLE),
        ("FileNameLength", wintypes.DWORD),
        ("FileName", wintypes.WCHAR * 1),
    ]


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


# --- erros ------------------------------------------------------------------------------


def _last_error() -> int:
    return ctypes.get_last_error()


def _os_error(code: int, path: str | None = None) -> OSError:
    err = OSError(None, ctypes.FormatError(code).strip(), path, code)
    return err


def winerror_of(exc: BaseException) -> int | None:
    if isinstance(exc, OSError):
        if getattr(exc, "winerror", None) is not None:
            return int(exc.winerror)
        if exc.errno == 28:  # ENOSPC
            return ERROR_DISK_FULL
    return None


def classify_os_error(exc: OSError, what: str) -> OwlVaultError:
    """Converte erros Win32 em erros de domínio com mensagens claras (ARCHITECTURE §5)."""
    code = winerror_of(exc)
    if code in (ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION):
        return FileInUseError(
            f"{what}: arquivo em uso por outro programa. Feche-o e tente novamente."
        )
    if code in (ERROR_DISK_FULL, ERROR_HANDLE_DISK_FULL):
        return InsufficientSpaceError(f"{what}: disco cheio.")
    if code == ERROR_FILE_TOO_LARGE:
        return FileTooLargeForFsError(
            f"{what}: arquivo grande demais para o sistema de arquivos de destino."
        )
    if code in (ERROR_VIRUS_INFECTED, ERROR_VIRUS_DELETED):
        return AntivirusBlockedError(f"{what}: operação bloqueada pelo antivírus.")
    if code == ERROR_ACCESS_DENIED:
        return OwlVaultError(
            f"{what}: acesso negado. Se o Windows Defender 'Acesso controlado a pastas' "
            "estiver ativo, permita o OwlVault.exe ou escolha outra pasta."
        )
    if code == ERROR_CANT_ACCESS_FILE:
        return OwlVaultError(f"{what}: o Windows não consegue acessar este arquivo.")
    if code in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
        return SourceChangedError(f"{what}: arquivo ou pasta não encontrado (foi removido?).")
    return OwlVaultError(f"{what}: erro do sistema ({exc.strerror or exc}).")


# --- caminhos ---------------------------------------------------------------------------


def is_extended(path: str) -> bool:
    return path.startswith(_EXTENDED_PREFIX)


def strip_extended(path: str) -> str:
    """Forma para exibição: remove ``\\\\?\\``."""
    if path.startswith(_UNC_EXTENDED_PREFIX):
        return "\\\\" + path[len(_UNC_EXTENDED_PREFIX) :]
    if path.startswith(_EXTENDED_PREFIX):
        return path[len(_EXTENDED_PREFIX) :]
    return path


def to_extended(path: str) -> str:
    """Normaliza um caminho fornecido pelo usuário para ``\\\\?\\C:\\...``.

    Recusa caminhos relativos, ``C:foo`` (relativo à unidade), UNC/rede e nomes cujo
    último componente seria alterado pelo Windows (ponto/espaço final).
    """
    if not isinstance(path, str) or not path.strip():
        raise UnsafePathError("caminho vazio")
    if path.startswith(_EXTENDED_PREFIX):
        rest = path[len(_EXTENDED_PREFIX) :]
        if rest.upper().startswith("UNC\\"):
            raise UnsafePathError("caminhos de rede não são suportados na v1")
        if not (len(rest) >= 3 and rest[0].isalpha() and rest[1] == ":" and rest[2] == "\\"):
            raise UnsafePathError("caminho estendido não suportado")
        return path.rstrip("\\") if len(rest) > 3 else path
    p = path.replace("/", "\\")
    if p.startswith("\\\\"):
        raise UnsafePathError("caminhos de rede (\\\\servidor\\...) não são suportados na v1")
    if not (len(p) >= 3 and p[0].isalpha() and p[1] == ":" and p[2] == "\\"):
        raise UnsafePathError("informe um caminho absoluto completo, como C:\\Pasta")
    # O Windows removeria pontos/espaços finais de QUALQUER componente (C:\proj.\docs viraria
    # C:\proj\docs — outra pasta). Recusa em vez de mudar silenciosamente de pasta.
    for comp in p[3:].split("\\"):
        if comp in ("", ".", ".."):
            continue
        if comp.endswith((".", " ")):
            raise UnsafePathError("nome de pasta termina com ponto ou espaço (não suportado)")
    full = os.path.abspath(p)
    full = full.rstrip("\\") if len(full) > 3 else full
    return _EXTENDED_PREFIX + full


def join(base: str, *components: str) -> str:
    """Une componentes com ``\\`` exatamente como armazenados (sem normalização)."""
    out = base.rstrip("\\")
    for c in components:
        out += "\\" + c
    return out


def parent_of(path: str) -> str:
    head, _, _ = path.rstrip("\\").rpartition("\\")
    if head.endswith(":"):
        return head + "\\"
    return head


def name_of(path: str) -> str:
    return path.rstrip("\\").rpartition("\\")[2]


# --- handles ----------------------------------------------------------------------------


def _create_file(path: str, access: int, share: int, disposition: int, flags: int) -> int:
    handle = _CreateFileW(path, access, share, None, disposition, flags, None)
    if handle is None or handle == INVALID_HANDLE_VALUE:
        raise _os_error(_last_error(), path)
    return int(handle)


def filetime_to_ns(ft: int) -> int:
    return (ft - _EPOCH_AS_FILETIME) * 100


def ns_to_filetime(ns: int) -> int:
    return ns // 100 + _EPOCH_AS_FILETIME


@dataclass(frozen=True, slots=True)
class HandleInfo:
    size: int
    mtime_ns: int
    ctime_ns: int
    attributes: int
    reparse_tag: int
    number_of_links: int
    is_directory: bool
    identity: FileIdentity

    def fingerprint(self) -> Fingerprint:
        return Fingerprint(self.identity, self.size, self.mtime_ns, self.ctime_ns)


class Win32File:
    """Wrapper fino de um HANDLE Win32 com operações por handle."""

    def __init__(self, handle: int, path: str) -> None:
        self._handle: int | None = handle
        self.path = path

    # -- construção
    @classmethod
    def open(cls, path: str, access: int, share: int, disposition: int, flags: int) -> Self:
        return cls(_create_file(path, access, share, disposition, flags), path)

    @classmethod
    def create_new(cls, path: str) -> Self:
        """Cria arquivo novo (falha se existir) com leitura, escrita e DELETE."""
        return cls.open(
            path,
            GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE_READ,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
        )

    @property
    def handle(self) -> int:
        if self._handle is None:
            raise ValueError("handle fechado")
        return self._handle

    def close(self) -> None:
        if self._handle is not None:
            _CloseHandle(self._handle)
            self._handle = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - rede de segurança
        try:
            self.close()
        except Exception:  # noqa: S110
            pass

    # -- dados
    def read(self, size: int) -> bytes:
        if size <= 0:
            return b""
        buf = ctypes.create_string_buffer(size)
        got = wintypes.DWORD(0)
        if not _ReadFile(self.handle, buf, size, ctypes.byref(got), None):
            raise _os_error(_last_error(), self.path)
        return buf.raw[: got.value]

    def read_exact(self, size: int) -> bytes:
        """Lê exatamente ``size`` bytes (menos ⇒ :class:`SourceChangedError`)."""
        chunks: list[bytes] = []
        remaining = size
        while remaining > 0:
            part = self.read(min(remaining, 8 * 1024 * 1024))
            if not part:
                raise SourceChangedError("o arquivo ficou menor durante a leitura")
            chunks.append(part)
            remaining -= len(part)
        return b"".join(chunks)

    def write(self, data: bytes) -> None:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            piece = bytes(view[offset : offset + 64 * 1024 * 1024])
            written = wintypes.DWORD(0)
            if not _WriteFile(self.handle, piece, len(piece), ctypes.byref(written), None):
                raise _os_error(_last_error(), self.path)
            if written.value == 0:
                raise _os_error(ERROR_DISK_FULL, self.path)
            offset += written.value

    def flush(self) -> None:
        if not _FlushFileBuffers(self.handle):
            raise _os_error(_last_error(), self.path)

    # -- informações
    def _get_info(self, cls: int, struct: ctypes.Structure) -> None:
        if not _GetFileInformationByHandleEx(
            self.handle, cls, ctypes.byref(struct), ctypes.sizeof(struct)
        ):
            raise _os_error(_last_error(), self.path)

    def info(self) -> HandleInfo:
        basic = _FILE_BASIC_INFO()
        std = _FILE_STANDARD_INFO()
        tag = _FILE_ATTRIBUTE_TAG_INFO()
        fid = _FILE_ID_INFO()
        self._get_info(FileBasicInfo, basic)
        self._get_info(FileStandardInfo, std)
        self._get_info(FileAttributeTagInfo, tag)
        self._get_info(FileIdInfo, fid)
        reparse_tag = tag.ReparseTag if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT else 0
        return HandleInfo(
            size=int(std.EndOfFile),
            mtime_ns=filetime_to_ns(int(basic.LastWriteTime)),
            ctime_ns=filetime_to_ns(int(basic.ChangeTime)),
            attributes=int(tag.FileAttributes),
            reparse_tag=int(reparse_tag),
            number_of_links=int(std.NumberOfLinks),
            is_directory=bool(std.Directory),
            identity=FileIdentity(int(fid.VolumeSerialNumber), bytes(fid.FileId)),
        )

    def final_path(self, kind: int = VOLUME_NAME_DOS) -> str:
        size = 1024
        while True:
            buf = ctypes.create_unicode_buffer(size)
            n = _GetFinalPathNameByHandleW(self.handle, buf, size, kind)
            if n == 0:
                raise _os_error(_last_error(), self.path)
            if n < size:
                return buf.value
            size = n + 1

    def volume_info(self) -> tuple[str, int, int]:
        """(nome do sistema de arquivos, flags, número de série)."""
        fs_name = ctypes.create_unicode_buffer(64)
        serial = wintypes.DWORD(0)
        max_len = wintypes.DWORD(0)
        flags = wintypes.DWORD(0)
        if not _GetVolumeInformationByHandleW(
            self.handle,
            None,
            0,
            ctypes.byref(serial),
            ctypes.byref(max_len),
            ctypes.byref(flags),
            fs_name,
            64,
        ):
            raise _os_error(_last_error(), self.path)
        return fs_name.value, int(flags.value), int(serial.value)

    # -- alterações pelo handle
    def set_mtime_ns(self, mtime_ns: int) -> None:
        basic = _FILE_BASIC_INFO()  # zeros = "não alterar"
        basic.LastWriteTime = ns_to_filetime(mtime_ns)
        if basic.LastWriteTime <= 0:
            raise ValueError("data fora da faixa do sistema de arquivos")
        if not _SetFileInformationByHandle(
            self.handle, FileBasicInfo, ctypes.byref(basic), ctypes.sizeof(basic)
        ):
            raise _os_error(_last_error(), self.path)

    def rename_in_place(self, new_name: str, *, retries: int = 8) -> None:
        """Renomeia DENTRO da mesma pasta, pelo handle, SEM substituir destino existente."""
        if "\\" in new_name or "/" in new_name or ":" in new_name:
            raise ValueError("rename_in_place aceita apenas um nome simples")
        # Atenção: um nome simples seria interpretado relativo ao diretório ATUAL do
        # processo pela camada Win32. Por isso o destino é sempre o caminho completo
        # (mesma pasta do arquivo de origem do handle).
        self.rename_to(join(parent_of(self.path), new_name), retries=retries)

    def rename_to(self, target: str, *, retries: int = 8) -> None:
        """Renomeia/move pelo handle para ``target`` (caminho estendido completo, mesmo
        volume), SEM substituir destino existente. Atômico no NTFS/ReFS."""
        if not is_extended(target):
            raise ValueError("rename_to exige caminho estendido")
        encoded = target.encode("utf-16-le")
        base = ctypes.sizeof(_FILE_RENAME_INFO)
        total = base + len(encoded)
        buf = ctypes.create_string_buffer(total)
        info = _FILE_RENAME_INFO.from_buffer(buf)
        info.ReplaceIfExists = 0
        info.RootDirectory = None
        info.FileNameLength = len(encoded)
        ctypes.memmove(
            ctypes.addressof(info) + _FILE_RENAME_INFO.FileName.offset, encoded, len(encoded)
        )
        delay = 0.05
        for attempt in range(retries + 1):
            if _SetFileInformationByHandle(self.handle, FileRenameInfo, buf, total):
                self.path = target
                return
            code = _last_error()
            if code in (ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION, ERROR_ACCESS_DENIED) and (
                attempt < retries
            ):
                time.sleep(delay)  # antivírus/indexador segurando o arquivo
                delay = min(delay * 2, 1.0)
                continue
            if code in (ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS):
                raise FileExistsError(None, "destino já existe", target, code)
            raise _os_error(code, self.path)

    def mark_delete(self) -> None:
        """Marca o arquivo para exclusão no fechamento (pelo handle)."""
        disp = _FILE_DISPOSITION_INFO(1)
        if not _SetFileInformationByHandle(
            self.handle, FileDispositionInfo, ctypes.byref(disp), ctypes.sizeof(disp)
        ):
            raise _os_error(_last_error(), self.path)

    def delete_now(self) -> None:
        """Exclui pelo handle, ignorando o atributo somente leitura (POSIX: o nome some na
        hora). Não passa pela Lixeira. Cai para o modo clássico em Windows antigos."""
        ex = _FILE_DISPOSITION_INFO_EX(
            FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE
        )
        if _SetFileInformationByHandle(
            self.handle, FileDispositionInfoEx, ctypes.byref(ex), ctypes.sizeof(ex)
        ):
            return
        code = _last_error()
        if code not in (ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_INVALID_FUNCTION):
            raise _os_error(code, self.path)
        # Windows sem FileDispositionInfoEx: tira o somente leitura e usa o modo clássico
        basic = _FILE_BASIC_INFO()
        self._get_info(FileBasicInfo, basic)
        if basic.FileAttributes & 0x1:
            basic.FileAttributes &= ~0x1
            if basic.FileAttributes == 0:
                basic.FileAttributes = FILE_ATTRIBUTE_NORMAL
            basic.CreationTime = basic.LastAccessTime = basic.LastWriteTime = 0
            basic.ChangeTime = 0
            if not _SetFileInformationByHandle(
                self.handle, FileBasicInfo, ctypes.byref(basic), ctypes.sizeof(basic)
            ):
                raise _os_error(_last_error(), self.path)
        self.mark_delete()


def delete_checked(path: str, expected: Fingerprint | None, *, is_dir: bool = False) -> None:
    """Apaga UM original com conferência no próprio handle (pastas protegidas, §4.1.5).

    Abre sem compartilhamento (nenhum outro programa pode estar com o arquivo aberto), sem
    seguir links; confere: não é ponto de reparse, um único vínculo, e — para arquivos — a
    impressão digital registrada na cifragem (FileId, tamanho, LastWriteTime, ChangeTime).
    Só então exclui pelo MESMO handle. Pastas: só vazias (o NTFS recusa as outras).
    """
    flags = FILE_FLAG_OPEN_REPARSE_POINT | (FILE_FLAG_BACKUP_SEMANTICS if is_dir else 0)
    delay = 0.05
    for attempt in range(9):
        try:
            f = Win32File.open(
                path, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0, OPEN_EXISTING, flags
            )
            break
        except OSError as exc:
            code = winerror_of(exc)
            if code in (ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION) and attempt < 8:
                time.sleep(delay)  # indexador/antivírus segurando por instantes
                delay = min(delay * 2, 1.0)
                continue
            raise classify_os_error(exc, "Não foi possível apagar o original") from exc
    with f:
        info = f.info()
        if info.attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise UnsafePathError("é um link/ponto de reparse; não foi apagado")
        if is_dir != info.is_directory:
            raise SourceChangedError("o tipo do item mudou (arquivo/pasta); não foi apagado")
        if not is_dir:
            if info.number_of_links > 1:
                raise UnsafePathError("o arquivo tem outro vínculo (hard link); não foi apagado")
            if expected is None or info.fingerprint() != expected:
                raise SourceChangedError(
                    "o arquivo mudou depois de ser criptografado; não foi apagado"
                )
        try:
            f.delete_now()
        except OSError as exc:
            if winerror_of(exc) == ERROR_DIR_NOT_EMPTY:
                raise SourceChangedError("a pasta não está vazia; não foi apagada") from exc
            raise classify_os_error(exc, "Não foi possível apagar o original") from exc


def rename_dir(path: str, target: str) -> None:
    """Move uma pasta pelo handle para ``target`` no mesmo volume, sem substituir."""
    f = Win32File.open(
        path,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    with f:
        info = f.info()
        if not info.is_directory or info.attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise UnsafePathError("o item a mover não é uma pasta comum")
        f.rename_to(target)


# --- origem -----------------------------------------------------------------------------


def open_source(path: str, expected: FileIdentity | None = None) -> tuple[Win32File, HandleInfo]:
    """Abre um arquivo de origem para leitura (ARCHITECTURE §6).

    * ``FILE_SHARE_READ`` apenas: outros processos não podem escrever enquanto lemos;
      quem já está com o arquivo aberto para escrita faz esta abertura falhar (em uso).
    * ``OPEN_REPARSE_POINT | OPEN_NO_RECALL``: nunca segue links nem baixa da nuvem.
    """
    try:
        f = Win32File.open(
            path,
            GENERIC_READ,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL,
        )
    except OSError as exc:
        raise classify_os_error(exc, "Não foi possível abrir um arquivo da origem") from exc
    try:
        info = f.info()
        if info.attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise UnsafePathError("arquivo é um link/ponto de reparse (não suportado)")
        if info.attributes & RECALL_ATTRIBUTES:
            raise UnsafePathError("arquivo está somente na nuvem/offline (não suportado)")
        if info.is_directory or info.attributes & FILE_ATTRIBUTE_DIRECTORY:
            raise SourceChangedError("esperava um arquivo, encontrou uma pasta")
        if expected is not None and info.identity != expected:
            raise SourceChangedError("o arquivo da origem foi substituído desde a varredura")
    except BaseException:
        f.close()
        raise
    return f, info


# --- resolução de caminhos --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Resolved:
    """Caminho resolvido para comparações seguras (FORMAT/ARCHITECTURE §4.1)."""

    input_path: str
    parts: tuple[str, ...]  # componentes dobrados, a partir de 'VOLUME{GUID}'
    dos_path: str  # caminho final DOS (\\?\C:\...) incluindo cauda inexistente
    exists: bool
    is_directory: bool
    identity: FileIdentity | None
    fs_name: str
    fs_flags: int
    volume_serial: int
    existing_ancestor: str  # caminho DOS final do ancestral existente mais próximo

    @property
    def volume(self) -> str:
        return self.parts[0]

    def is_within(self, other: Resolved) -> bool:
        """``self`` é igual a ``other`` ou está dentro dele."""
        n = len(other.parts)
        return len(self.parts) >= n and self.parts[:n] == other.parts

    def same(self, other: Resolved) -> bool:
        return self.parts == other.parts

    def overlaps(self, other: Resolved) -> bool:
        return self.is_within(other) or other.is_within(self)


def _split_final(final: str) -> tuple[str, ...]:
    p = strip_extended(final)
    return tuple(fold(c) for c in p.split("\\") if c)


def resolve(path: str) -> Resolved:
    """Resolve ``path`` (ou o ancestral existente mais próximo) pelo sistema.

    Caminhos de rede (sem nome de volume GUID ou com ``\\\\?\\UNC\\``) levantam
    :class:`UnsafePathError`.
    """
    ext = to_extended(path)
    current = ext
    tail: list[str] = []
    while True:
        try:
            f = Win32File.open(
                current,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
            )
            break
        except OSError as exc:
            if winerror_of(exc) not in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
                raise classify_os_error(exc, "Não foi possível acessar o caminho") from exc
            parent = parent_of(current)
            if not parent or parent == current or len(strip_extended(parent)) < 3:
                raise UnsafePathError("caminho inexistente e sem pasta existente acima") from exc
            tail.insert(0, name_of(current))
            current = parent
    with f:
        try:
            dos = f.final_path(VOLUME_NAME_DOS)
        except OSError as exc:
            raise UnsafePathError("não foi possível resolver o caminho final") from exc
        if dos.upper().startswith(_UNC_EXTENDED_PREFIX.upper()):
            raise UnsafePathError("caminhos de rede não são suportados na v1")
        try:
            guid = f.final_path(VOLUME_NAME_GUID)
        except OSError as exc:
            raise UnsafePathError(
                "caminho não está em um volume local (rede/unidade mapeada não suportada)"
            ) from exc
        root = dos[: len(_EXTENDED_PREFIX) + 3]
        if _GetDriveTypeW(root) == DRIVE_REMOTE:
            raise UnsafePathError("unidades de rede não são suportadas na v1")
        info = f.info()
        fs_name, fs_flags, serial = f.volume_info()
    parts = _split_final(guid) + tuple(fold(c) for c in tail)
    dos_full = join(dos, *tail) if tail else dos
    exists = not tail
    return Resolved(
        input_path=ext,
        parts=parts,
        dos_path=dos_full,
        exists=exists,
        is_directory=info.is_directory if exists else False,
        identity=info.identity if exists else None,
        fs_name=fs_name,
        fs_flags=fs_flags,
        volume_serial=serial,
        existing_ancestor=dos,
    )


def handle_resolved_parts(f: Win32File) -> tuple[str, ...]:
    return _split_final(f.final_path(VOLUME_NAME_GUID))


# --- volume / memória -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VolumeSpace:
    free_bytes: int
    cluster_size: int


def volume_space(existing_dir: str) -> VolumeSpace:
    """Espaço livre (para o usuário atual) e tamanho de cluster do volume."""
    free = ctypes.c_ulonglong(0)
    total = ctypes.c_ulonglong(0)
    total_free = ctypes.c_ulonglong(0)
    d = existing_dir if existing_dir.endswith("\\") else existing_dir + "\\"
    if not _GetDiskFreeSpaceExW(
        d, ctypes.byref(free), ctypes.byref(total), ctypes.byref(total_free)
    ):
        raise _os_error(_last_error(), existing_dir)
    cluster = 4096
    # raiz REAL do volume (funciona também para volumes montados numa pasta)
    vbuf = ctypes.create_unicode_buffer(1024)
    root = vbuf.value if _GetVolumePathNameW(d, vbuf, 1024) else strip_extended(d)[:3]
    spc = wintypes.DWORD(0)
    bps = wintypes.DWORD(0)
    fc = wintypes.DWORD(0)
    tc = wintypes.DWORD(0)
    if _GetDiskFreeSpaceW(
        root, ctypes.byref(spc), ctypes.byref(bps), ctypes.byref(fc), ctypes.byref(tc)
    ):
        cluster = max(512, int(spc.value) * int(bps.value))
    return VolumeSpace(free_bytes=int(free.value), cluster_size=cluster)


@dataclass(frozen=True, slots=True)
class MemoryStatus:
    total_physical: int
    available_physical: int
    available_commit: int  # RAM + arquivo de paginação ainda comprometíveis


def memory_status() -> MemoryStatus | None:
    status = _MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
    if not _kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return None
    return MemoryStatus(
        total_physical=int(status.ullTotalPhys),
        available_physical=int(status.ullAvailPhys),
        available_commit=int(status.ullAvailPageFile),
    )


def available_physical_memory() -> int | None:
    st = memory_status()
    return None if st is None else st.available_physical


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_fat(fs_name: str) -> bool:
    return fs_name.upper() in ("FAT", "FAT12", "FAT16", "FAT32", "EXFAT")


DRIVE_REMOVABLE = 2
_IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
#: barramentos de unidades que a pessoa costuma desconectar (USB, 1394, SD, MMC)
_REMOVABLE_BUSES = frozenset({4, 7, 12, 13})


class _STORAGE_PROPERTY_QUERY(ctypes.Structure):
    _fields_ = [
        ("PropertyId", wintypes.DWORD),
        ("QueryType", wintypes.DWORD),
        ("AdditionalParameters", ctypes.c_ubyte * 1),
    ]


class _STORAGE_DEVICE_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("Version", wintypes.DWORD),
        ("Size", wintypes.DWORD),
        ("DeviceType", ctypes.c_ubyte),
        ("DeviceTypeModifier", ctypes.c_ubyte),
        ("RemovableMedia", ctypes.c_ubyte),
        ("CommandQueueing", ctypes.c_ubyte),
        ("VendorIdOffset", wintypes.DWORD),
        ("ProductIdOffset", wintypes.DWORD),
        ("ProductRevisionOffset", wintypes.DWORD),
        ("SerialNumberOffset", wintypes.DWORD),
        ("BusType", wintypes.DWORD),
        ("RawPropertiesLength", wintypes.DWORD),
        ("RawDeviceProperties", ctypes.c_ubyte * 1),
    ]


def is_removable_drive(path: str) -> bool:
    """A pasta está numa unidade que se desconecta (pendrive, HD externo USB, cartão SD)?

    HDs externos USB costumam aparecer como "fixos" para o Windows; por isso também se
    consulta o barramento (IOCTL_STORAGE_QUERY_PROPERTY). Erros → False.
    """
    try:
        vbuf = ctypes.create_unicode_buffer(1024)
        if not _GetVolumePathNameW(to_extended(path), vbuf, 1024):
            return False
        root = vbuf.value
        if _GetDriveTypeW(root) == DRIVE_REMOVABLE:
            return True
        # \\?\C:\ ou C:\ ou \\?\Volume{…}\  →  \\.\C: / \\.\Volume{…}
        device = "\\\\.\\" + strip_extended(root).rstrip("\\")
        handle = _CreateFileW(
            device, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None
        )
        if handle == INVALID_HANDLE_VALUE:
            return False
        try:
            query = _STORAGE_PROPERTY_QUERY(0, 0)
            desc = _STORAGE_DEVICE_DESCRIPTOR()
            returned = wintypes.DWORD()
            ok = _DeviceIoControl(
                handle,
                _IOCTL_STORAGE_QUERY_PROPERTY,
                ctypes.byref(query),
                ctypes.sizeof(query),
                ctypes.byref(desc),
                ctypes.sizeof(desc),
                ctypes.byref(returned),
                None,
            )
            if not ok:
                return False
            return bool(desc.RemovableMedia) or int(desc.BusType) in _REMOVABLE_BUSES
        finally:
            _CloseHandle(handle)
    except (OSError, OwlVaultError, ValueError):
        return False


def is_fat32_limited(fs_name: str) -> bool:
    """FAT/FAT32 limitam arquivos a 4 GiB − 1 (exFAT não)."""
    return fs_name.upper() in ("FAT", "FAT12", "FAT16", "FAT32")


# --- leitura sem cache ------------------------------------------------------------------


_FALLBACKS = [0]


def unbuffered_fallback_count() -> int:
    """Quantas leituras "sem cache" precisaram usar cache (o chamador compara antes/depois)."""
    return _FALLBACKS[0]


def is_plain_file_at(path: str) -> bool:
    try:
        return is_plain_file(os.lstat(path))
    except OSError:
        return False


def is_plain_dir_at(path: str) -> bool:
    try:
        return is_plain_dir(os.lstat(path))
    except OSError:
        return False


class UnbufferedReader:
    """Leitor sequencial com ``FILE_FLAG_NO_BUFFERING`` (bytes vêm do dispositivo).

    Lê blocos alinhados de 1 MiB num buffer alinhado a página (mmap anônimo) e entrega
    bytes com a interface ``read(n)``. Se o sistema recusar a abertura sem cache,
    usa leitura normal e marca ``buffered_fallback``.
    """

    BLOCK = 1024 * 1024

    def __init__(self, path: str) -> None:
        self.path = path
        self.buffered_fallback = False
        try:
            self._file = Win32File.open(
                path,
                GENERIC_READ,
                FILE_SHARE_READ,
                OPEN_EXISTING,
                FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT,
            )
        except OSError as exc:
            # Só cai para leitura com cache quando o sistema de arquivos não suporta E/S sem
            # cache; qualquer outro erro (compartilhamento, acesso negado...) é propagado.
            if winerror_of(exc) not in (
                ERROR_INVALID_FUNCTION,
                ERROR_NOT_SUPPORTED,
                ERROR_INVALID_PARAMETER,
            ):
                raise
            self._file = Win32File.open(
                path,
                GENERIC_READ,
                FILE_SHARE_READ,
                OPEN_EXISTING,
                FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT,
            )
            self.buffered_fallback = True
            _FALLBACKS[0] += 1
        self._mm = mmap.mmap(-1, self.BLOCK)
        self._cbuf: Any = (ctypes.c_char * self.BLOCK).from_buffer(self._mm)
        self._pending = bytearray()
        self._eof = False

    def info(self) -> HandleInfo:
        return self._file.info()

    def _fill(self) -> None:
        got = wintypes.DWORD(0)
        if not _ReadFile(self._file.handle, self._cbuf, self.BLOCK, ctypes.byref(got), None):
            raise _os_error(_last_error(), self.path)
        if got.value == 0:
            self._eof = True
            return
        self._pending += self._mm[: got.value]
        if got.value < self.BLOCK:
            self._eof = True

    def read(self, size: int) -> bytes:
        while len(self._pending) < size and not self._eof:
            self._fill()
        out = bytes(self._pending[:size])
        del self._pending[:size]
        return out

    def close(self) -> None:
        self._file.close()
        del self._cbuf
        self._mm.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# --- travas -----------------------------------------------------------------------------


class ExclusiveLock:
    """Trava de escritor único: arquivo aberto sem compartilhamento e DELETE_ON_CLOSE."""

    def __init__(self, path: str, what: str) -> None:
        self.path = path
        self._what = what
        self._file: Win32File | None = None

    def _check_existing(self) -> os.stat_result | None:
        try:
            st = os.lstat(self.path)
        except FileNotFoundError:
            return None
        if not is_plain_file(st) or st.st_nlink > 1:
            raise UnsafePathError(
                f"{self._what}: trava inválida ou adulterada ({name_of(self.path)} não é um "
                "arquivo comum). Nada foi apagado."
            )
        return st

    def acquire(self) -> None:
        # Nunca seguir links: um cofre adulterado poderia apontar a trava para um arquivo do
        # usuário e a exclusão no fechamento apagaria o ALVO. Por isso: lstat antes,
        # OPEN_REPARSE_POINT na abertura, conferência no handle, e só então "apagar ao fechar".
        self._check_existing()
        try:
            f = Win32File.open(
                self.path,
                GENERIC_READ | GENERIC_WRITE | DELETE,
                0,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            )
        except OSError as exc:
            code = winerror_of(exc)
            if code == ERROR_ACCESS_DENIED:
                st = self._check_existing()
                if st is None:
                    # sem trava existente: falta de permissão de escrita, não outra janela
                    raise OwlVaultError(
                        f"{self._what}: sem permissão de escrita nesta pasta."
                    ) from exc
                if getattr(st, "st_file_attributes", 0) & stat_mod.FILE_ATTRIBUTE_READONLY:
                    raise OwlVaultError(
                        f"{self._what}: há uma trava antiga marcada como somente leitura."
                    ) from exc
            if code in (ERROR_SHARING_VIOLATION, ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION):
                raise VaultLockedError(
                    f"{self._what} está em uso por outra janela do Owl Vault."
                ) from exc
            raise classify_os_error(exc, "Não foi possível criar a trava") from exc
        try:
            info = f.info()
            if (
                info.attributes & FILE_ATTRIBUTE_REPARSE_POINT
                or info.is_directory
                or info.number_of_links > 1
            ):
                raise UnsafePathError(
                    f"{self._what}: trava inválida ou adulterada (link). Nada foi apagado."
                )
            f.mark_delete()  # apaga a PRÓPRIA trava ao fechar (inclusive se o processo morrer)
        except BaseException:
            f.close()
            raise
        self._file = f

    def release(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self) -> Self:
        self.acquire()
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


# --- utilidades de diretório ------------------------------------------------------------


def lstat_attrs(path: str) -> os.stat_result:
    return os.lstat(path)


def is_plain_file(st: os.stat_result) -> bool:
    attrs = getattr(st, "st_file_attributes", 0)
    return stat_mod.S_ISREG(st.st_mode) and not (attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def is_plain_dir(st: os.stat_result) -> bool:
    attrs = getattr(st, "st_file_attributes", 0)
    return stat_mod.S_ISDIR(st.st_mode) and not (attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def mkdir_exclusive(path: str) -> None:
    """Cria uma pasta; falha se já existir."""
    os.mkdir(path)


def ensure_own_dir(path: str) -> None:
    """Cria a pasta se não existir; se existir, exige pasta real (sem reparse)."""
    try:
        os.mkdir(path)
    except FileExistsError:
        st = os.lstat(path)
        if not is_plain_dir(st):
            raise UnsafePathError("pasta interna do cofre é um link/ponto de reparse") from None


def retry_on_sharing(fn: Callable[[], None], attempts: int = 8) -> None:
    delay = 0.05
    for i in range(attempts):
        try:
            fn()
            return
        except OSError as exc:
            if winerror_of(exc) in (
                ERROR_SHARING_VIOLATION,
                ERROR_LOCK_VIOLATION,
                ERROR_ACCESS_DENIED,
            ) and (i < attempts - 1):
                time.sleep(delay)
                delay = min(delay * 2, 1.0)
                continue
            raise
