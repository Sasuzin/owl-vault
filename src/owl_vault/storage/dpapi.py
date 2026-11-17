"""DPAPI do Windows (CryptProtectData/CryptUnprotectData), escopo do usuário atual.

Usado para amarrar o PIN do dia a dia à conta do Windows: quem copiar o disco sem a senha do
Windows não consegue sequer começar a testar PINs. Não é usado para os cofres (estes dependem
só da senha mestra, para poderem ser abertos em qualquer computador).
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from owl_vault.domain.errors import AuthenticationError, OwlVaultError

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("owl_vault.storage.dpapi requer Windows")

_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

CRYPTPROTECT_UI_FORBIDDEN = 0x1


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


_CryptProtectData = _crypt32.CryptProtectData
_CryptProtectData.argtypes = [
    ctypes.POINTER(_DATA_BLOB),
    wintypes.LPCWSTR,
    ctypes.POINTER(_DATA_BLOB),
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(_DATA_BLOB),
]
_CryptProtectData.restype = wintypes.BOOL

_CryptUnprotectData = _crypt32.CryptUnprotectData
_CryptUnprotectData.argtypes = [
    ctypes.POINTER(_DATA_BLOB),
    ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(_DATA_BLOB),
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(_DATA_BLOB),
]
_CryptUnprotectData.restype = wintypes.BOOL

_LocalFree = _kernel32.LocalFree
_LocalFree.argtypes = [wintypes.HLOCAL]
_LocalFree.restype = wintypes.HLOCAL


def _blob(data: bytes) -> tuple[_DATA_BLOB, ctypes.Array[ctypes.c_char]]:
    buf = ctypes.create_string_buffer(data, len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def protect(data: bytes, entropy: bytes, description: str = "Owl Vault") -> bytes:
    """Cifra ``data`` para o usuário atual do Windows (não depende de admin)."""
    din, _keep1 = _blob(data)
    ent, _keep2 = _blob(entropy)
    out = _DATA_BLOB()
    if not _CryptProtectData(
        ctypes.byref(din),
        description,
        ctypes.byref(ent),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out),
    ):
        raise OwlVaultError(
            f"o Windows recusou proteger os dados do perfil (erro {ctypes.get_last_error()})"
        )
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        _LocalFree(ctypes.cast(out.pbData, wintypes.HLOCAL))


def unprotect(blob: bytes, entropy: bytes) -> bytes:
    """Decifra um blob do DPAPI do usuário atual. Outro usuário/PC ⇒ AuthenticationError."""
    din, _keep1 = _blob(blob)
    ent, _keep2 = _blob(entropy)
    out = _DATA_BLOB()
    if not _CryptUnprotectData(
        ctypes.byref(din),
        None,
        ctypes.byref(ent),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out),
    ):
        raise AuthenticationError(
            "o PIN deste perfil não pode ser usado nesta conta do Windows; use a senha mestra"
        )
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        _LocalFree(ctypes.cast(out.pbData, wintypes.HLOCAL))
