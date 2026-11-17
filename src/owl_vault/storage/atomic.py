"""Escrita sem substituição, arquivo de estado e remoção restrita (ARCHITECTURE §5)."""

from __future__ import annotations

import os
import re
import secrets
from collections.abc import Iterable

from owl_vault.domain.errors import UnsafePathError
from owl_vault.storage import faults, winfs


def write_new_no_replace(final_path: str, data: bytes, op: str = "write") -> None:
    """Grava ``data`` em ``final_path`` sem jamais substituir um arquivo existente.

    Temporário ``<nome>.<rand32>.tmp`` com ``CREATE_NEW`` na MESMA pasta → escreve →
    ``FlushFileBuffers`` → renomeia pelo handle sem substituição. Em qualquer falha o
    temporário é removido pelo handle.
    """
    folder = winfs.parent_of(final_path)
    name = winfs.name_of(final_path)
    tmp = winfs.join(folder, f"{name}.{secrets.token_hex(16)}.tmp")
    f = winfs.Win32File.create_new(tmp)
    try:
        faults.checkpoint(f"{op}.write")
        f.write(data)
        faults.checkpoint(f"{op}.flush")
        f.flush()
        faults.checkpoint(f"{op}.rename")
        f.rename_in_place(name)
    except BaseException:
        try:
            f.mark_delete()
        except OSError:
            pass
        raise
    finally:
        f.close()


def replace_small_file(final_path: str, data: bytes) -> None:
    """Único caso com substituição: ``state.json`` (melhor esforço, sem papel de segurança)."""
    folder = winfs.parent_of(final_path)
    name = winfs.name_of(final_path)
    tmp = winfs.join(folder, f"{name}.{secrets.token_hex(16)}.tmp")
    f = winfs.Win32File.create_new(tmp)
    try:
        f.write(data)
        f.flush()
    except BaseException:
        f.mark_delete()
        f.close()
        raise
    f.close()
    try:
        winfs.retry_on_sharing(lambda: os.replace(tmp, final_path))
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def flush_existing(path: str) -> None:
    """Reabre um arquivo próprio e chama FlushFileBuffers (commita metadados do NTFS)."""
    with winfs.Win32File.open(
        path,
        winfs.GENERIC_READ | winfs.GENERIC_WRITE,
        winfs.FILE_SHARE_READ,
        winfs.OPEN_EXISTING,
        winfs.FILE_FLAG_OPEN_REPARSE_POINT,
    ) as f:
        f.flush()


def safe_remove_own(
    path: str,
    allowed_dir: winfs.Resolved,
    name_pattern: re.Pattern[str],
    forbidden: Iterable[winfs.Resolved] = (),
) -> None:
    """Remove um arquivo criado pelo Owl Vault — e somente isso.

    Exige: arquivo regular sem reparse; nome casando ``name_pattern``; pasta-pai (resolvida)
    dentro de ``allowed_dir``; fora de qualquer caminho ``forbidden`` (ex.: a origem).
    """
    name = winfs.name_of(path)
    if not name_pattern.fullmatch(name):
        raise UnsafePathError("remoção recusada: nome não é de um arquivo do Owl Vault")
    st = os.lstat(path)
    if not winfs.is_plain_file(st):
        raise UnsafePathError("remoção recusada: não é um arquivo regular")
    parent = winfs.resolve(winfs.parent_of(path))
    if not parent.exists or not parent.is_within(allowed_dir):
        raise UnsafePathError("remoção recusada: fora da pasta controlada pelo Owl Vault")
    for bad in forbidden:
        if parent.is_within(bad):
            raise UnsafePathError("remoção recusada: caminho dentro da origem")
    faults.checkpoint("remove")
    os.remove(path)


def safe_rmdir_own(
    path: str, allowed_dir: winfs.Resolved, forbidden: Iterable[winfs.Resolved] = ()
) -> bool:
    """Remove uma pasta VAZIA criada pelo Owl Vault. Retorna False se não estiver vazia."""
    st = os.lstat(path)
    if not winfs.is_plain_dir(st):
        raise UnsafePathError("remoção recusada: não é uma pasta comum")
    res = winfs.resolve(path)
    if not res.is_within(allowed_dir):
        raise UnsafePathError("remoção recusada: fora da pasta controlada pelo Owl Vault")
    for bad in forbidden:
        if res.is_within(bad):
            raise UnsafePathError("remoção recusada: caminho dentro da origem")
    try:
        os.rmdir(path)
    except OSError:
        return False
    return True


def write_probe(folder: str) -> None:
    """Sonda de escrita: cria, grava, dá flush, renomeia e remove um arquivo aleatório."""
    probe = winfs.join(folder, f".owlvault-probe-{secrets.token_hex(16)}.tmp")
    f = winfs.Win32File.create_new(probe)
    try:
        f.write(b"owl-vault-probe")
        f.flush()
        f.rename_in_place(f".owlvault-probe-{secrets.token_hex(16)}.tmp")
    finally:
        try:
            f.mark_delete()
        finally:
            f.close()
