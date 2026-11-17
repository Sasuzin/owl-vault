"""Restauração para pasta nova/vazia (ARCHITECTURE §4.4) e rotina por arquivo compartilhada
com o teste de restauração da criação."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass, field

from owl_vault.application.common import (
    FILE_NAMED_STREAMS,
    display,
    max_zone_id,
    round_up,
    write_motw,
)
from owl_vault.application.progress import CancelToken, NullProgress, ProgressSink
from owl_vault.application.protection import ProtectedPaths, destination_location_problems
from owl_vault.application.vault import OpenedVault, open_vault, read_completion, read_manifest
from owl_vault.crypto.kdf import KdfPolicy
from owl_vault.crypto.stream import blob_size
from owl_vault.domain.errors import (
    CancelledError,
    IntegrityError,
    OwlVaultError,
    StateError,
    UnsafePathError,
)
from owl_vault.domain.limits import (
    FAT32_MAX_FILE_SIZE,
    LEGACY_MAX_PATH,
    MAX_EXTENDED_PATH_UTF16,
    MIB,
)
from owl_vault.domain.models import DirEntryRecord, FileEntryRecord
from owl_vault.domain.names import display_path, fold_path, is_short_name_legal, utf16_len
from owl_vault.storage import faults, winfs
from owl_vault.storage.atomic import safe_remove_own, write_new_no_replace
from owl_vault.storage.blob import decrypt_blob
from owl_vault.storage.manifest import Manifest

MARKER_NAME = ".owlvault-restore.json"
RESTORE_LOCK_NAME = ".owlvault-restore.lock"
_MARKER_RE = re.compile(re.escape(MARKER_NAME))
_LONGEST_TEMP = len(".owl-") + 32 + 1 + 32 + len(".part")


def _part_re(prefix: str) -> re.Pattern[str]:
    return re.compile(re.escape(prefix) + r"[0-9a-f]{32}\.part")


@dataclass
class FileRestoreOutcome:
    path: str
    warnings: list[str] = field(default_factory=list)


def restore_file_content(
    opened: OpenedVault,
    *,
    blob_path: str,
    expected_file_id: bytes | None,
    expected_size: int | None,
    expected_sha256: bytes | None,
    dest_dir: str,
    final_name: str,
    part_prefix: str,
    root: winfs.Resolved,
    mtime_ns: int | None,
    motw: bool,
    cancel: CancelToken,
    progress: ProgressSink,
) -> FileRestoreOutcome:
    """Rotina ÚNICA de restauração de um arquivo (usada pela restauração real e pelo teste).

    ``.part`` com CREATE_NEW → confere o caminho final do handle sob ``root`` → decifra
    verificando tudo → confere SHA-256 → flush → Mark-of-the-Web → mtime pelo handle →
    renomeia pelo handle SEM substituir. Qualquer falha remove o ``.part`` pelo handle.
    """
    part = winfs.join(dest_dir, f"{part_prefix}{secrets.token_hex(16)}.part")
    out = winfs.Win32File.create_new(part)
    warnings: list[str] = []
    try:
        parts = winfs.handle_resolved_parts(out)
        if parts[: len(root.parts)] != root.parts:
            raise UnsafePathError(
                "o arquivo temporário foi criado fora da pasta de destino (pasta trocada por link?)"
            )

        def sink(data: bytes) -> None:
            faults.checkpoint("restore.write")
            out.write(data)

        sha, _ = decrypt_blob(
            blob_path,
            opened.master_key,
            opened.vault_id,
            expected_file_id,
            expected_size,
            sink,
            cancel.check,
            lambda n: progress.advance(n),
            unbuffered=False,
        )
        if expected_sha256 is not None and sha != expected_sha256:
            raise IntegrityError("o conteúdo decifrado não confere com o hash do manifesto")
        faults.checkpoint("restore.flush")
        out.flush()
        if motw:
            try:
                write_motw(out.path)
            except OSError:
                warnings.append("não foi possível gravar a marca de origem da internet")
        if mtime_ns is not None:
            try:
                out.set_mtime_ns(mtime_ns)
            except (OSError, ValueError):
                warnings.append("data de modificação não pôde ser aplicada")
        faults.checkpoint("restore.rename")
        out.rename_in_place(final_name)
    except BaseException:
        try:
            out.mark_delete()
        except OSError:
            pass
        raise
    finally:
        out.close()
    return FileRestoreOutcome(winfs.join(dest_dir, final_name), warnings)


def hash_file_unbuffered(path: str, cancel: CancelToken) -> bytes:
    sha = hashlib.sha256()
    with winfs.UnbufferedReader(path) as r:
        while True:
            cancel.check()
            block = r.read(4 * MIB)
            if not block:
                break
            sha.update(block)
    return sha.digest()


@dataclass
class RestoreReport:
    destination: str
    creation_status: str
    restored: int = 0
    skipped_existing: int = 0
    dirs_created: int = 0
    failed: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failed and not self.conflicts


def inspect_destination(dest: str) -> str:
    """'missing' | 'empty' | 'resumable' | 'nonempty' (para a UI decidir o que perguntar)."""
    ext = winfs.to_extended(dest)
    try:
        names = os.listdir(ext)
    except FileNotFoundError:
        return "missing"
    names = [
        n
        for n in names
        if not (n == RESTORE_LOCK_NAME and winfs.is_plain_file_at(winfs.join(ext, n)))
    ]
    if not names:
        return "empty"
    if MARKER_NAME in names:
        return "resumable"
    return "nonempty"


def _ordered(manifest: Manifest) -> list[DirEntryRecord | FileEntryRecord]:
    """Por profundidade; dentro de cada pasta, nomes já 8.3 legais primeiro."""
    return sorted(
        manifest.entries,
        key=lambda e: (
            len(e.path),
            fold_path(e.path[:-1]),
            not is_short_name_legal(e.path[-1]),
            e.path,
        ),
    )


def restore_vault(
    vault_dir: str,
    password: str,
    dest_dir: str,
    *,
    policy: KdfPolicy,
    protected: ProtectedPaths | None = None,
    session_sources: list[str] | None = None,
    allow_resume: bool = False,
    progress: ProgressSink | None = None,
    cancel: CancelToken | None = None,
) -> RestoreReport:
    progress = progress or NullProgress()
    cancel = cancel or CancelToken()
    protected = protected if protected is not None else ProtectedPaths.from_environment()
    vault_ext = winfs.to_extended(vault_dir)
    dest_ext = winfs.to_extended(dest_dir)

    # 1. destino: regras de localização
    vres = winfs.resolve(vault_ext)
    dres = winfs.resolve(dest_ext)
    problems = destination_location_problems(dres, protected, "O destino da restauração")
    if dres.overlaps(vres):
        problems.append("O destino não pode ficar dentro do cofre (nem o cofre dentro do destino).")
    for s in session_sources or []:
        try:
            sres = winfs.resolve(s)
        except OwlVaultError:
            continue
        if dres.overlaps(sres):
            problems.append(
                "O destino não pode ser a pasta de origem (nem ficar dentro/acima dela): "
                "restaure sempre numa pasta nova."
            )
    if problems:
        raise UnsafePathError(" ".join(problems))
    state = inspect_destination(dest_ext)
    if state == "nonempty":
        raise UnsafePathError("A pasta de destino não está vazia. Escolha uma pasta nova ou vazia.")
    if state == "resumable" and not allow_resume:
        raise StateError(
            "A pasta de destino contém uma restauração interrompida. Confirme a retomada."
        )
    if state != "missing":
        st = os.lstat(dest_ext)
        if not winfs.is_plain_dir(st):
            raise UnsafePathError("O destino não é uma pasta comum (link/ponto de reparse).")
    elif not os.path.isdir(winfs.parent_of(dest_ext)):
        raise UnsafePathError("A pasta onde o destino seria criado não existe.")

    # 2. abre cofre e valida TUDO antes de escrever
    progress.stage("Abrindo o cofre (derivando chave — não cancelável)")
    opened = open_vault(vault_ext, password, policy)
    mread = read_manifest(opened)
    manifest = mread.manifest
    _, creation_status = read_completion(opened, mread.raw)
    report = RestoreReport(display(dest_ext), creation_status)
    report.notes.extend(opened.notes + mread.notes)

    progress.stage("Conferindo o cofre antes de restaurar")
    unavailable: set[bytes] = set()
    for fe in manifest.files:
        cancel.check()
        bp = opened.layout.blob(fe.file_id)
        try:
            bst = os.lstat(bp)
            if not winfs.is_plain_file(bst) or bst.st_size != blob_size(
                fe.size, manifest.chunk_size
            ):
                raise IntegrityError("tamanho")
        except (OSError, IntegrityError):
            unavailable.add(fe.file_id)
            report.failed.append(f"{display_path(fe.path)}: dado criptografado ausente ou truncado")
    long_paths = 0
    base_len = utf16_len(dest_ext)
    for e in manifest.entries:
        total = base_len + sum(utf16_len(c) + 1 for c in e.path) + _LONGEST_TEMP
        if total > MAX_EXTENDED_PATH_UTF16:
            raise UnsafePathError(
                f"Caminho longo demais para o destino escolhido: {display_path(e.path)}"
            )
        if total - _LONGEST_TEMP + 1 - len("\\\\?\\") > LEGACY_MAX_PATH:
            long_paths += 1
    if long_paths:
        report.warnings.append(
            f"{long_paths} caminho(s) passarão de 260 caracteres; alguns programas antigos podem "
            "não abri-los."
        )
    if winfs.is_fat32_limited(dres.fs_name):
        big = [e for e in manifest.files if e.size > FAT32_MAX_FILE_SIZE]
        if big:
            raise UnsafePathError(
                f"{len(big)} arquivo(s) maiores que 4 GiB não cabem em {dres.fs_name}: "
                f"{display_path(big[0].path)}"
            )
    space = winfs.volume_space(dres.existing_ancestor)
    needed = sum(round_up(e.size, space.cluster_size) + 1024 for e in manifest.files)
    needed += 1024 * len(manifest.dirs) + 64 * MIB
    if state != "resumable" and needed > space.free_bytes:
        raise OwlVaultError(
            f"Espaço insuficiente no destino: necessário ~{needed / MIB:.0f} MiB, "
            f"livre {space.free_bytes / MIB:.0f} MiB."
        )
    zone = max_zone_id([opened.layout.header, opened.layout.manifest])
    motw = zone is not None and zone >= 3
    if motw and not (dres.fs_flags & FILE_NAMED_STREAMS):
        report.warnings.append(
            "O cofre veio da internet, mas o destino não suporta a marca de origem (FAT/exFAT)."
        )
        motw = False

    # 3. trava + marcador
    if state == "missing":
        os.mkdir(dest_ext)
    root = winfs.resolve(dest_ext)
    if not root.exists or not root.is_directory:
        raise UnsafePathError("O destino não pôde ser criado como pasta.")
    with winfs.ExclusiveLock(winfs.join(dest_ext, RESTORE_LOCK_NAME), "A pasta de destino"):
        marker_path = winfs.join(dest_ext, MARKER_NAME)
        manifest_sha = hashlib.sha256(mread.raw).hexdigest()
        if state == "resumable":
            restore_id = _check_marker(marker_path, opened.vault_id.hex(), manifest_sha)
            _cleanup_parts(dest_ext, root, f".owl-{restore_id}-", cancel)
        else:
            restore_id = secrets.token_hex(16)
            marker = {
                "app": "Owl Vault",
                "vault_id": opened.vault_id.hex(),
                "manifest_sha256": manifest_sha,
                "restore_id": restore_id,
                "phase": "restoring",
            }
            write_new_no_replace(marker_path, json.dumps(marker).encode("ascii"), op="marker")
        prefix = f".owl-{restore_id}-"

        # 4. pastas e arquivos
        progress.stage("Restaurando", manifest.total_bytes(), len(manifest.files))
        resuming = state == "resumable"
        # Pastas que conflitaram/falharam (ou que são links): nada abaixo delas é tocado.
        blocked: set[tuple[str, ...]] = set()

        def under_blocked(path: tuple[str, ...]) -> bool:
            key = fold_path(path)
            return any(key[:i] in blocked for i in range(1, len(key)))

        try:
            for e in _ordered(manifest):
                cancel.check()
                target_dir = winfs.join(dest_ext, *e.path[:-1]) if len(e.path) > 1 else dest_ext
                target = winfs.join(dest_ext, *e.path)
                shown = display_path(e.path)
                if under_blocked(e.path):
                    if isinstance(e, FileEntryRecord):
                        report.failed.append(f"{shown}: pasta de destino indisponível")
                    blocked.add(fold_path(e.path))
                    continue
                if isinstance(e, DirEntryRecord):
                    problem = _make_dir(target, root, resuming)
                    if problem == "created":
                        report.dirs_created += 1
                    elif problem != "existing":
                        report.conflicts.append(f"{shown}: {problem}")
                        blocked.add(fold_path(e.path))
                    continue
                if e.file_id in unavailable:
                    continue
                if os.path.lexists(target):
                    if resuming and _existing_matches(target, e, root, cancel):
                        report.skipped_existing += 1
                        progress.advance(e.size, 1)
                        continue
                    report.conflicts.append(f"{shown}: já existe no destino (não foi alterado)")
                    continue
                if not os.path.isdir(target_dir):
                    report.failed.append(f"{shown}: pasta de destino indisponível")
                    continue
                try:
                    outcome = restore_file_content(
                        opened,
                        blob_path=opened.layout.blob(e.file_id),
                        expected_file_id=e.file_id,
                        expected_size=e.size,
                        expected_sha256=e.sha256,
                        dest_dir=target_dir,
                        final_name=e.path[-1],
                        part_prefix=prefix,
                        root=root,
                        mtime_ns=e.mtime_ns,
                        motw=motw,
                        cancel=cancel,
                        progress=progress,
                    )
                except (IntegrityError, UnsafePathError) as exc:
                    report.failed.append(f"{shown}: {exc}")
                    continue
                except FileExistsError:
                    report.conflicts.append(f"{shown}: já existe no destino (colisão de nome)")
                    continue
                if outcome.warnings:
                    report.warnings.extend(f"{shown}: {w}" for w in outcome.warnings)
                report.restored += 1
                progress.advance(0, 1)
        except CancelledError:
            raise
        except OSError as exc:
            raise winfs.classify_os_error(exc, "Restauração interrompida") from exc
        # 5. conclusão: remove o marcador
        if report.ok:
            safe_remove_own(marker_path, root, _MARKER_RE)
        else:
            report.notes.append(
                "O marcador de restauração foi mantido: corrija os problemas e retome, ou "
                "restaure novamente numa pasta nova."
            )
    return report


def _check_marker(marker_path: str, vault_id_hex: str, manifest_sha: str) -> str:
    try:
        with open(marker_path, "rb") as fh:
            obj = json.loads(fh.read(4096).decode("ascii"))
    except (OSError, ValueError) as exc:
        raise StateError("Marcador de restauração ilegível; restaure numa pasta nova.") from exc
    if (
        not isinstance(obj, dict)
        or obj.get("vault_id") != vault_id_hex
        or obj.get("manifest_sha256") != manifest_sha
        or not isinstance(obj.get("restore_id"), str)
        or not re.fullmatch(r"[0-9a-f]{32}", obj["restore_id"])
    ):
        raise StateError("A restauração interrompida nesta pasta é de outro cofre/versão.")
    return str(obj["restore_id"])


def _cleanup_parts(dest_ext: str, root: winfs.Resolved, prefix: str, cancel: CancelToken) -> None:
    pattern = _part_re(prefix)
    stack = [dest_ext]
    while stack:
        cancel.check()
        folder = stack.pop()
        with os.scandir(folder) as it:
            for entry in it:
                st = entry.stat(follow_symlinks=False)
                attrs = getattr(st, "st_file_attributes", 0)
                if attrs & winfs.FILE_ATTRIBUTE_REPARSE_POINT:
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(entry.path)
                elif pattern.fullmatch(entry.name):
                    safe_remove_own(entry.path, root, pattern)


def _within(parts: tuple[str, ...], root: winfs.Resolved) -> bool:
    return parts[: len(root.parts)] == root.parts


def _make_dir(target: str, root: winfs.Resolved, resuming: bool) -> str:
    """Cria (ou aceita, na retomada) uma pasta, conferindo o caminho FINAL pelo handle.

    Retorna "created", "existing" ou a descrição do conflito.
    """
    try:
        os.mkdir(target)
        created = True
    except FileExistsError:
        created = False
    except OSError as exc:
        return f"pasta de destino indisponível ({exc.strerror or exc})"
    try:
        st = os.lstat(target)
    except OSError as exc:
        return f"pasta de destino indisponível ({exc.strerror or exc})"
    if not winfs.is_plain_dir(st):
        return "já existe no destino e não é uma pasta comum (link?)"
    if not created and not resuming:
        return "já existe no destino"
    try:
        with winfs.Win32File.open(
            target,
            winfs.FILE_READ_ATTRIBUTES,
            winfs.FILE_SHARE_READ | winfs.FILE_SHARE_WRITE | winfs.FILE_SHARE_DELETE,
            winfs.OPEN_EXISTING,
            winfs.FILE_FLAG_BACKUP_SEMANTICS | winfs.FILE_FLAG_OPEN_REPARSE_POINT,
        ) as f:
            if not _within(winfs.handle_resolved_parts(f), root):
                return "pasta fora do destino (link no caminho?)"
    except OSError as exc:
        return f"pasta de destino indisponível ({exc.strerror or exc})"
    return "created" if created else "existing"


def _existing_matches(
    target: str, e: FileEntryRecord, root: winfs.Resolved, cancel: CancelToken
) -> bool:
    """Arquivo já existente na retomada: só conta como restaurado se for um arquivo comum,
    DENTRO do destino (caminho final do handle) e com o hash do manifesto."""
    st = os.lstat(target)
    if not winfs.is_plain_file(st) or st.st_size != e.size:
        return False
    try:
        f = winfs.Win32File.open(
            target,
            winfs.FILE_WRITE_ATTRIBUTES | winfs.FILE_READ_ATTRIBUTES,
            winfs.FILE_SHARE_READ,
            winfs.OPEN_EXISTING,
            winfs.FILE_FLAG_OPEN_REPARSE_POINT,
        )
    except OSError:
        return False
    with f:
        info = f.info()
        if info.attributes & winfs.FILE_ATTRIBUTE_REPARSE_POINT or info.is_directory:
            return False
        if not _within(winfs.handle_resolved_parts(f), root):
            return False
        if hash_file_unbuffered(target, cancel) != e.sha256:
            return False
        try:
            f.set_mtime_ns(e.mtime_ns)
        except (OSError, ValueError):
            pass
    return True


def open_for_restore(vault_dir: str, password: str, policy: KdfPolicy) -> OpenedVault:
    return open_vault(winfs.to_extended(vault_dir), password, policy)
