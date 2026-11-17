"""Verificar cofre (ARCHITECTURE §4.3) — somente leitura, E/S sem cache."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from owl_vault.application.common import display
from owl_vault.application.progress import CancelToken, NullProgress, ProgressSink
from owl_vault.application.vault import (
    ManifestRead,
    OpenedVault,
    open_vault,
    read_completion,
    read_manifest,
)
from owl_vault.crypto.kdf import KdfPolicy
from owl_vault.domain.errors import (
    CancelledError,
    OwlVaultError,
    UnsafePathError,
    VaultLockedError,
)
from owl_vault.domain.names import display_path
from owl_vault.storage import winfs
from owl_vault.storage.blob import decrypt_blob, read_blob_header
from owl_vault.storage.layout import (
    BLOB_RE,
    DATA_DIR,
    HH_RE,
    JOURNAL_DIR,
    KNOWN_ROOT_NAMES,
    VaultLayout,
)


@dataclass
class VerifyReport:
    vault: str
    creation_status: str = ""
    completed: bool = False
    files_ok: int = 0
    total_files: int = 0
    total_bytes: int = 0
    bad: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: cópias redundantes (cabeçalho/manifesto) ausentes, corrompidas ou divergentes
    redundancy: list[str] = field(default_factory=list)
    unbuffered_fallback: bool = False
    lock_note: str = ""

    @property
    def ok(self) -> bool:
        return not self.bad

    @property
    def fully_ok(self) -> bool:
        return (
            self.ok
            and not self.anomalies
            and not self.redundancy
            and self.completed
            and not self.unbuffered_fallback
        )


def verify_contents(
    opened: OpenedVault,
    mread: ManifestRead,
    report: VerifyReport,
    progress: ProgressSink,
    cancel: CancelToken,
    *,
    in_creation: bool = False,
) -> None:
    manifest = mread.manifest
    report.total_files = len(manifest.files)
    report.total_bytes = manifest.total_bytes()
    progress.stage("Verificando blocos criptografados", report.total_bytes, report.total_files)
    for e in manifest.files:
        cancel.check()
        path = opened.layout.blob(e.file_id)
        shown = display_path(e.path)
        try:
            sha, _ = decrypt_blob(
                path,
                opened.master_key,
                opened.vault_id,
                e.file_id,
                e.size,
                None,
                cancel.check,
                lambda n: progress.advance(n),
                unbuffered=True,
            )
        except FileNotFoundError:
            report.bad.append(f"{shown}: dado criptografado ausente")
            continue
        except OwlVaultError as exc:
            if isinstance(exc, (VaultLockedError, CancelledError)):
                raise
            report.bad.append(f"{shown}: {exc}")
            continue
        except OSError as exc:
            report.bad.append(f"{shown}: erro de leitura ({exc.strerror or exc})")
            continue
        if sha != e.sha256:
            report.bad.append(f"{shown}: conteúdo não confere com o hash do manifesto")
            continue
        report.files_ok += 1
        progress.advance(0, 1)
    report.anomalies.extend(
        data_anomalies(
            opened.layout, opened.vault_id, {e.file_id for e in manifest.files}, in_creation
        )
    )


def data_anomalies(
    layout: VaultLayout, vault_id: bytes, referenced: set[bytes], in_creation: bool
) -> list[str]:
    """Tudo em data/ (e na raiz) que não é exatamente um blob do manifesto."""
    out: list[str] = []
    try:
        root_names = os.listdir(layout.root)
    except OSError as exc:
        return [f"não foi possível listar a pasta do cofre ({exc})"]
    for name in root_names:
        if name in KNOWN_ROOT_NAMES:
            continue
        out.append(f"item desconhecido na pasta do cofre: {name}")
    try:
        hh_names = os.listdir(layout.data_dir)
    except FileNotFoundError:
        hh_names = []
    for hh in hh_names:
        hh_path = winfs.join(layout.data_dir, hh)
        st = os.lstat(hh_path)
        if not HH_RE.fullmatch(hh) or not winfs.is_plain_dir(st):
            out.append(f"item desconhecido em {DATA_DIR}: {hh}")
            continue
        for name in os.listdir(hh_path):
            p = winfs.join(hh_path, name)
            if not BLOB_RE.fullmatch(name):
                out.append(f"arquivo inesperado em {DATA_DIR}\\{hh}: {name}")
                continue
            fid = bytes.fromhex(name[:32])
            if name[:2] != hh:
                out.append(f"blob na subpasta errada: {DATA_DIR}\\{hh}\\{name}")
                continue
            if fid in referenced:
                continue
            try:
                header = read_blob_header(p)
                if header.vault_id != vault_id:
                    out.append(f"blob de outro cofre: {DATA_DIR}\\{hh}\\{name}")
                    continue
            except (OSError, OwlVaultError):
                out.append(f"blob ilegível não referenciado: {DATA_DIR}\\{hh}\\{name}")
                continue
            out.append(f"blob não referenciado pelo manifesto: {DATA_DIR}\\{hh}\\{name}")
    if not in_creation and os.path.isdir(layout.journal_dir):
        out.append(f"pasta {JOURNAL_DIR} presente (criação não finalizada)")
    return out


def verify_vault(
    vault_dir: str,
    password: str,
    *,
    policy: KdfPolicy,
    progress: ProgressSink | None = None,
    cancel: CancelToken | None = None,
) -> VerifyReport:
    progress = progress or NullProgress()
    cancel = cancel or CancelToken()
    root = winfs.to_extended(vault_dir)
    report = VerifyReport(display(root))
    lock = winfs.ExclusiveLock(VaultLayout(root).lock, "O cofre")
    locked = False
    try:
        lock.acquire()
        locked = True
    except VaultLockedError:
        raise
    except UnsafePathError as exc:
        report.lock_note = f"{exc} Verificação feita sem trava."
        report.anomalies.append("trava do cofre inválida/adulterada (.owlvault.lock)")
    except OwlVaultError as exc:
        report.lock_note = f"{exc} Verificação feita sem trava (mídia somente leitura?)."
    fallbacks_before = winfs.unbuffered_fallback_count()
    try:
        progress.stage("Abrindo o cofre (derivando chave — não cancelável)")
        opened = open_vault(root, password, policy, unbuffered=True)
        # Problemas nas cópias redundantes NÃO são observações menores: o cofre perdeu a
        # redundância do cabeçalho/manifesto (FORMAT §3.1 passo 5).
        report.redundancy.extend(opened.notes)
        mread = read_manifest(opened, unbuffered=True)
        report.redundancy.extend(mread.notes)
        info, status = read_completion(opened, mread.raw)
        report.creation_status = status
        report.completed = info is not None
        verify_contents(opened, mread, report, progress, cancel)
    finally:
        if locked:
            lock.release()
    if winfs.unbuffered_fallback_count() != fallbacks_before:
        report.unbuffered_fallback = True
        report.notes.append(
            "O sistema de arquivos não aceitou leitura sem cache em alguns arquivos; eles foram "
            "conferidos com leitura normal. Verifique de novo após reconectar a mídia."
        )
    return report
