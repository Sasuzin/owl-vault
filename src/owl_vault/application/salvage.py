"""Salvamento de emergência sem manifesto (ARCHITECTURE §4.5, docs/RECOVERY.md).

Decifra cada blob autenticável do cofre para ``recuperado-00001.bin``... numa pasta nova e
vazia. Os nomes originais NÃO são recuperáveis sem o manifesto.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from owl_vault.application.common import display
from owl_vault.application.progress import CancelToken, NullProgress, ProgressSink
from owl_vault.application.protection import ProtectedPaths, destination_location_problems
from owl_vault.application.restore import restore_file_content
from owl_vault.application.vault import open_vault
from owl_vault.crypto.kdf import KdfPolicy
from owl_vault.domain.errors import IntegrityError, OwlVaultError, UnsafePathError
from owl_vault.storage import winfs
from owl_vault.storage.blob import read_blob_header
from owl_vault.storage.layout import BLOB_RE, HH_RE


@dataclass
class SalvageReport:
    destination: str
    recovered: int = 0
    failed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def salvage_vault(
    vault_dir: str,
    password: str,
    dest_dir: str,
    *,
    policy: KdfPolicy,
    protected: ProtectedPaths | None = None,
    progress: ProgressSink | None = None,
    cancel: CancelToken | None = None,
) -> SalvageReport:
    progress = progress or NullProgress()
    cancel = cancel or CancelToken()
    protected = protected if protected is not None else ProtectedPaths.from_environment()
    vault_ext = winfs.to_extended(vault_dir)
    dest_ext = winfs.to_extended(dest_dir)
    vres = winfs.resolve(vault_ext)
    dres = winfs.resolve(dest_ext)
    problems = destination_location_problems(dres, protected, "O destino")
    if dres.overlaps(vres):
        problems.append("O destino não pode ficar dentro do cofre.")
    if problems:
        raise UnsafePathError(" ".join(problems))
    if dres.exists:
        if os.listdir(dest_ext):
            raise UnsafePathError("A pasta de destino não está vazia.")
    else:
        os.mkdir(dest_ext)
    root = winfs.resolve(dest_ext)
    opened = open_vault(vault_ext, password, policy, strict_hints=False)
    report = SalvageReport(display(dest_ext), notes=list(opened.notes))
    blobs: list[str] = []
    data_dir = opened.layout.data_dir
    for hh in sorted(os.listdir(data_dir)) if os.path.isdir(data_dir) else []:
        hp = winfs.join(data_dir, hh)
        if not HH_RE.fullmatch(hh) or not winfs.is_plain_dir(os.lstat(hp)):
            continue
        for name in sorted(os.listdir(hp)):
            if BLOB_RE.fullmatch(name):
                blobs.append(winfs.join(hp, name))
    progress.stage("Salvamento de emergência", 0, len(blobs))
    with winfs.ExclusiveLock(winfs.join(dest_ext, ".owlvault-restore.lock"), "A pasta de destino"):
        for i, path in enumerate(blobs, start=1):
            cancel.check()
            name = winfs.name_of(path)
            try:
                header = read_blob_header(path)
                if header.vault_id != opened.vault_id:
                    raise IntegrityError("blob de outro cofre")
                restore_file_content(
                    opened,
                    blob_path=path,
                    expected_file_id=header.file_id,
                    expected_size=None,
                    expected_sha256=None,
                    dest_dir=dest_ext,
                    final_name=f"recuperado-{i:05d}.bin",
                    part_prefix=".owl-salvage-",
                    root=root,
                    mtime_ns=None,
                    motw=False,
                    cancel=cancel,
                    progress=progress,
                )
                report.recovered += 1
            except (OwlVaultError, OSError) as exc:
                report.failed.append(f"{name}: {exc}")
            progress.advance(0, 1)
    return report
