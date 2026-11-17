"""Abertura do cofre: algoritmo normativo do cabeçalho (FORMAT §3.1), manifesto com cópia
de segurança (FORMAT §5.1) e registro de conclusão (FORMAT §5.4)."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

from owl_vault.crypto.kdf import KdfPolicy, derive_kek
from owl_vault.domain.errors import (
    AuthenticationError,
    FormatError,
    InconsistentVaultError,
    IntegrityError,
    OwlVaultError,
    ResourceError,
    StateError,
    UnsafePathError,
)
from owl_vault.domain.limits import ID_SIZE, MAX_ENTRIES, MAX_FILE_SIZE
from owl_vault.storage import winfs
from owl_vault.storage.container import (
    ContainerKind,
    get_hex,
    get_int,
    get_str,
    parse_container_header,
    read_container,
    read_file_bounded,
    require_object,
)
from owl_vault.storage.header import HEADER_SIZE, VaultHeader, parse_header, unwrap_with_kek
from owl_vault.storage.journal import list_segment_files
from owl_vault.storage.layout import HEADER_BAK_NAME, HEADER_NAME, VaultLayout
from owl_vault.storage.manifest import Manifest, manifest_from_obj


def read_unbuffered(path: str, max_size: int) -> bytes:
    """Lê um arquivo pequeno do cofre sem cache do sistema (bytes do dispositivo)."""
    with winfs.UnbufferedReader(path) as r:
        size = r.info().size
        if size > max_size:
            raise FormatError("arquivo do cofre maior que o permitido")
        return r.read(size + 1)


@dataclass
class OpenedVault:
    layout: VaultLayout
    header: VaultHeader
    master_key: bytes
    header_used: str
    notes: list[str] = field(default_factory=list)

    @property
    def vault_id(self) -> bytes:
        return self.header.vault_id


def hint_vault_ids(layout: VaultLayout) -> set[bytes]:
    """``vault_id`` em claro (NÃO autenticados) do manifesto, do .bak e do segmento 0.

    São apenas dicas: uma cópia corrompida não pode vetar sozinha um cabeçalho autêntico,
    por isso o conjunto inteiro é considerado.
    """
    candidates = [layout.manifest, layout.manifest_bak]
    segs = list_segment_files(layout)
    if segs:
        candidates.append(segs[0][1])
    found: set[bytes] = set()
    for path in candidates:
        kind = ContainerKind.JOURNAL if path.endswith(".owlj") else ContainerKind.MANIFEST
        if not winfs.is_plain_file_at(path):  # nunca seguir links ao ler arquivos do cofre
            continue
        try:
            with open(path, "rb") as fh:
                head = fh.read(4096)
            vid, _, _ = parse_container_header(head + b"\x00" * 16, kind)
            found.add(vid)
        except (OSError, FormatError):
            continue
    return found


def open_vault(
    vault_dir: str,
    password: str,
    policy: KdfPolicy,
    *,
    unbuffered: bool = False,
    strict_hints: bool = True,
) -> OpenedVault:
    """Desbloqueia o cofre seguindo o algoritmo normativo do cabeçalho.

    ``strict_hints=False`` (só para o salvamento de emergência): os ``vault_id`` em claro do
    manifesto/diário apenas ORDENAM as cópias; não podem vetar um cabeçalho autêntico.
    """
    root = winfs.to_extended(vault_dir)
    layout = VaultLayout(root)
    try:
        st = os.lstat(root)
    except FileNotFoundError as exc:
        raise OwlVaultError("A pasta do cofre não existe.") from exc
    if not winfs.is_plain_dir(st):
        raise UnsafePathError("a pasta do cofre não é uma pasta comum (link/ponto de reparse?)")

    notes: list[str] = []
    copies: list[tuple[str, bytes, VaultHeader]] = []
    for name, path in ((HEADER_NAME, layout.header), (HEADER_BAK_NAME, layout.header_bak)):
        try:
            raw = (
                read_unbuffered(path, HEADER_SIZE)
                if unbuffered
                else read_file_bounded(path, HEADER_SIZE)
            )
            copies.append((name, raw, parse_header(raw, policy)))
        except FileNotFoundError:
            notes.append(f"{name}: ausente")
        except (FormatError, OSError) as exc:
            notes.append(f"{name}: inválido ({exc})")
    if not copies:
        raise FormatError(
            "Esta pasta não contém um cabeçalho de cofre válido do Owl Vault "
            "(vault.owl e vault.owl.bak ausentes ou inválidos)."
        )
    mem = winfs.memory_status()
    avail = mem.available_commit if mem else None
    hints = hint_vault_ids(layout)

    def matches(vid: bytes) -> bool:
        if not hints or vid in hints:
            return True
        if not strict_hints:
            note = "manifesto/diário em claro não corresponde ao cabeçalho (ignorado)"
            if note not in notes:
                notes.append(note)
            return True
        return False

    # Caso comum: duas cópias idênticas ⇒ uma derivação.
    if len(copies) == 2 and copies[0][1] == copies[1][1]:
        name, _, hdr = copies[0]
        kek = derive_kek(password, hdr.salt, hdr.kdf, policy, avail)
        try:
            master = unwrap_with_kek(hdr, kek)
        except AuthenticationError as exc:
            raise AuthenticationError(
                "Senha incorreta (ou as duas cópias do cabeçalho estão corrompidas)."
            ) from exc
        if not matches(hdr.vault_id):
            raise InconsistentVaultError(
                "O cabeçalho não corresponde ao conteúdo desta pasta (cofre misturado?)."
            )
        return OpenedVault(layout, hdr, master, name, notes)

    if len(copies) == 2:
        notes.append("as duas cópias do cabeçalho são diferentes (provável corrupção de uma delas)")
    copies.sort(key=lambda c: 0 if hints and c[2].vault_id in hints else 1)
    kek_cache: dict[tuple[bytes, object], bytes] = {}
    successes: list[tuple[str, VaultHeader, bytes]] = []
    resource_error: ResourceError | None = None
    for name, _, hdr in copies:
        key = (hdr.salt, hdr.kdf)
        try:
            if key not in kek_cache:
                kek_cache[key] = derive_kek(password, hdr.salt, hdr.kdf, policy, avail)
            master = unwrap_with_kek(hdr, kek_cache[key])
        except AuthenticationError:
            notes.append(f"{name}: não autenticou")
            continue
        except ResourceError as exc:
            # falta de memória não é "senha incorreta": guarda e relata se nada abrir
            resource_error = exc
            continue
        successes.append((name, hdr, master))
    if not successes and resource_error is not None:
        raise resource_error
    if not successes:
        if len(copies) == 1:
            raise AuthenticationError(
                "Senha incorreta ou cabeçalho corrompido (a cópia de segurança do cabeçalho "
                "está ausente ou inválida)."
            )
        raise AuthenticationError(
            "Cabeçalhos divergentes — provável corrupção (ou senha incorreta)."
        )
    if len(successes) == 2:
        (_, h1, m1), (_, h2, m2) = successes
        if h1.vault_id != h2.vault_id or m1 != m2:
            raise InconsistentVaultError(
                "As duas cópias do cabeçalho abrem com esta senha, mas são de cofres diferentes."
            )
    for name, hdr, master in successes:
        if matches(hdr.vault_id):
            if name != HEADER_NAME:
                notes.append(f"usando a cópia de segurança do cabeçalho ({name})")
            return OpenedVault(layout, hdr, master, name, notes)
    raise InconsistentVaultError(
        "O cabeçalho abre com esta senha, mas não corresponde ao manifesto desta pasta."
    )


@dataclass(frozen=True, slots=True)
class ManifestRead:
    manifest: Manifest
    raw: bytes
    used: str
    notes: list[str]


def read_manifest(opened: OpenedVault, *, unbuffered: bool = False) -> ManifestRead:
    """Regra de leitura do manifesto e de sua cópia (FORMAT §5.1)."""
    layout = opened.layout
    good: dict[str, tuple[Manifest, bytes]] = {}
    notes: list[str] = []
    absent = 0
    reader = (
        (lambda p: read_unbuffered(p, ContainerKind.MANIFEST.max_file_size)) if unbuffered else None
    )
    for name, path in (
        ("manifest.owl", layout.manifest),
        ("manifest.owl.bak", layout.manifest_bak),
    ):
        try:
            read = read_container(
                path, ContainerKind.MANIFEST, opened.master_key, opened.vault_id, reader
            )
            good[name] = (manifest_from_obj(read.obj, opened.vault_id), read.raw)
        except FileNotFoundError:
            absent += 1
            notes.append(f"{name}: ausente")
        except (OwlVaultError, OSError) as exc:
            notes.append(f"{name}: inválido ({exc})")
    if len(good) == 2:
        (m1, r1), (_, r2) = good["manifest.owl"], good["manifest.owl.bak"]
        if r1 != r2:
            raise InconsistentVaultError(
                "Manifestos divergentes: as duas cópias são autênticas e diferentes."
            )
        return ManifestRead(m1, r1, "manifest.owl", notes)
    if len(good) == 1:
        name, (m, raw) = next(iter(good.items()))
        notes.append(f"usando {name} (a outra cópia do manifesto está ausente ou inválida)")
        return ManifestRead(m, raw, name, notes)
    if absent == 2:
        raise StateError(
            "O manifesto ainda não foi gravado: a criação deste cofre não foi concluída. "
            "Use 'Retomar criação'."
        )
    raise IntegrityError(
        "Manifesto corrompido nas duas cópias. Veja docs/RECOVERY.md (salvamento de emergência)."
    )


@dataclass(frozen=True, slots=True)
class CompletionInfo:
    files: int
    dirs: int
    total_bytes: int
    divergences: int
    completed_utc: str


def read_completion(opened: OpenedVault, manifest_raw: bytes) -> tuple[CompletionInfo | None, str]:
    """Retorna (info, mensagem de status da criação)."""
    path = opened.layout.complete
    not_done = "Criação NÃO concluída / teste de restauração não executado."
    try:
        read = read_container(path, ContainerKind.COMPLETE, opened.master_key, opened.vault_id)
    except FileNotFoundError:
        return None, not_done
    except (OwlVaultError, OSError):
        return None, not_done + " (registro de conclusão inválido)"
    try:
        o = require_object(
            read.obj,
            {
                "kind",
                "vault_id",
                "manifest_sha256",
                "files",
                "dirs",
                "bytes",
                "restore_test",
                "divergences",
                "completed_utc",
            },
        )
        if get_hex(o, "vault_id", ID_SIZE) != opened.vault_id:
            return None, not_done + " (registro de outro cofre)"
        if get_hex(o, "manifest_sha256", 32) != hashlib.sha256(manifest_raw).digest():
            return None, not_done + " (registro não corresponde ao manifesto)"
        if o["restore_test"] != "passed":
            return None, not_done
        info = CompletionInfo(
            files=get_int(o, "files", 0, MAX_ENTRIES),
            dirs=get_int(o, "dirs", 0, MAX_ENTRIES),
            total_bytes=get_int(o, "bytes", 0, MAX_ENTRIES * MAX_FILE_SIZE),
            divergences=get_int(o, "divergences", 0, MAX_ENTRIES),
            completed_utc=get_str(o, "completed_utc", 64),
        )
    except OwlVaultError:
        return None, not_done + " (registro de conclusão inválido)"
    if info.divergences:
        return info, (
            f"Criação concluída e testada em {info.completed_utc}, COM {info.divergences} "
            "divergência(s): a origem mudou durante/após a cifragem."
        )
    return info, f"Criação concluída e testada em {info.completed_utc}."
