"""Pastas protegidas: trancar no lugar, abrir, esconder, mostrar, remover proteção.

PASTAS_PROTEGIDAS.md §3–§5. Regras de segurança (resultado da revisão adversarial):

* Os dados cifrados ficam DENTRO da pasta (``P\\.owlvault``); a área temporária
  ``<pai>\\.owlvault-<id>`` (mesmo volume, fora de P) guarda o cofre em criação (``novo``) e o
  cofre da pasta aberta (``anterior``).
* Originais só são apagados depois de ``create_vault`` concluir com sucesso (verificação +
  teste de restauração) e cada arquivo é conferido no handle antes (impressão digital).
* **Regra de ouro** (``_vault_may_be_deleted``): um cofre só é apagado se tudo o que ele tem
  está num cofre mais novo e concluído da mesma pasta (ou o usuário aceitou a lista exata).
* Nunca roda outro ``create_vault`` enquanto um cofre estiver parcialmente aplicado.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field

from owl_vault.application.common import read_zone_id, write_motw
from owl_vault.application.create import CreateResult, create_vault
from owl_vault.application.keysource import KeySource
from owl_vault.application.preflight import CreatePlan, preflight_create
from owl_vault.application.profile import FolderRecord, KekEntry, ProfileSession, VaultRef
from owl_vault.application.progress import CancelToken, NullProgress, ProgressSink
from owl_vault.application.protection import ProtectedPaths
from owl_vault.application.restore import (
    MARKER_NAME,
    RESTORE_LOCK_NAME,
    RestoreReport,
    inspect_destination,
    remove_restore_marker,
    restore_vault,
    write_restore_marker,
)
from owl_vault.application.vault import open_vault, read_completion, read_manifest
from owl_vault.crypto.kdf import PRODUCTION_POLICY, KdfPolicy, derive_kek
from owl_vault.domain.errors import (
    AuthenticationError,
    OwlVaultError,
    PreflightError,
    StateError,
    UnsafePathError,
)
from owl_vault.domain.models import FileEntryRecord, FileIdentity, Fingerprint
from owl_vault.domain.names import display_path, fold_path
from owl_vault.storage import shell, winfs
from owl_vault.storage.atomic import safe_remove_own, safe_rmdir_own, write_new_no_replace
from owl_vault.storage.header import HEADER_SIZE, parse_header
from owl_vault.storage.layout import (
    BLOB_RE,
    CHK_RE,
    HH_RE,
    PROBE_RE,
    ROOT_TMP_RE,
    SEGMENT_RE,
    SEGMENT_TMP_RE,
    TEST_DIR_RE,
    TEST_PART_RE,
)
from owl_vault.storage.scan import scan_tree

VAULT_DIR = ".owlvault"
ICON_NAME = ".owlvault.ico"
DESKTOP_INI = "desktop.ini"
SHORTCUT_NAME = "Abrir com Owl Vault.lnk"
HELP_NAME = "Como abrir esta pasta.txt"
PLACEHOLDER = (DESKTOP_INI, ICON_NAME, SHORTCUT_NAME, HELP_NAME)
_PLACEHOLDER_RE = re.compile("|".join(re.escape(n) for n in PLACEHOLDER))
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
HIDE = shell.FILE_ATTRIBUTE_HIDDEN | shell.FILE_ATTRIBUTE_SYSTEM
INFOTIP = "Pasta protegida pelo Owl Vault — os arquivos estão aqui, criptografados. Não apague."
HELP_TEXT = (
    "Esta pasta está protegida pelo Owl Vault e seus arquivos estão aqui dentro, "
    "criptografados.\r\n\r\n"
    "Para abrir: dê dois cliques em 'Abrir com Owl Vault' ou abra o programa Owl Vault e "
    "digite seu PIN.\r\n\r\n"
    "Se o programa não estiver mais neste computador, instale-o de novo e use 'Recuperar uma "
    "pasta protegida' com a sua senha mestra.\r\n\r\n"
    "Não apague esta pasta: apagar a pasta apaga os arquivos.\r\n"
)

# estados gravados no índice
ABERTA = "aberta"
TRANCANDO = "trancando"
APAGANDO = "apagando"
TRANCADA = "trancada"
ABRINDO = "abrindo"
ABERTURA_INCOMPLETA = "abertura_incompleta"
#: papel de cofre "versão anterior mantida": nunca apagado sem a confirmação do usuário
MANTIDO = "mantido"


@dataclass
class FolderView:
    record: FolderRecord
    label: str  # estado por extenso para a interface
    action: str  # "abrir" | "trancar" | "resolver" | ""
    attention: str = ""
    available: bool = True
    #: "" | apagando | abertura_incompleta | abrindo | trancando | itens_extras | sem_dados |
    #: nao_encontrada | indisponivel | versao_anterior | senha_antiga
    issue: str = ""
    base_action: str = ""  # ação normal do estado (para o menu ⋯ quando há atenção)


@dataclass
class LockOutcome:
    record: FolderRecord
    complete: bool
    pending: list[str] = field(default_factory=list)
    kept_previous: bool = False
    removable: bool = False


@dataclass
class UnlockOutcome:
    record: FolderRecord
    complete: bool
    report: RestoreReport | None = None
    path: str = ""


@dataclass
class ProtectCheck:
    """Resultado da pré-verificação, para a caixa de confirmação (UI T5d)."""

    path: str
    name: str
    files: int
    total_bytes: int
    plan: CreatePlan


def _rel_key(path: tuple[str, ...]) -> str:
    return "\\".join(path)


def _fp_to_list(fp: Fingerprint) -> list[object]:
    return [fp.identity.volume_serial, fp.identity.file_id.hex(), fp.size, fp.mtime_ns, fp.ctime_ns]


def _fp_from_list(v: list[object]) -> Fingerprint:
    vol, fid, size, mtime, ctime = v
    return Fingerprint(
        FileIdentity(int(str(vol)), bytes.fromhex(str(fid))),
        int(str(size)),
        int(str(mtime)),
        int(str(ctime)),
    )


class LockerManager:
    def __init__(
        self,
        session: ProfileSession,
        *,
        icon_bytes: bytes,
        launcher: tuple[str, str],
        policy: KdfPolicy = PRODUCTION_POLICY,
        protected: ProtectedPaths | None = None,
        known_folders: dict[str, str] | None = None,
        create_shortcuts: bool = True,
    ) -> None:
        self.session = session
        self.icon_bytes = icon_bytes
        self.launcher = launcher
        self.policy = policy
        self.protected = protected
        self._known = known_folders
        self.create_shortcuts = create_shortcuts

    # ------------------------------------------------------------------ utilidades
    @property
    def folders(self) -> list[FolderRecord]:
        return self.session.index.folders

    def _save(self) -> None:
        self.session.save()

    def _protected(self) -> ProtectedPaths:
        if self.protected is None:
            self.protected = ProtectedPaths.from_environment()
        return self.protected

    def _known_folders(self) -> dict[str, str]:
        if self._known is None:
            self._known = shell.known_folders()
        return self._known

    @staticmethod
    def staging_of(rec: FolderRecord) -> str:
        return winfs.join(winfs.parent_of(rec.path), f".owlvault-{rec.id}")

    def _get(self, folder_id: str) -> FolderRecord:
        rec = self.session.index.folder(folder_id)
        if rec is None:
            raise StateError("Pasta protegida não encontrada na lista.")
        return rec

    def _locate(self, rec: FolderRecord) -> str:
        """Confere que a pasta no caminho registrado é a MESMA (volume + FileId)."""
        try:
            res = winfs.resolve(rec.path)
        except OwlVaultError as exc:
            raise StateError(f"A unidade de '{rec.name}' não está disponível.") from exc
        if (
            not res.exists
            or not res.is_directory
            or res.identity is None
            or res.identity.file_id.hex() != rec.file_id
            or res.volume != rec.volume
        ):
            raise StateError(
                f"A pasta '{rec.name}' não está mais em {winfs.strip_extended(rec.path)} (foi "
                "movida, renomeada ou substituída). Use 'Procurar a pasta…'."
            )
        return rec.path

    def keys_for_vault(self, vault_dir: str) -> KeySource:
        """Escolhe a KEK do perfil cujo salt/params batem com o cabeçalho do cofre."""
        hdr = None
        for name in ("vault.owl", "vault.owl.bak"):
            p = winfs.join(vault_dir, name)
            if not winfs.is_plain_file_at(p):
                continue
            try:
                with open(p, "rb") as fh:
                    hdr = parse_header(fh.read(HEADER_SIZE + 1), self.policy)
                break
            except (OSError, OwlVaultError):
                continue
        if hdr is None:
            raise OwlVaultError("o cofre da pasta está ilegível (cabeçalho ausente)")
        for k in self.session.index.keks:
            if k.salt == hdr.salt and k.params == hdr.kdf:
                return KeySource(salt=k.salt, params=k.params, kek=k.kek)
        raise AuthenticationError(
            "Esta pasta foi protegida com outra senha mestra. Use 'Recuperar uma pasta protegida'."
        )

    @staticmethod
    def _vault_id_of(vault_dir: str) -> str:
        with open(winfs.join(vault_dir, "vault.owl"), "rb") as fh:
            raw = fh.read(HEADER_SIZE)
        return raw[16:32].hex()

    # ------------------------------------------------------------------ estado exibido
    def views(self) -> list[FolderView]:
        out: list[FolderView] = []
        for rec in self.folders:
            out.append(self.view(rec))
        return out

    def view(self, rec: FolderRecord) -> FolderView:
        attention = "Precisa de atenção"
        try:
            self._locate(rec)
        except StateError as exc:
            if "unidade" in str(exc):
                drive = winfs.strip_extended(rec.path)[:2]
                return FolderView(
                    rec,
                    f"Indisponível — conecte a unidade {drive}",
                    "",
                    str(exc),
                    available=False,
                    issue="indisponivel",
                )
            return FolderView(rec, attention, "resolver", str(exc), issue="nao_encontrada")
        texts = {
            APAGANDO: (
                "O trancamento foi interrompido. Seus arquivos já estão guardados; "
                "clique em 'Continuar trancando' ou 'Desfazer'."
            ),
            ABERTURA_INCOMPLETA: "Alguns arquivos não puderam ser abertos.",
            ABRINDO: "A abertura foi interrompida. Clique em 'Continuar abrindo'.",
            TRANCANDO: "O trancamento foi interrompido antes de apagar qualquer arquivo.",
        }
        if rec.state in texts:
            return FolderView(
                rec, attention, "resolver", rec.attention or texts[rec.state], issue=rec.state
            )
        base = "abrir" if rec.state == TRANCADA else "trancar"
        if rec.state == TRANCADA:
            problem = self._locked_content_problem(rec)
            if problem:
                issue = "sem_dados" if "não foram encontrados" in problem else "itens_extras"
                return FolderView(
                    rec, attention, "resolver", problem, issue=issue, base_action=base
                )
        if any(v.role == MANTIDO for v in rec.vaults):
            n = len(self.kept_only_files(rec.id))
            return FolderView(
                rec,
                attention,
                "resolver",
                f"Foi mantida uma versão anterior de '{rec.name}' com {n} arquivo(s) que não "
                "estão na pasta.",
                issue="versao_anterior",
                base_action=base,
            )
        if rec.state == TRANCADA and self._uses_old_master(rec):
            return FolderView(
                rec,
                attention,
                "resolver",
                "Você criou uma senha mestra nova. Abra e tranque esta pasta de novo para que ela "
                "passe a usar a senha nova.",
                issue="senha_antiga",
                base_action=base,
            )
        if rec.state == TRANCADA:
            return FolderView(
                rec, "Escondida" if rec.hidden else "Trancada", "abrir", base_action=base
            )
        return FolderView(rec, "Aberta — visível neste computador", "trancar", base_action=base)

    def _uses_old_master(self, rec: FolderRecord) -> bool:
        current = rec.vault("atual")
        if current is None or not self.session.index.keks:
            return False
        try:
            ks = self.keys_for_vault(current.location)
        except (OwlVaultError, OSError):
            return False
        return ks.salt != self.session.index.keks[0].salt

    # ------------------------------------------------------------------ versões mantidas
    def kept_only_files(self, folder_id: str) -> list[str]:
        """Arquivos que só existem nas versões anteriores mantidas (não estão no cofre atual
        nem na pasta aberta)."""
        rec = self._get(folder_id)
        present: set[tuple[str, ...]] = set()
        current = (
            rec.vault("atual") if rec.state == TRANCADA else self._latest_previous_or_none(rec)
        )
        if current is not None:
            present |= self._manifest_keys(current.location)
        kept = self._manifest_entries_of_kept(rec)
        if rec.state != TRANCADA:
            for e in kept:
                if os.path.lexists(winfs.join(rec.path, *e)):
                    present.add(fold_path(e))
        return sorted({_rel_key(e) for e in kept if fold_path(e) not in present})

    def _manifest_keys(self, vault_dir: str) -> set[tuple[str, ...]]:
        try:
            opened = open_vault(vault_dir, self.keys_for_vault(vault_dir), self.policy)
            return {fold_path(e.path) for e in read_manifest(opened).manifest.files}
        except (OwlVaultError, OSError):
            return set()

    def _manifest_entries_of_kept(self, rec: FolderRecord) -> list[tuple[str, ...]]:
        out: list[tuple[str, ...]] = []
        for v in rec.vaults:
            if v.role != MANTIDO:
                continue
            try:
                opened = open_vault(v.location, self.keys_for_vault(v.location), self.policy)
                out.extend(e.path for e in read_manifest(opened).manifest.files)
            except (OwlVaultError, OSError):
                continue
        return out

    @staticmethod
    def _latest_previous_or_none(rec: FolderRecord) -> VaultRef | None:
        prev = None
        for v in rec.vaults:
            if v.role == "anterior":
                prev = v
        return prev

    def restore_kept(
        self,
        folder_id: str,
        dest_parent: str,
        progress: ProgressSink | None = None,
        cancel: CancelToken | None = None,
    ) -> list[RestoreReport]:
        """Recupera as versões mantidas em pastas NOVAS dentro de ``dest_parent``."""
        rec = self._get(folder_id)
        reports: list[RestoreReport] = []
        n = 1
        for v in rec.vaults:
            if v.role != MANTIDO:
                continue
            while True:
                suffix = "" if n == 1 else f" {n}"
                dest = winfs.join(
                    winfs.to_extended(dest_parent), f"{rec.name} (versão anterior{suffix})"
                )
                n += 1
                if not os.path.lexists(dest):
                    break
            reports.append(
                restore_vault(
                    v.location,
                    self.keys_for_vault(v.location),
                    dest,
                    policy=self.policy,
                    protected=self._protected(),
                    session_sources=[rec.path],
                    progress=progress,
                    cancel=cancel,
                )
            )
        return reports

    def delete_kept(self, folder_id: str, confirmed: list[str]) -> None:
        """'Apagar a versão anterior…': só com a lista exata confirmada pelo usuário."""
        rec = self._get(folder_id)
        if sorted(confirmed) != self.kept_only_files(folder_id):
            raise StateError("A lista de arquivos mudou; confira de novo antes de apagar.")
        for v in list(rec.vaults):
            if v.role == MANTIDO:
                self._remove_vault_tree(v.location, rec)
                if not os.path.lexists(v.location):
                    rec.vaults.remove(v)
        rec.attention = ""
        self._save()
        self._cleanup_staging(rec)

    def _locked_content_problem(self, rec: FolderRecord) -> str:
        names = set(os.listdir(rec.path))
        extra = sorted(n for n in names if n not in PLACEHOLDER and n != VAULT_DIR)
        if extra:
            shown = ", ".join(extra[:5]) + (f" e mais {len(extra) - 5}" if len(extra) > 5 else "")
            return (
                f"Há item(ns) colocado(s) em '{rec.name}' depois de trancar: {shown}. Mova-os para "
                "outro lugar e tente de novo."
            )
        if VAULT_DIR not in names:
            return f"Os arquivos criptografados de '{rec.name}' não foram encontrados na pasta."
        return ""

    # ------------------------------------------------------------------ proteger
    def check_protect(
        self, path: str, progress: ProgressSink | None = None, cancel: CancelToken | None = None
    ) -> ProtectCheck:
        """Pré-verificação do modo trancar (nada é gravado além da área temporária vazia)."""
        p_ext = winfs.to_extended(path)
        rid = secrets.token_hex(16)
        staging = winfs.join(winfs.parent_of(p_ext), f".owlvault-{rid}")
        try:
            os.mkdir(staging)
        except OSError as exc:
            raise PreflightError(
                "O Windows não deixa criar arquivos ao lado desta pasta. Mova-a para dentro de "
                "Documentos e tente de novo.",
                [str(exc)],
            ) from exc
        try:
            plan = self._preflight(p_ext, winfs.join(staging, "novo"), staging, progress, cancel)
        finally:
            try:
                os.rmdir(staging)
            except OSError:
                pass
        name = winfs.name_of(p_ext)
        return ProtectCheck(p_ext, name, len(plan.files), plan.total_bytes, plan)

    def _preflight(
        self,
        p_ext: str,
        vault_dir: str,
        staging: str,
        progress: ProgressSink | None,
        cancel: CancelToken | None,
        *,
        exclude_record: str | None = None,
    ) -> CreatePlan:
        plan = preflight_create(
            p_ext,
            vault_dir,
            test_parent=staging,
            protected=self._protected(),
            progress=progress,
            cancel=cancel,
        )
        blockers = list(plan.blockers)
        src = plan.source_res
        if src is not None and src.exists:
            if src.fs_name.upper() not in ("NTFS", "REFS"):
                blockers.insert(
                    0,
                    f"Esta unidade usa {src.fs_name}. O Owl Vault só tranca pastas em unidades "
                    "NTFS. Para pendrives, use ☰ > Cópia criptografada de uma pasta.",
                )
            for label, kpath in self._known_folders().items():
                try:
                    kres = winfs.resolve(kpath)
                except OwlVaultError:
                    continue
                if kres.same(src):
                    blockers.insert(
                        0,
                        f"Não dá para proteger a pasta {label} inteira. Crie uma pasta dentro dela "
                        f"(ex.: {label}\\Particular), coloque lá o que quer esconder e proteja essa.",
                    )
                elif kres.is_within(src):
                    blockers.insert(
                        0,
                        f"Esta pasta contém a pasta {label}, que o Windows usa. Escolha uma pasta "
                        "que não contenha pastas do sistema.",
                    )
            for other in self.folders:
                if other.id == exclude_record:
                    continue
                try:
                    ores = winfs.resolve(other.path)
                except OwlVaultError:
                    continue
                if ores.overlaps(src):
                    blockers.insert(
                        0, f"Esta pasta fica dentro (ou contém) '{other.name}', que já é protegida."
                    )
        for d in plan.dirs:
            if d.path[-1].lower() == VAULT_DIR:
                blockers.append(
                    f"{display_path(d.path)}: já é uma pasta protegida pelo Owl Vault (dentro desta)."
                )
        for f in plan.files:
            if f.links > 1:
                blockers.append(
                    f"O arquivo '{display_path(f.path)}' também existe em outro lugar do computador "
                    "(vínculo do Windows). Trancado aqui, continuaria visível lá."
                )
            if f.path[-1].lower() == DESKTOP_INI:
                try:
                    with open(f.ext_path, "rb") as fh:
                        raw = fh.read(65536)
                    text = raw.decode("utf-16") if raw[:2] == b"\xff\xfe" else raw.decode("latin-1")
                except (OSError, UnicodeDecodeError):
                    text = ""
                low = text.lower()
                if "clsid" in low or "localizedresourcename" in low:
                    blockers.append(
                        f"A pasta '{display_path(f.path[:-1]) or winfs.name_of(p_ext)}' é uma pasta "
                        "especial do Windows (desktop.ini). Escolha outra pasta."
                    )
        # sonda de exclusão (Acesso controlado a pastas, permissões, arquivos em uso)
        if not blockers:
            for f in plan.files:
                try:
                    h = winfs.Win32File.open(
                        f.ext_path,
                        winfs.DELETE | winfs.FILE_WRITE_ATTRIBUTES,
                        winfs.FILE_SHARE_READ | winfs.FILE_SHARE_WRITE | winfs.FILE_SHARE_DELETE,
                        winfs.OPEN_EXISTING,
                        winfs.FILE_FLAG_OPEN_REPARSE_POINT,
                    )
                    h.close()
                except OSError as exc:
                    if winfs.winerror_of(exc) == winfs.ERROR_ACCESS_DENIED:
                        blockers.append(
                            "O Windows não deixou o Owl Vault apagar arquivos aqui "
                            f"('{display_path(f.path)}'). Em Segurança do Windows > Proteção contra "
                            "ransomware > Permitir um aplicativo, adicione o Owl Vault."
                        )
                        break
                    blockers.append(
                        f"{display_path(f.path)}: {winfs.classify_os_error(exc, 'em uso')}"
                    )
        if blockers:
            plan.blockers = blockers
            raise PreflightError("Não é possível proteger esta pasta.", blockers)
        return plan

    def protect(
        self,
        check: ProtectCheck,
        progress: ProgressSink | None = None,
        cancel: CancelToken | None = None,
    ) -> LockOutcome:
        """Registra a pasta e tranca pela primeira vez."""
        res = winfs.resolve(check.path)
        if res.identity is None:
            raise UnsafePathError("A pasta não existe mais.")
        rec = FolderRecord(
            id=secrets.token_hex(16),
            name=check.name,
            path=check.path,
            volume=res.volume,
            file_id=res.identity.file_id.hex(),
            state=ABERTA,
        )
        self.folders.append(rec)
        self._save()
        try:
            return self.lock(rec.id, progress, cancel)
        except BaseException:
            if rec.state == ABERTA and not rec.vaults:
                self.folders.remove(rec)  # nada foi feito: tira da lista
                self._save()
            raise

    # ------------------------------------------------------------------ trancar
    def missing_since_open(self, folder_id: str) -> list[str]:
        """Arquivos que estavam no cofre anterior e sumiram da pasta aberta (T7)."""
        rec = self._get(folder_id)
        prev = self._latest_previous_or_none(rec)
        if rec.state != ABERTA or prev is None:
            return []
        p = self._locate(rec)
        try:
            opened = open_vault(prev.location, self.keys_for_vault(prev.location), self.policy)
            manifest = read_manifest(opened).manifest
        except (OwlVaultError, OSError):
            return []
        missing = []
        for e in manifest.files:
            if not os.path.lexists(winfs.join(p, *e.path)):
                missing.append(_rel_key(e.path))
        return missing

    def lock(
        self,
        folder_id: str,
        progress: ProgressSink | None = None,
        cancel: CancelToken | None = None,
        accept_missing: list[str] | None = None,
    ) -> LockOutcome:
        progress = progress or NullProgress()
        cancel = cancel or CancelToken()
        rec = self._get(folder_id)
        if rec.state == APAGANDO:
            raise StateError(
                "Esta pasta tem um trancamento interrompido: use 'Continuar trancando' ou 'Desfazer'."
            )
        if rec.state != ABERTA:
            raise StateError("Só uma pasta aberta pode ser trancada.")
        p = self._locate(rec)
        if VAULT_DIR in os.listdir(p):
            raise StateError("A pasta já contém dados protegidos; ela não está aberta.")
        self._clear_stale_restore_files(p)
        rec.accepted_missing = list(accept_missing or [])
        staging = self.staging_of(rec)
        winfs.ensure_own_dir(staging)
        shell.change_attributes(staging, add=HIDE)
        progress.stage("Conferindo a pasta")
        # nome único: nunca reaproveita (nem apaga) a pasta de outro cofre
        novo = winfs.join(staging, f"novo-{secrets.token_hex(8)}")
        plan = self._preflight(p, novo, staging, progress, cancel, exclude_record=rec.id)
        rec.state = TRANCANDO
        rec.vaults = [v for v in rec.vaults if v.role != "novo"] + [VaultRef("", "novo", novo)]
        rec.attention = ""
        rec.pending = []
        self._save()
        keys = self.session.key_source()
        try:
            result: CreateResult = create_vault(
                p,
                novo,
                keys,
                test_parent=staging,
                kdf_policy=self.policy,
                protected=self._protected(),
                plan=plan,
                progress=progress,
                cancel=cancel,
            )
            if result.status != "success":
                raise OwlVaultError(
                    "A pasta mudou enquanto era protegida; nada foi apagado. Tente de novo. "
                    + "; ".join(result.divergences[:5])
                )
        except BaseException:
            self._discard_novo(rec)
            raise
        # --- cofre novo completo: agora (e só agora) os originais podem ser apagados
        vault_id = self._vault_id_of(novo)
        for v in rec.vaults:
            if v.role == "novo":
                v.vault_id = vault_id
        rec.fingerprints = {_rel_key(k): _fp_to_list(fp) for k, fp in result.fingerprints.items()}
        rec.zone_files = [
            k for k in rec.fingerprints if (read_zone_id(winfs.join(p, *k.split("\\"))) or 0) >= 3
        ]
        rec.kek_epoch = 0
        rec.state = APAGANDO
        self._save()
        self._ensure_marker(p, novo)
        return self._finish_lock(rec, progress, cancel)

    def _ensure_marker(self, p: str, vault_dir: str) -> None:
        """Marcador de restauração em P: permite 'Desfazer' (restaurar por cima) com retomada."""
        if os.path.lexists(winfs.join(p, MARKER_NAME)):
            return
        opened = open_vault(vault_dir, self.keys_for_vault(vault_dir), self.policy)
        mread = read_manifest(opened)
        write_restore_marker(p, opened.vault_id.hex(), hashlib.sha256(mread.raw).hexdigest())

    @staticmethod
    def _clear_stale_restore_files(p: str) -> None:
        remove_restore_marker(p)

    def continue_lock(
        self,
        folder_id: str,
        progress: ProgressSink | None = None,
        cancel: CancelToken | None = None,
    ) -> LockOutcome:
        rec = self._get(folder_id)
        if rec.state != APAGANDO:
            raise StateError("Não há trancamento interrompido nesta pasta.")
        self._locate(rec)
        return self._finish_lock(rec, progress or NullProgress(), cancel or CancelToken())

    def _finish_lock(
        self, rec: FolderRecord, progress: ProgressSink, cancel: CancelToken
    ) -> LockOutcome:
        p = rec.path
        novo = rec.vault("novo")
        assert novo is not None
        opened = open_vault(novo.location, self.keys_for_vault(novo.location), self.policy)
        manifest = read_manifest(opened).manifest
        files = manifest.files
        progress.stage("Apagando as cópias legíveis", 0, len(files))
        pending: list[str] = []
        for e in files:
            cancel.check()
            target = winfs.join(p, *e.path)
            if not os.path.lexists(target):
                progress.advance(0, 1)
                continue
            fp_raw = rec.fingerprints.get(_rel_key(e.path))
            try:
                winfs.delete_checked(target, _fp_from_list(fp_raw) if fp_raw else None)
            except OwlVaultError as exc:
                pending.append(f"{display_path(e.path)}: {exc}")
            progress.advance(0, 1)
        for d in sorted(manifest.dirs, key=lambda d: len(d.path), reverse=True):
            target = winfs.join(p, *d.path)
            if not os.path.lexists(target):
                continue
            try:
                winfs.delete_checked(target, None, is_dir=True)
            except OwlVaultError:
                if not any(x.startswith(display_path(d.path) + "\\") for x in pending):
                    pending.append(f"{display_path(d.path)}: a pasta não ficou vazia")
        known = {MARKER_NAME, RESTORE_LOCK_NAME}
        extra = [n for n in os.listdir(p) if n not in known]
        top_pending = {x.split("\\", 1)[0].split(":", 1)[0] for x in pending}
        for n in extra:
            if n not in top_pending:
                pending.append(f"{n}: item novo colocado na pasta durante o trancamento")
        if pending:
            rec.pending = pending
            rec.attention = (
                f"Seus arquivos já estão guardados. {len(pending)} item(ns) ainda não foram "
                "apagados da pasta porque estavam abertos ou foram alterados. Feche-os e clique "
                "em 'Continuar trancando' (ou 'Desfazer' para deixar a pasta aberta)."
            )
            self._save()
            return LockOutcome(rec, complete=False, pending=pending)
        # tudo apagado: cofre entra na pasta, espaço reservado é gravado
        remove_restore_marker(p)
        final = winfs.join(p, VAULT_DIR)
        winfs.rename_dir(novo.location, final)
        shell.change_attributes(final, add=HIDE)
        self._write_placeholder(rec)
        rec.state = TRANCADA
        rec.pending = []
        rec.attention = ""
        new_manifest_keys = {fold_path(e.path) for e in files}
        accepted = {fold_path(tuple(x.split("\\"))) for x in rec.accepted_missing}
        kept = False
        remaining: list[VaultRef] = []
        for v in rec.vaults:
            if v.role == "novo":
                remaining.append(VaultRef(v.vault_id, "atual", final))
                continue
            covered = new_manifest_keys | (accepted if v.role == "anterior" else set())
            if v.role in ("anterior", MANTIDO) and self._vault_may_be_deleted(v, covered, rec):
                self._remove_vault_tree(v.location, rec)
                if not os.path.lexists(v.location):
                    continue
            remaining.append(VaultRef(v.vault_id, MANTIDO, v.location))
            kept = True
        rec.vaults = remaining
        rec.accepted_missing = []
        rec.fingerprints = {}
        if kept:
            rec.attention = f"Foi mantida uma versão anterior de '{rec.name}' com arquivos que não estão na pasta."
        self._save()
        self._cleanup_staging(rec)
        removable = winfs.is_fat(winfs.resolve(p).fs_name)
        return LockOutcome(rec, complete=True, kept_previous=kept, removable=removable)

    def undo_lock(
        self,
        folder_id: str,
        progress: ProgressSink | None = None,
        cancel: CancelToken | None = None,
    ) -> UnlockOutcome:
        """Trancamento interrompido ⇒ devolve à pasta o que já foi apagado (cofre ``novo``)."""
        rec = self._get(folder_id)
        if rec.state != APAGANDO:
            raise StateError("Não há trancamento interrompido nesta pasta.")
        p = self._locate(rec)
        novo = rec.vault("novo")
        assert novo is not None
        self._ensure_marker(p, novo.location)
        report = restore_vault(
            novo.location,
            self.keys_for_vault(novo.location),
            p,
            policy=self.policy,
            protected=self._protected(),
            allow_resume=True,
            progress=progress,
            cancel=cancel,
        )
        # "já existe" = o arquivo continua na pasta (talvez alterado depois): é mantido como está
        if report.failed:
            rec.attention = "Não foi possível devolver todos os arquivos: " + "; ".join(
                report.failed[:5]
            )
            self._save()
            return UnlockOutcome(rec, complete=False, report=report, path=p)
        remove_restore_marker(p)
        for v in rec.vaults:
            if v.role == "novo":
                v.role = "anterior"
        rec.state = ABERTA
        rec.pending = []
        rec.attention = ""
        rec.fingerprints = {}
        self._save()
        return UnlockOutcome(rec, complete=True, report=report, path=p)

    # ------------------------------------------------------------------ abrir
    def unlock(
        self,
        folder_id: str,
        progress: ProgressSink | None = None,
        cancel: CancelToken | None = None,
    ) -> UnlockOutcome:
        progress = progress or NullProgress()
        cancel = cancel or CancelToken()
        rec = self._get(folder_id)
        p = self._locate(rec)
        if rec.state == ABRINDO:
            self._move_vault_out(rec)
            return self._finish_unlock(rec, progress, cancel)
        if rec.state == ABERTURA_INCOMPLETA:  # "Tentar de novo"
            return self._finish_unlock(rec, progress, cancel)
        if rec.state != TRANCADA:
            raise StateError("Esta pasta não está trancada.")
        problem = self._locked_content_problem(rec)
        if problem:
            raise StateError(problem)
        current = rec.vault("atual")
        vault_dir = winfs.join(p, VAULT_DIR)
        if current is None or self._vault_id_of(vault_dir) != current.vault_id:
            raise StateError("Os dados criptografados desta pasta não correspondem ao registro.")
        if rec.hidden:
            self.show(folder_id)
        staging = self.staging_of(rec)
        winfs.ensure_own_dir(staging)
        shell.change_attributes(staging, add=HIDE)
        target = winfs.join(staging, f"anterior-{secrets.token_hex(8)}")
        # destino gravado ANTES de mover: a retomada sabe para onde o cofre vai
        rec.vaults.remove(current)
        rec.vaults.append(VaultRef(current.vault_id, "anterior", target))
        rec.state = ABRINDO
        self._save()
        self._move_vault_out(rec)
        return self._finish_unlock(rec, progress, cancel)

    def _move_vault_out(self, rec: FolderRecord) -> None:
        """ABRINDO, 1ª parte: tira o espaço reservado e move o cofre para a área temporária.

        Ordem segura: o espaço reservado sai ENQUANTO o cofre ainda está em P (P não tem
        arquivo do usuário nesse momento); só depois o cofre sai e a restauração começa.
        """
        p = rec.path
        prev = self._latest_previous(rec)
        vault_dir = winfs.join(p, VAULT_DIR)
        if os.path.lexists(prev.location) or not os.path.lexists(vault_dir):
            return  # já movido
        if self._vault_id_of(vault_dir) != prev.vault_id:
            raise StateError("Os dados criptografados desta pasta não correspondem ao registro.")
        extra = [n for n in os.listdir(p) if n not in PLACEHOLDER and n != VAULT_DIR]
        if extra:
            raise StateError(
                f"Há item(ns) colocado(s) em '{rec.name}' enquanto estava trancada. Mova-os para "
                "outro lugar e tente de novo."
            )
        self._remove_placeholder(rec)
        winfs.rename_dir(vault_dir, prev.location)

    @staticmethod
    def _latest_previous(rec: FolderRecord) -> VaultRef:
        prev = None
        for v in rec.vaults:
            if v.role == "anterior":
                prev = v  # o mais recente fica por último
        if prev is None:
            raise StateError("O cofre desta pasta não foi encontrado.")
        return prev

    def _finish_unlock(
        self, rec: FolderRecord, progress: ProgressSink, cancel: CancelToken
    ) -> UnlockOutcome:
        p = rec.path
        prev = self._latest_previous(rec)
        try:
            shell.change_attributes(p, add=FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
        except OSError:
            pass
        keys = self.keys_for_vault(prev.location)
        opened = open_vault(prev.location, keys, self.policy)
        manifest = read_manifest(opened).manifest
        total = len(manifest.files)
        if inspect_destination(p) == "nonempty":
            # a restauração terminou (marcador já removido) antes de o estado ser gravado
            missing = [
                display_path(e.path)
                for e in manifest.files
                if not winfs.is_plain_file_at(winfs.join(p, *e.path))
                or os.lstat(winfs.join(p, *e.path)).st_size != e.size
            ]
            report = RestoreReport(
                display_path(()), "complete", skipped_existing=total - len(missing)
            )
            report.failed.extend(f"{m}: não está na pasta" for m in missing)
        else:
            report = restore_vault(
                prev.location,
                keys,
                p,
                policy=self.policy,
                protected=self._protected(),
                allow_resume=True,
                progress=progress,
                cancel=cancel,
            )
        if report.ok and report.restored + report.skipped_existing == total:
            rec.state = ABERTA
            rec.attention = ""
            rec.pending = []
        else:
            rec.state = ABERTURA_INCOMPLETA
            rec.pending = report.failed + report.conflicts
            rec.attention = (
                f"{len(rec.pending)} arquivo(s) não puderam ser abertos. A cópia protegida deles "
                "continua guardada."
            )
        for rel in rec.zone_files:
            try:
                write_motw(winfs.join(p, *rel.split("\\")))
            except OSError:
                pass
        self._save()
        shell.notify_changed(p)
        return UnlockOutcome(rec, complete=rec.state == ABERTA, report=report, path=p)

    def accept_incomplete_unlock(self, folder_id: str) -> None:
        """'Continuar sem eles': a pasta fica aberta; o cofre anterior é MANTIDO."""
        rec = self._get(folder_id)
        if rec.state == ABERTURA_INCOMPLETA:
            self._clear_stale_restore_files(self._locate(rec))
            prev = self._latest_previous_or_none(rec)
            if prev is not None:
                prev.role = MANTIDO  # tem arquivos que não voltaram: nunca apagar sozinho
            rec.state = ABERTA
            rec.attention = "Foi mantida uma versão anterior com arquivos que não voltaram à pasta."
            self._save()

    # ------------------------------------------------------------------ esconder/mostrar
    def hide(self, folder_id: str) -> None:
        rec = self._get(folder_id)
        p = self._locate(rec)
        if rec.state != TRANCADA:
            raise StateError("Só uma pasta trancada pode ser escondida.")
        shell.change_attributes(p, add=HIDE)
        rec.hidden = True
        self._save()
        shell.notify_changed(winfs.parent_of(p))

    def show(self, folder_id: str) -> None:
        rec = self._get(folder_id)
        p = self._locate(rec)
        shell.change_attributes(p, remove=shell.FILE_ATTRIBUTE_HIDDEN)
        if rec.state != TRANCADA:
            shell.change_attributes(p, remove=shell.FILE_ATTRIBUTE_SYSTEM)
        rec.hidden = False
        self._save()
        shell.notify_changed(winfs.parent_of(p))

    # ------------------------------------------------------------------ remover proteção
    def removal_missing(self, folder_id: str) -> list[str]:
        """Para 'Remover proteção' de uma pasta ABERTA: o que está no cofre e não na pasta."""
        rec = self._get(folder_id)
        p = self._locate(rec)
        missing: list[str] = []
        for v in rec.vaults:
            try:
                opened = open_vault(v.location, self.keys_for_vault(v.location), self.policy)
                manifest = read_manifest(opened).manifest
            except (OwlVaultError, OSError):
                continue
            for e in manifest.files:
                if not os.path.lexists(winfs.join(p, *e.path)):
                    missing.append(_rel_key(e.path))
        return sorted(set(missing))

    def remove_protection(
        self, folder_id: str, *, confirmed_missing: list[str] | None = None
    ) -> None:
        """Só para pasta ABERTA: apaga os cofres (regra de ouro com a pasta) e tira da lista."""
        rec = self._get(folder_id)
        p = self._locate(rec)
        if rec.state != ABERTA:
            raise StateError("Abra a pasta antes de remover a proteção.")
        missing = self.removal_missing(folder_id)
        accepted = set(confirmed_missing or [])
        if any(m not in accepted for m in missing):
            raise StateError(
                "Há arquivos protegidos que não estão na pasta; confirme a lista antes de remover."
            )
        for v in list(rec.vaults):
            self._remove_vault_tree(v.location, rec)
            if not os.path.lexists(v.location):
                rec.vaults.remove(v)
        if rec.vaults:
            self._save()
            raise StateError(
                "Não foi possível apagar todos os dados protegidos desta pasta; nada mais foi feito."
            )
        self.folders.remove(rec)
        self._save()
        self._cleanup_staging(rec)
        try:
            shell.change_attributes(p, remove=FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
        except OSError:
            pass

    def forget(self, folder_id: str) -> None:
        """'Tirar da lista' — não apaga nada."""
        rec = self._get(folder_id)
        self.folders.remove(rec)
        self._save()

    # ------------------------------------------------------------------ recuperar
    def find_recoverable(self, path: str) -> list[str]:
        p_ext = winfs.to_extended(path)
        out: list[str] = []
        if winfs.is_plain_dir_at(winfs.join(p_ext, VAULT_DIR)):
            out.append(p_ext)
            return out
        try:
            names = os.listdir(p_ext)
        except OSError:
            return out
        for n in sorted(names):
            sub = winfs.join(p_ext, n)
            if winfs.is_plain_dir_at(sub) and winfs.is_plain_dir_at(winfs.join(sub, VAULT_DIR)):
                out.append(sub)
        return out

    def recover(self, folder: str, master_password: str) -> FolderRecord:
        p_ext = winfs.to_extended(folder)
        vault_dir = winfs.join(p_ext, VAULT_DIR)
        opened = open_vault(vault_dir, master_password, self.policy)
        mread = read_manifest(opened)
        info, _ = read_completion(opened, mread.raw)
        if info is None:
            raise StateError("Os dados desta pasta estão incompletos; não é possível recuperá-la.")
        hdr = opened.header
        if not any(k.salt == hdr.salt and k.params == hdr.kdf for k in self.session.index.keks):
            mem = winfs.memory_status()
            kek = derive_kek(
                master_password,
                hdr.salt,
                hdr.kdf,
                self.policy,
                mem.available_commit if mem else None,
            )
            self.session.index.keks.append(KekEntry(hdr.salt, hdr.kdf, kek))
        res = winfs.resolve(p_ext)
        assert res.identity is not None
        for existing in self.folders:
            if existing.file_id == res.identity.file_id.hex() and existing.volume == res.volume:
                raise StateError("Esta pasta já está na lista.")
        names = set(os.listdir(p_ext))
        hidden = bool(shell.get_attributes(p_ext) & shell.FILE_ATTRIBUTE_HIDDEN)
        rec = FolderRecord(
            id=secrets.token_hex(16),
            name=winfs.name_of(p_ext),
            path=p_ext,
            volume=res.volume,
            file_id=res.identity.file_id.hex(),
            state=TRANCADA,
            hidden=hidden,
            vaults=[VaultRef(opened.vault_id.hex(), "atual", vault_dir)],
        )
        self.folders.append(rec)
        self._save()
        if SHORTCUT_NAME in names:
            self.refresh_shortcut(rec)
        return rec

    def relocate(self, folder_id: str, new_path: str) -> None:
        """'Procurar a pasta…': aceita só se o cofre dentro dela é o registrado."""
        rec = self._get(folder_id)
        p_ext = winfs.to_extended(new_path)
        current = rec.vault("atual")
        vault_dir = winfs.join(p_ext, VAULT_DIR)
        if current is None or not winfs.is_plain_dir_at(vault_dir):
            raise StateError("Esta pasta não contém os dados protegidos esperados.")
        if self._vault_id_of(vault_dir) != current.vault_id:
            raise StateError("Esta não é a mesma pasta protegida.")
        res = winfs.resolve(p_ext)
        assert res.identity is not None
        rec.path = p_ext
        rec.name = winfs.name_of(p_ext)
        rec.volume = res.volume
        rec.file_id = res.identity.file_id.hex()
        current.location = vault_dir
        rec.attention = ""
        self._save()
        self.refresh_shortcut(rec)

    # ------------------------------------------------------------------ espaço reservado
    def _write_placeholder(self, rec: FolderRecord) -> None:
        p = rec.path
        icon = winfs.join(p, ICON_NAME)
        ini = winfs.join(p, DESKTOP_INI)
        write_new_no_replace(icon, self.icon_bytes, op="placeholder")
        shell.change_attributes(icon, add=HIDE)
        write_new_no_replace(ini, shell.desktop_ini_bytes(ICON_NAME, INFOTIP), op="placeholder")
        shell.change_attributes(ini, add=HIDE)
        write_new_no_replace(
            winfs.join(p, HELP_NAME), HELP_TEXT.encode("utf-8-sig"), op="placeholder"
        )
        self.refresh_shortcut(rec)
        shell.make_system_folder(p)
        shell.notify_changed(p)
        shell.notify_changed(winfs.parent_of(p))

    def refresh_shortcut(self, rec: FolderRecord) -> None:
        if not self.create_shortcuts:
            return
        lnk = winfs.join(rec.path, SHORTCUT_NAME)
        exe, base = self.launcher
        args = (base + " " if base else "") + f"--abrir {rec.id}"
        if os.path.lexists(lnk):
            safe_remove_own(lnk, winfs.resolve(rec.path), _PLACEHOLDER_RE)
        shell.create_shortcut(
            lnk,
            exe,
            args,
            winfs.join(rec.path, ICON_NAME),
            "Abrir com o Owl Vault",
            winfs.parent_of(exe),
        )

    def _remove_placeholder(self, rec: FolderRecord) -> None:
        p = rec.path
        allowed = winfs.resolve(p)
        for name in PLACEHOLDER:
            target = winfs.join(p, name)
            if os.path.lexists(target):
                shell.change_attributes(target, remove=HIDE | shell.FILE_ATTRIBUTE_READONLY)
                safe_remove_own(target, allowed, _PLACEHOLDER_RE)
        shell.unmake_system_folder(p)
        shell.change_attributes(p, remove=HIDE | shell.FILE_ATTRIBUTE_READONLY)
        shell.notify_changed(p)

    # ------------------------------------------------------------------ cofres
    def _vault_may_be_deleted(
        self, v: VaultRef, covered: set[tuple[str, ...]], rec: FolderRecord
    ) -> bool:
        """Regra de ouro: tudo o que o cofre tem está coberto (cofre mais novo ou aceito)."""
        try:
            opened = open_vault(v.location, self.keys_for_vault(v.location), self.policy)
            if v.vault_id and opened.vault_id.hex() != v.vault_id:
                return False
            mread = read_manifest(opened)
            info, _ = read_completion(opened, mread.raw)
            if info is None:
                return False
            return all(fold_path(e.path) in covered for e in mread.manifest.files)
        except (OwlVaultError, OSError):
            return False

    def _discard_novo(self, rec: FolderRecord) -> None:
        novo = rec.vault("novo")
        if novo is not None and os.path.lexists(novo.location):
            try:
                self._remove_vault_tree(novo.location, rec)
            except OwlVaultError:
                pass
        rec.vaults = [v for v in rec.vaults if v.role != "novo"]
        rec.state = ABERTA
        self._save()

    def _remove_vault_tree(self, vault_dir: str, rec: FolderRecord) -> None:
        """Apaga um cofre NOSSO: só nomes do layout v1; qualquer outro item é mantido."""
        if not os.path.lexists(vault_dir):
            return
        if not winfs.is_plain_dir_at(vault_dir):
            raise UnsafePathError("o cofre a apagar não é uma pasta comum")
        root = winfs.resolve(vault_dir)
        root_names = re.compile(
            r"vault\.owl|vault\.owl\.bak|manifest\.owl|manifest\.owl\.bak|complete\.owl|"
            r"state\.json|LEIA-ME\.txt|\.owlvault\.lock"
        )
        data = winfs.join(vault_dir, "data")
        if winfs.is_plain_dir_at(data):
            for hh in os.listdir(data):
                hp = winfs.join(data, hh)
                if HH_RE.fullmatch(hh) and winfs.is_plain_dir_at(hp):
                    for name in os.listdir(hp):
                        if BLOB_RE.fullmatch(name) or re.fullmatch(r"[0-9a-f]{32}\.tmp", name):
                            safe_remove_own(winfs.join(hp, name), root, re.compile(re.escape(name)))
                    safe_rmdir_own(hp, root)
            safe_rmdir_own(data, root)
        journal = winfs.join(vault_dir, "journal")
        if winfs.is_plain_dir_at(journal):
            for name in os.listdir(journal):
                if SEGMENT_RE.fullmatch(name) or SEGMENT_TMP_RE.fullmatch(name):
                    safe_remove_own(winfs.join(journal, name), root, re.compile(re.escape(name)))
            safe_rmdir_own(journal, root)
        for name in os.listdir(vault_dir):
            path = winfs.join(vault_dir, name)
            ours = (
                root_names.fullmatch(name)
                or ROOT_TMP_RE.fullmatch(name)
                or PROBE_RE.fullmatch(name)
            )
            if ours and winfs.is_plain_file_at(path):
                safe_remove_own(path, root, re.compile(re.escape(name)))
        if not safe_rmdir_own(vault_dir, winfs.resolve(winfs.parent_of(vault_dir))):
            rec.attention = "Sobraram itens desconhecidos numa pasta interna do Owl Vault."

    def _cleanup_staging(self, rec: FolderRecord) -> None:
        staging = self.staging_of(rec)
        if not winfs.is_plain_dir_at(staging):
            return
        parent_res = winfs.resolve(winfs.parent_of(staging))
        for name in os.listdir(staging):
            path = winfs.join(staging, name)
            if TEST_DIR_RE.fullmatch(name) and winfs.is_plain_dir_at(path):
                test_res = winfs.resolve(path)
                for inner in os.listdir(path):
                    if CHK_RE.fullmatch(inner) or TEST_PART_RE.fullmatch(inner):
                        safe_remove_own(
                            winfs.join(path, inner), test_res, re.compile(re.escape(inner))
                        )
                safe_rmdir_own(path, winfs.resolve(staging))
        if any(v.location.startswith(staging) for v in rec.vaults):
            return
        try:
            shell.change_attributes(staging, remove=HIDE)
        except OSError:
            return
        safe_rmdir_own(staging, parent_res)

    # ------------------------------------------------------------------ início
    def reconcile_on_start(self) -> list[str]:
        """Recuperação de quedas (§4.5): devolve mensagens para a interface."""
        notes: list[str] = []
        for rec in list(self.folders):
            try:
                self._locate(rec)
            except StateError:
                continue
            if rec.state == TRANCANDO:
                self._discard_novo(rec)
                notes.append(
                    f"O trancamento de '{rec.name}' foi interrompido antes de apagar qualquer "
                    "arquivo; a pasta continua aberta."
                )
            elif rec.state == APAGANDO and not rec.attention:
                rec.attention = (
                    "O trancamento foi interrompido. Seus arquivos já estão guardados; clique em "
                    "'Continuar trancando' ou 'Desfazer'."
                )
                self._save()
            elif rec.state == ABRINDO:
                rec.attention = "A abertura foi interrompida. Clique em 'Continuar abrindo'."
                self._save()
        return notes


def plain_files(manifest_files: list[FileEntryRecord]) -> int:
    return len(manifest_files)


ProgressFactory = Callable[[], ProgressSink]
_ = scan_tree  # usado pelos testes (varredura independente)
