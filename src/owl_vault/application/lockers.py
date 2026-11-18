"""Pastas protegidas: trancar no lugar, abrir, esconder, mostrar, remover proteção.

PASTAS_PROTEGIDAS.md §3–§5. Regras de segurança (resultado das revisões adversariais):

* Os dados cifrados ficam DENTRO da pasta (``P\\.owlvault``); a área temporária
  ``<pai>\\.owlvault-<id>`` (mesmo volume, fora de P) guarda o cofre em criação (``novo``) e o
  cofre da pasta aberta (``anterior``).
* Originais só são apagados depois de ``create_vault`` concluir com sucesso (verificação +
  teste de restauração) e com o estado ``apagando`` GRAVADO; cada arquivo é conferido no
  handle antes (impressão digital ou, sem ela, o conteúdo pelo SHA-256 do manifesto).
* **Regra de ouro** (primitivo único ``_apagar_cofre``): um cofre só é apagado se o vault_id é o
  registrado, ``complete.owl`` é autêntico, o manifesto foi lido e tudo o que ele tem está
  coberto (cofre mais novo da mesma pasta, a própria pasta ou a lista exata que o usuário
  confirmou). Cofre ilegível ou ausente NUNCA conta como vazio.
* O índice é gravado ANTES de cada passo irreversível; os passos de acabamento (espaço
  reservado, apagar versões já conferidas) são melhor esforço e refeitos ao iniciar.
* Nunca roda outro ``create_vault`` enquanto um cofre estiver parcialmente aplicado.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
from collections.abc import Callable, Set
from dataclasses import dataclass, field
from typing import Any

from owl_vault.application.common import read_zone_id, round_up, write_motw
from owl_vault.application.create import CreateResult, create_vault
from owl_vault.application.keysource import KeySource
from owl_vault.application.preflight import CreatePlan, preflight_create
from owl_vault.application.profile import (
    KEK_RECUPERADA,
    KEK_TROCADA,
    FolderRecord,
    KekEntry,
    ProfileSession,
    VaultRef,
)
from owl_vault.application.progress import CancelToken, NullProgress, ProgressSink
from owl_vault.application.protection import ProtectedPaths, destination_location_problems
from owl_vault.application.restore import (
    MARKER_NAME,
    RESTORE_LOCK_NAME,
    RestoreReport,
    hash_file_unbuffered,
    inspect_destination,
    remove_restore_marker,
    restore_vault,
    write_restore_marker,
)
from owl_vault.application.vault import open_vault, read_completion, read_manifest
from owl_vault.crypto.kdf import PRODUCTION_POLICY, KdfPolicy, derive_kek
from owl_vault.domain.errors import (
    AuthenticationError,
    CancelledError,
    InsufficientSpaceError,
    OwlVaultError,
    PreflightError,
    SourceChangedError,
    StateError,
    UnsafePathError,
    VaultLockedError,
)
from owl_vault.domain.limits import FAT32_MAX_FILE_SIZE, MAX_EXTENDED_PATH_UTF16, MIB
from owl_vault.domain.models import FileEntryRecord, FileIdentity, Fingerprint
from owl_vault.domain.names import display_path, fold_path, utf16_len
from owl_vault.storage import acl, shell, winfs
from owl_vault.storage.atomic import safe_remove_own, safe_rmdir_own, write_new_no_replace
from owl_vault.storage.header import HEADER_SIZE, parse_header
from owl_vault.storage.layout import (
    BLOB_RE,
    CHK_RE,
    COMPLETE_NAME,
    HEADER_BAK_NAME,
    HEADER_NAME,
    HH_RE,
    PROBE_RE,
    ROOT_TMP_RE,
    SEGMENT_RE,
    SEGMENT_TMP_RE,
    TEST_DIR_RE,
    TEST_PART_RE,
)
from owl_vault.storage.manifest import Manifest
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
    "Para abrir: abra o programa Owl Vault pelo Menu Iniciar e digite seu PIN (o atalho "
    "'Abrir com Owl Vault' desta pasta faz o mesmo).\r\n\r\n"
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
#: subfase de "abrindo", gravada logo ANTES de a restauração começar. Só com ela uma pasta
#: não vazia e sem marcador conta como "restauração concluída". A interface a mostra como
#: "abrindo" (``FolderView.issue``).
RESTAURANDO = "restaurando"
ABERTURA_INCOMPLETA = "abertura_incompleta"
#: papel de cofre "versão anterior mantida": nunca apagado sem a confirmação do usuário
MANTIDO = "mantido"
#: papel de cofre já aprovado pela regra de ouro cuja exclusão começou (retomada ao iniciar)
DESCARTANDO = "descartando"

# issues (``FolderView.issue``) além dos estados intermediários; a interface trata QUALQUER
# issue que não conhece com um "Resolver" genérico (attention + Procurar a pasta… + Tirar da
# lista), então nenhuma linha fica sem saída.
#: a cópia criptografada de que o estado intermediário precisa (área temporária
#: ``.owlvault-<id>`` ou dentro da pasta) sumiu ou não pode ser lida: nem Continuar nem Desfazer
COFRE_INACESSIVEL = "cofre_inacessivel"
#: ``P\\.owlvault`` de uma pasta trancada NÃO é o cofre registrado (ex.: backup antigo no lugar)
COFRE_DIFERENTE = "cofre_diferente"
#: o Windows não deixa o Owl Vault ler a pasta (permissões)
SEM_ACESSO = "sem_acesso"
#: outro erro ao conferir a pasta (a lista continua mostrando as outras)
ERRO_LEITURA = "erro_leitura"

#: mesmo limite de caminho usado por ``restore_vault`` (nome do temporário mais longo)
_LONGEST_TEMP = len(".owl-") + 32 + 1 + 32 + len(".part")
_STAGING_VAULT_RE = re.compile(r"(?:novo|anterior)-[0-9a-f]{16}")
_INTERRUPTED_LOCK = (
    "O trancamento foi interrompido. O que já saiu da pasta está guardado; clique em "
    "'Continuar trancando' ou 'Desfazer'."
)
_NEW_ITEM = "item novo colocado na pasta durante o trancamento (não está guardado)"
_CHANGED = "o arquivo mudou depois de ser criptografado; não foi apagado"
_UNDO_LEFTOVER = (
    "pedaço de arquivo deixado por um 'Desfazer' interrompido (o arquivo está guardado); não "
    "pôde ser apagado agora"
)
_RESTORE_ID_RE = re.compile(r"[0-9a-f]{32}")


class FolderUnavailableError(StateError):
    """A unidade da pasta não está acessível (desconectada, sem acesso)."""


class FolderMovedError(StateError):
    """No caminho registrado não está a MESMA pasta (movida, renomeada ou substituída)."""


@dataclass
class FolderView:
    record: FolderRecord
    label: str  # estado por extenso para a interface
    action: str  # "abrir" | "trancar" | "resolver" | ""
    attention: str = ""
    available: bool = True
    #: "" | apagando | abertura_incompleta | abrindo | trancando | itens_extras | sem_dados |
    #: nao_encontrada | indisponivel | versao_anterior | versao_anterior_ilegivel | senha_antiga |
    #: cofre_inacessivel | cofre_diferente | sem_acesso | erro_leitura
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


def _key_of(rel: str) -> tuple[str, ...]:
    """Caminho dobrado de um texto "a\\b" (ou "a\\b: motivo", como em ``pending``)."""
    return fold_path(tuple(rel.split(":", 1)[0].split("\\")))


def _inside(path: str, folder: str) -> bool:
    return os.path.normcase(path).startswith(os.path.normcase(folder).rstrip("\\") + "\\")


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
        #: a última gravação do índice falhou: nada destrutivo roda antes de uma dar certo
        self._unsaved = False

    # ------------------------------------------------------------------ utilidades
    @property
    def folders(self) -> list[FolderRecord]:
        return self.session.index.folders

    def _save(self) -> None:
        try:
            self.session.save()
        except BaseException:
            self._unsaved = True
            raise
        self._unsaved = False

    def _require_saved(self) -> None:
        """Antes de apagar originais: o estado em memória TEM de estar no disco."""
        if self._unsaved:
            self._save()

    def _protected(self) -> ProtectedPaths:
        if self.protected is None:
            self.protected = ProtectedPaths.from_environment()
        return self.protected

    def _known_folders(self) -> dict[str, str]:
        if self._known is None:
            self._known = shell.known_folders()
        return self._known

    @staticmethod
    def _restrict(path: str, *, directory: bool) -> bool:
        """DACL só da conta atual + SYSTEM + Administradores (melhor esforço, ``acl.py``)."""
        try:
            return acl.restrict_to_owner(path, directory=directory)
        except (OSError, OwlVaultError, ValueError):
            return False

    def _prepare_staging(self, staging: str) -> None:
        if winfs.is_plain_file_at(staging):
            raise UnsafePathError(
                f"Já existe um arquivo chamado '{winfs.name_of(staging)}' ao lado da pasta, e o "
                "Owl Vault precisa desse nome. Mova esse arquivo para outro lugar e tente de novo."
            )
        winfs.ensure_own_dir(staging)
        shell.change_attributes(staging, add=HIDE)
        self._restrict(staging, directory=True)

    @staticmethod
    def _is_removable(p: str) -> bool:
        try:
            return bool(winfs.is_removable_drive(p))
        except (OSError, OwlVaultError, ValueError):
            return False

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
            raise FolderUnavailableError(f"A unidade de '{rec.name}' não está disponível.") from exc
        if (
            not res.exists
            or not res.is_directory
            or res.identity is None
            or res.identity.file_id.hex() != rec.file_id
            or res.volume != rec.volume
        ):
            hint = (
                " Ela está escondida: em 'Procurar a pasta…', escolha a pasta onde ela fica."
                if rec.hidden
                else ""
            )
            raise FolderMovedError(
                f"A pasta '{rec.name}' não está mais em {winfs.strip_extended(rec.path)} (foi "
                f"movida, renomeada ou substituída). Use 'Procurar a pasta…'.{hint}"
            )
        return rec.path

    def _kek_for_vault(self, vault_dir: str) -> KekEntry:
        """A KEK do perfil cujo salt/params batem com o cabeçalho do cofre."""
        hdr = None
        for name in (HEADER_NAME, HEADER_BAK_NAME):
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
                return k
        raise AuthenticationError(
            "Esta pasta foi protegida com outra senha mestra. Use 'Recuperar uma pasta protegida'."
        )

    def keys_for_vault(self, vault_dir: str) -> KeySource:
        """Escolhe a KEK do perfil cujo salt/params batem com o cabeçalho do cofre.

        O ``.owlvault`` de uma pasta TRANCADA da lista só é aceito se for o cofre registrado
        (senão StateError): o cofre errado nunca é aberto nem conferido como se fosse o da pasta
        ('Verificar arquivos' não diz "Tudo certo" de uma cópia antiga posta no lugar).
        """
        self._check_registered_inner(vault_dir)
        k = self._kek_for_vault(vault_dir)
        return KeySource(salt=k.salt, params=k.params, kek=k.kek)

    def _check_registered_inner(self, vault_dir: str) -> None:
        wanted = os.path.normcase(winfs.strip_extended(vault_dir)).rstrip("\\")
        for rec in self.folders:
            current = rec.vault("atual")
            if rec.state != TRANCADA or current is None or not current.vault_id:
                continue
            inner = winfs.strip_extended(winfs.join(rec.path, VAULT_DIR))
            if os.path.normcase(inner).rstrip("\\") != wanted:
                continue
            try:
                found = self._vault_id_of(vault_dir)
            except OSError:
                return  # ilegível: quem abrir o cofre explica
            if found != current.vault_id:
                raise StateError(self._different_vault_text(rec))
            return

    @staticmethod
    def _different_vault_text(rec: FolderRecord) -> str:
        return (
            f"Os dados criptografados que estão em '{rec.name}' não são os que o Owl Vault "
            "guardou por último nesta pasta (talvez uma cópia antiga tenha sido colocada no "
            "lugar). Por segurança, eles não são abertos nem conferidos como se fossem os da "
            "pasta. Se você tem a cópia certa, coloque-a de volta. Para usar a que está na pasta, "
            "tire a pasta da lista e use '☰ > Recuperar uma pasta protegida' com a senha mestra."
        )

    def _inner_differs(self, rec: FolderRecord) -> bool:
        """Pasta trancada cujo ``P\\.owlvault`` tem OUTRO vault_id que o 'atual' registrado."""
        current = rec.vault("atual")
        inner = winfs.join(rec.path, VAULT_DIR)
        if current is None or not current.vault_id or not winfs.is_plain_dir_at(inner):
            return False
        try:
            return self._vault_id_of(inner) != current.vault_id
        except OSError:
            return False

    def _vault_problem(self, location: str) -> str:
        """Texto vazio se o cofre existe e o cabeçalho abre com uma KEK do perfil; senão
        "ausente" ou "ilegivel" (um cofre assim nunca conta como vazio)."""
        if not os.path.lexists(location):
            return "ausente"
        if not winfs.is_plain_dir_at(location):
            return "ilegivel"
        try:
            self._kek_for_vault(location)
        except (OwlVaultError, OSError):
            return "ilegivel"
        return ""

    @staticmethod
    def _inaccessible_text(rec: FolderRecord, v: VaultRef, problem: str) -> str:
        """Explica que a cópia criptografada de um estado intermediário sumiu ou não abre."""
        area = winfs.parent_of(v.location)
        where = winfs.strip_extended(area)
        if rec.state == APAGANDO:
            what = f"A cópia criptografada com os arquivos que já saíram de '{rec.name}'"
            after = (
                "Por isso não dá para continuar nem desfazer o trancamento. Os arquivos que "
                "ainda estão na pasta continuam lá."
            )
        elif rec.state == ABERTURA_INCOMPLETA:
            what = f"A cópia criptografada de '{rec.name}'"
            after = (
                "Por isso não dá para tentar abrir de novo. Os arquivos que voltaram para a pasta "
                "continuam lá; para ficar só com eles, clique em 'Continuar sem eles'."
            )
        else:
            what = f"A cópia criptografada de '{rec.name}'"
            after = (
                "Por isso não dá para continuar abrindo. Os arquivos que já voltaram para a "
                "pasta continuam lá."
            )
        if problem == "ausente":
            first = f"{what} não foi encontrada em {where} (uma pasta oculta)."
            fix = (
                f"Se você moveu ou apagou a pasta oculta '{winfs.name_of(area)}', coloque-a de "
                "volta ao lado da pasta."
            )
        else:
            first = (
                f"{what} está em {where} (uma pasta oculta), mas não pode ser lida (pode estar "
                "danificada)."
            )
            fix = "Se você tem uma cópia dela, coloque-a no lugar."
        return f"{first} {after} {fix} Se não for possível, use 'Tirar da lista' (nada é apagado)."

    def _located(self, rec: FolderRecord) -> bool:
        """A pasta registrada está no lugar (mesma identidade)? Sem levantar erro."""
        try:
            self._locate(rec)
        except (StateError, OSError):
            return False
        return True

    def _require_vault(self, rec: FolderRecord, v: VaultRef) -> None:
        problem = self._vault_problem(v.location)
        if problem:
            raise StateError(self._inaccessible_text(rec, v, problem))

    def _intermediate_vault(self, rec: FolderRecord) -> VaultRef | None:
        """O cofre de que um estado intermediário precisa, se ele NÃO está dentro da pasta.

        APAGANDO: o 'novo' (a não ser que já tenha entrado em P); ABRINDO/RESTAURANDO/
        ABERTURA_INCOMPLETA: o 'anterior' mais recente (em ABRINDO ele pode ainda estar em P).
        """
        if rec.state == APAGANDO:
            novo = rec.vault("novo")
            if novo is None or self._novo_moved_into_folder(rec, novo):
                return None
            return novo
        if rec.state in (ABRINDO, RESTAURANDO, ABERTURA_INCOMPLETA):
            prev = self._latest_previous_or_none(rec)
            if prev is None:
                return None
            inner = winfs.join(rec.path, VAULT_DIR)
            if rec.state == ABRINDO and not os.path.lexists(prev.location):
                try:
                    if winfs.is_plain_dir_at(inner) and self._vault_id_of(inner) == prev.vault_id:
                        return None  # o cofre ainda está na pasta (não saiu)
                except OSError:
                    pass
            return prev
        return None

    @staticmethod
    def _vault_id_of(vault_dir: str) -> str:
        """vault_id (em claro) do cabeçalho; sem ``vault.owl``, o da cópia ``.bak``."""
        last: OSError | None = None
        for name in (HEADER_NAME, HEADER_BAK_NAME):
            try:
                with open(winfs.join(vault_dir, name), "rb") as fh:
                    raw = fh.read(HEADER_SIZE)
            except OSError as exc:
                last = exc
                continue
            if len(raw) >= 32:
                return raw[16:32].hex()
        raise last or OSError(f"cabeçalho de cofre ausente em {winfs.strip_extended(vault_dir)}")

    # ------------------------------------------------------------------ estado exibido
    def views(self) -> list[FolderView]:
        """Uma linha por pasta: um problema numa pasta nunca esconde as outras (§4.5)."""
        return [self.view(rec) for rec in self.folders]

    def view(self, rec: FolderRecord) -> FolderView:
        """Estado exibido de uma pasta. Nunca levanta erro de disco: uma pasta que não pode ser
        conferida vira "Precisa de atenção" com o motivo (sem caminho cru do Windows)."""
        try:
            return self._view(rec)
        except PermissionError:
            return FolderView(
                rec,
                "Precisa de atenção",
                "resolver",
                f"O Windows não deixa o Owl Vault ler a pasta '{rec.name}' (acesso negado). "
                "Confira as permissões dela; se ela veio de outro computador ou de outra "
                "instalação do Windows, pode ser preciso tomar posse dela.",
                issue=SEM_ACESSO,
            )
        except (OwlVaultError, OSError) as exc:
            # str() de um OSError traz o caminho cru do Windows: só o motivo vai para a tela
            why = (
                str(exc) if isinstance(exc, OwlVaultError) else (exc.strerror or "erro do sistema")
            )
            return FolderView(
                rec,
                "Precisa de atenção",
                "resolver",
                f"Não foi possível conferir a pasta '{rec.name}' agora ({why}). Tente de novo "
                "mais tarde.",
                issue=ERRO_LEITURA,
            )

    def _view(self, rec: FolderRecord) -> FolderView:
        attention = "Precisa de atenção"
        try:
            self._locate(rec)
        except FolderUnavailableError as exc:
            drive = winfs.strip_extended(rec.path)[:2]
            return FolderView(
                rec,
                f"Indisponível — conecte a unidade {drive}",
                "",
                str(exc),
                available=False,
                issue="indisponivel",
            )
        except FolderMovedError as exc:
            return FolderView(rec, attention, "resolver", str(exc), issue="nao_encontrada")
        opening = "A abertura foi interrompida. Clique em 'Continuar abrindo'."
        texts = {
            APAGANDO: _INTERRUPTED_LOCK,
            ABERTURA_INCOMPLETA: "Alguns arquivos não puderam ser abertos.",
            ABRINDO: opening,
            RESTAURANDO: opening,
            TRANCANDO: (
                "O trancamento foi interrompido. Clique em 'Resolver' para o Owl Vault conferir "
                "a pasta."
            ),
        }
        if rec.state in texts:
            issue = ABRINDO if rec.state == RESTAURANDO else rec.state
            needed = self._intermediate_vault(rec)
            problem = self._vault_problem(needed.location) if needed is not None else ""
            if needed is not None and problem:
                if rec.state != ABERTURA_INCOMPLETA:
                    # nem Continuar nem Desfazer funcionam: Procurar a pasta… / Tirar da lista
                    issue = COFRE_INACESSIVEL
                text = self._inaccessible_text(rec, needed, problem)
                return FolderView(rec, attention, "resolver", text, issue=issue)
            return FolderView(
                rec, attention, "resolver", rec.attention or texts[rec.state], issue=issue
            )
        base = "abrir" if rec.state == TRANCADA else "trancar"
        if rec.state == TRANCADA:
            problem = self._locked_content_problem(rec)
            if problem:
                issue = "sem_dados" if "não foram encontrados" in problem else "itens_extras"
                return FolderView(
                    rec, attention, "resolver", problem, issue=issue, base_action=base
                )
            if self._inner_differs(rec):
                return FolderView(
                    rec,
                    attention,
                    "resolver",
                    self._different_vault_text(rec),
                    issue=COFRE_DIFERENTE,
                )
        if any(v.role == MANTIDO for v in rec.vaults):
            try:
                n = len(self.kept_only_files(rec.id))
            except StateError as exc:
                return FolderView(
                    rec,
                    attention,
                    "resolver",
                    f"A versão anterior de '{rec.name}' que foi mantida não pôde ser lida. {exc} "
                    "Para tentar salvar esses arquivos, use 'Recuperar…' ou o salvamento de "
                    "emergência.",
                    issue="versao_anterior_ilegivel",
                    base_action=base,
                )
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
        """Só é "senha antiga" se a KEK que abre o cofre foi SUBSTITUÍDA por 'Criar nova senha
        mestra' (as KEKs trazidas por 'Recuperar' não disparam o aviso)."""
        current = rec.vault("atual")
        if current is None:
            return False
        try:
            entry = self._kek_for_vault(current.location)
        except (OwlVaultError, OSError):
            return False
        return entry.origin == KEK_TROCADA

    def forget_warning(self, folder_id: str) -> str:
        """Aviso para a confirmação de 'Tirar da lista' — vale em QUALQUER estado e é verdadeiro
        para o estado atual. "" só numa pasta trancada com tudo dentro dela (o texto padrão da
        interface — 'Recuperar uma pasta protegida' a acha — vale). 'Tirar da lista' nunca apaga
        nada; a interface põe "Nada será apagado." antes deste texto.

        Diz onde ficam os arquivos legíveis (se ficam), onde fica cada cópia criptografada fora
        da pasta (área temporária ``.owlvault-<id>``, versão mantida) e que 'Recuperar uma pasta
        protegida' NÃO acha essas cópias (só o ``.owlvault`` de dentro da pasta). Um erro de
        disco nunca vira "" (que a interface leria como "use Recuperar").
        """
        rec = self._get(folder_id)
        try:
            return self._forget_warning(rec)
        except (OwlVaultError, OSError):
            return (
                f"Não foi possível conferir agora onde estão os arquivos de '{rec.name}'. Se ela "
                f"tem cópias criptografadas fora da pasta (na pasta oculta '.owlvault-{rec.id}', "
                "ao lado dela), essas cópias NÃO aparecem em 'Recuperar uma pasta protegida'."
            )

    def _forget_warning(self, rec: FolderRecord) -> str:
        name = rec.name
        # ABRINDO com o cofre ainda em P / APAGANDO com o 'novo' já em P: o destino gravado na
        # área temporária ainda (ou já) não existe, e não é uma cópia que sumiu
        inside_now = rec.state in (ABRINDO, APAGANDO) and self._intermediate_vault(rec) is None
        outside: list[VaultRef] = []
        for v in rec.vaults:
            if v.role == DESCARTANDO or _inside(v.location, rec.path):
                continue  # exclusão já aprovada (nada único) / cofre dentro da pasta
            if inside_now and v.role in ("anterior", "novo") and not os.path.lexists(v.location):
                continue
            outside.append(v)
        present = [v for v in outside if os.path.lexists(v.location)]
        missing = [v for v in outside if not os.path.lexists(v.location)]
        parts: list[str] = []
        if rec.state == TRANCADA:
            in_place = os.path.lexists(rec.path) and self._located(rec)
            if self._inner_differs(rec):
                parts.append(
                    f"Os dados criptografados que estão em '{name}' não são os registrados (podem "
                    "ser de uma versão mais antiga). Depois de tirar da lista, '☰ > Recuperar uma "
                    "pasta protegida' abre essa cópia que está na pasta, com a senha mestra."
                )
            elif in_place and not winfs.is_plain_dir_at(winfs.join(rec.path, VAULT_DIR)):
                parts.append(
                    f"Os arquivos criptografados de '{name}' não estão na pasta (a pasta oculta "
                    f"'{VAULT_DIR}' sumiu). Se você a moveu, coloque-a de volta: só assim "
                    "'☰ > Recuperar uma pasta protegida' encontra os arquivos depois de tirar a "
                    "pasta da lista."
                )
            elif present or missing:
                parts.append(
                    f"Os arquivos de '{name}' continuam criptografados dentro da pasta; para "
                    "voltar a usá-la, use '☰ > Recuperar uma pasta protegida'."
                )
            else:
                return ""
        elif rec.state == ABERTA:
            parts.append(
                f"Os arquivos legíveis continuam na pasta '{name}'; para trancá-la de novo, use "
                "'+ Proteger uma pasta…'."
            )
        elif rec.state == TRANCANDO:
            parts.append(f"Os arquivos legíveis que estão na pasta '{name}' continuam lá.")
        elif rec.state == APAGANDO:
            parts.append(
                f"O trancamento de '{name}' parou no meio: parte dos arquivos (talvez todos) já "
                "saiu da pasta e só existe na cópia criptografada."
            )
            if inside_now:
                parts.append(
                    "Essa cópia já está dentro da pasta; depois de tirar da lista, '☰ > Recuperar "
                    "uma pasta protegida' a encontra."
                )
        elif rec.state in (ABRINDO, RESTAURANDO):
            if inside_now:
                parts.append(
                    f"Os arquivos de '{name}' continuam criptografados dentro da pasta; depois de "
                    "tirar da lista, '☰ > Recuperar uma pasta protegida' a encontra."
                )
            else:
                parts.append(
                    f"A abertura de '{name}' parou no meio: os arquivos que ainda não voltaram "
                    "para a pasta só existem na cópia criptografada."
                )
        elif rec.state == ABERTURA_INCOMPLETA:
            parts.append(
                f"Alguns arquivos de '{name}' não voltaram para a pasta e só existem na cópia "
                "criptografada."
            )
        if present:
            where = ", ".join(
                sorted({winfs.strip_extended(winfs.parent_of(v.location)) for v in present})
            )
            parts.append(
                f"{len(present)} cópia(s) criptografada(s) desta pasta fica(m) fora dela, em "
                f"{where} (pasta oculta)."
            )
            if any(v.role == MANTIDO for v in present):
                parts.append("Os arquivos da versão anterior mantida só existem lá.")
            parts.append(
                "Depois de tirar da lista, essa(s) cópia(s) NÃO aparece(m) em 'Recuperar uma "
                "pasta protegida'; para abrir uma delas, use '☰ > Cópia criptografada de uma "
                "pasta' > 'Abrir uma cópia', com a senha mestra."
            )
        if missing:
            where = ", ".join(
                sorted({winfs.strip_extended(winfs.parent_of(v.location)) for v in missing})
            )
            parts.append(
                f"{len(missing)} cópia(s) criptografada(s) registrada(s) não foi(ram) "
                f"encontrada(s) em {where}."
            )
            if rec.state == ABRINDO:
                parts.append(
                    "Se a cópia ainda estiver dentro da pasta, '☰ > Recuperar uma pasta "
                    "protegida' a encontra."
                )
        if rec.state == APAGANDO:
            parts.append(
                "Se puder, use antes 'Desfazer' ou 'Continuar trancando' (ou 'Procurar a "
                "pasta…', se ela mudou de lugar)."
            )
        elif rec.state in (ABRINDO, RESTAURANDO, ABERTURA_INCOMPLETA):
            parts.append(
                "Se puder, resolva antes a abertura (ou use 'Procurar a pasta…', se ela mudou "
                "de lugar)."
            )
        return " ".join(parts)

    # ------------------------------------------------------------------ versões mantidas
    @staticmethod
    def _what(v: VaultRef) -> str:
        return {
            MANTIDO: "A versão anterior mantida",
            "anterior": "A cópia protegida da pasta aberta",
            "novo": "O cofre novo",
            "atual": "O cofre da pasta",
        }.get(v.role, "A cópia protegida")

    def _checked_manifest(self, v: VaultRef) -> Manifest:
        """Manifesto de um cofre conferindo vault_id registrado e ``complete.owl`` autêntico.

        Cofre ausente ou ilegível NUNCA é tratado como vazio: levanta StateError explicando.
        """
        what = self._what(v)
        where = winfs.strip_extended(v.location)
        if not os.path.lexists(v.location):
            raise StateError(f"{what} não foi encontrada em {where}. Nada foi apagado.")
        other_id = ""
        try:
            opened = open_vault(v.location, self.keys_for_vault(v.location), self.policy)
            if v.vault_id and opened.vault_id.hex() != v.vault_id:
                other_id = opened.vault_id.hex()
            mread = read_manifest(opened)
            info, _ = read_completion(opened, mread.raw)
        except (OwlVaultError, OSError) as exc:
            raise StateError(
                f"Não foi possível ler {what[0].lower()}{what[1:]} em {where} ({exc}). "
                "Nada foi apagado."
            ) from exc
        if other_id:
            raise StateError(f"{what} em {where} não é a registrada. Nada foi apagado.")
        if info is None:
            raise StateError(
                f"{what} em {where} está incompleta (sem registro de conclusão válido). "
                "Nada foi apagado."
            )
        return mread.manifest

    def _manifest_digests(self, vault_dir: str) -> dict[tuple[str, ...], bytes] | None:
        """Caminho dobrado → SHA-256 do manifesto (None se o cofre não pôde ser lido)."""
        try:
            opened = open_vault(vault_dir, self.keys_for_vault(vault_dir), self.policy)
            return {fold_path(e.path): e.sha256 for e in read_manifest(opened).manifest.files}
        except (OwlVaultError, OSError):
            return None

    @staticmethod
    def _same_in_folder(target: str, e: FileEntryRecord) -> bool:
        """A MESMA versão está na pasta? Arquivo comum com o tamanho e a data de modificação do
        manifesto (a abertura devolve a data; qualquer edição a muda)."""
        try:
            st = os.lstat(target)
        except OSError:
            return False
        return winfs.is_plain_file(st) and st.st_size == e.size and st.st_mtime_ns == e.mtime_ns

    def _uncovered(
        self,
        v: VaultRef,
        manifest: Manifest,
        *,
        newer: dict[tuple[str, ...], bytes] | None = None,
        in_folder: str | None = None,
        accepted: Set[tuple[str, ...]] = frozenset(),
    ) -> list[str]:
        """Arquivos do cofre ``v`` que NÃO estão cobertos: nem num cofre mais novo (``newer``),
        nem na pasta (``in_folder``), nem na lista confirmada (``accepted``).

        Cofres comuns são comparados pelo caminho (regra de ouro, §3); a versão anterior
        MANTIDA, pelo conteúdo: ela existe justamente porque o conteúdo dela não está em outro
        lugar.
        """
        by_content = v.role == MANTIDO
        out: list[str] = []
        for e in manifest.files:
            key = fold_path(e.path)
            if key in accepted:
                continue
            if newer is not None and key in newer and (not by_content or newer[key] == e.sha256):
                continue
            if in_folder is not None:
                target = winfs.join(in_folder, *e.path)
                if self._same_in_folder(target, e) if by_content else os.path.lexists(target):
                    continue
            out.append(_rel_key(e.path))
        return out

    def _kept_reference(
        self, rec: FolderRecord
    ) -> tuple[dict[tuple[str, ...], bytes] | None, str | None]:
        """Com o que a versão mantida é comparada (pelo conteúdo): o cofre 'atual' de uma pasta
        trancada; nos outros estados, SÓ a própria pasta. Um 'anterior' nunca conta como
        cobertura: ele pode ser mais velho que a versão mantida e o próximo trancamento o
        apaga pela regra de caminho."""
        if rec.state == TRANCADA:
            current = rec.vault("atual")
            newer = self._manifest_digests(current.location) if current is not None else None
            return newer, None
        return None, rec.path

    def kept_only_files(self, folder_id: str) -> list[str]:
        """Arquivos cuja versão só existe nas versões anteriores mantidas (não está — com o
        mesmo conteúdo — no cofre atual nem na pasta aberta).

        Versão mantida ausente ou ilegível levanta StateError (nunca conta como "0 arquivos").
        """
        rec = self._get(folder_id)
        newer, in_folder = self._kept_reference(rec)
        out: set[str] = set()
        for v in rec.vaults:
            if v.role == MANTIDO:
                manifest = self._checked_manifest(v)
                out.update(self._uncovered(v, manifest, newer=newer, in_folder=in_folder))
        return sorted(out)

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
        """'Apagar a versão anterior…': só com a lista exata confirmada pelo usuário.

        Versão mantida ausente ou ilegível levanta StateError: nada é apagado nem esquecido.
        """
        rec = self._get(folder_id)
        if sorted(confirmed) != self.kept_only_files(folder_id):
            raise StateError("A lista de arquivos mudou; confira de novo antes de apagar.")
        newer, in_folder = self._kept_reference(rec)
        accepted = {_key_of(x) for x in confirmed}
        for v in list(rec.vaults):
            if v.role == DESCARTANDO:
                self._discard_vault(rec, v)
            elif v.role == MANTIDO and not self._apagar_cofre(
                rec, v, newer=newer, in_folder=in_folder, accepted=accepted
            ):
                raise StateError("A lista de arquivos mudou; confira de novo antes de apagar.")
        if not any(v.role in (MANTIDO, DESCARTANDO) for v in rec.vaults):
            rec.attention = ""
        self._save()
        self._cleanup_staging(rec)

    def forget_missing_kept(self, folder_id: str) -> int:
        """Esquece versões mantidas cuja pasta NÃO existe mais (apagada fora do programa).

        Ação explícita do usuário; nada é apagado. Versões que existem mas não abrem nunca são
        esquecidas aqui (use 'Recuperar…' ou o salvamento de emergência). Devolve quantas.
        """
        rec = self._get(folder_id)
        self._locate(rec)
        gone = [v for v in rec.vaults if v.role == MANTIDO and not os.path.lexists(v.location)]
        for v in gone:
            rec.vaults.remove(v)
        if gone:
            if not any(v.role == MANTIDO for v in rec.vaults):
                rec.attention = ""
            self._save()
        return len(gone)

    @staticmethod
    def _is_restore_lock(p: str, name: str) -> bool:
        return name == RESTORE_LOCK_NAME and winfs.is_plain_file_at(winfs.join(p, name))

    def _locked_content_problem(self, rec: FolderRecord) -> str:
        names = set(os.listdir(rec.path))
        extra = sorted(
            n
            for n in names
            if n not in PLACEHOLDER and n != VAULT_DIR and not self._is_restore_lock(rec.path, n)
        )
        if extra:
            shown = ", ".join(extra[:5]) + (f" e mais {len(extra) - 5}" if len(extra) > 5 else "")
            return (
                f"Há item(ns) colocado(s) em '{rec.name}' depois de trancar: {shown}. Mova-os para "
                "outro lugar e tente de novo."
            )
        if VAULT_DIR not in names:
            return f"Os arquivos criptografados de '{rec.name}' não foram encontrados na pasta."
        return ""

    @staticmethod
    def _clear_orphan_restore_lock(p: str) -> str:
        """Remove a trava de restauração que sobrou de uma queda (``.owlvault-restore.lock``).

        Pega a trava como a restauração faz e a solta: o arquivo é apagado ao fechar. Se outra
        janela estiver restaurando, devolve o motivo e nada é feito ("" = tudo certo).
        """
        lock = winfs.join(p, RESTORE_LOCK_NAME)
        if not os.path.lexists(lock):
            return ""
        try:
            with winfs.ExclusiveLock(lock, "A pasta"):
                pass
        except VaultLockedError:
            return (
                "outra janela do Owl Vault está restaurando arquivos nesta pasta; espere terminar"
            )
        except (OwlVaultError, OSError) as exc:
            return f"a trava de restauração não pôde ser removida ({exc})"
        if os.path.lexists(lock):
            return "a trava de restauração não pôde ser removida"
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
            if rec.state == ABERTA and not rec.vaults and rec in self.folders:
                self.folders.remove(rec)  # nada foi feito: tira da lista
                with contextlib.suppress(OwlVaultError, OSError):
                    self._cleanup_staging(rec)
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
        self._prepare_staging(staging)
        progress.stage("Conferindo a pasta")
        # nome único: nunca reaproveita (nem apaga) a pasta de outro cofre
        novo = winfs.join(staging, f"novo-{secrets.token_hex(8)}")
        try:
            plan = self._preflight(p, novo, staging, progress, cancel, exclude_record=rec.id)
        except BaseException:
            with contextlib.suppress(OwlVaultError, OSError):
                self._cleanup_staging(rec)  # só nomes nossos; nunca fica área órfã
            raise
        old_vaults, old_attention, old_pending = list(rec.vaults), rec.attention, list(rec.pending)
        rec.state = TRANCANDO
        rec.vaults = [v for v in rec.vaults if v.role != "novo"] + [VaultRef("", "novo", novo)]
        rec.attention = ""
        rec.pending = []
        try:
            self._save()
        except BaseException:
            # O disco continua em ABERTA e nada foi criado: a memória volta igual (como em
            # unlock() com ABRINDO), para "Tente de novo" funcionar.
            rec.state = ABERTA
            rec.vaults = old_vaults
            rec.attention = old_attention
            rec.pending = old_pending
            with contextlib.suppress(OwlVaultError, OSError):
                self._cleanup_staging(rec)
            raise
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
            # 'apagando' ainda não foi gravado: este trancamento não apagou nada. Um arquivo que
            # falta em P foi tirado pelo usuário — a pasta volta a ABERTA (§4.1.3). O 'novo' sai
            # mesmo que o perfil não grave DESCARTANDO (must_record=False): sem isso a pasta
            # ficaria em TRANCANDO e o 'Resolver' a julgaria pela heurística de "arquivo
            # faltando" (APAGANDO, "começou a apagar"), o que seria falso. O cabeçalho sai
            # primeiro; no início, um 'novo' sem cabeçalho e sem marcador é descartado, e um
            # 'novo' que não existe some da lista.
            with contextlib.suppress(OwlVaultError, OSError):
                self._discard_novo(rec, must_record=False, nothing_deleted=True)
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
        try:
            self._save()
        except BaseException:
            # Nenhum original foi tocado: desfaz na memória (a interface nunca oferece
            # "Continuar trancando" para um estado que não está no disco) e descarta o 'novo'.
            rec.state = TRANCANDO
            rec.fingerprints = {}
            rec.zone_files = []
            with contextlib.suppress(OwlVaultError, OSError):
                self._discard_novo(rec, must_record=False, nothing_deleted=True)
            raise
        self._ensure_marker(p, novo)
        # marcador novo (id novo): nenhuma sobra de 'Desfazer' pode casar com ele
        return self._finish_lock(rec, progress, cancel, undo_leftovers=False)

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
        # A lista da passada anterior deixa de valer ANTES de apagar qualquer coisa: uma queda
        # no meio desta passada nunca deixa no disco uma lista antiga (e falsa).
        rec.pending = []
        rec.attention = _INTERRUPTED_LOCK
        self._save()
        return self._finish_lock(rec, progress or NullProgress(), cancel or CancelToken())

    @staticmethod
    def _current_fingerprint(target: str) -> Fingerprint | None:
        """Impressão digital atual de um arquivo comum, lida do handle sem bloquear ninguém
        (None se não der para ler, se for pasta ou link)."""
        try:
            with winfs.Win32File.open(
                target,
                winfs.FILE_READ_ATTRIBUTES,
                winfs.FILE_SHARE_READ | winfs.FILE_SHARE_WRITE | winfs.FILE_SHARE_DELETE,
                winfs.OPEN_EXISTING,
                winfs.FILE_FLAG_OPEN_REPARSE_POINT,
            ) as f:
                info = f.info()
        except (OwlVaultError, OSError):
            return None
        if info.is_directory or info.attributes & winfs.FILE_ATTRIBUTE_REPARSE_POINT:
            return None
        return info.fingerprint()

    @staticmethod
    def _content_check(
        target: str, e: FileEntryRecord, cancel: CancelToken
    ) -> tuple[Fingerprint | None, str, str]:
        """Confere o CONTEÚDO de um original (tamanho + SHA-256 do manifesto, sem mudar durante a
        conferência). Devolve (impressão digital, "", "") ou (None, motivo, tipo), com tipo
        "mudou" (não é a versão guardada) ou "uso" (aberto/sem acesso). A exclusão confere de
        novo no próprio handle."""

        def info() -> winfs.HandleInfo:
            with winfs.Win32File.open(
                target,
                winfs.FILE_READ_ATTRIBUTES,
                winfs.FILE_SHARE_READ | winfs.FILE_SHARE_WRITE | winfs.FILE_SHARE_DELETE,
                winfs.OPEN_EXISTING,
                winfs.FILE_FLAG_OPEN_REPARSE_POINT,
            ) as f:
                return f.info()

        def unreadable(exc: Exception) -> tuple[None, str, str]:
            if isinstance(exc, OSError):
                exc = winfs.classify_os_error(exc, "Não foi possível conferir o arquivo")
            return None, f"{exc}; não foi apagado", "uso"

        if not winfs.is_plain_file_at(target):
            return None, "não é mais um arquivo comum (pasta ou link); não foi apagado", "mudou"
        try:
            before = info()
        except (OwlVaultError, OSError) as exc:
            return unreadable(exc)
        if before.attributes & winfs.FILE_ATTRIBUTE_REPARSE_POINT or before.is_directory:
            return None, "não é mais um arquivo comum (pasta ou link); não foi apagado", "mudou"
        if before.number_of_links > 1:
            return None, "o arquivo tem outro vínculo (hard link); não foi apagado", "uso"
        if before.size != e.size:
            return None, _CHANGED, "mudou"
        try:
            digest = hash_file_unbuffered(target, cancel)
            after = info()
        except CancelledError:
            raise
        except (OwlVaultError, OSError) as exc:
            return unreadable(exc)
        if digest != e.sha256:
            return None, _CHANGED, "mudou"
        if after.fingerprint() != before.fingerprint():
            return None, "o arquivo mudou durante a conferência; não foi apagado", "uso"
        return before.fingerprint(), "", ""

    def _deletable(
        self, rec: FolderRecord, target: str, e: FileEntryRecord, cancel: CancelToken
    ) -> tuple[Fingerprint | None, str, str]:
        """Com que impressão digital o original ``target`` pode ser apagado.

        A impressão gravada na cifragem vale se o arquivo ainda é exatamente aquele. Sem ela —
        ou se ela não bate mais (arquivo devolvido por um 'Desfazer', data regravada pela
        restauração, o mesmo conteúdo posto de volta) — vale o CONTEÚDO conferido com o
        manifesto do cofre novo: apagar um arquivo idêntico ao guardado nunca perde nada.
        """
        raw = rec.fingerprints.get(_rel_key(e.path))
        if raw:
            try:
                recorded: Fingerprint | None = _fp_from_list(raw)
            except (ValueError, TypeError):
                recorded = None
            if recorded is not None and self._current_fingerprint(target) == recorded:
                return recorded, "", ""
        return self._content_check(target, e, cancel)

    @staticmethod
    def _pending_attention(
        in_use: list[str],
        changed: list[str],
        new_items: list[str],
        leftovers: list[str] | None = None,
    ) -> str:
        """Texto de 'Precisa de atenção' de um trancamento parado em 'apagando', específico de
        cada problema (em uso ≠ mudou ≠ item novo ≠ sobra de um 'Desfazer' interrompido)."""

        def names(items: list[str]) -> str:
            more = f" e mais {len(items) - 3}" if len(items) > 3 else ""
            return ", ".join(items[:3]) + more

        parts = ["O trancamento não terminou. O que já saiu da pasta está guardado."]
        if leftovers:
            parts.append(
                f"{len(leftovers)} pedaço(s) de arquivo deixados por um 'Desfazer' interrompido "
                f"não puderam ser apagados agora: {names(leftovers)}. Os arquivos estão "
                "guardados; não mova esses pedaços: clique em 'Continuar trancando' de novo."
            )
        if in_use:
            parts.append(
                f"{len(in_use)} item(ns) não foram apagados porque estavam abertos em outro "
                f"programa (ou o Windows não deixou): {names(in_use)}. Feche-os e clique em "
                "'Continuar trancando'."
            )
        if changed:
            parts.append(
                f"{len(changed)} arquivo(s) mudaram depois de serem guardados: {names(changed)}. "
                "A versão nova deles NÃO está guardada; para guardá-la, clique em 'Desfazer' e "
                "tranque de novo."
            )
        if new_items:
            parts.append(
                f"{len(new_items)} item(ns) foram colocados na pasta durante o trancamento e NÃO "
                f"estão guardados: {names(new_items)}. Mova-os para outro lugar e clique em "
                "'Continuar trancando'."
            )
        parts.append("Para deixar a pasta aberta, clique em 'Desfazer'.")
        return " ".join(parts)

    @staticmethod
    def _marker_restore_id(p: str, vault_id_hex: str, manifest_sha: str) -> str | None:
        """``restore_id`` do marcador de restauração em P, se o marcador é DESTE cofre (mesmo
        vault_id e mesmo manifesto); senão None."""
        marker = winfs.join(p, MARKER_NAME)
        if not winfs.is_plain_file_at(marker):
            return None
        try:
            with open(marker, "rb") as fh:
                obj = json.loads(fh.read(4096).decode("ascii"))
        except (OSError, ValueError):
            return None
        if (
            not isinstance(obj, dict)
            or obj.get("vault_id") != vault_id_hex
            or obj.get("manifest_sha256") != manifest_sha
        ):
            return None
        rid = obj.get("restore_id")
        return rid if isinstance(rid, str) and _RESTORE_ID_RE.fullmatch(rid) else None

    def _clear_undo_parts(
        self, p: str, vault_id_hex: str, manifest_sha: str, cancel: CancelToken
    ) -> list[str]:
        """Apaga os temporários ``.owl-<restore_id>-….part`` que um 'Desfazer' derrubado por uma
        queda (energia, processo morto) deixou em P e nas subpastas.

        São cópias parciais, já decifradas, de arquivos guardados no cofre 'novo': apagá-las não
        perde nada, e quem as movesse para fora tiraria da pasta um pedaço legível de um arquivo
        protegido. Só valem os nomes do marcador de restauração DESTE cofre em P (o mesmo padrão
        e a mesma remoção de ``restore_vault`` na retomada), com a trava de restauração tomada
        (nenhum 'Desfazer' rodando). Devolve os caminhos (relativos a P, para a tela) que não
        puderam ser apagados agora.
        """
        restore_id = self._marker_restore_id(p, vault_id_hex, manifest_sha)
        if restore_id is None:
            return []
        pattern = re.compile(re.escape(f".owl-{restore_id}-") + r"[0-9a-f]{32}\.part")

        def scan() -> list[tuple[str, tuple[str, ...]]]:
            found: list[tuple[str, tuple[str, ...]]] = []
            stack: list[tuple[str, tuple[str, ...]]] = [(p, ())]
            while stack:
                cancel.check()
                folder, rel = stack.pop()
                try:
                    with os.scandir(folder) as it:
                        entries = list(it)
                except OSError:
                    continue  # pasta que não dá para listar: a exclusão acusa o problema
                for entry in entries:
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if getattr(st, "st_file_attributes", 0) & winfs.FILE_ATTRIBUTE_REPARSE_POINT:
                        continue  # nunca segue links
                    if entry.is_dir(follow_symlinks=False):
                        stack.append((entry.path, (*rel, entry.name)))
                    elif pattern.fullmatch(entry.name):
                        found.append((entry.path, (*rel, entry.name)))
            return found

        lock = winfs.ExclusiveLock(winfs.join(p, RESTORE_LOCK_NAME), "A pasta")
        try:
            lock.acquire()
        except (OwlVaultError, OSError):
            # outro 'Desfazer' rodando (ou trava inválida): nada é apagado agora
            return [display_path(rel) for _, rel in scan()]
        try:
            root = winfs.resolve(p)
            failed: list[str] = []
            for path, rel in scan():
                try:
                    safe_remove_own(path, root, pattern)
                except (OwlVaultError, OSError):
                    failed.append(display_path(rel))
            return failed
        finally:
            lock.release()

    def _finish_lock(
        self,
        rec: FolderRecord,
        progress: ProgressSink,
        cancel: CancelToken,
        *,
        undo_leftovers: bool = True,
    ) -> LockOutcome:
        self._require_saved()  # nada é apagado sem o estado 'apagando' no disco
        p = rec.path
        novo = rec.vault("novo")
        if novo is None:
            raise StateError("O cofre novo desta pasta não foi encontrado.")
        if self._novo_moved_into_folder(rec, novo):
            # queda depois de mover o cofre para P e antes de gravar 'trancada'
            return self._conclude_lock(rec, novo)
        self._require_vault(rec, novo)
        opened = open_vault(novo.location, self.keys_for_vault(novo.location), self.policy)
        mread = read_manifest(opened)
        manifest = mread.manifest
        files = manifest.files
        progress.stage("Apagando as cópias legíveis", 0, len(files))
        pending: list[str] = []
        in_use: list[str] = []
        changed: list[str] = []
        new_items: list[str] = []
        # Sobras de um 'Desfazer' que caiu no meio: apagadas aqui, nunca "itens novos" (vd2-2).
        leftovers = (
            self._clear_undo_parts(
                p, opened.vault_id.hex(), hashlib.sha256(mread.raw).hexdigest(), cancel
            )
            if undo_leftovers
            else []
        )
        for shown in leftovers:
            pending.append(f"{shown}: {_UNDO_LEFTOVER}")
        for e in files:
            cancel.check()
            target = winfs.join(p, *e.path)
            if not os.path.lexists(target):
                progress.advance(0, 1)
                continue
            shown = display_path(e.path)
            expected, why, kind = self._deletable(rec, target, e, cancel)
            if expected is None:
                pending.append(f"{shown}: {why}")
                (changed if kind == "mudou" else in_use).append(shown)
                progress.advance(0, 1)
                continue
            try:
                winfs.delete_checked(target, expected)
            except CancelledError:
                raise
            except OwlVaultError as exc:
                if os.path.lexists(target):  # sumiu sozinho no meio: nada a fazer
                    pending.append(f"{shown}: {exc}")
                    (changed if isinstance(exc, SourceChangedError) else in_use).append(shown)
            progress.advance(0, 1)
        for d in sorted(manifest.dirs, key=lambda d: len(d.path), reverse=True):
            target = winfs.join(p, *d.path)
            if not os.path.lexists(target):
                continue
            shown = display_path(d.path)
            if not winfs.is_plain_dir_at(target):
                # outro item (arquivo, link) no lugar da pasta: não é guardado por este cofre
                pending.append(f"{shown}: {_NEW_ITEM}")
                new_items.append(shown)
                continue
            try:
                winfs.delete_checked(target, None, is_dir=True)
            except OwlVaultError as exc:
                if any(x.startswith(shown + "\\") for x in pending):
                    continue  # consequência de um item já listado
                try:
                    inside = sorted(os.listdir(target))
                except OSError:
                    inside = []
                if not inside:
                    pending.append(f"{shown}: {exc}")
                    in_use.append(shown)
                for n in inside:  # nada do manifesto sobrou aqui: são itens colocados
                    pending.append(f"{shown}\\{n}: {_NEW_ITEM}")
                    new_items.append(f"{shown}\\{n}")
        lock_problem = self._clear_orphan_restore_lock(p)
        if lock_problem:
            pending.append(f"{RESTORE_LOCK_NAME}: {lock_problem}")
            in_use.append(RESTORE_LOCK_NAME)
        known = {MARKER_NAME, RESTORE_LOCK_NAME}
        top_pending = {fold_path((x.split("\\", 1)[0].split(":", 1)[0],)) for x in pending}
        for n in sorted(os.listdir(p)):
            if n not in known and fold_path((n,)) not in top_pending:
                pending.append(f"{n}: {_NEW_ITEM}")
                new_items.append(n)
        if pending:
            rec.pending = pending
            rec.attention = self._pending_attention(in_use, changed, new_items, leftovers)
            self._save()
            return LockOutcome(rec, complete=False, pending=pending)
        # tudo apagado: o cofre entra na pasta e o índice é gravado LOGO EM SEGUIDA
        remove_restore_marker(p)
        winfs.rename_dir(novo.location, winfs.join(p, VAULT_DIR))
        return self._conclude_lock(rec, novo, {fold_path(e.path): e.sha256 for e in files})

    def _novo_moved_into_folder(self, rec: FolderRecord, novo: VaultRef) -> bool:
        """'apagando' com o cofre novo já dentro de P (queda depois do rename)?"""
        if rec.state != APAGANDO or not novo.vault_id or os.path.lexists(novo.location):
            return False
        final = winfs.join(rec.path, VAULT_DIR)
        if not winfs.is_plain_dir_at(final):
            return False
        try:
            return self._vault_id_of(final) == novo.vault_id
        except OSError:
            return False

    def _conclude_lock(
        self,
        rec: FolderRecord,
        novo: VaultRef,
        newer: dict[tuple[str, ...], bytes] | None = None,
    ) -> LockOutcome:
        """O cofre novo já está em ``P\\.owlvault``: grava 'trancada' ANTES de qualquer outro passo.

        Espaço reservado e regra de ouro vêm depois, como melhor esforço: se falharem, a pasta
        já está trancada e o passo é refeito ao iniciar (``reconcile_on_start``). ``newer``: o
        manifesto do cofre novo já lido (caminho dobrado → SHA-256), se houver.
        """
        p = rec.path
        final = winfs.join(p, VAULT_DIR)
        novo.role = "atual"
        novo.location = final
        rec.state = TRANCADA
        rec.pending = []
        rec.attention = ""
        rec.fingerprints = {}
        self._save()
        with contextlib.suppress(OSError):
            shell.change_attributes(final, add=HIDE)
        self._restrict(final, directory=True)
        placeholder_problem = ""
        try:
            self._write_placeholder(rec)
        except (OwlVaultError, OSError) as exc:
            placeholder_problem = (
                f"O atalho e o aviso de '{rec.name}' não puderam ser gravados ({exc}); o Owl "
                "Vault tenta de novo ao iniciar."
            )
        kept = self._settle_previous(rec, newer)
        if placeholder_problem:
            rec.attention = (rec.attention + " " + placeholder_problem).strip()
            with contextlib.suppress(OwlVaultError, OSError):
                self._save()
        with contextlib.suppress(OwlVaultError, OSError):
            self._cleanup_staging(rec)
        return LockOutcome(rec, complete=True, kept_previous=kept, removable=self._is_removable(p))

    def _settle_previous(
        self, rec: FolderRecord, newer: dict[tuple[str, ...], bytes] | None = None
    ) -> bool:
        """Regra de ouro para os cofres anteriores de uma pasta trancada (melhor esforço).

        Coberto pelo cofre atual ⇒ apagado; senão (ou se não deu para ler) vira versão MANTIDA;
        exclusão já aprovada que falhou no meio fica DESCARTANDO e é retomada ao iniciar.
        Devolve se ficou alguma versão mantida.
        """
        current = rec.vault("atual")
        if newer is None and current is not None:
            newer = self._manifest_digests(current.location)
        accepted = {_key_of(x) for x in rec.accepted_missing}
        problems: list[str] = []
        for v in list(rec.vaults):
            try:
                if v.role == DESCARTANDO:
                    self._discard_vault(rec, v)
                    continue
                if v.role not in ("anterior", MANTIDO) or newer is None:
                    continue
                try:
                    gone = self._apagar_cofre(
                        rec, v, newer=newer, accepted=accepted if v.role == "anterior" else set()
                    )
                except StateError:
                    gone = False  # ausente/ilegível: nunca apagado; fica como versão mantida
                if not gone and v.role != DESCARTANDO:
                    v.role = MANTIDO
            except (OwlVaultError, OSError) as exc:
                problems.append(str(exc))
        if newer is not None and not any(v.role in ("anterior", DESCARTANDO) for v in rec.vaults):
            rec.accepted_missing = []
        kept = any(v.role == MANTIDO for v in rec.vaults)
        texts = []
        if kept:
            texts.append(
                f"Foi mantida uma versão anterior de '{rec.name}' com arquivos que não estão na "
                "pasta."
            )
        if problems:
            texts.append(
                "Uma versão anterior já conferida não pôde ser apagada agora; o Owl Vault tenta "
                "de novo ao iniciar."
            )
        rec.attention = " ".join(texts)
        with contextlib.suppress(OwlVaultError, OSError):
            self._save()
        return kept

    def undo_lock(
        self,
        folder_id: str,
        progress: ProgressSink | None = None,
        cancel: CancelToken | None = None,
    ) -> UnlockOutcome:
        """Trancamento interrompido ⇒ devolve à pasta o que já foi apagado (cofre ``novo``).

        Conflito num caminho que o Owl Vault apagou (outro conteúdo foi colocado no lugar) ⇒ o
        cofre vira versão MANTIDA (nunca apagada sem confirmação) e o relatório traz a lista.
        "Nunca apagado" é decidido pelo PRÓPRIO arquivo (mesmo volume + FileId da impressão
        gravada na cifragem), nunca pela lista de pendências: um arquivo apagado e recriado tem
        outro FileId, e uma lista antiga (queda) não vale. Na dúvida, a versão é mantida.
        """
        rec = self._get(folder_id)
        if rec.state != APAGANDO:
            raise StateError("Não há trancamento interrompido nesta pasta.")
        p = self._locate(rec)
        novo = rec.vault("novo")
        if novo is None:
            raise StateError("O cofre novo desta pasta não foi encontrado.")
        if self._novo_moved_into_folder(rec, novo):
            # o cofre já entrou na pasta: conclui o trancamento e abre normalmente
            self._conclude_lock(rec, novo)
            return self.unlock(folder_id, progress, cancel)
        self._require_vault(rec, novo)
        fingerprints = {fold_path(tuple(k.split("\\"))): v for k, v in rec.fingerprints.items()}
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
        if report.failed:
            rec.attention = "Não foi possível devolver todos os arquivos: " + "; ".join(
                report.failed[:5]
            )
            self._save()
            return UnlockOutcome(rec, complete=False, report=report, path=p)
        lost = [c for c in report.conflicts if not self._never_deleted(p, c, fingerprints)]
        remove_restore_marker(p)
        before = (novo.role, rec.state, rec.pending, rec.fingerprints, rec.attention)
        novo.role = MANTIDO if lost else "anterior"
        rec.state = ABERTA
        rec.pending = []
        rec.fingerprints = {}
        rec.attention = (
            f"{len(lost)} arquivo(s) não voltaram para a pasta porque já havia outro item com o "
            f"mesmo nome: {'; '.join(lost[:5])}. A versão guardada deles foi mantida."
            if lost
            else ""
        )
        try:
            self._save()
        except BaseException:
            # a memória volta ao que está no disco (APAGANDO): "Desfazer" de novo, no mesmo
            # processo, faz o mesmo que depois de reiniciar
            novo.role, rec.state, rec.pending, rec.fingerprints, rec.attention = before
            raise
        return UnlockOutcome(rec, complete=True, report=report, path=p)

    def _never_deleted(
        self, p: str, conflict: str, fingerprints: dict[tuple[str, ...], list[Any]]
    ) -> bool:
        """O item em conflito no 'Desfazer' é o MESMO arquivo que foi criptografado (mesmo
        volume + FileId da impressão digital da cifragem)? Só então o Owl Vault nunca o apagou
        e a cópia da pasta é a mais nova. Sem impressão, sem leitura ou com outro FileId ⇒ conta
        como apagado (a versão guardada é mantida)."""
        rel = conflict.split(":", 1)[0]
        raw = fingerprints.get(_key_of(rel))
        if not raw:
            return False
        try:
            recorded = _fp_from_list(raw)
        except (ValueError, TypeError):
            return False
        current = self._current_fingerprint(winfs.join(p, *rel.split("\\")))
        return current is not None and current.identity == recorded.identity

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
        if rec.state in (ABRINDO, RESTAURANDO):
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
        lock_problem = self._clear_orphan_restore_lock(p)
        if lock_problem:
            raise StateError(f"Não foi possível abrir '{rec.name}': {lock_problem}.")
        # espaço e destino conferidos com o cofre ainda na pasta (nada gravado até aqui)
        self._check_room_to_open(rec, vault_dir)
        staging = self.staging_of(rec)
        self._prepare_staging(staging)
        target = winfs.join(staging, f"anterior-{secrets.token_hex(8)}")
        # destino gravado ANTES de mover: a retomada sabe para onde o cofre vai. A pasta deixa
        # de ser "escondida" na MESMA gravação (os atributos saem com o espaço reservado, em
        # _move_vault_out): uma falha antes daqui deixa a pasta trancada E escondida.
        old_vaults = list(rec.vaults)
        was_hidden = rec.hidden
        rec.vaults.remove(current)
        rec.vaults.append(VaultRef(current.vault_id, "anterior", target))
        rec.state = ABRINDO
        rec.hidden = False
        try:
            self._save()
        except BaseException:
            rec.vaults = old_vaults
            rec.state = TRANCADA
            rec.hidden = was_hidden
            raise
        self._move_vault_out(rec, checked=True)
        if was_hidden:
            shell.notify_changed(winfs.parent_of(p))
        return self._finish_unlock(rec, progress, cancel)

    def _check_room_to_open(self, rec: FolderRecord, vault_dir: str) -> None:
        """As conferências de ``restore_vault`` (destino, caminhos longos, FAT32, espaço) feitas
        ANTES de o cofre sair da pasta: se não couber, nada muda e a pasta continua trancada."""
        p = rec.path
        opened = open_vault(vault_dir, self.keys_for_vault(vault_dir), self.policy)
        manifest = read_manifest(opened).manifest
        dres = winfs.resolve(p)
        problems = destination_location_problems(dres, self._protected(), f"A pasta '{rec.name}'")
        if problems:
            raise UnsafePathError(" ".join(problems))
        base_len = utf16_len(p)
        for e in manifest.entries:
            if base_len + sum(utf16_len(c) + 1 for c in e.path) + _LONGEST_TEMP > (
                MAX_EXTENDED_PATH_UTF16
            ):
                raise UnsafePathError(
                    f"Caminho longo demais para abrir em '{rec.name}': {display_path(e.path)}"
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
        if needed > space.free_bytes:
            raise InsufficientSpaceError(
                f"Não há espaço para abrir '{rec.name}': são necessários ~{needed / MIB:.0f} MiB "
                f"e há {space.free_bytes / MIB:.0f} MiB livres. Libere espaço e tente de novo; "
                "a pasta continua trancada."
            )

    def _move_vault_out(self, rec: FolderRecord, *, checked: bool = False) -> None:
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
        extra = [
            n
            for n in os.listdir(p)
            if n not in PLACEHOLDER and n != VAULT_DIR and not self._is_restore_lock(p, n)
        ]
        if extra:
            raise self._stuck(
                rec,
                f"Há item(ns) colocado(s) em '{rec.name}' enquanto estava trancada. Mova-os para "
                "outro lugar e clique em 'Continuar abrindo'.",
            )
        lock_problem = self._clear_orphan_restore_lock(p)
        if lock_problem:
            raise StateError(f"Não foi possível abrir '{rec.name}': {lock_problem}.")
        if not checked:
            self._check_room_to_open(rec, vault_dir)
        self._prepare_staging(winfs.parent_of(prev.location))
        self._remove_placeholder(rec)
        winfs.rename_dir(vault_dir, prev.location)

    def _stuck(self, rec: FolderRecord, text: str) -> StateError:
        """Erro de uma abertura interrompida que só o usuário resolve: o texto também vira a
        atenção da linha (o 'Resolver' mostra o problema de verdade, não uma frase fixa)."""
        if rec.state in (ABRINDO, RESTAURANDO) and rec.attention != text:
            rec.attention = text
            with contextlib.suppress(OwlVaultError, OSError):
                self._save()
        return StateError(text)

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
        self._require_vault(rec, prev)
        try:
            shell.change_attributes(p, add=FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
        except OSError:
            pass
        keys = self.keys_for_vault(prev.location)
        opened = open_vault(prev.location, keys, self.policy)
        manifest = read_manifest(opened).manifest
        total = len(manifest.files)
        if inspect_destination(p) == "nonempty":
            if rec.state not in (RESTAURANDO, ABERTURA_INCOMPLETA):
                # a restauração nem começou: o que está na pasta foi colocado por alguém
                names = sorted(n for n in os.listdir(p) if not self._is_restore_lock(p, n))
                shown = ", ".join(names[:5]) + (
                    f" e mais {len(names) - 5}" if len(names) > 5 else ""
                )
                raise self._stuck(
                    rec,
                    f"Há item(ns) colocado(s) em '{rec.name}' enquanto ela abria: {shown}. "
                    "Mova-os para outro lugar e clique em 'Continuar abrindo'.",
                )
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
            if rec.state == ABRINDO:
                rec.state = RESTAURANDO  # fase gravada ANTES de restaurar
                try:
                    self._save()
                except BaseException:
                    # nada foi restaurado: a memória volta a 'abrindo' (igual ao disco); a nova
                    # tentativa grava a fase de novo antes de restaurar
                    rec.state = ABRINDO
                    raise
            else:
                self._require_saved()  # a fase em memória TEM de estar no disco
            try:
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
            except (OwlVaultError, OSError):
                # a restauração não chegou a começar (sem marcador): a fase volta a 'abrindo'
                if rec.state == RESTAURANDO and not os.path.lexists(winfs.join(p, MARKER_NAME)):
                    rec.state = ABRINDO
                    with contextlib.suppress(OwlVaultError, OSError):
                        self._save()
                raise
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
        """Para 'Remover proteção' de uma pasta ABERTA: o que está guardado e não na pasta.

        Cópia protegida ausente ou ilegível levanta StateError (nunca conta como vazia).
        """
        rec = self._get(folder_id)
        p = self._locate(rec)
        missing: set[str] = set()
        for v in rec.vaults:
            if v.role == DESCARTANDO:
                continue  # já conferido e aprovado; a exclusão só não terminou
            manifest = self._checked_manifest(v)
            missing.update(self._uncovered(v, manifest, in_folder=p))
        return sorted(missing)

    def remove_protection(
        self, folder_id: str, *, confirmed_missing: list[str] | None = None
    ) -> None:
        """Só para pasta ABERTA: apaga os cofres (regra de ouro com a pasta) e tira da lista."""
        rec = self._get(folder_id)
        p = self._locate(rec)
        if rec.state != ABERTA:
            raise StateError("Abra a pasta antes de remover a proteção.")
        missing = self.removal_missing(folder_id)
        confirmed = set(confirmed_missing or [])
        if any(m not in confirmed for m in missing):
            raise StateError(
                "Há arquivos protegidos que não estão na pasta; confirme a lista antes de remover."
            )
        accepted = {_key_of(x) for x in confirmed}
        for v in list(rec.vaults):
            if v.role == DESCARTANDO:
                self._discard_vault(rec, v)
            elif not self._apagar_cofre(rec, v, in_folder=p, accepted=accepted):
                raise StateError(
                    "A pasta mudou; confira de novo a lista antes de remover a proteção."
                )
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
        """'Tirar da lista' — vale em QUALQUER estado e não apaga nada (veja ``forget_warning``)."""
        rec = self._get(folder_id)
        self.folders.remove(rec)
        self._save()

    def leave_open(self, folder_id: str) -> str:
        """'Deixar a pasta aberta' — saída de um trancamento interrompido em TRANCANDO que a
        conferência não decide (a cópia que estava sendo criada não pode ser lida).

        Nada é apagado: nesse estado nenhum original foi tocado ('apagando' nunca foi gravado),
        então a pasta volta a ABERTA e a cópia em dúvida vira versão MANTIDA (nunca apagada sem
        a confirmação do usuário). Se a conferência decidir (cópia descartável, ou 'apagando'),
        segue o caminho normal. Devolve o estado final.
        """
        rec = self._get(folder_id)
        if rec.state != TRANCANDO:
            raise StateError("Não há trancamento interrompido nesta pasta.")
        self._locate(rec)
        if self._discard_novo(rec) != "manter":
            return rec.state
        novo = rec.vault("novo")
        if novo is not None:
            if not novo.vault_id:
                with contextlib.suppress(OSError):
                    novo.vault_id = self._vault_id_of(novo.location)
            novo.role = MANTIDO
        rec.state = ABERTA
        rec.pending = []
        rec.fingerprints = {}
        rec.attention = (
            "A cópia criptografada do trancamento interrompido foi mantida como versão anterior; "
            "nada foi apagado."
        )
        self._save()
        return rec.state

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
            # KEK "recuperada": abre a pasta, mas não é uma senha mestra substituída (sem aviso
            # de "senha antiga" depois de 'Recuperar')
            self.session.index.keks.append(KekEntry(hdr.salt, hdr.kdf, kek, KEK_RECUPERADA))
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
            with contextlib.suppress(OwlVaultError, OSError):
                self.refresh_shortcut(rec)
        return rec

    def relocate(self, folder_id: str, new_path: str) -> None:
        """'Procurar a pasta…' — funciona em QUALQUER estado.

        Aceita a mesma pasta (volume + FileId) ou uma pasta cujo ``.owlvault`` tem o vault_id
        que o estado espera DENTRO da pasta (``_expected_inside``): uma cópia trancada (backup)
        nunca toma o lugar de uma pasta aberta. Se a pasta escolhida não for ela, procura entre
        as pastas logo abaixo (o seletor do Windows não mostra uma pasta escondida: o usuário
        escolhe a pasta onde ela fica). Recalcula o lugar de cada cofre (dentro da pasta, na área
        temporária antiga ou na nova ao lado dela, conferindo o vault_id) e recusa — sem mudar
        nada — se algum não for achado.
        """
        rec = self._get(folder_id)
        p_ext = winfs.to_extended(new_path)
        try:
            res, inner, inner_id = self._relocate_candidate(rec, p_ext)
        except StateError:
            child = self._relocate_child(rec, p_ext)
            if child is None:
                raise
            p_ext, (res, inner, inner_id) = child
        assert res.identity is not None
        for other in self.folders:
            if (
                other is not rec
                and other.file_id == res.identity.file_id.hex()
                and other.volume == res.volume
            ):
                raise StateError("Esta pasta já está na lista.")
        new_staging = winfs.join(winfs.parent_of(p_ext), f".owlvault-{rec.id}")
        found: list[tuple[VaultRef, str]] = []
        lost: list[VaultRef] = []
        for v in rec.vaults:
            loc = self._relocated_vault(rec, v, inner, inner_id, new_staging)
            if loc is None:
                lost.append(v)
            else:
                found.append((v, loc))
        if lost:
            where = ", ".join(winfs.strip_extended(v.location) for v in lost[:3])
            raise StateError(
                f"Nem todos os dados protegidos de '{rec.name}' foram encontrados ({where}). Nada "
                f"foi alterado. Se você moveu a pasta oculta '.owlvault-{rec.id}' que fica ao lado "
                "dela, coloque-a de volta ao lado da pasta e tente de novo."
            )
        rec.path = p_ext
        rec.name = winfs.name_of(p_ext)
        rec.volume = res.volume
        rec.file_id = res.identity.file_id.hex()
        for v, loc in found:
            if loc:
                v.location = loc
            else:
                rec.vaults.remove(v)
        if rec.state in (TRANCADA, ABERTA):
            rec.attention = ""
        self._save()
        if rec.state == TRANCADA and winfs.is_plain_dir_at(inner):
            with contextlib.suppress(OwlVaultError, OSError):
                self._write_placeholder(rec)

    def _expected_inside(self, rec: FolderRecord) -> set[str]:
        """vault_id que pode estar em ``P\\.owlvault`` no estado atual: o 'atual' (trancada), o
        cofre que está saindo (abrindo) ou o 'novo' que já entrou (apagando, queda no fim)."""
        if rec.state == TRANCADA:
            v = rec.vault("atual")
        elif rec.state == ABRINDO:
            v = self._latest_previous_or_none(rec)
            if v is not None and os.path.lexists(v.location):
                v = None  # o cofre já saiu para a área temporária: em P só haveria uma cópia
        elif rec.state == APAGANDO:
            v = rec.vault("novo")
            if v is not None and os.path.lexists(v.location):
                v = None  # o 'novo' ainda está na área temporária: não entrou em P
        else:
            v = None  # aberta, restaurando, abertura incompleta, trancando: nenhum cofre em P
        return {v.vault_id} if v is not None and v.vault_id else set()

    def _relocate_candidate(self, rec: FolderRecord, p_ext: str) -> tuple[winfs.Resolved, str, str]:
        """Confere se ``p_ext`` é a pasta de ``rec`` (StateError explica por que não é).
        Devolve (resolução, ``P\\.owlvault``, vault_id de dentro em que se pode confiar)."""
        try:
            res = winfs.resolve(p_ext)
        except OwlVaultError as exc:
            raise StateError(f"Não foi possível acessar a pasta escolhida: {exc}") from exc
        if not res.exists or not res.is_directory or res.identity is None:
            raise StateError("A pasta escolhida não existe.")
        inner = winfs.join(p_ext, VAULT_DIR)
        inner_id = ""
        if winfs.is_plain_dir_at(inner):
            with contextlib.suppress(OSError):
                inner_id = self._vault_id_of(inner)
        known = {v.vault_id for v in rec.vaults if v.vault_id}
        same = res.identity.file_id.hex() == rec.file_id and res.volume == rec.volume
        if inner_id and inner_id not in known:
            raise StateError("Esta não é a mesma pasta protegida.")
        expected = self._expected_inside(rec)
        if not same:
            if not inner_id:
                raise StateError("Esta pasta não contém os dados protegidos esperados.")
            if inner_id not in expected:
                if rec.state in (ABERTA, ABERTURA_INCOMPLETA, RESTAURANDO):
                    raise StateError(
                        f"Esta é uma cópia trancada de '{rec.name}' (por exemplo, um backup), não "
                        "a pasta que está aberta. Escolha a pasta com os arquivos legíveis."
                    )
                if rec.state == TRANCADA:
                    raise StateError(
                        f"Esta pasta tem uma cópia criptografada antiga de '{rec.name}', não a "
                        "atual. Escolha a pasta que estava na lista."
                    )
                raise StateError(
                    f"Esta é uma cópia trancada de '{rec.name}' (por exemplo, um backup), não a "
                    "pasta que estava na lista. Escolha a pasta que estava na lista."
                )
        elif inner_id not in expected:
            inner_id = ""  # a mesma pasta, mas um .owlvault que o estado não espera: não confiar
        return res, inner, inner_id

    def _relocate_child(
        self, rec: FolderRecord, parent: str
    ) -> tuple[str, tuple[winfs.Resolved, str, str]] | None:
        """A pasta de ``rec`` logo abaixo de ``parent`` (só pastas com ``.owlvault``: é o caso
        da pasta trancada e escondida). Uma só pela identidade, ou uma só pelo cofre; senão
        None (na dúvida, nada é escolhido)."""
        try:
            names = sorted(os.listdir(parent))
        except OSError:
            return None
        same: list[tuple[str, tuple[winfs.Resolved, str, str]]] = []
        by_vault: list[tuple[str, tuple[winfs.Resolved, str, str]]] = []
        for n in names:
            sub = winfs.join(parent, n)
            if not winfs.is_plain_dir_at(sub) or not winfs.is_plain_dir_at(
                winfs.join(sub, VAULT_DIR)
            ):
                continue
            try:
                found = self._relocate_candidate(rec, sub)
            except StateError:
                continue
            ident = found[0].identity
            is_same = (
                ident is not None
                and ident.file_id.hex() == rec.file_id
                and found[0].volume == rec.volume
            )
            (same if is_same else by_vault).append((sub, found))
        hits = same or by_vault
        return hits[0] if len(hits) == 1 else None

    def _relocated_vault(
        self, rec: FolderRecord, v: VaultRef, inner: str, inner_id: str, new_staging: str
    ) -> str | None:
        """Novo lugar do cofre ``v`` depois de a pasta mudar de lugar (None = não achado;
        "" = referência que pode cair: exclusão já aprovada que não deixou nada)."""

        def holds(d: str) -> bool:
            if not winfs.is_plain_dir_at(d):
                return False
            if not v.vault_id:
                return True
            try:
                return self._vault_id_of(d) == v.vault_id
            except OSError:
                return False

        base = winfs.name_of(v.location)
        candidate = winfs.join(new_staging, base)
        if v.vault_id and v.vault_id == inner_id:
            # dentro da pasta: o 'atual' fica lá; os demais (abrindo/apagando) ainda vão sair ou
            # já entraram — o destino gravado passa a ser a área temporária nova
            return inner if v.role == "atual" else candidate
        if v.role == "atual":
            return None
        if v.role == DESCARTANDO:
            if winfs.is_plain_dir_at(v.location):
                return v.location
            return candidate if winfs.is_plain_dir_at(candidate) else ""
        if holds(v.location):
            return v.location  # a área temporária antiga não se moveu
        if holds(candidate):
            return candidate
        if v.vault_id and winfs.is_plain_dir_at(new_staging):
            for n in sorted(os.listdir(new_staging)):
                d = winfs.join(new_staging, n)
                if _STAGING_VAULT_RE.fullmatch(n) and holds(d):
                    return d
        if v.role == "novo" and not v.vault_id:
            return candidate  # criação nunca concluída: o início a descarta
        return None

    # ------------------------------------------------------------------ espaço reservado
    @staticmethod
    def _has_bytes(path: str, data: bytes) -> bool:
        if not winfs.is_plain_file_at(path):
            return False
        try:
            if os.lstat(path).st_size != len(data):
                return False
            with open(path, "rb") as fh:
                return fh.read(len(data) + 1) == data
        except OSError:
            return False

    def _shortcut_target(self, rec: FolderRecord) -> tuple[str, str]:
        exe, base = self.launcher
        return exe, (base + " " if base else "") + f"--abrir {rec.id}"

    def _write_placeholder(self, rec: FolderRecord) -> list[str]:
        """Grava — ou refaz — o espaço reservado de uma pasta trancada.

        Idempotente: só reescreve o que falta ou está diferente e só mexe nos nossos nomes de
        arquivo. Aplica a DACL restrita (melhor esforço) a cada item. Devolve avisos (atalho
        trocado) para a interface.
        """
        p = rec.path
        allowed = winfs.resolve(p)
        notes: list[str] = []
        for name, data, hide in (
            (ICON_NAME, self.icon_bytes, True),
            (DESKTOP_INI, shell.desktop_ini_bytes(ICON_NAME, INFOTIP), True),
            (HELP_NAME, HELP_TEXT.encode("utf-8-sig"), False),
        ):
            target = winfs.join(p, name)
            if not self._has_bytes(target, data):
                if os.path.lexists(target):
                    shell.change_attributes(target, remove=HIDE | shell.FILE_ATTRIBUTE_READONLY)
                    safe_remove_own(target, allowed, _PLACEHOLDER_RE)
                write_new_no_replace(target, data, op="placeholder")
            if hide:
                shell.change_attributes(target, add=HIDE)
            self._restrict(target, directory=False)
        if self.create_shortcuts:
            lnk = winfs.join(p, SHORTCUT_NAME)
            exe, args = self._shortcut_target(rec)
            if not shell.shortcut_matches(lnk, exe, args):
                if os.path.lexists(lnk):
                    notes.append(
                        f"O atalho 'Abrir com Owl Vault' de '{rec.name}' estava diferente do "
                        "esperado e foi refeito. Abra suas pastas pelo Menu Iniciar ou pelo "
                        "próprio Owl Vault."
                    )
                self.refresh_shortcut(rec)
            else:
                self._restrict(lnk, directory=False)
        shell.make_system_folder(p)
        if rec.hidden:
            # PathMakeSystemFolderW tira o atributo SISTEMA: a pasta escondida voltaria a
            # aparecer para quem mostra arquivos ocultos
            shell.change_attributes(p, add=HIDE)
        shell.notify_changed(p)
        shell.notify_changed(winfs.parent_of(p))
        return notes

    def repair_placeholders(self, folder_id: str) -> list[str]:
        """Pasta trancada: confere o espaço reservado (atalho, ícone, desktop.ini, aviso) e o
        refaz se faltar ou estiver diferente — use antes de atender um pedido de abrir.

        Só mexe nos nossos nomes de arquivo; pasta não trancada, fora do lugar ou sem dados ⇒
        nada é feito. Devolve avisos para a interface (ex.: atalho trocado).
        """
        rec = self._get(folder_id)
        if rec.state != TRANCADA:
            return []
        p = self._locate(rec)
        if not winfs.is_plain_dir_at(winfs.join(p, VAULT_DIR)):
            return []
        return self._write_placeholder(rec)

    def refresh_shortcut(self, rec: FolderRecord) -> None:
        """(Re)cria o atalho 'Abrir com Owl Vault'. O ícone é o do próprio programa: o atalho
        não leva o caminho da pasta nem das pastas-mãe."""
        if not self.create_shortcuts:
            return
        lnk = winfs.join(rec.path, SHORTCUT_NAME)
        exe, args = self._shortcut_target(rec)
        if os.path.lexists(lnk):
            shell.change_attributes(lnk, remove=shell.FILE_ATTRIBUTE_READONLY)
            safe_remove_own(lnk, winfs.resolve(rec.path), _PLACEHOLDER_RE)
        shell.create_shortcut(lnk, exe, args, exe, "Abrir com o Owl Vault", winfs.parent_of(exe))
        self._restrict(lnk, directory=False)

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
    def _apagar_cofre(
        self,
        rec: FolderRecord,
        v: VaultRef,
        *,
        newer: dict[tuple[str, ...], bytes] | None = None,
        in_folder: str | None = None,
        accepted: Set[tuple[str, ...]] = frozenset(),
    ) -> bool:
        """Primitivo ÚNICO de exclusão de cofre (PASTAS_PROTEGIDAS §3, regra de ouro).

        Confere vault_id registrado, ``complete.owl`` autêntico e manifesto lido (cofre ausente
        ou ilegível ⇒ StateError: nada é apagado nem esquecido) e só apaga se TODO arquivo
        estiver coberto (``_uncovered``). Devolve False — sem mexer em nada — se algum não
        estiver. Antes de apagar grava o papel DESCARTANDO (exclusão retomada se cair).
        """
        manifest = self._checked_manifest(v)
        if self._uncovered(v, manifest, newer=newer, in_folder=in_folder, accepted=accepted):
            return False
        self._discard_vault(rec, v)
        return all(x is not v for x in rec.vaults)

    def _discard_vault(self, rec: FolderRecord, v: VaultRef, *, must_record: bool = True) -> None:
        """Apaga um cofre JÁ aprovado (regra de ouro, ou 'novo' que não apagou nada).

        O papel DESCARTANDO é gravado antes; com ``must_record=False`` (gravação do índice
        falhando e nenhum original tocado) a exclusão segue mesmo sem gravar.
        """
        if v.role != DESCARTANDO:
            old = v.role
            v.role = DESCARTANDO
            try:
                self._save()
            except BaseException as exc:
                if must_record or not isinstance(exc, (OwlVaultError, OSError)):
                    v.role = old
                    raise
        self._remove_vault_tree(v.location, rec)
        if not os.path.lexists(v.location):
            rec.vaults = [x for x in rec.vaults if x is not v]
            parent = winfs.parent_of(v.location)
            if winfs.name_of(parent) == f".owlvault-{rec.id}" and os.path.normcase(
                parent
            ) != os.path.normcase(self.staging_of(rec)):
                with contextlib.suppress(OwlVaultError, OSError):
                    self._cleanup_staging(rec, parent)  # área temporária antiga (pasta movida)

    def _judge_novo(self, p: str, novo: VaultRef) -> tuple[str, str, Manifest | None]:
        """O que fazer com o 'novo' de um trancamento interrompido em TRANCANDO.

        "descartar": nenhum original pode ter sido apagado por ele; "apagando": cofre concluído
        e (marcador em P ou algum arquivo do manifesto falta em P) — pode ser a ÚNICA cópia;
        "manter": não deu para conferir (nada é apagado).
        """
        loc = novo.location
        marker = os.path.lexists(winfs.join(p, MARKER_NAME))
        if not any(os.path.lexists(winfs.join(loc, n)) for n in (HEADER_NAME, HEADER_BAK_NAME)):
            # sem cabeçalho: a criação não chegou a gravá-lo (ou o cofre já não decifra)
            return ("manter" if marker else "descartar"), "", None
        complete_exists = os.path.lexists(winfs.join(loc, COMPLETE_NAME))
        unfinished = "manter" if marker or complete_exists else "descartar"
        try:
            opened = open_vault(loc, self.keys_for_vault(loc), self.policy)
        except (OwlVaultError, OSError):
            return unfinished, "", None
        vault_id = opened.vault_id.hex()
        if novo.vault_id and vault_id != novo.vault_id:
            return "manter", "", None
        try:
            mread = read_manifest(opened)
            info, _ = read_completion(opened, mread.raw)
        except (OwlVaultError, OSError):
            return unfinished, vault_id, None
        manifest = mread.manifest
        missing = any(not os.path.lexists(winfs.join(p, *e.path)) for e in manifest.files)
        if info is not None:
            return ("apagando" if marker or missing else "descartar"), vault_id, manifest
        # criação não concluída: a exclusão dos originais nunca começou
        if marker or (missing and complete_exists):
            return "manter", vault_id, manifest
        return "descartar", vault_id, manifest

    def _discard_novo(
        self, rec: FolderRecord, *, must_record: bool = True, nothing_deleted: bool = False
    ) -> str:
        """Desfaz um trancamento que não apagou nada: descarta o 'novo' e volta a ABERTA.

        NUNCA apaga um 'novo' concluído se houver marcador em P ou se algum arquivo do manifesto
        faltar em P: aí a pasta vai para APAGANDO ('Desfazer'/'Continuar'), sem impressões
        digitais (a exclusão passa a conferir o conteúdo). Devolve "descartado", "apagando" ou
        "manter".

        ``nothing_deleted``: chamado pelo próprio trancamento ANTES de gravar 'apagando' (falha,
        cancelamento ou divergência em ``create_vault``). Este processo não apagou nada, então um
        arquivo que falta em P foi tirado pelo usuário: o 'novo' é descartado e a pasta volta a
        ABERTA (§4.1.3), como a mensagem "nada foi apagado. Tente de novo" promete. A heurística
        de "arquivo faltando" vale só para o estado TRANCANDO lido do disco (início). Um
        marcador em P (que não é deste trancamento: ele limpa o antigo ao começar) ainda faz
        conferir.
        """
        p = rec.path
        novo = rec.vault("novo")
        if novo is not None and os.path.lexists(novo.location):
            verdict: str
            vault_id = ""
            manifest: Manifest | None = None
            if nothing_deleted and not os.path.lexists(winfs.join(p, MARKER_NAME)):
                verdict = "descartar"
            else:
                verdict, vault_id, manifest = self._judge_novo(p, novo)
            if verdict == "apagando" and manifest is not None:
                novo.vault_id = vault_id
                rec.state = APAGANDO
                rec.fingerprints = {}
                rec.pending = []
                rec.zone_files = [
                    _rel_key(e.path)
                    for e in manifest.files
                    if (read_zone_id(winfs.join(p, *e.path)) or 0) >= 3
                ]
                rec.attention = (
                    "O trancamento foi interrompido depois de começar a apagar os arquivos da "
                    "pasta. Seus arquivos estão guardados: clique em 'Desfazer' para devolvê-los "
                    "à pasta ou em 'Continuar trancando'."
                )
                self._save()
                return "apagando"
            if verdict != "descartar":
                where = winfs.strip_extended(winfs.parent_of(novo.location))
                rec.attention = (
                    "O trancamento foi interrompido e o Owl Vault não conseguiu conferir a cópia "
                    f"criptografada que estava sendo criada (em {where}, uma pasta oculta). Por "
                    "segurança, ela foi mantida e nada mais foi feito; os arquivos que estão na "
                    "pasta continuam lá. Para voltar a usar a pasta, clique em 'Deixar a pasta "
                    "aberta': essa cópia fica guardada como versão anterior e nada é apagado. "
                    "Outra saída é 'Tirar da lista' (nada é apagado)."
                )
                with contextlib.suppress(OwlVaultError, OSError):
                    self._save()
                return "manter"
            self._discard_vault(rec, novo, must_record=must_record)
        rec.vaults = [v for v in rec.vaults if v.role != "novo"]
        rec.state = ABERTA
        rec.attention = ""
        rec.fingerprints = {}
        try:
            self._save()
        except (OwlVaultError, OSError):
            if must_record:
                raise
        with contextlib.suppress(OwlVaultError, OSError):
            self._cleanup_staging(rec)
        return "descartado"

    def _remove_vault_tree(self, vault_dir: str, rec: FolderRecord) -> None:
        """Apaga um cofre NOSSO: só nomes do layout v1; qualquer outro item é mantido.

        Só é chamado por ``_discard_vault`` (cofre já aprovado). O cabeçalho sai PRIMEIRO: um
        cofre apagado pela metade nunca é confundido com um cofre íntegro.
        """
        if not os.path.lexists(vault_dir):
            return
        if not winfs.is_plain_dir_at(vault_dir):
            raise UnsafePathError("o cofre a apagar não é uma pasta comum")
        root = winfs.resolve(vault_dir)
        for name in (HEADER_BAK_NAME, HEADER_NAME):
            path = winfs.join(vault_dir, name)
            if winfs.is_plain_file_at(path):
                safe_remove_own(path, root, re.compile(re.escape(name)))
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

    def _cleanup_staging(self, rec: FolderRecord, staging: str | None = None) -> None:
        """Limpa a área temporária (só nomes nossos) e a remove quando ficou vazia.

        Uma área que ainda guarda qualquer item nunca perde o atributo oculto.
        """
        staging = staging or self.staging_of(rec)
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
        if any(_inside(v.location, staging) for v in rec.vaults):
            return
        if os.listdir(staging):
            return
        try:
            shell.change_attributes(staging, remove=HIDE)
        except OSError:
            return
        safe_rmdir_own(staging, parent_res)

    # ------------------------------------------------------------------ início
    def reconcile_on_start(self) -> list[str]:
        """Recuperação de quedas (§4.5) e conferência do espaço reservado: devolve mensagens
        para a interface. Um problema numa pasta não impede as outras."""
        notes: list[str] = []
        for rec in list(self.folders):
            try:
                self._locate(rec)
            except StateError:
                continue
            try:
                notes.extend(self._reconcile(rec))
            except (OwlVaultError, OSError) as exc:
                # str() de um OSError traz o caminho cru do Windows: só o motivo vai para a tela
                why = str(exc) if isinstance(exc, OwlVaultError) else exc.strerror
                notes.append(f"'{rec.name}': {why or 'erro do sistema'}")
        return notes

    def _reconcile(self, rec: FolderRecord) -> list[str]:
        notes: list[str] = []
        stale = [v for v in rec.vaults if v.role == DESCARTANDO]
        for v in stale:  # exclusões já aprovadas que caíram no meio (refeitas a cada início)
            try:
                self._discard_vault(rec, v)
            except (OwlVaultError, OSError) as exc:
                notes.append(
                    f"Uma cópia antiga de '{rec.name}' (já conferida) ainda não pôde ser apagada: "
                    f"{exc}"
                )
        if stale:
            self._save()
            with contextlib.suppress(OwlVaultError, OSError):
                self._cleanup_staging(rec)
        if rec.state == TRANCANDO:
            outcome = self._discard_novo(rec)
            if outcome == "descartado":
                notes.append(
                    f"O trancamento de '{rec.name}' foi interrompido antes de apagar arquivos "
                    "(todos continuam na pasta); a pasta continua aberta."
                )
            elif outcome == "apagando":
                notes.append(
                    f"O trancamento de '{rec.name}' foi interrompido depois de começar a apagar "
                    "os arquivos. Eles estão guardados: use 'Resolver' para devolvê-los à pasta."
                )
            else:
                notes.append(
                    f"O trancamento de '{rec.name}' foi interrompido e a cópia criptografada que "
                    "estava sendo criada não pôde ser conferida; ela foi mantida e nada mais foi "
                    "feito."
                )
        elif rec.state == APAGANDO:
            novo = rec.vault("novo")
            if novo is not None and self._novo_moved_into_folder(rec, novo):
                self._conclude_lock(rec, novo)
                notes.append(f"O trancamento de '{rec.name}' (interrompido no fim) foi concluído.")
            elif not rec.attention:
                rec.attention = _INTERRUPTED_LOCK
                self._save()
        elif rec.state in (ABRINDO, RESTAURANDO):
            rec.attention = "A abertura foi interrompida. Clique em 'Continuar abrindo'."
            self._save()
        elif rec.state == TRANCADA:
            if any(v.role == "anterior" for v in rec.vaults):
                self._settle_previous(rec)
            if winfs.is_plain_dir_at(winfs.join(rec.path, VAULT_DIR)):
                notes.extend(self._write_placeholder(rec))
        return notes


def plain_files(manifest_files: list[FileEntryRecord]) -> int:
    return len(manifest_files)


ProgressFactory = Callable[[], ProgressSink]
_ = scan_tree  # usado pelos testes (varredura independente)
