"""Criar cofre e retomar criação (ARCHITECTURE §4.0–§4.2).

Máquina de estados: ENCRYPTING → MANIFEST_WRITTEN → VERIFIED → RESTORE_TESTED → COMPLETE,
gravada no diário autenticado. "Sucesso" só depois de verificação completa, teste de
restauração (mesma rotina da restauração real) e nova varredura da origem.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import time
from dataclasses import dataclass, field

from owl_vault.application.common import (
    display,
    local_snapshot_label,
    now_utc_iso,
    validate_new_password,
)
from owl_vault.application.keysource import KeySource
from owl_vault.application.preflight import CreatePlan, SourceRecord, preflight_create
from owl_vault.application.progress import CancelToken, NullProgress, ProgressSink
from owl_vault.application.protection import ProtectedPaths
from owl_vault.application.restore import hash_file_unbuffered, restore_file_content
from owl_vault.application.vault import (
    CompletionInfo,
    ManifestRead,
    OpenedVault,
    open_vault,
    read_completion,
    read_manifest,
)
from owl_vault.application.verify import VerifyReport, verify_contents
from owl_vault.crypto.kdf import PRODUCTION_POLICY, KdfPolicy, calibrate
from owl_vault.crypto.stream import blob_size
from owl_vault.domain.errors import (
    CancelledError,
    InconsistentVaultError,
    IntegrityError,
    OwlVaultError,
    PreflightError,
    SourceChangedError,
    StateError,
    UnsafePathError,
)
from owl_vault.domain.limits import DEFAULT_CHUNK_SIZE, ID_SIZE, KEY_SIZE, MIB
from owl_vault.domain.models import (
    DirEntryRecord,
    Entry,
    FileEntryRecord,
    FileIdentity,
    Fingerprint,
    KdfParams,
    Phase,
)
from owl_vault.domain.names import display_path, fold_path
from owl_vault.storage import winfs
from owl_vault.storage.atomic import (
    flush_existing,
    safe_remove_own,
    safe_rmdir_own,
    write_new_no_replace,
    write_probe,
)
from owl_vault.storage.blob import encrypt_source_to_blob, read_blob_header
from owl_vault.storage.container import ContainerKind, write_container
from owl_vault.storage.header import build_header
from owl_vault.storage.journal import JournalInit, JournalState, JournalWriter, read_journal
from owl_vault.storage.layout import (
    CHK_RE,
    DATA_FILE_RE,
    HH_RE,
    PROBE_RE,
    README_TEXT,
    ROOT_TMP_RE,
    SEGMENT_RE,
    SEGMENT_TMP_RE,
    TEST_DIR_RE,
    TEST_PART_RE,
    VaultLayout,
)
from owl_vault.storage.manifest import build_manifest, manifest_to_obj
from owl_vault.storage.scan import scan_tree
from owl_vault.storage.state import StateHint, read_state, write_state

_CHECKPOINT_FILES = 64
_CHECKPOINT_BYTES = 256 * MIB
_CHECKPOINT_SECONDS = 5.0
_TEST_PART_PREFIX = ".owl-test-"
_COMPLETE_RE = re.compile(re.escape("complete.owl"))


@dataclass
class CreateResult:
    vault: str
    status: str  # "success" | "divergences"
    files: int
    dirs: int
    total_bytes: int
    snapshot_label: str
    divergences: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    removable_media: bool = False
    #: impressão digital de cada arquivo no momento da cifragem (caminho relativo → fp),
    #: usada pelas pastas protegidas para apagar os originais com segurança
    fingerprints: dict[tuple[str, ...], Fingerprint] = field(default_factory=dict)

    @property
    def message(self) -> str:
        base = (
            f"Cópia criptografada criada e verificada (cópia da pasta como estava em "
            f"{self.snapshot_label}). A pasta original NÃO foi alterada e continua legível até "
            "você removê-la manualmente. Mantenha a origem e um backup externo até verificar "
            "o cofre (de preferência em outro computador)."
        )
        if self.status == "divergences":
            base = (
                "Cofre criado e testado, mas COM DIVERGÊNCIAS: a origem mudou durante/após a "
                "cifragem (veja a lista). O cofre corresponde à pasta como estava quando cada "
                "arquivo foi lido. " + base.split(". ", 1)[1]
            )
        if self.removable_media:
            base += (
                " Use 'Remover hardware com segurança'; depois reconecte a mídia e rode "
                "'Verificar cofre' antes de remover qualquer original."
            )
        return base


@dataclass
class VaultStatus:
    """Dica sem senha para a UI (lida de state.json e da presença de arquivos)."""

    kind: str  # "missing" | "empty" | "vault-complete" | "vault-incomplete" | "not-vault"
    phase: str | None = None
    files_total: int | None = None
    files_done: int | None = None


def inspect_vault_dir(vault_dir: str) -> VaultStatus:
    ext = winfs.to_extended(vault_dir)
    try:
        names = set(os.listdir(ext))
    except FileNotFoundError:
        return VaultStatus("missing")
    except OSError:
        return VaultStatus("not-vault")
    names.discard(".owlvault.lock")
    if not names:
        return VaultStatus("empty")
    layout = VaultLayout(ext)
    if "vault.owl" not in names and "vault.owl.bak" not in names:
        return VaultStatus("not-vault")
    hint = read_state(layout.state) or {}
    phase = hint.get("phase") if isinstance(hint.get("phase"), str) else None
    ft = hint.get("files_total") if isinstance(hint.get("files_total"), int) else None
    fd = hint.get("files_done") if isinstance(hint.get("files_done"), int) else None
    if "journal" in names:
        # o diário só é removido depois de complete.owl: se ainda existe, a execução não
        # terminou (a retomada decide entre limpar o que sobrou ou refazer as etapas 5–7)
        return VaultStatus("vault-incomplete", phase, ft, fd)
    if "complete.owl" in names:
        return VaultStatus("vault-complete", phase, ft, fd)
    return VaultStatus("vault-incomplete", phase, ft, fd)


class _Session:
    """Estado de uma execução de criação/retomada (com a trava do cofre já obtida)."""

    def __init__(
        self,
        layout: VaultLayout,
        master_key: bytes,
        vault_id: bytes,
        password: str | KeySource,
        policy: KdfPolicy,
        journal: JournalWriter,
        jstate: JournalState,
        init: JournalInit,
        progress: ProgressSink,
        cancel: CancelToken,
    ) -> None:
        self.layout = layout
        self.mk = master_key
        self.vid = vault_id
        self.password = password
        self.policy = policy
        self.journal = journal
        self.state = jstate
        self.init = init
        self.progress = progress
        self.cancel = cancel
        self.warnings: list[str] = []
        self.notes: list[str] = []
        self.plan_dirs: list[DirEntryRecord] | None = None
        self.files_total = len(jstate.files)
        self.vault_res = winfs.resolve(layout.root)
        self.source_res = winfs.resolve(init.source_root)

    # -- dicas não sensíveis
    def hint(self, phase: str) -> None:
        write_state(
            self.layout.state,
            StateHint(
                self.vid.hex(),
                phase,
                self.files_total,
                len(self.state.files),
                winfs.name_of(self.init.test_dir),
            ),
        )

    # -- etapa 3: cifragem
    def encrypt(self, plan: CreatePlan) -> None:
        self.plan_dirs = [DirEntryRecord(d.path) for d in plan.dirs]
        self.files_total = len(plan.files)
        todo: list[SourceRecord] = [
            r for r in plan.files if fold_path(r.path) not in self.state.files
        ]
        secrets.SystemRandom().shuffle(todo)  # ordem não revela a ordem dos caminhos
        total_bytes = sum(r.fingerprint.size for r in todo)
        self.progress.stage("Criptografando", total_bytes, len(todo))
        pending: list[tuple[Entry, Fingerprint | None]] = []
        last = time.monotonic()
        since = 0
        failed = True
        try:
            for rec in todo:
                self.cancel.check()
                shown = display_path(rec.path)
                try:
                    src, info = winfs.open_source(rec.ext_path, rec.fingerprint.identity)
                except OwlVaultError as exc:
                    raise type(exc)(f"{shown}: {exc}") from exc
                with src:
                    try:
                        res = encrypt_source_to_blob(
                            src,
                            info.fingerprint(),
                            self.layout,
                            self.mk,
                            self.vid,
                            self.init.chunk_size,
                            self.cancel.check,
                            lambda n: self.progress.advance(n),
                        )
                    except OSError as exc:
                        raise winfs.classify_os_error(exc, shown) from exc
                    except SourceChangedError as exc:
                        raise SourceChangedError(
                            f"{shown}: {exc}. Feche o programa que está alterando o arquivo e "
                            "retome."
                        ) from exc
                entry = FileEntryRecord(
                    rec.path, res.size, res.fingerprint_after.mtime_ns, res.file_id, res.sha256
                )
                self.state.files[fold_path(rec.path)] = (entry, res.fingerprint_after)
                pending.append((entry, res.fingerprint_after))
                since += res.size
                self.progress.advance(0, 1)
                if (
                    len(pending) >= _CHECKPOINT_FILES
                    or since >= _CHECKPOINT_BYTES
                    or time.monotonic() - last >= _CHECKPOINT_SECONDS
                ):
                    batch, pending = pending, []  # nunca regravar um lote que falhou
                    self.journal.write(Phase.ENCRYPTING, added=batch)
                    since = 0
                    last = time.monotonic()
                    self.hint(Phase.ENCRYPTING.value)
            # último checkpoint no caminho de SUCESSO: uma falha aqui deve interromper
            # (não pode ser engolida, senão o diário avança de fase sem essas entradas)
            if pending:
                batch, pending = pending, []
                self.journal.write(Phase.ENCRYPTING, added=batch)
            failed = False
        finally:
            if failed and pending:
                try:
                    self.journal.write(Phase.ENCRYPTING, added=pending)
                except (OSError, OwlVaultError):
                    pass  # blobs viram órfãos; a retomada os limpa e recifra
            self.hint(Phase.INTERRUPTED.value if failed else Phase.ENCRYPTING.value)

    # -- etapa 4: manifesto
    def write_manifest(self) -> None:
        assert self.plan_dirs is not None
        entries: list[Entry] = list(self.plan_dirs)
        entries.extend(f for f, _ in self.state.files.values())
        manifest = build_manifest(self.vid, self.init.chunk_size, entries)
        raw = write_container(
            self.layout.manifest,
            ContainerKind.MANIFEST,
            self.mk,
            self.vid,
            manifest_to_obj(manifest),
            "manifest",
        )
        self._finish_manifest_copy(raw)
        self.journal.write(Phase.MANIFEST_WRITTEN)
        self.hint(Phase.MANIFEST_WRITTEN.value)

    def _finish_manifest_copy(self, raw: bytes) -> None:
        with open(self.layout.manifest, "rb") as fh:
            if fh.read() != raw:
                raise IntegrityError("o manifesto gravado não confere ao ser relido")
        if not os.path.lexists(self.layout.manifest_bak):
            write_new_no_replace(self.layout.manifest_bak, raw, op="manifest")

    # -- etapa 5: verificação (reabre do zero)
    def verify(self) -> tuple[OpenedVault, ManifestRead]:
        self.progress.stage("Verificando o cofre (derivando chave — não cancelável)")
        opened = open_vault(self.layout.root, self.password, self.policy, unbuffered=True)
        if opened.master_key != self.mk or opened.vault_id != self.vid:
            raise InconsistentVaultError("o cofre reaberto não corresponde ao cofre em criação")
        if opened.notes:
            raise IntegrityError("cabeçalho com problemas: " + "; ".join(opened.notes))
        mread = read_manifest(opened, unbuffered=True)
        if mread.notes:
            raise IntegrityError("manifesto com problemas: " + "; ".join(mread.notes))
        report = VerifyReport(display(self.layout.root))
        before = winfs.unbuffered_fallback_count()
        verify_contents(opened, mread, report, self.progress, self.cancel, in_creation=True)
        if winfs.unbuffered_fallback_count() != before:
            self.warnings.append(
                "O sistema de arquivos do cofre não aceitou leitura sem cache: a verificação "
                "pode ter lido dados do cache do Windows. Reconecte a mídia e rode 'Verificar "
                "cofre' (de preferência em outro computador)."
            )
        if report.bad:
            raise IntegrityError(
                "A verificação do cofre recém-criado falhou (" + "; ".join(report.bad[:5]) + "). "
                "Não use este cofre; verifique o disco de destino e crie um cofre novo."
            )
        if report.anomalies:
            raise IntegrityError(
                "Itens inesperados no cofre recém-criado: " + "; ".join(report.anomalies[:5])
            )
        self.journal.write(Phase.VERIFIED)
        self.hint(Phase.VERIFIED.value)
        return opened, mread

    # -- etapa 6: teste de restauração + nova varredura
    def restore_test(self, opened: OpenedVault, mread: ManifestRead) -> list[str]:
        manifest = mread.manifest
        test_dir = self.init.test_dir
        if not os.path.lexists(test_dir):
            os.mkdir(test_dir)
        tst = os.lstat(test_dir)
        if not winfs.is_plain_dir(tst):
            raise UnsafePathError("a pasta do teste de restauração não é uma pasta comum")
        test_res = winfs.resolve(test_dir)
        if test_res.is_within(self.source_res) or test_res.is_within(self.vault_res):
            raise UnsafePathError("a pasta do teste de restauração está na origem ou no cofre")
        self._cleanup_test_dir(test_res)
        divergences: list[str] = []
        failures: list[str] = []
        self.progress.stage("Teste de restauração", 2 * manifest.total_bytes(), len(manifest.files))
        for e in manifest.files:
            self.cancel.check()
            shown = display_path(e.path)
            recorded = self.state.files.get(fold_path(e.path))
            recorded_fp = recorded[1] if recorded else None
            # (1) releitura nova da origem
            src_sha: bytes | None = None
            fp_now: Fingerprint | None = None
            try:
                src, info = winfs.open_source(
                    winfs.join(self.init.source_root, *e.path),
                    recorded_fp.identity if recorded_fp else None,
                )
                with src:
                    sha = hashlib.sha256()
                    while True:
                        self.cancel.check()
                        block = src.read(4 * MIB)
                        if not block:
                            break
                        sha.update(block)
                        self.progress.advance(len(block))
                    src_sha = sha.digest()
                    fp_now = src.info().fingerprint()
                    if fp_now != info.fingerprint():
                        divergences.append(f"{shown}: alterado na origem durante o teste")
                        src_sha = None
            except CancelledError:
                raise
            except (SourceChangedError, UnsafePathError):
                divergences.append(f"{shown}: removido ou substituído na origem após a cifragem")
            except OwlVaultError as exc:
                src_sha = None
                divergences.append(f"{shown}: não foi possível reler a origem ({exc})")
            except OSError as exc:  # trava de intervalo, setor ilegível...
                src_sha = None
                divergences.append(
                    f"{shown}: não foi possível reler a origem "
                    f"({winfs.classify_os_error(exc, 'leitura')})"
                )
            # (2) restauração do conteúdo pela rotina real (sem nomes originais)
            chk_name = f"{e.file_id.hex()}.chk"
            try:
                outcome = restore_file_content(
                    opened,
                    blob_path=opened.layout.blob(e.file_id),
                    expected_file_id=e.file_id,
                    expected_size=e.size,
                    expected_sha256=e.sha256,
                    dest_dir=test_dir,
                    final_name=chk_name,
                    part_prefix=_TEST_PART_PREFIX,
                    root=test_res,
                    mtime_ns=None,
                    motw=False,
                    cancel=self.cancel,
                    progress=self.progress,
                )
                # (3) relê do disco sem cache
                restored_sha = hash_file_unbuffered(outcome.path, self.cancel)
            except IntegrityError as exc:
                failures.append(f"{shown}: restauração de teste falhou ({exc})")
                continue
            finally:
                chk = winfs.join(test_dir, chk_name)
                if os.path.lexists(chk):
                    safe_remove_own(chk, test_res, CHK_RE, [self.source_res])
            if restored_sha != e.sha256:
                failures.append(f"{shown}: o arquivo restaurado não confere com o manifesto")
                continue
            if src_sha is not None and src_sha != e.sha256:
                if recorded_fp is not None and fp_now == recorded_fp:
                    failures.append(
                        f"{shown}: leitura instável da origem (mesmo arquivo, conteúdo diferente)"
                    )
                else:
                    divergences.append(f"{shown}: alterado na origem após a cifragem")
            self.progress.advance(0, 1)
        if failures:
            raise IntegrityError(
                "O teste de restauração FALHOU: " + "; ".join(failures[:5]) + ". "
                "Não use este cofre; crie um cofre novo."
            )
        # (4) nova varredura independente da origem
        self.progress.stage("Comparando a origem atual com o cofre")
        scan = scan_tree(self.init.source_root, self.cancel.check)
        divergences.extend(f"origem: {b}" for b in scan.blockers)
        in_vault: dict[tuple[str, ...], Entry] = {fold_path(x.path): x for x in manifest.entries}
        now: dict[tuple[str, ...], object] = {}
        for d in scan.dirs:
            now[fold_path(d.path)] = d
        for f in scan.files:
            now[fold_path(f.path)] = f
        reported = {x.split(":", 1)[0] for x in divergences}
        for key, x in now.items():
            if key not in in_vault:
                path = getattr(x, "path", ())
                divergences.append(f"{display_path(path)}: adicionado na origem após a cifragem")
        for key, ent in in_vault.items():
            if key not in now:
                if display_path(ent.path) not in reported:
                    divergences.append(
                        f"{display_path(ent.path)}: removido da origem após a cifragem"
                    )
                continue
            cur = now[key]
            if isinstance(ent, FileEntryRecord):
                size = getattr(cur, "size", None)
                if size is None:
                    divergences.append(f"{display_path(ent.path)}: virou pasta na origem")
                elif display_path(ent.path) not in reported:
                    if size != ent.size:
                        divergences.append(f"{display_path(ent.path)}: tamanho mudou na origem")
                    elif getattr(cur, "mtime_ns", ent.mtime_ns) != ent.mtime_ns:
                        divergences.append(
                            f"{display_path(ent.path)}: alterado na origem após a cifragem "
                            "(data de modificação)"
                        )
            elif hasattr(cur, "size"):
                divergences.append(f"{display_path(ent.path)}: virou arquivo na origem")
        self.journal.write(Phase.RESTORE_TESTED)
        self.hint(Phase.RESTORE_TESTED.value)
        return divergences

    def _cleanup_test_dir(self, test_res: winfs.Resolved) -> None:
        for name in os.listdir(self.init.test_dir):
            p = winfs.join(self.init.test_dir, name)
            if CHK_RE.fullmatch(name):
                safe_remove_own(p, test_res, CHK_RE, [self.source_res])
            elif TEST_PART_RE.fullmatch(name):
                safe_remove_own(p, test_res, TEST_PART_RE, [self.source_res])
            else:
                self.warnings.append(
                    f"item inesperado na pasta do teste de restauração foi mantido: {name}"
                )

    # -- etapa 7: finalização
    def finalize(self, mread: ManifestRead, divergences: list[str]) -> None:
        self.progress.stage("Finalizando")
        for p in (
            self.layout.header,
            self.layout.header_bak,
            self.layout.manifest,
            self.layout.manifest_bak,
        ):
            flush_existing(p)
        manifest = mread.manifest
        completion = {
            "kind": "completion",
            "vault_id": self.vid.hex(),
            "manifest_sha256": hashlib.sha256(mread.raw).hexdigest(),
            "files": len(manifest.files),
            "dirs": len(manifest.dirs),
            "bytes": manifest.total_bytes(),
            "restore_test": "passed",
            "divergences": len(divergences),
            "completed_utc": now_utc_iso(),
        }
        write_container(
            self.layout.complete, ContainerKind.COMPLETE, self.mk, self.vid, completion, "complete"
        )
        write_state(
            self.layout.state,
            StateHint(
                self.vid.hex(),
                Phase.COMPLETE.value,
                len(manifest.files),
                len(manifest.files),
                winfs.name_of(self.init.test_dir),
            ),
        )
        # A partir daqui o cofre ESTÁ concluído: a limpeza é melhor esforço e nunca
        # transforma um sucesso em "interrompido" (a retomada termina o que sobrar).
        cleanup_after_completion(
            self.layout, self.vault_res, self.source_res, self.init.test_dir, self.warnings
        )

    # -- orquestração a partir de uma fase
    def run_from(self, phase: Phase, plan: CreatePlan | None, removable: bool) -> CreateResult:
        try:
            if phase == Phase.ENCRYPTING:
                assert plan is not None
                self.encrypt(plan)
                self.write_manifest()
            opened, mread = self.verify()
            before = winfs.unbuffered_fallback_count()
            divergences = self.restore_test(opened, mread)
            if winfs.unbuffered_fallback_count() != before:
                self.warnings.append(
                    "A releitura do teste de restauração usou leitura com cache (o sistema de "
                    "arquivos não aceitou leitura sem cache)."
                )
            self.finalize(mread, divergences)
        except OSError as exc:
            # disco cheio, antivírus, acesso negado... → erro de domínio com mensagem clara;
            # o cofre continua retomável (o diário registra a fase).
            raise winfs.classify_os_error(exc, "Criação interrompida (use 'Retomar')") from exc
        manifest = mread.manifest
        return CreateResult(
            vault=display(self.layout.root),
            status="divergences" if divergences else "success",
            files=len(manifest.files),
            dirs=len(manifest.dirs),
            total_bytes=manifest.total_bytes(),
            snapshot_label=local_snapshot_label(),
            divergences=divergences,
            warnings=self.warnings,
            notes=self.notes,
            removable_media=removable,
            fingerprints={f.path: fp for f, fp in self.state.files.values()},
        )


def cleanup_after_completion(
    layout: VaultLayout,
    vault_res: winfs.Resolved,
    source_res: winfs.Resolved | None,
    test_dir: str | None,
    warnings: list[str],
) -> None:
    """Remove diário e pasta de teste de um cofre JÁ concluído (melhor esforço)."""
    forbidden = [source_res] if source_res is not None else []
    try:
        if os.path.isdir(layout.journal_dir) and winfs.is_plain_dir(os.lstat(layout.journal_dir)):
            journal_res = winfs.resolve(layout.journal_dir)
            for name in os.listdir(layout.journal_dir):
                p = winfs.join(layout.journal_dir, name)
                if SEGMENT_RE.fullmatch(name):
                    safe_remove_own(p, journal_res, SEGMENT_RE, forbidden)
                elif SEGMENT_TMP_RE.fullmatch(name):
                    safe_remove_own(p, journal_res, SEGMENT_TMP_RE, forbidden)
            if not safe_rmdir_own(layout.journal_dir, vault_res, forbidden):
                warnings.append("a pasta journal não pôde ser removida (itens inesperados)")
    except (OSError, OwlVaultError) as exc:
        warnings.append(f"resíduo do diário não removido ({exc}); rode 'Retomar' para limpar")
    if test_dir is None:
        return
    try:
        if os.path.isdir(test_dir) and TEST_DIR_RE.fullmatch(winfs.name_of(test_dir)):
            test_res = winfs.resolve(test_dir)
            for name in os.listdir(test_dir):
                p = winfs.join(test_dir, name)
                if CHK_RE.fullmatch(name):
                    safe_remove_own(p, test_res, CHK_RE, forbidden)
                elif TEST_PART_RE.fullmatch(name):
                    safe_remove_own(p, test_res, TEST_PART_RE, forbidden)
            test_parent = winfs.resolve(winfs.parent_of(test_dir))
            if not safe_rmdir_own(test_dir, test_parent, forbidden):
                warnings.append("a pasta do teste de restauração não ficou vazia e foi mantida")
    except (OSError, OwlVaultError) as exc:
        warnings.append(f"pasta do teste de restauração não removida ({exc})")


def create_vault(
    source: str,
    vault_dir: str,
    password: str | KeySource,
    *,
    test_parent: str | None = None,
    kdf_params: KdfParams | None = None,
    kdf_policy: KdfPolicy = PRODUCTION_POLICY,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    protected: ProtectedPaths | None = None,
    plan: CreatePlan | None = None,
    fat_acknowledged: bool = False,
    progress: ProgressSink | None = None,
    cancel: CancelToken | None = None,
) -> CreateResult:
    """Cria um cofre novo a partir de ``source`` (que NUNCA é alterada).

    ``password`` pode ser a senha (str) ou um :class:`KeySource` com KEK pré-derivada
    (pastas protegidas: salt/params do perfil, sem Argon2id a cada trava)."""
    keys = KeySource.of(password)
    if keys.has_kek:
        kdf_params = keys.params
    else:
        assert keys.password is not None
        validate_new_password(keys.password)
    progress = progress or NullProgress()
    cancel = cancel or CancelToken()
    if plan is None:
        plan = preflight_create(
            source,
            vault_dir,
            test_parent=test_parent,
            chunk_size=chunk_size,
            protected=protected,
            progress=progress,
            cancel=cancel,
        )
    if plan.blockers:
        raise PreflightError("A pré-verificação encontrou bloqueios.", plan.blockers)
    if plan.needs_fat_ack and not fat_acknowledged:
        raise PreflightError(
            "Confirme o aviso sobre mídia FAT/exFAT antes de continuar.", plan.warnings
        )
    assert plan.source_res is not None and plan.source_res.identity is not None
    try:
        layout = VaultLayout(plan.vault_ext)
        if not os.path.lexists(layout.root):
            os.mkdir(layout.root)
        st = os.lstat(layout.root)
        if not winfs.is_plain_dir(st):
            raise UnsafePathError("a pasta do cofre não é uma pasta comum")
        with winfs.ExclusiveLock(layout.lock, "O cofre"):
            leftovers = [n for n in os.listdir(layout.root) if n != ".owlvault.lock"]
            if leftovers:
                raise UnsafePathError("a pasta do cofre não está vazia")
            write_probe(layout.root)
            mem = winfs.memory_status()
            if kdf_params is None:
                progress.stage("Calibrando a derivação de chave")
                kdf_params = calibrate(
                    mem.available_commit if mem else None, mem.total_physical if mem else None
                )
            vault_id = os.urandom(ID_SIZE)
            master_key = os.urandom(KEY_SIZE)
            if not keys.has_kek:
                progress.stage("Derivando chave (não cancelável)")
            header = build_header(
                master_key,
                vault_id,
                keys.password,
                kdf_params,
                kdf_policy,
                mem.available_commit if mem else None,
                salt=keys.salt if keys.has_kek else None,
                kek=keys.kek if keys.has_kek else None,
            )
            raw = header.pack()
            write_new_no_replace(layout.header, raw, op="header")
            write_new_no_replace(layout.header_bak, raw, op="header")
            test_dir = winfs.join(plan.test_parent_ext, f"OwlVault-teste-{secrets.token_hex(16)}")
            init = JournalInit(
                source_root=plan.source_ext,
                source_volume=plan.source_res.identity.volume_serial,
                source_root_fid=plan.source_res.identity.file_id,
                test_dir=test_dir,
                chunk_size=plan.chunk_size,
                created_utc=now_utc_iso(),
            )
            journal = JournalWriter(layout, master_key, vault_id, 0)
            journal.write(
                Phase.ENCRYPTING,
                init=init,
                added=[(DirEntryRecord(d.path), None) for d in plan.dirs],
            )
            write_new_no_replace(layout.readme, README_TEXT.encode("utf-8"), op="readme")
            os.mkdir(test_dir)
            write_probe(test_dir)
            jstate = JournalState(init=init, phase=Phase.ENCRYPTING, next_seq=journal.next_seq)
            session = _Session(
                layout,
                master_key,
                vault_id,
                keys,
                kdf_policy,
                journal,
                jstate,
                init,
                progress,
                cancel,
            )
            session.warnings.extend(plan.warnings)
            session.hint(Phase.ENCRYPTING.value)
            return session.run_from(Phase.ENCRYPTING, plan, plan.removable_like)

    except OSError as exc:
        raise winfs.classify_os_error(exc, "Criação interrompida (use 'Retomar')") from exc


def resume_create(
    vault_dir: str,
    source: str,
    password: str | KeySource,
    *,
    kdf_policy: KdfPolicy = PRODUCTION_POLICY,
    protected: ProtectedPaths | None = None,
    fat_acknowledged: bool = False,
    progress: ProgressSink | None = None,
    cancel: CancelToken | None = None,
) -> CreateResult:
    """Retoma uma criação interrompida (ARCHITECTURE §4.2)."""
    try:
        return _resume_create(
            vault_dir,
            source,
            password,
            kdf_policy=kdf_policy,
            protected=protected,
            fat_acknowledged=fat_acknowledged,
            progress=progress or NullProgress(),
            cancel=cancel or CancelToken(),
        )
    except OSError as exc:
        raise winfs.classify_os_error(exc, "Retomada interrompida") from exc


def _resume_create(
    vault_dir: str,
    source: str,
    password: str | KeySource,
    *,
    kdf_policy: KdfPolicy,
    protected: ProtectedPaths | None,
    fat_acknowledged: bool,
    progress: ProgressSink,
    cancel: CancelToken,
) -> CreateResult:
    root = winfs.to_extended(vault_dir)
    layout = VaultLayout(root)
    with winfs.ExclusiveLock(layout.lock, "O cofre"):
        progress.stage("Abrindo o cofre (derivando chave — não cancelável)")
        opened = open_vault(root, password, kdf_policy)
        mk, vid = opened.master_key, opened.vault_id
        stale_completion = False
        if os.path.lexists(layout.complete):
            try:
                mread = read_manifest(opened)
                info, _ = read_completion(opened, mread.raw)
            except OwlVaultError:
                info = None
            if info is not None:
                if os.path.lexists(layout.journal_dir):
                    return _finish_completed_cleanup(layout, opened, mread, info, root)
                raise StateError("Este cofre já foi concluído; não há nada para retomar.")
            stale_completion = True  # registro não autêntico: será descartado (sob a trava)
        jstate = read_journal(layout, mk, vid)
        if jstate.init is None or jstate.phase is None:
            raise StateError(
                "A criação foi interrompida antes do primeiro registro de progresso. "
                "Remova a pasta do cofre manualmente e crie o cofre novamente."
            )
        init = jstate.init
        source_res = winfs.resolve(init.source_root)
        # A pasta que será LIDA é a do caminho registrado: confere a identidade DELA (se a
        # origem foi movida e outra pasta ocupou o caminho, cifraríamos a pasta errada).
        expected = FileIdentity(init.source_volume, init.source_root_fid)
        if not (source_res.exists and source_res.is_directory and source_res.identity == expected):
            raise UnsafePathError(
                "A pasta de origem registrada neste cofre ("
                + display(init.source_root)
                + ") foi movida, renomeada ou substituída. Devolva a pasta original a esse "
                "caminho e retome (ou crie um cofre novo)."
            )
        given = winfs.resolve(source)
        if not given.same(source_res):
            raise UnsafePathError(
                "A pasta de origem informada não é a mesma usada ao criar este cofre ("
                + display(init.source_root)
                + ")."
            )
        vault_res = winfs.resolve(root)
        journal_res = winfs.resolve(layout.journal_dir)
        for p in jstate.stale_segments:
            safe_remove_own(p, journal_res, SEGMENT_RE, [source_res])
        _cleanup_root_tmp(layout, vault_res, source_res)
        if stale_completion:
            safe_remove_own(layout.complete, vault_res, _COMPLETE_RE, [source_res])
        if not os.path.lexists(layout.readme):
            write_new_no_replace(layout.readme, README_TEXT.encode("utf-8"), op="readme")
        journal = JournalWriter(layout, mk, vid, jstate.next_seq)
        session = _Session(
            layout, mk, vid, password, kdf_policy, journal, jstate, init, progress, cancel
        )
        phase = jstate.phase

        if phase == Phase.ENCRYPTING and (
            os.path.lexists(layout.manifest) or os.path.lexists(layout.manifest_bak)
        ):
            phase = _adopt_or_discard_manifest(session, opened, vault_res, source_res)

        if phase == Phase.ENCRYPTING:
            already = 0
            for entry, _ in jstate.files.values():
                try:
                    already += os.lstat(layout.blob(entry.file_id)).st_size
                except OSError:
                    continue
            plan = preflight_create(
                init.source_root,
                root,
                test_parent=winfs.parent_of(init.test_dir),
                chunk_size=init.chunk_size,
                protected=protected,
                progress=progress,
                cancel=cancel,
                resume=True,
                already_written=already,
            )
            if plan.blockers:
                raise PreflightError("A pré-verificação encontrou bloqueios.", plan.blockers)
            if plan.source_res is None or plan.source_res.identity != expected:
                raise UnsafePathError("A pasta de origem mudou durante a retomada.")
            if plan.needs_fat_ack and not fat_acknowledged:
                raise PreflightError("Confirme o aviso sobre mídia FAT/exFAT.", plan.warnings)
            _reconcile(session, plan, vault_res, source_res)
            session.warnings.extend(plan.warnings)
            return session.run_from(Phase.ENCRYPTING, plan, plan.removable_like)

        # Fases posteriores: reexecuta apenas verificação, teste e finalização.
        if not os.path.lexists(layout.manifest_bak) and os.path.lexists(layout.manifest):
            mread = read_manifest(opened)
            session._finish_manifest_copy(mread.raw)
        removable = winfs.is_fat(vault_res.fs_name)
        return session.run_from(Phase.VERIFIED, None, removable)


def _finish_completed_cleanup(
    layout: VaultLayout,
    opened: OpenedVault,
    mread: ManifestRead,
    info: CompletionInfo,
    root: str,
) -> CreateResult:
    """Cofre concluído cuja limpeza final foi interrompida: só remove os resíduos."""
    warnings: list[str] = []
    test_dir: str | None = None
    source_res: winfs.Resolved | None = None
    try:
        jstate = read_journal(layout, opened.master_key, opened.vault_id)
        if jstate.init is not None:
            test_dir = jstate.init.test_dir
            source_res = winfs.resolve(jstate.init.source_root)
    except (OSError, OwlVaultError):
        pass
    cleanup_after_completion(layout, winfs.resolve(root), source_res, test_dir, warnings)
    manifest = mread.manifest
    return CreateResult(
        vault=display(root),
        status="divergences" if info.divergences else "success",
        files=len(manifest.files),
        dirs=len(manifest.dirs),
        total_bytes=manifest.total_bytes(),
        snapshot_label=info.completed_utc,
        warnings=warnings,
        notes=[
            "O cofre já estava concluído e testado; foram removidos apenas resíduos da finalização."
        ],
        removable_media=False,
    )


def _adopt_or_discard_manifest(
    session: _Session, opened: OpenedVault, vault_res: winfs.Resolved, source_res: winfs.Resolved
) -> Phase:
    """Manifesto gravado mas fase não registrada: adota se bater com o diário; senão descarta."""
    try:
        mread = read_manifest(opened)
        recorded = {(fold_path(f.path), f.file_id) for f, _ in session.state.files.values()}
        in_manifest = {(fold_path(f.path), f.file_id) for f in mread.manifest.files}
        if recorded == in_manifest:
            session._finish_manifest_copy(mread.raw)
            session.journal.write(Phase.MANIFEST_WRITTEN)
            session.notes.append("manifesto já gravado foi adotado na retomada")
            return Phase.MANIFEST_WRITTEN
    except OwlVaultError:
        pass
    for path, name in (
        (session.layout.manifest, "manifest.owl"),
        (session.layout.manifest_bak, "manifest.owl.bak"),
    ):
        if os.path.lexists(path):
            safe_remove_own(path, vault_res, re.compile(re.escape(name)), [source_res])
    session.warnings.append("um manifesto incompleto de uma execução anterior foi descartado")
    return Phase.ENCRYPTING


def _blob_ok(layout: VaultLayout, vault_id: bytes, entry: FileEntryRecord, chunk_size: int) -> bool:
    path = layout.blob(entry.file_id)
    try:
        st = os.lstat(path)
        if not winfs.is_plain_file(st) or st.st_size != blob_size(entry.size, chunk_size):
            return False
        h = read_blob_header(path)
    except (OSError, OwlVaultError):
        return False
    return h.vault_id == vault_id and h.file_id == entry.file_id and h.plaintext_size == entry.size


def _reconcile(
    session: _Session, plan: CreatePlan, vault_res: winfs.Resolved, source_res: winfs.Resolved
) -> None:
    layout = session.layout
    current = {fold_path(r.path): r for r in plan.files}
    removed: list[bytes] = []
    for key, (entry, fp) in list(session.state.files.items()):
        rec = current.get(key)
        keep = (
            rec is not None
            and rec.fingerprint == fp
            and _blob_ok(layout, session.vid, entry, session.init.chunk_size)
        )
        if not keep:
            removed.append(entry.file_id)
            del session.state.files[key]
            blob = layout.blob(entry.file_id)
            if os.path.lexists(blob):
                safe_remove_own(blob, vault_res, DATA_FILE_RE, [source_res])
    if removed:
        session.journal.write(Phase.ENCRYPTING, removed=removed)
        session.notes.append(f"{len(removed)} arquivo(s) serão criptografados novamente")
    referenced = {f.file_id.hex() for f, _ in session.state.files.values()}
    if os.path.isdir(layout.data_dir):
        for hh in os.listdir(layout.data_dir):
            hh_path = winfs.join(layout.data_dir, hh)
            if not HH_RE.fullmatch(hh) or not winfs.is_plain_dir(os.lstat(hh_path)):
                session.warnings.append(f"item inesperado mantido em data: {hh}")
                continue
            for name in os.listdir(hh_path):
                p = winfs.join(hh_path, name)
                if DATA_FILE_RE.fullmatch(name) and name[:2] == hh:
                    if name.endswith(".owlb") and name[:32] in referenced:
                        continue
                    safe_remove_own(p, vault_res, DATA_FILE_RE, [source_res])
                else:
                    session.warnings.append(f"item inesperado mantido em data\\{hh}: {name}")
    new_files = [r for r in plan.files if fold_path(r.path) not in session.state.files]
    if new_files:
        session.notes.append(f"{len(new_files)} arquivo(s) a criptografar nesta retomada")


def _cleanup_root_tmp(
    layout: VaultLayout, vault_res: winfs.Resolved, source_res: winfs.Resolved
) -> None:
    for name in os.listdir(layout.root):
        p = winfs.join(layout.root, name)
        if ROOT_TMP_RE.fullmatch(name):
            safe_remove_own(p, vault_res, ROOT_TMP_RE, [source_res])
        elif PROBE_RE.fullmatch(name):
            safe_remove_own(p, vault_res, PROBE_RE, [source_res])
    if os.path.isdir(layout.journal_dir):
        jres = winfs.resolve(layout.journal_dir)
        for name in os.listdir(layout.journal_dir):
            if SEGMENT_TMP_RE.fullmatch(name):
                safe_remove_own(
                    winfs.join(layout.journal_dir, name), jres, SEGMENT_TMP_RE, [source_res]
                )


def cancel_is_clean(exc: BaseException) -> bool:
    return isinstance(exc, CancelledError)
