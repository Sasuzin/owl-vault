"""Pré-verificação da criação (ARCHITECTURE §4.1 passo 1) — nenhuma escrita."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field

from owl_vault.application.common import display, round_up
from owl_vault.application.progress import CancelToken, NullProgress, ProgressSink
from owl_vault.application.protection import (
    ProtectedPaths,
    destination_location_problems,
    source_location_problems,
)
from owl_vault.crypto.stream import blob_size, validate_chunk_size
from owl_vault.domain.errors import OwlVaultError
from owl_vault.domain.limits import (
    DEFAULT_CHUNK_SIZE,
    FAT32_MAX_FILE_SIZE,
    MAX_MANIFEST_PLAINTEXT,
    MIB,
)
from owl_vault.domain.models import Fingerprint
from owl_vault.domain.names import display_path
from owl_vault.storage import winfs
from owl_vault.storage.manifest import estimate_manifest_size
from owl_vault.storage.scan import ScannedDir, scan_tree

_MARGIN = 64 * MIB


@dataclass(frozen=True, slots=True)
class SourceRecord:
    path: tuple[str, ...]
    ext_path: str
    fingerprint: Fingerprint
    links: int


@dataclass
class CreatePlan:
    source_ext: str
    vault_ext: str
    test_parent_ext: str
    chunk_size: int
    source_res: winfs.Resolved | None = None
    vault_res: winfs.Resolved | None = None
    test_res: winfs.Resolved | None = None
    files: list[SourceRecord] = field(default_factory=list)
    dirs: list[ScannedDir] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    needs_fat_ack: bool = False
    vault_fs: str = ""
    total_bytes: int = 0
    estimated_vault_bytes: int = 0
    manifest_size: int = 0
    largest_file: int = 0
    removable_like: bool = False

    @property
    def ok(self) -> bool:
        return not self.blockers

    def summary_lines(self) -> list[str]:
        lines = [
            f"Origem: {display(self.source_ext)}",
            f"Cofre: {display(self.vault_ext)}",
            f"Pasta temporária do teste de restauração: {display(self.test_parent_ext)}",
            f"Arquivos: {len(self.files)} | Pastas: {len(self.dirs)} | "
            f"Tamanho: {self.total_bytes / MIB:.1f} MiB",
            f"Espaço estimado do cofre: {self.estimated_vault_bytes / MIB:.1f} MiB "
            f"(sistema de arquivos: {self.vault_fs or '?'})",
        ]
        return lines


def default_test_parent(source_res: winfs.Resolved) -> str:
    """%TEMP% se estiver no volume da origem; senão a pasta-pai da origem."""
    temp = tempfile.gettempdir()
    try:
        t = winfs.resolve(temp)
        if t.exists and t.volume == source_res.volume and not t.is_within(source_res):
            return winfs.to_extended(temp)
    except OwlVaultError:
        pass
    return winfs.parent_of(winfs.to_extended(source_res.dos_path))


def preflight_create(
    source: str,
    vault_dir: str,
    *,
    test_parent: str | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    protected: ProtectedPaths | None = None,
    progress: ProgressSink | None = None,
    cancel: CancelToken | None = None,
    resume: bool = False,
    already_written: int = 0,
) -> CreatePlan:
    progress = progress or NullProgress()
    cancel = cancel or CancelToken()
    protected = protected if protected is not None else ProtectedPaths.from_environment()
    validate_chunk_size(chunk_size)
    progress.stage("Pré-verificação: conferindo caminhos")

    try:
        source_ext = winfs.to_extended(source)
        vault_ext = winfs.to_extended(vault_dir)
    except OwlVaultError as exc:
        plan = CreatePlan(source, vault_dir, "", chunk_size)
        plan.blockers.append(str(exc))
        return plan
    plan = CreatePlan(source_ext, vault_ext, "", chunk_size)

    # --- origem
    try:
        src = winfs.resolve(source_ext)
    except OwlVaultError as exc:
        plan.blockers.append(f"Origem: {exc}")
        return plan
    plan.source_res = src
    if not src.exists or not src.is_directory:
        plan.blockers.append("Origem: a pasta não existe.")
        return plan
    try:
        st = os.lstat(source_ext)
    except OSError as exc:
        plan.blockers.append(f"Origem: não foi possível acessar ({exc.strerror or exc}).")
        return plan
    if not winfs.is_plain_dir(st):
        plan.blockers.append("Origem: a pasta é um link/junction/ponto de reparse (não suportado).")
        return plan
    plan.blockers.extend(f"Origem: {p}" for p in source_location_problems(src, protected))

    # --- cofre
    try:
        vres = winfs.resolve(vault_ext)
    except OwlVaultError as exc:
        plan.blockers.append(f"Cofre: {exc}")
        return plan
    plan.vault_res = vres
    plan.vault_fs = vres.fs_name
    plan.blockers.extend(destination_location_problems(vres, protected, "O cofre"))
    if vres.overlaps(src):
        plan.blockers.append(
            "O cofre não pode ficar dentro da origem (nem a origem dentro do cofre)."
        )
    parent = winfs.parent_of(vault_ext)
    if not os.path.isdir(parent):
        plan.blockers.append("Cofre: a pasta onde o cofre será criado não existe.")
    if vres.exists:
        try:
            vst = os.lstat(vault_ext)
            if not winfs.is_plain_dir(vst):
                plan.blockers.append("Cofre: o caminho existe e não é uma pasta comum.")
            elif not resume:
                leftovers = [
                    n
                    for n in os.listdir(vault_ext)
                    if not (
                        n == ".owlvault.lock" and winfs.is_plain_file_at(winfs.join(vault_ext, n))
                    )
                ]
                if leftovers:
                    plan.blockers.append(
                        "Cofre: a pasta já existe e não está vazia (escolha um nome novo; "
                        "para continuar um cofre interrompido use 'Retomar')."
                    )
        except OSError as exc:
            plan.blockers.append(f"Cofre: não foi possível acessar ({exc.strerror or exc}).")

    # --- pasta do teste de restauração
    try:
        plan.test_parent_ext = (
            winfs.to_extended(test_parent) if test_parent else default_test_parent(src)
        )
        tres = winfs.resolve(plan.test_parent_ext)
        plan.test_res = tres
        if not tres.exists or not tres.is_directory:
            plan.blockers.append("Teste de restauração: a pasta escolhida não existe.")
        if tres.is_within(src):
            plan.blockers.append("Teste de restauração: a pasta não pode ficar dentro da origem.")
        if tres.is_within(vres):
            plan.blockers.append("Teste de restauração: a pasta não pode ficar dentro do cofre.")
        if tres.volume == vres.volume and tres.volume != src.volume:
            plan.blockers.append(
                "Teste de restauração: escolha uma pasta no volume da ORIGEM, não no volume do "
                "cofre (texto claro temporário deixaria rastros na mídia do cofre)."
            )
        plan.blockers.extend(
            destination_location_problems(tres, protected, "A pasta do teste de restauração")
        )
    except OwlVaultError as exc:
        plan.blockers.append(f"Teste de restauração: {exc}")

    if plan.blockers:
        return plan

    # --- varredura
    progress.stage("Pré-verificação: listando a origem")
    scan = scan_tree(source_ext, cancel.check)
    plan.blockers.extend(scan.blockers)
    plan.warnings.extend(scan.warnings)
    plan.dirs = scan.dirs
    if scan.blocker_count > len(scan.blockers):
        plan.warnings.append(f"Total de bloqueios na varredura: {scan.blocker_count}.")

    # --- abre cada arquivo (em uso? identidade, tamanho e datas do handle)
    progress.stage(
        "Pré-verificação: abrindo arquivos", sum(f.size for f in scan.files), len(scan.files)
    )
    hard_links = 0
    for sf in scan.files:
        cancel.check()
        try:
            fh, info = winfs.open_source(sf.ext_path)
            fh.close()
        except OwlVaultError as exc:
            plan.blockers.append(f"{display_path(sf.path)}: {exc}")
            continue
        if info.number_of_links > 1:
            hard_links += 1
        plan.files.append(
            SourceRecord(sf.path, sf.ext_path, info.fingerprint(), info.number_of_links)
        )
        progress.advance(0, 1)
    if hard_links:
        plan.warnings.append(
            f"{hard_links} arquivo(s) com hard links: o conteúdo será copiado, os vínculos não."
        )
    plan.warnings.append(
        "Não são preservados: permissões (ACLs), atributos (oculto/somente leitura), data de "
        "criação e fluxos alternativos NTFS. São preservados: conteúdo, nomes, pastas (inclusive "
        "vazias) e data de modificação."
    )
    if winfs.is_elevated():
        plan.warnings.append("O Owl Vault está rodando como administrador; isso não é necessário.")

    plan.total_bytes = sum(f.fingerprint.size for f in plan.files)
    plan.largest_file = max((f.fingerprint.size for f in plan.files), default=0)

    # --- manifesto (tamanho exato)
    paths = [(d.path, False) for d in plan.dirs] + [(f.path, True) for f in plan.files]
    plan.manifest_size = estimate_manifest_size(paths)
    if plan.manifest_size > MAX_MANIFEST_PLAINTEXT:
        plan.blockers.append(
            f"A lista de nomes ficaria com {plan.manifest_size / MIB:.0f} MiB (limite de 256 MiB): "
            "pasta com itens/nomes demais para a v1."
        )

    # --- sistema de arquivos e espaço do cofre
    try:
        space = winfs.volume_space(vres.existing_ancestor)
    except OSError as exc:
        plan.blockers.append(f"Cofre: não foi possível consultar o espaço livre ({exc}).")
        return plan
    if winfs.is_fat32_limited(vres.fs_name):
        too_big = [
            f for f in plan.files if blob_size(f.fingerprint.size, chunk_size) > FAT32_MAX_FILE_SIZE
        ]
        for f in too_big[:50]:
            plan.blockers.append(
                f"{display_path(f.path)}: grande demais para {vres.fs_name} (limite de 4 GiB por arquivo)."
            )
    if winfs.is_fat(vres.fs_name):
        plan.needs_fat_ack = True
        plan.removable_like = True
        plan.warnings.append(
            f"O destino usa {vres.fs_name}, sem journaling: não remova a mídia durante a operação "
            "e rode 'Verificar cofre' depois de reconectá-la."
        )
    cluster = space.cluster_size
    estimate = sum(
        round_up(blob_size(f.fingerprint.size, chunk_size), cluster) + 1024 for f in plan.files
    )
    estimate += 1024 * len(plan.dirs) + 256 * cluster
    estimate += 3 * round_up(plan.manifest_size + 80, cluster) + _MARGIN
    plan.estimated_vault_bytes = estimate
    # na retomada, os blobs ja gravados ocupam espaco que ja foi descontado do livre
    vault_need = max(0, estimate - already_written)
    if vault_need > space.free_bytes:
        plan.blockers.append(
            f"Espaço insuficiente para o cofre: necessário ~{estimate / MIB:.0f} MiB, "
            f"livre {space.free_bytes / MIB:.0f} MiB."
        )
    # --- espaço do teste de restauração (pico = maior arquivo)
    if plan.test_res is not None:
        try:
            tspace = winfs.volume_space(plan.test_res.existing_ancestor)
            need = round_up(plan.largest_file, tspace.cluster_size) + _MARGIN
            if plan.test_res.volume == vres.volume:
                need += vault_need
            if need > tspace.free_bytes:
                plan.blockers.append(
                    "Espaço insuficiente na pasta do teste de restauração "
                    f"(necessário ~{need / MIB:.0f} MiB)."
                )
        except OSError:
            plan.warnings.append("Não foi possível consultar o espaço da pasta de teste.")
    return plan
