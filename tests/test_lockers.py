"""Pastas protegidas (PASTAS_PROTEGIDAS.md §3–§5): ``LockerManager`` de ponta a ponta.

Somente pastas temporárias (``tmp_path``) com dados sintéticos. O perfil é sempre sintético
(``ProfileStore(tmp_path / "perfil", TESTING_POLICY)`` com ``TESTING_PARAMS``): nada toca o
perfil real (%LOCALAPPDATA%\\Owl Vault) nem pastas do usuário.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from owl_vault.application import lockers
from owl_vault.application.common import read_zone_id
from owl_vault.application.lockers import (
    ABERTA,
    ABERTURA_INCOMPLETA,
    ABRINDO,
    APAGANDO,
    DESKTOP_INI,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
    HELP_NAME,
    ICON_NAME,
    MANTIDO,
    SHORTCUT_NAME,
    TRANCADA,
    TRANCANDO,
    VAULT_DIR,
    LockerManager,
    LockOutcome,
)
from owl_vault.application.profile import FolderRecord, ProfileSession, ProfileStore
from owl_vault.application.progress import CancelToken, NullProgress, ProgressSink
from owl_vault.application.protection import ProtectedPaths
from owl_vault.application.restore import MARKER_NAME
from owl_vault.crypto.kdf import TESTING_PARAMS, TESTING_POLICY
from owl_vault.domain.errors import (
    AuthenticationError,
    CancelledError,
    PreflightError,
    StateError,
)
from owl_vault.storage import faults, shell, winfs
from tests.conftest import tree_digest, write_tree

SM = "senha mestra sintética 2026"
SM_OUTRA = "outra senha mestra sintética"
SM_ERRADA = "senha mestra errada qualquer"
PIN = "947361"
PIN_OUTRO = "583920"
LAUNCHER = ("C:\\Windows\\notepad.exe", "")
ICON = b"\x00\x00\x01\x00ico"

HIDDEN = shell.FILE_ATTRIBUTE_HIDDEN
SYSTEM = shell.FILE_ATTRIBUTE_SYSTEM
READONLY = shell.FILE_ATTRIBUTE_READONLY
HIDE = HIDDEN | SYSTEM
PLACEHOLDER_NAMES = {VAULT_DIR, ICON_NAME, DESKTOP_INI, HELP_NAME}

#: 2009-02-13, múltiplo de 100 ns (resolução do NTFS)
OLD_MTIME_NS = 1_234_567_890_123_456_700

SPEC: dict[str, Any] = {
    "relatório.txt": b"relatorio confidencial\n" * 40,
    "notas.bin": bytes(range(256)) * 300,
    "Fotos de família": {"praia.jpg": b"\xff\xd8 jpeg sintetico " * 500, "vazia": {}},
    "sub": {"a.txt": b"a" * 10, "fundo": {"ção.dat": b"profundo"}},
    "vazia": {},
}
SPEC_FILES = 5

SMALL: dict[str, Any] = {"um.txt": b"um", "pasta": {"dois.txt": b"dois"}}


class Crash(BaseException):
    """Queda simulada do processo: passa por cima do tratamento normal de erros."""


def _raise_crash(*_args: object, **_kw: object) -> None:
    raise Crash


# --- ambiente ----------------------------------------------------------------------------


def new_profile(directory: Path, master: str = SM, pin: str = PIN) -> ProfileSession:
    store = ProfileStore(directory, TESTING_POLICY)
    return store.create(master, pin, params=TESTING_PARAMS)


def new_manager(session: ProfileSession, **kw: Any) -> LockerManager:
    opts: dict[str, Any] = {
        "icon_bytes": ICON,
        "launcher": LAUNCHER,
        "policy": TESTING_POLICY,
        "protected": ProtectedPaths.none(),
        "known_folders": {},
        "create_shortcuts": False,
    }
    opts.update(kw)
    return LockerManager(session, **opts)


@dataclass
class Env:
    root: Path
    base: Path  # pasta-mãe das pastas protegidas (a área temporária fica aqui)
    session: ProfileSession
    mgr: LockerManager

    def reopen(self) -> LockerManager:
        """Queda simulada: relê o perfil do DISCO (o estado em memória é perdido)."""
        session = self.session.store.unlock_with_master(SM)
        return new_manager(session)


@pytest.fixture
def env(tmp_path: Path) -> Env:
    session = new_profile(tmp_path / "perfil")
    base = tmp_path / "dados"
    base.mkdir()
    return Env(tmp_path, base, session, new_manager(session))


def make_folder(base: Path, name: str = "Particular", spec: dict[str, Any] | None = None) -> Path:
    p = base / name
    p.mkdir()
    write_tree(p, SPEC if spec is None else spec)
    if spec is None:
        os.utime(p / "relatório.txt", ns=(OLD_MTIME_NS, OLD_MTIME_NS))
    return p


def protect(
    mgr: LockerManager,
    path: Path,
    progress: ProgressSink | None = None,
    cancel: CancelToken | None = None,
) -> LockOutcome:
    return mgr.protect(mgr.check_protect(str(path)), progress, cancel)


def attrs(p: Path) -> int:
    return shell.get_attributes(str(p))


def staging_dirs(parent: Path) -> list[str]:
    return sorted(n for n in os.listdir(parent) if n.startswith(".owlvault-"))


def roles(rec: FolderRecord) -> list[str]:
    return sorted(v.role for v in rec.vaults)


def refused(mgr: LockerManager, path: Path) -> list[str]:
    with pytest.raises(PreflightError) as ei:
        mgr.check_protect(str(path))
    return ei.value.blockers


def has(blockers: list[str], *parts: str) -> bool:
    return any(all(part in b for part in parts) for b in blockers)


class OnStage(NullProgress):
    """Executa ``action`` (uma vez) quando começa a etapa cujo nome começa com ``prefix``."""

    def __init__(self, prefix: str, action: Callable[[], None]) -> None:
        self.prefix = prefix
        self.action = action
        self.fired = False

    def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
        if not self.fired and name.startswith(self.prefix):
            self.fired = True
            self.action()


@contextlib.contextmanager
def held_open_on_delete(target: Path) -> Iterator[OnStage]:
    """Abre ``target`` (sem FILE_SHARE_DELETE) no início da fase "Apagando…"; fecha na saída."""
    with contextlib.ExitStack() as stack:

        def grab() -> None:
            stack.enter_context(open(target, "rb"))

        yield OnStage("Apagando", grab)


# --- proteger ----------------------------------------------------------------------------


def test_proteger_deixa_so_o_espaco_reservado(env: Env) -> None:
    p = make_folder(env.base)
    out = protect(env.mgr, p)
    rec = out.record

    assert out.complete and not out.pending and not out.kept_previous and not out.removable
    assert rec.state == TRANCADA
    assert set(os.listdir(p)) == PLACEHOLDER_NAMES
    for name in ("relatório.txt", "notas.bin", "Fotos de família", "sub", "vazia"):
        assert not os.path.lexists(p / name)

    raw = (p / DESKTOP_INI).read_bytes()
    assert raw[:2] == b"\xff\xfe"  # UTF-16LE com BOM
    text = raw[2:].decode("utf-16-le")
    assert "IconResource=.owlvault.ico,0" in text  # relativo à própria pasta
    assert ":\\" not in text  # nenhum caminho absoluto
    assert "InfoTip=Pasta protegida pelo Owl Vault — os arquivos estão aqui" in text
    assert (p / ICON_NAME).read_bytes() == ICON
    help_raw = (p / HELP_NAME).read_bytes()
    assert help_raw.startswith(b"\xef\xbb\xbf")
    assert "Recuperar uma pasta protegida" in help_raw.decode("utf-8-sig")

    for name in (VAULT_DIR, DESKTOP_INI, ICON_NAME):
        assert attrs(p / name) & HIDE == HIDE, name
    assert not attrs(p / HELP_NAME) & HIDDEN
    assert attrs(p) & (READONLY | SYSTEM)
    assert not attrs(p) & HIDDEN
    assert staging_dirs(env.base) == []

    current = rec.vault("atual")
    assert current is not None and roles(rec) == ["atual"]
    assert winfs.strip_extended(current.location) == str(p / VAULT_DIR)
    assert len(current.vault_id) == 32
    assert rec.fingerprints == {} and rec.pending == [] and rec.attention == ""

    view = env.mgr.view(rec)
    assert (view.label, view.action, view.issue) == ("Trancada", "abrir", "")
    # o índice foi gravado: o perfil relido do disco mostra a pasta trancada
    again = env.reopen().session.index.folder(rec.id)
    assert again is not None and again.state == TRANCADA


def test_atalho_abrir_com_owl_vault(env: Env) -> None:
    mgr = new_manager(env.session, create_shortcuts=True)
    p = make_folder(env.base)
    before = tree_digest(p)
    rec = protect(mgr, p).record

    assert set(os.listdir(p)) == PLACEHOLDER_NAMES | {SHORTCUT_NAME}
    lnk = p / SHORTCUT_NAME
    data = lnk.read_bytes()
    assert data[:4] == b"\x4c\x00\x00\x00"  # cabeçalho de um .lnk
    assert f"--abrir {rec.id}".encode("utf-16-le") in data
    assert ICON_NAME.encode("utf-16-le") in data
    low = data.lower()
    assert b"notepad.exe" in low or "notepad.exe".encode("utf-16-le") in low
    assert not attrs(lnk) & HIDDEN  # o atalho fica visível

    out = mgr.unlock(rec.id)
    assert out.complete
    assert not lnk.exists()
    assert tree_digest(p) == before


# --- abrir -------------------------------------------------------------------------------


def test_abrir_devolve_tudo_identico(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    assert before["relatório.txt"][2] == OLD_MTIME_NS
    rec = protect(env.mgr, p).record

    out = env.mgr.unlock(rec.id)

    assert out.complete and out.report is not None and out.report.ok
    assert out.report.restored == SPEC_FILES
    assert winfs.strip_extended(out.path) == str(p)
    assert rec.state == ABERTA and rec.pending == [] and rec.attention == ""
    # conteúdo, subpastas vazias, nomes com acento e data de modificação idênticos
    assert tree_digest(p) == before
    names = set(os.listdir(p))
    assert not names & (PLACEHOLDER_NAMES | {SHORTCUT_NAME, MARKER_NAME})
    a = attrs(p)
    assert not a & (READONLY | SYSTEM | HIDDEN)
    assert a & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
    # o cofre fica guardado na área temporária enquanto a pasta está aberta
    prev = rec.vault("anterior")
    assert prev is not None and roles(rec) == ["anterior"]
    assert os.path.isdir(prev.location)
    assert staging_dirs(env.base) == [f".owlvault-{rec.id}"]
    assert attrs(env.base / f".owlvault-{rec.id}") & HIDE == HIDE
    view = env.mgr.view(rec)
    assert view.label.startswith("Aberta") and view.action == "trancar" and view.issue == ""
    again = env.reopen().session.index.folder(rec.id)
    assert again is not None and again.state == ABERTA


def test_operacoes_recusadas_fora_do_estado(env: Env) -> None:
    p = make_folder(env.base, spec=SMALL)
    rec = protect(env.mgr, p).record
    with pytest.raises(StateError):
        env.mgr.lock(rec.id)
    with pytest.raises(StateError):
        env.mgr.continue_lock(rec.id)
    with pytest.raises(StateError):
        env.mgr.undo_lock(rec.id)
    env.mgr.unlock(rec.id)
    with pytest.raises(StateError):
        env.mgr.unlock(rec.id)
    with pytest.raises(StateError):
        env.mgr.lock("0" * 32)
    assert rec.state == ABERTA


def test_cofre_trocado_entre_pastas_e_recusado(env: Env) -> None:
    a = make_folder(env.base, "A", SMALL)
    b = make_folder(env.base, "B", {"b.txt": b"bbb"})
    ra = protect(env.mgr, a).record
    protect(env.mgr, b)
    os.rename(a / VAULT_DIR, env.base / "tmp-a")
    os.rename(b / VAULT_DIR, a / VAULT_DIR)
    os.rename(env.base / "tmp-a", b / VAULT_DIR)

    with pytest.raises(StateError, match="não correspondem"):
        env.mgr.unlock(ra.id)
    assert ra.state == TRANCADA
    assert set(os.listdir(a)) == PLACEHOLDER_NAMES
    assert staging_dirs(env.base) == []


# --- ciclo trancar / abrir / alterar / trancar ------------------------------------------


def test_ciclo_inclui_arquivos_novos_e_alterados(env: Env) -> None:
    p = make_folder(env.base)
    rec = protect(env.mgr, p).record
    env.mgr.unlock(rec.id)
    (p / "novo.txt").write_bytes(b"arquivo novo")
    (p / "sub" / "a.txt").write_bytes(b"alterado depois de abrir")
    (p / "vazia" / "nova pasta").mkdir()
    expected = tree_digest(p)
    assert env.mgr.missing_since_open(rec.id) == []

    out = env.mgr.lock(rec.id)

    assert out.complete and not out.kept_previous
    assert roles(rec) == ["atual"]
    assert set(os.listdir(p)) == PLACEHOLDER_NAMES
    assert staging_dirs(env.base) == []
    assert env.mgr.unlock(rec.id).complete
    assert tree_digest(p) == expected


def test_apagado_com_accept_missing_apaga_o_cofre_anterior(env: Env) -> None:
    p = make_folder(env.base)
    rec = protect(env.mgr, p).record
    env.mgr.unlock(rec.id)
    prev = rec.vault("anterior")
    assert prev is not None
    os.remove(p / "notas.bin")
    expected = tree_digest(p)
    assert env.mgr.missing_since_open(rec.id) == ["notas.bin"]

    out = env.mgr.lock(rec.id, accept_missing=["notas.bin"])

    assert out.complete and not out.kept_previous
    assert not os.path.lexists(prev.location)  # regra de ouro: tudo coberto ⇒ apagado
    assert roles(rec) == ["atual"]
    assert rec.accepted_missing == []
    assert staging_dirs(env.base) == []
    assert env.mgr.view(rec).issue == ""
    env.mgr.unlock(rec.id)
    assert tree_digest(p) == expected


def test_apagado_sem_accept_missing_mantem_versao_anterior(env: Env) -> None:
    p = make_folder(env.base)
    original = tree_digest(p)
    rec = protect(env.mgr, p).record
    env.mgr.unlock(rec.id)
    gone = "Fotos de família\\praia.jpg"
    os.remove(p / "Fotos de família" / "praia.jpg")
    assert env.mgr.missing_since_open(rec.id) == [gone]

    out = env.mgr.lock(rec.id)

    assert out.complete and out.kept_previous
    assert roles(rec) == ["atual", MANTIDO]
    kept = rec.vault(MANTIDO)
    assert kept is not None and os.path.isdir(kept.location)
    assert set(os.listdir(p)) == PLACEHOLDER_NAMES
    view = env.mgr.view(rec)
    assert (view.issue, view.action, view.base_action) == ("versao_anterior", "resolver", "abrir")
    assert "1 arquivo(s)" in view.attention
    assert env.mgr.kept_only_files(rec.id) == [gone]
    again = env.reopen().session.index.folder(rec.id)
    assert again is not None and sorted(v.role for v in again.vaults) == ["atual", MANTIDO]

    # recupera a versão mantida numa pasta NOVA (a pasta trancada não é tocada)
    dest_parent = env.root / "recuperado"
    dest_parent.mkdir()
    reports = env.mgr.restore_kept(rec.id, str(dest_parent))
    assert len(reports) == 1 and reports[0].ok
    assert tree_digest(dest_parent / "Particular (versão anterior)") == original
    reports = env.mgr.restore_kept(rec.id, str(dest_parent))
    assert tree_digest(dest_parent / "Particular (versão anterior 2)") == original
    assert set(os.listdir(p)) == PLACEHOLDER_NAMES

    # apagar a versão anterior só com a lista EXATA
    with pytest.raises(StateError):
        env.mgr.delete_kept(rec.id, [])
    with pytest.raises(StateError):
        env.mgr.delete_kept(rec.id, [gone, "outro.txt"])
    assert os.path.isdir(kept.location)
    env.mgr.delete_kept(rec.id, [gone])
    assert not os.path.lexists(kept.location)
    assert roles(rec) == ["atual"]
    assert env.mgr.view(rec).issue == ""
    assert staging_dirs(env.base) == []


def test_abertura_incompleta_nunca_apaga_a_versao_anterior(env: Env) -> None:
    p = make_folder(env.base)
    rec = protect(env.mgr, p).record
    blobs = sorted((p / VAULT_DIR / "data").rglob("*.owlb"))
    assert len(blobs) == SPEC_FILES
    with open(blobs[0], "r+b") as fh:  # dado criptografado truncado
        fh.truncate(10)

    out = env.mgr.unlock(rec.id)

    assert not out.complete
    assert rec.state == ABERTURA_INCOMPLETA and len(rec.pending) == 1
    assert env.mgr.view(rec).issue == ABERTURA_INCOMPLETA
    assert not env.mgr.unlock(rec.id).complete  # "Tentar de novo"
    env.mgr.accept_incomplete_unlock(rec.id)
    assert rec.state == ABERTA
    assert roles(rec) == [MANTIDO]
    assert MARKER_NAME not in os.listdir(p)
    [lost] = env.mgr.kept_only_files(rec.id)
    assert not (p / lost).exists()
    assert env.mgr.view(rec).issue == "versao_anterior"
    kept = rec.vault(MANTIDO)
    assert kept is not None

    out2 = env.mgr.lock(rec.id)
    assert out2.complete and out2.kept_previous
    assert os.path.isdir(kept.location)  # nunca apagada sozinha
    assert roles(rec) == ["atual", MANTIDO]


def test_marca_da_internet_volta_ao_abrir(env: Env) -> None:
    p = make_folder(env.base)
    target = p / "notas.bin"
    with open(str(target) + ":Zone.Identifier", "wb") as fh:
        fh.write(b"[ZoneTransfer]\r\nZoneId=3\r\n")
    rec = protect(env.mgr, p).record
    assert rec.zone_files == ["notas.bin"]
    env.mgr.unlock(rec.id)
    assert read_zone_id(str(target)) == 3
    assert read_zone_id(str(p / "relatório.txt")) is None


# --- interrupções ------------------------------------------------------------------------


def test_arquivo_aberto_durante_a_exclusao_e_continuar(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    target = p / "relatório.txt"
    with held_open_on_delete(target) as sink:
        out = protect(env.mgr, p, progress=sink)
        rec = out.record
        assert sink.fired
        assert not out.complete
        assert rec.state == APAGANDO
        assert len(out.pending) == 1 and out.pending[0].startswith("relatório.txt:")
        assert "em uso" in out.pending[0]
        assert rec.pending == out.pending
        assert target.exists()
        assert set(os.listdir(p)) == {"relatório.txt", MARKER_NAME}  # o resto foi apagado
        assert roles(rec) == ["novo"]
        view = env.mgr.view(rec)
        assert (view.issue, view.action) == (APAGANDO, "resolver")
        with pytest.raises(StateError):
            env.mgr.lock(rec.id)
        with pytest.raises(StateError):
            env.mgr.unlock(rec.id)
    again = env.reopen().session.index.folder(rec.id)
    assert again is not None and again.state == APAGANDO

    out2 = env.mgr.continue_lock(rec.id)

    assert out2.complete and rec.state == TRANCADA
    assert set(os.listdir(p)) == PLACEHOLDER_NAMES
    assert roles(rec) == ["atual"]
    assert staging_dirs(env.base) == []
    env.mgr.unlock(rec.id)
    assert tree_digest(p) == before


def test_desfazer_devolve_tudo_e_mantem_o_arquivo_alterado(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    target = p / "sub" / "a.txt"
    with held_open_on_delete(target) as sink:
        out = protect(env.mgr, p, progress=sink)
    rec = out.record
    assert not out.complete and rec.state == APAGANDO
    assert [x.split(":", 1)[0] for x in out.pending] == ["sub\\a.txt"]
    target.write_bytes(b"alterado enquanto a pasta estava em 'apagando'")
    altered = tree_digest(p)["sub\\a.txt"]

    res = env.mgr.undo_lock(rec.id)

    assert res.complete and res.report is not None
    assert rec.state == ABERTA and rec.pending == [] and rec.attention == ""
    assert roles(rec) == ["anterior"]
    assert any(c.startswith("sub\\a.txt") for c in res.report.conflicts)
    expected = dict(before)
    expected["sub\\a.txt"] = altered
    assert tree_digest(p) == expected
    assert MARKER_NAME not in os.listdir(p)

    # trancar de novo funciona e o cofre anterior (todo coberto) é apagado
    out2 = env.mgr.lock(rec.id)
    assert out2.complete and not out2.kept_previous
    assert roles(rec) == ["atual"]
    env.mgr.unlock(rec.id)
    assert tree_digest(p) == expected


def test_arquivo_aberto_antes_recusa_e_nada_muda(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    with open(p / "notas.bin", "rb"):
        blockers = refused(env.mgr, p)
    assert has(blockers, "notas.bin", "em uso")
    assert tree_digest(p) == before
    assert env.mgr.folders == []
    assert staging_dirs(env.base) == []


def test_trancar_pasta_aberta_com_arquivo_em_uso_recusa(env: Env) -> None:
    p = make_folder(env.base)
    rec = protect(env.mgr, p).record
    env.mgr.unlock(rec.id)
    before = tree_digest(p)
    prev = rec.vault("anterior")
    assert prev is not None
    with open(p / "notas.bin", "rb"), pytest.raises(PreflightError):
        env.mgr.lock(rec.id)
    assert rec.state == ABERTA and roles(rec) == ["anterior"]
    assert os.path.isdir(prev.location)
    assert tree_digest(p) == before
    assert env.mgr.lock(rec.id).complete


@pytest.mark.xfail(
    strict=True,
    reason="BUG: lock() cria a área temporária <pai>\\.owlvault-<id> ANTES da pré-verificação "
    "e não a remove quando ela falha; protect() tira a pasta da lista e a área fica órfã.",
)
def test_arquivo_aberto_entre_conferir_e_proteger(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    check = env.mgr.check_protect(str(p))
    with open(p / "notas.bin", "rb"), pytest.raises(PreflightError):
        env.mgr.protect(check)
    assert env.mgr.folders == []
    assert env.reopen().folders == []
    assert tree_digest(p) == before
    assert staging_dirs(env.base) == []  # nada sobra ao lado da pasta


def test_cancelar_durante_a_cifragem_nao_apaga_nada(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    cancel = CancelToken()
    with pytest.raises(CancelledError):
        protect(env.mgr, p, progress=OnStage("Criptografando", cancel.cancel), cancel=cancel)
    assert tree_digest(p) == before
    assert env.mgr.folders == []
    assert env.reopen().folders == []


@pytest.mark.xfail(
    strict=True,
    reason="BUG: protect() cancelado/que falha em create_vault tira a pasta da lista, mas a "
    "área temporária <pai>\\.owlvault-<id> (com a pasta do teste de restauração) fica órfã.",
)
def test_cancelar_durante_a_cifragem_nao_deixa_area_temporaria(env: Env) -> None:
    p = make_folder(env.base)
    cancel = CancelToken()
    with pytest.raises(CancelledError):
        protect(env.mgr, p, progress=OnStage("Criptografando", cancel.cancel), cancel=cancel)
    assert staging_dirs(env.base) == []


def test_arquivo_alterado_antes_da_exclusao_nao_e_apagado(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    target = p / "notas.bin"
    novo = b"conteudo novo, gravado depois da cifragem"

    def rewrite() -> None:
        target.write_bytes(novo)

    out = protect(env.mgr, p, progress=OnStage("Apagando", rewrite))
    rec = out.record

    assert not out.complete and rec.state == APAGANDO
    assert len(out.pending) == 1 and out.pending[0].startswith("notas.bin:")
    assert "mudou" in out.pending[0]
    assert target.read_bytes() == novo
    # "Continuar trancando" também não apaga o arquivo alterado
    out2 = env.mgr.continue_lock(rec.id)
    assert not out2.complete and rec.state == APAGANDO
    assert target.read_bytes() == novo

    res = env.mgr.undo_lock(rec.id)

    assert res.complete and rec.state == ABERTA
    after = tree_digest(p)
    assert target.read_bytes() == novo
    expected = dict(before)
    expected["notas.bin"] = after["notas.bin"]
    assert after == expected


def test_item_novo_durante_o_trancamento_fica_pendente(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    intruso = p / "chegou agora.txt"

    def drop() -> None:
        intruso.write_bytes(b"novo")

    out = protect(env.mgr, p, progress=OnStage("Apagando", drop))
    rec = out.record

    assert not out.complete and rec.state == APAGANDO
    assert len(out.pending) == 1
    assert out.pending[0].startswith("chegou agora.txt:") and "item novo" in out.pending[0]
    assert intruso.read_bytes() == b"novo"
    intruso.unlink()
    assert env.mgr.continue_lock(rec.id).complete
    assert set(os.listdir(p)) == PLACEHOLDER_NAMES
    env.mgr.unlock(rec.id)
    assert tree_digest(p) == before


# --- quedas simuladas --------------------------------------------------------------------


@pytest.mark.parametrize("resolve", ["continuar", "desfazer"])
def test_queda_durante_a_exclusao(env: Env, monkeypatch: pytest.MonkeyPatch, resolve: str) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    real = winfs.delete_checked
    calls: list[str] = []

    def crash_on_third(path: str, expected: Any, *, is_dir: bool = False) -> None:
        calls.append(path)
        if len(calls) == 3:
            raise Crash
        real(path, expected, is_dir=is_dir)

    with monkeypatch.context() as m:
        m.setattr(winfs, "delete_checked", crash_on_third)
        with pytest.raises(Crash):
            protect(env.mgr, p)

    mgr = env.reopen()
    [rec] = mgr.folders
    assert rec.state == APAGANDO and rec.attention == ""
    assert MARKER_NAME in os.listdir(p)
    remaining = [f for _, _, files in os.walk(p) for f in files if f != MARKER_NAME]
    assert len(remaining) == SPEC_FILES - 2  # 2 originais já tinham sido apagados
    assert mgr.reconcile_on_start() == []
    assert "interrompido" in rec.attention
    assert mgr.view(rec).issue == APAGANDO

    if resolve == "continuar":
        out = mgr.continue_lock(rec.id)
        assert out.complete and rec.state == TRANCADA
        assert set(os.listdir(p)) == PLACEHOLDER_NAMES
        assert mgr.unlock(rec.id).complete
    else:
        res = mgr.undo_lock(rec.id)
        assert res.complete and rec.state == ABERTA
        assert roles(rec) == ["anterior"]
    assert tree_digest(p) == before


@pytest.mark.xfail(
    strict=True,
    reason="BUG: queda entre mover o cofre novo para P\\.owlvault e gravar 'trancada' (espaço "
    "reservado, regra de ouro) deixa o índice em 'apagando' apontando para o cofre na área "
    "temporária: 'Continuar trancando' e 'Desfazer' falham para sempre.",
)
def test_queda_depois_de_mover_o_cofre_para_a_pasta(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    with monkeypatch.context() as m:
        m.setattr(LockerManager, "_write_placeholder", _raise_crash)
        with pytest.raises(Crash):
            protect(env.mgr, p)

    mgr = env.reopen()
    [rec] = mgr.folders
    assert rec.state == APAGANDO
    assert os.listdir(p) == [VAULT_DIR]  # originais apagados, cofre já dentro de P
    mgr.reconcile_on_start()

    out = mgr.continue_lock(rec.id)

    assert out.complete and rec.state == TRANCADA
    assert mgr.unlock(rec.id).complete
    assert tree_digest(p) == before


def test_queda_em_trancando_descarta_cofre_novo(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    check = env.mgr.check_protect(str(p))
    with monkeypatch.context() as m:
        # o processo "morre" durante create_vault: ninguém limpa o cofre novo
        m.setattr(LockerManager, "_discard_novo", lambda self, rec: None)
        with pytest.raises(Crash):
            env.mgr.protect(check, progress=OnStage("Teste de restauração", _raise_crash))

    mgr = env.reopen()
    [rec] = mgr.folders
    assert rec.state == TRANCANDO
    novo = rec.vault("novo")
    assert novo is not None and os.path.isdir(novo.location)
    assert tree_digest(p) == before
    assert mgr.view(rec).issue == TRANCANDO

    notes = mgr.reconcile_on_start()

    assert len(notes) == 1 and "continua aberta" in notes[0]
    assert rec.state == ABERTA and rec.vaults == []
    assert not os.path.lexists(novo.location)
    assert tree_digest(p) == before
    again = env.reopen().session.index.folder(rec.id)
    assert again is not None and again.state == ABERTA
    out = mgr.lock(rec.id)
    assert out.complete
    assert staging_dirs(env.base) == []
    mgr.unlock(rec.id)
    assert tree_digest(p) == before


def test_queda_ao_abrir_antes_de_mover_o_cofre(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    rec = protect(env.mgr, p).record
    with monkeypatch.context() as m:
        m.setattr(LockerManager, "_move_vault_out", _raise_crash)
        with pytest.raises(Crash):
            env.mgr.unlock(rec.id)

    mgr = env.reopen()
    r = mgr.session.index.folder(rec.id)
    assert r is not None and r.state == ABRINDO
    assert set(os.listdir(p)) == PLACEHOLDER_NAMES  # o cofre ainda está em P
    prev = r.vault("anterior")
    assert prev is not None and not os.path.lexists(prev.location)
    assert mgr.reconcile_on_start() == []
    assert "interrompida" in r.attention
    assert mgr.view(r).issue == ABRINDO

    out = mgr.unlock(r.id)

    assert out.complete and r.state == ABERTA
    assert tree_digest(p) == before


def test_queda_ao_abrir_com_cofre_ja_movido(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    rec = protect(env.mgr, p).record
    with monkeypatch.context() as m:
        m.setattr(LockerManager, "_finish_unlock", _raise_crash)
        with pytest.raises(Crash):
            env.mgr.unlock(rec.id)

    mgr = env.reopen()
    r = mgr.session.index.folder(rec.id)
    assert r is not None and r.state == ABRINDO
    assert os.listdir(p) == []
    prev = r.vault("anterior")
    assert prev is not None and os.path.isdir(prev.location)

    out = mgr.unlock(r.id)

    assert out.complete and r.state == ABERTA
    assert tree_digest(p) == before


def test_queda_no_meio_da_restauracao(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    rec = protect(env.mgr, p).record
    faults.fail_at("restore.write", 2, Crash)
    with pytest.raises(Crash):
        env.mgr.unlock(rec.id)
    faults.reset()
    assert MARKER_NAME in os.listdir(p)

    mgr = env.reopen()
    r = mgr.session.index.folder(rec.id)
    assert r is not None and r.state == ABRINDO
    out = mgr.unlock(r.id)

    assert out.complete and r.state == ABERTA
    assert tree_digest(p) == before
    assert MARKER_NAME not in os.listdir(p)


def test_restauracao_concluida_sem_gravar_o_estado(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    rec = protect(env.mgr, p).record
    real = lockers.restore_vault

    def restore_then_crash(*args: Any, **kw: Any) -> None:
        real(*args, **kw)
        raise Crash

    with monkeypatch.context() as m:
        m.setattr(lockers, "restore_vault", restore_then_crash)
        with pytest.raises(Crash):
            env.mgr.unlock(rec.id)

    mgr = env.reopen()
    r = mgr.session.index.folder(rec.id)
    assert r is not None and r.state == ABRINDO
    assert tree_digest(p) == before  # P cheio, sem marcador
    out = mgr.unlock(r.id)

    assert out.complete and r.state == ABERTA
    assert out.report is not None and out.report.skipped_existing == SPEC_FILES
    assert tree_digest(p) == before


# --- recusas da pré-verificação ----------------------------------------------------------


def test_recusa_pasta_dentro_de_outra_protegida(env: Env) -> None:
    a = make_folder(env.base, "A", {"interna": {"x.txt": b"x"}, "y.txt": b"y"})
    ra = protect(env.mgr, a).record
    env.mgr.unlock(ra.id)
    before = tree_digest(a)
    blockers = refused(env.mgr, a / "interna")
    assert has(blockers, "'A'", "já é protegida")
    assert tree_digest(a) == before
    assert env.mgr.folders == [ra]


def test_recusa_pasta_que_contem_outra_protegida(env: Env) -> None:
    ext = env.base / "Externa"
    ext.mkdir()
    (ext / "solto.txt").write_bytes(b"solto")
    protect(env.mgr, make_folder(ext, "Interna", SMALL))
    blockers = refused(env.mgr, ext)
    assert has(blockers, "'Interna'", "já é protegida")
    assert has(blockers, "Interna\\.owlvault", "já é uma pasta protegida")
    assert staging_dirs(env.base) == []
    assert len(env.mgr.folders) == 1


def test_recusa_pasta_que_contem_owlvault(env: Env) -> None:
    p = make_folder(env.base, "Copia", {"a.txt": b"a", "sub": {".owlvault": {"vault.owl": b"x"}}})
    before = tree_digest(p)
    blockers = refused(env.mgr, p)
    assert has(blockers, "sub\\.owlvault", "já é uma pasta protegida")
    assert tree_digest(p) == before
    assert staging_dirs(env.base) == []


def test_recusa_pastas_conhecidas_do_windows(env: Env) -> None:
    pai = env.base / "Pai"
    docs = pai / "Docs"
    docs.mkdir(parents=True)
    (docs / "x.txt").write_bytes(b"x")
    mgr = new_manager(env.session, known_folders={"Documentos": str(docs)})
    assert has(refused(mgr, docs), "pasta Documentos inteira")
    assert has(refused(mgr, pai), "contém a pasta Documentos")
    # uma pasta DENTRO da pasta conhecida pode ser protegida
    sub = docs / "Particular"
    sub.mkdir()
    (sub / "y.txt").write_bytes(b"y")
    assert mgr.check_protect(str(sub)).files == 1
    assert staging_dirs(env.base) == [] and staging_dirs(pai) == [] and staging_dirs(docs) == []


def test_recusa_arquivo_com_hard_link(env: Env) -> None:
    fora = env.base / "fora.txt"
    fora.write_bytes(b"compartilhado")
    p = make_folder(env.base, "HL", {"a.txt": b"a"})
    os.link(fora, p / "vinculo.txt")
    blockers = refused(env.mgr, p)
    assert has(blockers, "'vinculo.txt'", "vínculo do Windows")
    assert fora.read_bytes() == b"compartilhado"
    assert (p / "vinculo.txt").read_bytes() == b"compartilhado"
    assert staging_dirs(env.base) == []


@pytest.mark.parametrize(
    "raw",
    [
        b"[.ShellClassInfo]\r\nCLSID={645FF040-5081-101B-9F08-00AA002F954E}\r\n",
        b"\xff\xfe"
        + "[.ShellClassInfo]\r\nLocalizedResourceName=@%SystemRoot%\\x.dll,-1\r\n".encode(
            "utf-16-le"
        ),
    ],
    ids=["clsid", "localized-utf16"],
)
def test_recusa_desktop_ini_especial(env: Env, raw: bytes) -> None:
    p = make_folder(env.base, "Especial", {"a.txt": b"a", "desktop.ini": raw})
    assert has(refused(env.mgr, p), "pasta especial do Windows")
    assert (p / "desktop.ini").read_bytes() == raw
    assert staging_dirs(env.base) == []


def test_desktop_ini_comum_e_aceito(env: Env) -> None:
    raw = b"[.ShellClassInfo]\r\nIconResource=x.ico,0\r\n"
    p = make_folder(env.base, "Comum", {"a.txt": b"a", "desktop.ini": raw})
    check = env.mgr.check_protect(str(p))
    assert check.files == 2 and check.name == "Comum"
    assert staging_dirs(env.base) == []


def test_recusa_raiz_da_unidade_sem_gravar(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    drive_root = env.root.anchor  # ex.: "C:\\"
    sandbox = os.path.normcase(str(env.root))
    tried: list[str] = []
    real_mkdir = os.mkdir

    def guarded_mkdir(path: Any, *args: Any, **kw: Any) -> None:
        text = str(path)
        tried.append(text)
        if not os.path.normcase(winfs.strip_extended(text)).startswith(sandbox):
            raise PermissionError(13, "bloqueado pelo teste (fora da pasta temporária)", text)
        real_mkdir(path, *args, **kw)

    # nada fora de tmp_path pode ser criado durante a chamada
    monkeypatch.setattr(lockers.os, "mkdir", guarded_mkdir)
    with pytest.raises(PreflightError):
        env.mgr.check_protect(drive_root)
    monkeypatch.undo()
    assert env.mgr.folders == []
    # nenhuma área temporária foi tentada NA raiz da unidade
    root_l = drive_root.lower()
    assert not any(winfs.strip_extended(t).lower().startswith(root_l + ".owlvault") for t in tried)
    # a pré-verificação (só leitura, sem varredura) também recusa a raiz
    stage = env.base / "area"
    stage.mkdir()
    with pytest.raises(PreflightError) as ei:
        env.mgr._preflight(
            winfs.to_extended(drive_root),
            winfs.to_extended(str(stage / "novo")),
            winfs.to_extended(str(stage)),
            None,
            None,
        )
    assert has(ei.value.blockers, "raiz de uma unidade")


# --- itens extras, pasta movida, esquecer --------------------------------------------------


def test_item_colocado_na_pasta_trancada(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    rec = protect(env.mgr, p).record
    extra = p / "Nova planilha.xlsx"
    extra.write_bytes(b"planilha")
    vault_before = tree_digest(p / VAULT_DIR)

    view = env.mgr.view(rec)
    assert (view.issue, view.action, view.base_action) == ("itens_extras", "resolver", "abrir")
    assert "Nova planilha.xlsx" in view.attention
    with pytest.raises(StateError, match=r"Nova planilha\.xlsx"):
        env.mgr.unlock(rec.id)

    assert set(os.listdir(p)) == PLACEHOLDER_NAMES | {"Nova planilha.xlsx"}
    assert extra.read_bytes() == b"planilha"
    assert tree_digest(p / VAULT_DIR) == vault_before
    assert rec.state == TRANCADA
    again = env.reopen().session.index.folder(rec.id)
    assert again is not None and again.state == TRANCADA

    extra.unlink()
    assert env.mgr.unlock(rec.id).complete
    assert tree_digest(p) == before


def test_pasta_movida_relocate_e_forget(env: Env) -> None:
    a = make_folder(env.base, "A")
    before_a = tree_digest(a)
    b = make_folder(env.base, "B", SMALL)
    ra = protect(env.mgr, a).record
    rb = protect(env.mgr, b).record
    old_path = ra.path
    a2 = env.base / "A renomeada"
    os.rename(a, a2)

    view = env.mgr.view(ra)
    assert (view.issue, view.action, view.available) == ("nao_encontrada", "resolver", True)
    with pytest.raises(StateError):
        env.mgr.unlock(ra.id)
    # outra pasta protegida (outro vault_id) não é aceita
    with pytest.raises(StateError, match="mesma"):
        env.mgr.relocate(ra.id, str(b))
    # pasta comum sem dados protegidos também não
    plain = env.base / "comum"
    plain.mkdir()
    with pytest.raises(StateError):
        env.mgr.relocate(ra.id, str(plain))
    assert ra.path == old_path

    env.mgr.relocate(ra.id, str(a2))

    assert ra.name == "A renomeada"
    assert winfs.strip_extended(ra.path) == str(a2)
    assert env.mgr.view(ra).issue == ""
    assert env.mgr.unlock(ra.id).complete
    assert tree_digest(a2) == before_a

    # "Tirar da lista" não apaga nada
    snapshot = tree_digest(b)
    env.mgr.forget(rb.id)
    assert rb not in env.mgr.folders
    assert tree_digest(b) == snapshot
    assert set(os.listdir(b)) == PLACEHOLDER_NAMES
    assert env.reopen().session.index.folder(rb.id) is None


@pytest.mark.xfail(
    strict=True,
    reason="BUG: view() decide 'indisponível' procurando 'unidade' no texto do erro, que inclui "
    "o nome/caminho da pasta; uma pasta movida cujo nome contém 'unidade' some do 'Procurar'.",
)
def test_pasta_movida_com_unidade_no_nome(env: Env) -> None:
    p = make_folder(env.base, "Backup da unidade", SMALL)
    rec = protect(env.mgr, p).record
    os.rename(p, env.base / "Outro nome")
    view = env.mgr.view(rec)
    assert (view.issue, view.action, view.available) == ("nao_encontrada", "resolver", True)


@pytest.mark.xfail(
    strict=True,
    reason="BUG: relocate() exige o cofre 'atual' dentro da pasta; uma pasta ABERTA renomeada "
    "(mesmo FileId) nunca pode ser reencontrada e o cofre 'anterior' fica órfão.",
)
def test_pasta_aberta_renomeada_pode_ser_reencontrada(env: Env) -> None:
    p = make_folder(env.base, spec=SMALL)
    rec = protect(env.mgr, p).record
    env.mgr.unlock(rec.id)
    p2 = env.base / "Particular renomeada"
    os.rename(p, p2)
    assert env.mgr.view(rec).issue == "nao_encontrada"
    env.mgr.relocate(rec.id, str(p2))
    assert env.mgr.view(rec).issue == ""


# --- recuperar ---------------------------------------------------------------------------


def test_recuperar_em_perfil_novo(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    rec = protect(env.mgr, p).record
    env.mgr.hide(rec.id)

    # "outro computador": perfil novo, com OUTRA senha mestra
    s2 = new_profile(env.root / "perfil2", master=SM_OUTRA, pin=PIN_OUTRO)
    m2 = new_manager(s2)
    found = m2.find_recoverable(str(env.base))  # pasta escondida dentro do pai
    assert [winfs.strip_extended(f) for f in found] == [str(p)]
    assert m2.find_recoverable(str(p)) == [winfs.to_extended(str(p))]
    assert m2.find_recoverable(str(env.root / "perfil2")) == []

    with pytest.raises(AuthenticationError):
        m2.recover(found[0], SM_ERRADA)
    with pytest.raises(AuthenticationError):
        m2.recover(found[0], SM_OUTRA)  # a senha do perfil novo não abre esta pasta
    assert m2.folders == [] and len(s2.index.keks) == 1

    r2 = m2.recover(found[0], SM)

    assert r2.state == TRANCADA and r2.hidden
    current, original = r2.vault("atual"), rec.vault("atual")
    assert current is not None and original is not None
    assert current.vault_id == original.vault_id
    assert len(s2.index.keks) == 2
    assert m2.view(r2).issue == "senha_antiga"
    with pytest.raises(StateError, match="já está na lista"):
        m2.recover(found[0], SM)
    assert set(os.listdir(p)) == PLACEHOLDER_NAMES

    out = m2.unlock(r2.id)
    assert out.complete
    assert tree_digest(p) == before
    assert not attrs(p) & HIDDEN and not r2.hidden
    # trancar de novo no perfil novo passa a usar a senha mestra dele
    assert m2.lock(r2.id).complete
    assert m2.view(r2).issue == ""
    assert m2.keys_for_vault(winfs.join(r2.path, VAULT_DIR)).salt == s2.index.keks[0].salt


# --- remover proteção --------------------------------------------------------------------


def test_remover_protecao(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    rec = protect(env.mgr, p).record
    with pytest.raises(StateError, match="Abra a pasta"):
        env.mgr.remove_protection(rec.id)
    assert set(os.listdir(p)) == PLACEHOLDER_NAMES

    env.mgr.unlock(rec.id)
    os.remove(p / "notas.bin")
    expected = tree_digest(p)
    assert env.mgr.removal_missing(rec.id) == ["notas.bin"]
    with pytest.raises(StateError):
        env.mgr.remove_protection(rec.id)
    with pytest.raises(StateError):
        env.mgr.remove_protection(rec.id, confirmed_missing=["outro.txt"])
    prev = rec.vault("anterior")
    assert prev is not None and os.path.isdir(prev.location)
    assert rec in env.mgr.folders

    env.mgr.remove_protection(rec.id, confirmed_missing=["notas.bin"])

    assert not os.path.lexists(prev.location)
    assert staging_dirs(env.base) == []
    assert env.mgr.folders == []
    assert env.reopen().folders == []
    assert tree_digest(p) == expected
    assert len(expected) == len(before) - 1
    assert not attrs(p) & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED


def test_remover_protecao_sem_faltas(env: Env) -> None:
    p = make_folder(env.base, spec=SMALL)
    before = tree_digest(p)
    rec = protect(env.mgr, p).record
    env.mgr.unlock(rec.id)
    assert env.mgr.removal_missing(rec.id) == []
    env.mgr.remove_protection(rec.id)
    assert env.mgr.folders == []
    assert staging_dirs(env.base) == []
    assert tree_digest(p) == before


# --- esconder / mostrar ------------------------------------------------------------------


def test_esconder_e_mostrar(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    rec = protect(env.mgr, p).record

    env.mgr.hide(rec.id)
    assert attrs(p) & HIDE == HIDE and rec.hidden
    view = env.mgr.view(rec)
    assert (view.label, view.action) == ("Escondida", "abrir")
    again = env.reopen().session.index.folder(rec.id)
    assert again is not None and again.hidden

    env.mgr.show(rec.id)
    assert not attrs(p) & HIDDEN and not rec.hidden
    assert attrs(p) & (SYSTEM | READONLY)  # continua com o ícone de pasta trancada
    assert env.mgr.view(rec).label == "Trancada"
    assert set(os.listdir(p)) == PLACEHOLDER_NAMES

    # abrir uma pasta escondida a mostra antes
    env.mgr.hide(rec.id)
    assert env.mgr.unlock(rec.id).complete
    assert not attrs(p) & (HIDDEN | SYSTEM) and not rec.hidden
    assert tree_digest(p) == before
    with pytest.raises(StateError):
        env.mgr.hide(rec.id)  # pasta aberta não pode ser escondida
    assert not attrs(p) & HIDDEN and not rec.hidden
