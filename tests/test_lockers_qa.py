"""Regressões da revisão adversarial das pastas protegidas (achados confirmados do "motor").

Cada teste reproduz um defeito confirmado e falhava antes da correção. Somente pastas
temporárias (``tmp_path``) com dados sintéticos e perfil sintético
(``ProfileStore(tmp_path / "perfil", TESTING_POLICY)`` com ``TESTING_PARAMS``).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from owl_vault.application import lockers
from owl_vault.application.lockers import (
    ABERTA,
    ABERTURA_INCOMPLETA,
    ABRINDO,
    APAGANDO,
    COFRE_DIFERENTE,
    COFRE_INACESSIVEL,
    MANTIDO,
    RESTAURANDO,
    SEM_ACESSO,
    TRANCADA,
    TRANCANDO,
    VAULT_DIR,
    LockerManager,
)
from owl_vault.application.profile import FolderRecord
from owl_vault.application.progress import NullProgress
from owl_vault.application.restore import MARKER_NAME
from owl_vault.domain.errors import OwlVaultError, StateError, UnsafePathError
from owl_vault.storage import acl, faults, shell, winfs
from owl_vault.storage.layout import COMPLETE_NAME
from tests.conftest import tree_digest
from tests.test_lockers import (
    HIDDEN,
    HIDE,
    PLACEHOLDER_NAMES,
    READONLY,
    Crash,
    Env,
    OnStage,
    attrs,
    make_folder,
    new_manager,
    new_profile,
    protect,
    roles,
    staging_dirs,
)


@pytest.fixture
def env(tmp_path: Path) -> Env:
    session = new_profile(tmp_path / "perfil")
    base = tmp_path / "dados"
    base.mkdir()
    return Env(tmp_path, base, session, new_manager(session))


ICACLS = os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "System32", "icacls.exe")


def icacls(*args: str) -> int:
    """ACL de uma pasta de TESTE (só dentro de tmp_path)."""
    proc = subprocess.run(  # noqa: S603 - executável fixo do Windows, argumentos do teste
        [ICACLS, *args], capture_output=True, check=False
    )
    return proc.returncode


def wipe(path: Path) -> None:
    """Apaga uma pasta nossa de teste (tira oculto/sistema/somente-leitura antes)."""
    for dirpath, dirnames, filenames in os.walk(path):
        for n in dirnames + filenames:
            shell.change_attributes(os.path.join(dirpath, n), remove=HIDE | READONLY)
    shell.change_attributes(str(path), remove=HIDE | READONLY)
    shutil.rmtree(path)


def kept_contents(env: Env, mgr: LockerManager, folder_id: str, name: str) -> list[bytes]:
    """Conteúdo de ``name`` em cada versão mantida (recuperada numa pasta nova)."""
    dest = env.root / f"recuperado-{len(os.listdir(env.root))}"
    dest.mkdir()
    out: list[bytes] = []
    for report in mgr.restore_kept(folder_id, str(dest)):
        f = Path(winfs.strip_extended(report.destination)) / name
        if f.exists():
            out.append(f.read_bytes())
    return out


def _held(target: Path) -> tuple[contextlib.ExitStack, OnStage]:
    stack = contextlib.ExitStack()
    return stack, OnStage("Apagando", lambda: stack.enter_context(open(target, "rb")))


# --- dados-1: "nunca apagado" decidido pelo próprio arquivo, não pela lista de pendências -----


def test_desfazer_depois_de_continuar_mantem_o_original(env: Env) -> None:
    p = make_folder(env.base)
    original = (p / "notas.bin").read_bytes()
    stack, sink = _held(p / "sub" / "a.txt")
    with stack:
        rec = protect(env.mgr, p, progress=sink).record
        assert rec.state == APAGANDO and not (p / "notas.bin").exists()
        (p / "notas.bin").write_bytes(b"copia antiga tirada de um backup")
        out = env.mgr.continue_lock(rec.id)  # notas.bin entra na lista (mudou)
        assert any(x.startswith("notas.bin:") for x in out.pending)

    res = env.mgr.undo_lock(rec.id)

    assert res.complete and rec.state == ABERTA
    assert roles(rec) == [MANTIDO]  # antes: 'anterior' silencioso
    assert env.mgr.view(rec).issue == "versao_anterior"
    out2 = env.mgr.lock(rec.id)
    assert out2.complete and out2.kept_previous
    assert original in kept_contents(env, env.mgr, rec.id, "notas.bin")


class RecreateAfterDelete(NullProgress):
    """No laço 'Apagando…': logo depois de notas.bin sumir, outro programa o recria."""

    def __init__(self, target: Path) -> None:
        self.target = target
        self.phase = ""
        self.done = False

    def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
        self.phase = name

    def advance(self, nbytes: int, nitems: int = 0) -> None:  # type: ignore[override]
        if self.phase.startswith("Apagando") and not self.done and not self.target.exists():
            self.done = True
            self.target.write_bytes(b"autosave de outro programa")


def test_desfazer_com_arquivo_recriado_durante_a_exclusao(env: Env) -> None:
    p = make_folder(env.base)
    original = (p / "notas.bin").read_bytes()
    out = protect(env.mgr, p, progress=RecreateAfterDelete(p / "notas.bin"))
    rec = out.record
    assert rec.state == APAGANDO
    assert any(x.startswith("notas.bin:") for x in rec.pending)

    res = env.mgr.undo_lock(rec.id)

    assert res.complete and roles(rec) == [MANTIDO]
    assert (p / "notas.bin").read_bytes() == b"autosave de outro programa"
    assert env.mgr.lock(rec.id).kept_previous
    assert original in kept_contents(env, env.mgr, rec.id, "notas.bin")


def test_desfazer_depois_de_queda_no_continuar(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    p = make_folder(env.base)
    target = p / "notas.bin"
    original = target.read_bytes()
    stack, sink = _held(target)
    with stack:
        rec = protect(env.mgr, p, progress=sink).record
    assert rec.state == APAGANDO and any(x.startswith("notas.bin:") for x in rec.pending)
    real = winfs.delete_checked

    def delete_then_crash(path: str, expected: Any, *, is_dir: bool = False) -> None:
        real(path, expected, is_dir=is_dir)
        if path.endswith("notas.bin"):
            raise Crash  # o processo morre logo depois de apagar notas.bin

    with monkeypatch.context() as m:
        m.setattr(winfs, "delete_checked", delete_then_crash)
        with pytest.raises(Crash):
            env.mgr.continue_lock(rec.id)
    target.write_bytes(b"outra coisa posta no mesmo nome depois da queda")
    mgr = env.reopen()
    r = mgr.session.index.folder(rec.id)
    assert r is not None and r.state == APAGANDO
    assert r.pending == []  # a lista antiga não sobrevive a uma queda
    mgr.reconcile_on_start()

    res = mgr.undo_lock(r.id)

    assert res.complete and roles(r) == [MANTIDO]
    assert mgr.lock(r.id).kept_previous
    assert original in kept_contents(env, mgr, r.id, "notas.bin")


# --- dados-2: divergência no trancamento volta a ABERTA (nada foi apagado) --------------------


@pytest.mark.parametrize("acao", ["apagar", "renomear", "mover_para_fora"])
def test_divergencia_durante_o_trancamento_volta_a_aberta(env: Env, acao: str) -> None:
    p = make_folder(env.base)
    rec = protect(env.mgr, p).record
    env.mgr.unlock(rec.id)
    fora = env.root / "fora"
    fora.mkdir()

    def user() -> None:
        if acao == "apagar":
            os.remove(p / "notas.bin")
        elif acao == "renomear":
            os.rename(p / "notas.bin", p / "notas2.bin")
        else:
            os.rename(p / "notas.bin", fora / "notas.bin")

    with pytest.raises(OwlVaultError, match="nada foi apagado"):
        env.mgr.lock(rec.id, OnStage("Comparando a origem atual", user))

    assert rec.state == ABERTA and roles(rec) == ["anterior"] and rec.attention == ""
    assert MARKER_NAME not in os.listdir(p)
    again = env.reopen().session.index.folder(rec.id)
    assert again is not None and again.state == ABERTA
    after = tree_digest(p)
    out = env.mgr.lock(rec.id, accept_missing=["notas.bin"])  # "Tente de novo" funciona
    assert out.complete and rec.state == TRANCADA
    assert env.mgr.unlock(rec.id).complete
    assert tree_digest(p) == after  # nada ressuscitado nem duplicado


def test_divergencia_ao_proteger_tira_da_lista(env: Env) -> None:
    p = make_folder(env.base)

    def user() -> None:
        os.rename(p / "notas.bin", p / "notas2.bin")

    check = env.mgr.check_protect(str(p))
    with pytest.raises(OwlVaultError, match="nada foi apagado"):
        env.mgr.protect(check, progress=OnStage("Comparando a origem atual", user))
    assert env.mgr.folders == [] and env.reopen().folders == []
    assert (p / "notas2.bin").exists() and not (p / "notas.bin").exists()
    assert staging_dirs(env.base) == []


# --- dados-3: falha ao gravar 'restaurando' -------------------------------------------------


def test_falha_ao_gravar_restaurando_nao_restaura_sem_a_fase(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    rec = protect(env.mgr, p).record
    real_save = env.session.save
    failed: list[int] = []

    def save() -> None:
        if rec.state == RESTAURANDO and not failed:
            failed.append(1)
            raise OSError(32, "perfil em uso por outro processo (simulado)")
        real_save()

    with monkeypatch.context() as m:
        m.setattr(env.session, "save", save)
        with pytest.raises(OSError):
            env.mgr.unlock(rec.id)
    assert rec.state == ABRINDO  # a memória volta (igual ao disco)
    assert os.listdir(p) == []  # nada restaurado sem a fase gravada
    disk = env.reopen().session.index.folder(rec.id)
    assert disk is not None and disk.state == ABRINDO

    real_restore = lockers.restore_vault

    def restore_then_crash(*a: Any, **kw: Any) -> Any:
        real_restore(*a, **kw)
        raise Crash  # queda logo depois de restaurar, antes de gravar 'aberta'

    with monkeypatch.context() as m:
        m.setattr(lockers, "restore_vault", restore_then_crash)
        with pytest.raises(Crash):
            env.mgr.unlock(rec.id)  # 'Continuar abrindo'
    mgr = env.reopen()
    r = mgr.session.index.folder(rec.id)
    assert r is not None and r.state == RESTAURANDO  # a fase chegou ao disco antes
    mgr.reconcile_on_start()
    out = mgr.unlock(r.id)  # antes: "Há item(ns) colocado(s)…" com os próprios arquivos
    assert out.complete and r.state == ABERTA
    assert tree_digest(p) == before


# --- dados-5 / estados-13: 'Continuar trancando' depois de um 'Desfazer' interrompido ---------


def test_continuar_depois_de_queda_no_fim_do_desfazer(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    stack, sink = _held(p / "sub" / "a.txt")
    with stack:
        rec = protect(env.mgr, p, progress=sink).record
    assert rec.state == APAGANDO
    with monkeypatch.context() as m:
        m.setattr(lockers, "remove_restore_marker", _crash)
        with pytest.raises(Crash):
            env.mgr.undo_lock(rec.id)
    mgr = env.reopen()
    r = mgr.session.index.folder(rec.id)
    assert r is not None and r.state == APAGANDO and r.fingerprints
    mgr.reconcile_on_start()

    out = mgr.continue_lock(r.id)  # antes: todos "mudou depois de ser criptografado", em laço

    assert out.complete and r.state == TRANCADA
    assert set(os.listdir(p)) == PLACEHOLDER_NAMES
    assert mgr.unlock(r.id).complete
    assert tree_digest(p) == before


class CrashMidRestore(NullProgress):
    def __init__(self) -> None:
        self.phase = ""
        self.n = 0

    def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
        self.phase = name

    def advance(self, nbytes: int, nitems: int = 0) -> None:  # type: ignore[override]
        if self.phase.startswith("Restaurando") and nitems:
            self.n += 1
            if self.n == 2:
                raise Crash


def test_continuar_depois_de_queda_no_meio_do_desfazer(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    stack, sink = _held(p / "sub" / "a.txt")
    with stack:
        rec = protect(env.mgr, p, progress=sink).record
    with pytest.raises(Crash):
        env.mgr.undo_lock(rec.id, progress=CrashMidRestore())
    mgr = env.reopen()
    r = mgr.session.index.folder(rec.id)
    assert r is not None and r.state == APAGANDO
    mgr.reconcile_on_start()

    out = mgr.continue_lock(r.id)

    assert out.complete and r.state == TRANCADA
    assert mgr.unlock(r.id).complete
    assert tree_digest(p) == before


def test_falha_ao_gravar_o_fim_do_desfazer_deixa_desfazer_de_novo(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A gravação final do 'Desfazer' falha: a memória volta a APAGANDO (o que está no disco)
    e um 2º 'Desfazer', no mesmo processo, termina — antes dizia 'Não há trancamento
    interrompido' com o disco ainda em APAGANDO."""
    p = make_folder(env.base)
    before = tree_digest(p)
    stack, sink = _held(p / "sub" / "a.txt")
    with stack:
        rec = protect(env.mgr, p, progress=sink).record
    assert rec.state == APAGANDO
    real_remove = lockers.remove_restore_marker

    def disco_cheio() -> None:
        raise OSError(28, "Não há espaço suficiente no disco")

    def remove_then_fail(path: str) -> None:
        real_remove(path)
        monkeypatch.setattr(env.mgr, "_save", disco_cheio)

    with monkeypatch.context() as m:
        m.setattr(lockers, "remove_restore_marker", remove_then_fail)
        with pytest.raises(OSError):
            env.mgr.undo_lock(rec.id)
    monkeypatch.undo()
    assert rec.state == APAGANDO and "novo" in roles(rec)
    disk = env.reopen().session.index.folder(rec.id)
    assert disk is not None and disk.state == APAGANDO

    out = env.mgr.undo_lock(rec.id)

    assert out.complete and rec.state == ABERTA
    assert tree_digest(p) == before


def test_continuar_depois_de_desfazer_parcial(env: Env) -> None:
    spec = {"a.txt": b"a" * 100, "z.txt": b"z" * 100, "sub": {"c.txt": b"c" * 100}}
    p = make_folder(env.base, spec=spec)
    before = tree_digest(p)
    rec = protect(env.mgr, p).record
    env.mgr.unlock(rec.id)
    stack, sink = _held(p / "a.txt")
    with stack:
        out = env.mgr.lock(rec.id, sink)
    assert not out.complete and rec.state == APAGANDO
    (p / "sub").write_bytes(b"item do usuario")  # um ARQUIVO onde era a subpasta
    res = env.mgr.undo_lock(rec.id)
    assert not res.complete and rec.state == APAGANDO  # 'sub\\c.txt' não pôde voltar

    out = env.mgr.continue_lock(rec.id)
    assert not out.complete
    assert out.pending == [f"sub: {lockers._NEW_ITEM}"]  # só o item do usuário, nada "mudou"
    assert "NÃO estão guardados" in rec.attention and "Mova" in rec.attention
    (p / "sub").unlink()

    out = env.mgr.continue_lock(rec.id)  # antes: a.txt e z.txt "mudaram" para sempre

    assert out.complete and rec.state == TRANCADA
    assert env.mgr.unlock(rec.id).complete
    assert tree_digest(p) == before


def _crash(*_a: object, **_k: object) -> None:
    raise Crash


# --- estados-2: versão mantida comparada com a pasta, não com um 'anterior' mais velho --------


def test_versao_mantida_depois_de_desfazer_nao_e_coberta_por_cofre_velho(env: Env) -> None:
    original = b"original" * 50
    p = make_folder(env.base, spec={"X.txt": original, "Y.txt": b"y" * 300})
    rec = protect(env.mgr, p).record
    env.mgr.unlock(rec.id)  # o cofre V1 vira 'anterior'
    stack, sink = _held(p / "Y.txt")
    with stack:
        out = env.mgr.lock(rec.id, sink)
    assert not out.complete and not (p / "X.txt").exists()
    (p / "X.txt").write_bytes(b"novo conteudo")  # outro programa recria X
    res = env.mgr.undo_lock(rec.id)
    assert res.complete and roles(rec) == ["anterior", MANTIDO]

    assert env.mgr.kept_only_files(rec.id) == ["X.txt"]  # antes: [] ("0 arquivo(s)")
    view = env.mgr.view(rec)
    assert view.issue == "versao_anterior" and "1 arquivo(s)" in view.attention
    with pytest.raises(StateError):
        env.mgr.delete_kept(rec.id, [])
    assert env.mgr.lock(rec.id).kept_previous
    assert original in kept_contents(env, env.mgr, rec.id, "X.txt")


# --- estados-4: 'Procurar a pasta…' não aceita a cópia trancada no lugar da pasta aberta ------


def test_relocate_de_pasta_aberta_recusa_copia_trancada(env: Env) -> None:
    x = make_folder(env.base, "Fotos", {"um.txt": b"1" * 64, "d": {"dois.txt": b"2" * 64}})
    rec = protect(env.mgr, x).record
    backup = env.base / "Fotos - backup"
    shutil.copytree(x, backup)  # backup comum da pasta trancada (leva o .owlvault)
    env.mgr.unlock(rec.id)
    y = env.base / "Fotos 2026"
    os.rename(x, y)
    old_path = rec.path

    with pytest.raises(StateError, match="cópia trancada"):
        env.mgr.relocate(rec.id, str(backup))

    assert rec.path == old_path and rec.state == ABERTA
    env.mgr.relocate(rec.id, str(y))
    assert winfs.strip_extended(rec.path) == str(y)
    assert env.mgr.view(rec).issue == ""
    assert env.mgr.lock(rec.id).complete


def test_relocate_de_abertura_interrompida_recusa_copia_trancada(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    x = make_folder(env.base, "Fotos", {"um.txt": b"1" * 64, "d": {"dois.txt": b"2" * 64}})
    before = tree_digest(x)
    rec = protect(env.mgr, x).record
    backup = env.base / "Fotos - backup"
    shutil.copytree(x, backup)  # leva o mesmo .owlvault
    with monkeypatch.context() as m:
        m.setattr(LockerManager, "_finish_unlock", _crash)
        with pytest.raises(Crash):
            env.mgr.unlock(rec.id)
    assert rec.state == ABRINDO and os.listdir(x) == []  # o cofre já saiu da pasta
    y = env.base / "Fotos 2026"
    os.rename(x, y)

    with pytest.raises(StateError, match="cópia trancada"):
        env.mgr.relocate(rec.id, str(backup))  # o cofre que a pasta espera já saiu dela

    env.mgr.relocate(rec.id, str(y))
    assert env.mgr.unlock(rec.id).complete  # 'Continuar abrindo'
    assert tree_digest(y) == before
    assert set(os.listdir(backup)) >= {VAULT_DIR}  # a cópia (backup) não foi tocada


# --- estados-5: cofre da área temporária sumiu ou ilegível ------------------------------------


def test_apagando_com_a_area_temporaria_apagada_tem_saida(env: Env) -> None:
    p = make_folder(env.base, spec={"a.txt": b"a" * 100, "b.txt": b"b" * 100})
    rec = protect(env.mgr, p).record
    env.mgr.unlock(rec.id)
    stack, sink = _held(p / "a.txt")
    with stack:
        assert not env.mgr.lock(rec.id, sink).complete
    wipe(env.base / f".owlvault-{rec.id}")
    mgr = env.reopen()
    r = mgr.session.index.folder(rec.id)
    assert r is not None and r.state == APAGANDO
    mgr.reconcile_on_start()

    view = mgr.view(r)
    assert view.issue == COFRE_INACESSIVEL and view.action == "resolver"
    assert "não foi encontrada" in view.attention and f".owlvault-{r.id}" in view.attention
    assert "Tirar da lista" in view.attention
    for action in (mgr.continue_lock, mgr.undo_lock):
        with pytest.raises(StateError, match="não foi encontrada"):  # antes: "cabeçalho ausente"
            action(r.id)
    warning = mgr.forget_warning(r.id)
    assert "parou no meio" in warning and "não foi(ram) encontrada(s)" in warning
    mgr.forget(r.id)  # a saída: tirar da lista (nada é apagado)
    assert mgr.folders == [] and (p / "a.txt").exists()


def test_abrindo_com_a_area_temporaria_apagada_tem_saida(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = make_folder(env.base, spec={"a.txt": b"a" * 100})
    rec = protect(env.mgr, p).record
    with monkeypatch.context() as m:
        m.setattr(LockerManager, "_finish_unlock", _crash)
        with pytest.raises(Crash):
            env.mgr.unlock(rec.id)
    wipe(env.base / f".owlvault-{rec.id}")
    mgr = env.reopen()
    r = mgr.session.index.folder(rec.id)
    assert r is not None and r.state == ABRINDO
    mgr.reconcile_on_start()

    view = mgr.view(r)
    assert view.issue == COFRE_INACESSIVEL
    assert "não dá para continuar abrindo" in view.attention
    with pytest.raises(StateError, match="não foi encontrada"):
        mgr.unlock(r.id)
    assert "não voltaram" in mgr.forget_warning(r.id)


def test_abertura_com_item_colocado_mostra_o_problema_na_linha(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = make_folder(env.base, spec={"a.txt": b"a" * 100})
    rec = protect(env.mgr, p).record
    with monkeypatch.context() as m:
        m.setattr(LockerManager, "_finish_unlock", _crash)
        with pytest.raises(Crash):
            env.mgr.unlock(rec.id)
    (p / "intruso.txt").write_bytes(b"x")
    with pytest.raises(StateError, match="intruso"):
        env.mgr.unlock(rec.id)  # 'Continuar abrindo'

    view = env.mgr.view(rec)  # antes: "Clique em 'Continuar abrindo'" (que falha de novo)
    assert view.issue == ABRINDO and "intruso.txt" in view.attention and "Mova-os" in view.attention
    (p / "intruso.txt").unlink()
    assert env.mgr.unlock(rec.id).complete and rec.attention == ""


def test_abertura_incompleta_com_cofre_sumido_continua_com_saida(env: Env) -> None:
    p = make_folder(env.base)
    rec = protect(env.mgr, p).record
    blobs = sorted((p / VAULT_DIR / "data").rglob("*.owlb"))
    with open(blobs[0], "r+b") as fh:
        fh.truncate(10)
    assert not env.mgr.unlock(rec.id).complete and rec.state == ABERTURA_INCOMPLETA
    wipe(env.base / f".owlvault-{rec.id}")

    view = env.mgr.view(rec)
    assert view.issue == ABERTURA_INCOMPLETA and "Continuar sem eles" in view.attention
    with pytest.raises(StateError, match="não foi encontrada"):
        env.mgr.unlock(rec.id)  # 'Tentar de novo'
    env.mgr.accept_incomplete_unlock(rec.id)  # 'Continuar sem eles' segue funcionando
    assert rec.state == ABERTA


def _trancando_ilegivel(
    env: Env, monkeypatch: pytest.MonkeyPatch, p: Path
) -> tuple[LockerManager, FolderRecord]:
    """Pasta em TRANCANDO (queda durante o trancamento) com o cabeçalho do 'novo' danificado."""
    rec = protect(env.mgr, p).record
    env.mgr.unlock(rec.id)
    real = LockerManager._vault_id_of

    def crash_on_novo(vault_dir: str) -> str:
        if "novo-" in vault_dir:
            raise Crash
        return real(vault_dir)

    with monkeypatch.context() as m:
        m.setattr(LockerManager, "_vault_id_of", staticmethod(crash_on_novo))
        with pytest.raises(Crash):
            env.mgr.lock(rec.id)
    novo = rec.vault("novo")
    assert novo is not None
    for n in ("vault.owl", "vault.owl.bak"):  # cabeçalho danificado
        f = Path(winfs.strip_extended(novo.location)) / n
        if f.exists():
            with open(f, "r+b") as fh:
                fh.seek(40)
                fh.write(b"\x00" * 16)
    mgr = env.reopen()
    r = mgr.session.index.folder(rec.id)
    assert r is not None and r.state == TRANCANDO
    return mgr, r


def test_trancando_com_cofre_novo_ilegivel_explica_a_saida(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = make_folder(env.base, spec={"a.txt": b"a" * 100, "b.txt": b"b" * 100})
    before = tree_digest(p)
    mgr, r = _trancando_ilegivel(env, monkeypatch, p)

    notes = mgr.reconcile_on_start()

    assert len(notes) == 1 and "foi mantida" in notes[0]
    view = mgr.view(r)
    assert view.issue == TRANCANDO and "Tirar da lista" in view.attention
    assert "pasta oculta" in view.attention
    warning = mgr.forget_warning(r.id)
    assert "continuam lá" in warning and "NÃO aparece" in warning
    assert tree_digest(p) == before


def test_deixar_a_pasta_aberta_depois_de_trancamento_ilegivel(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = make_folder(env.base, spec={"a.txt": b"a" * 100, "b.txt": b"b" * 100})
    before = tree_digest(p)
    mgr, r = _trancando_ilegivel(env, monkeypatch, p)
    mgr.reconcile_on_start()
    assert r.state == TRANCANDO  # antes: preso aqui para sempre (nem trancar, nem abrir)

    assert mgr.leave_open(r.id) == ABERTA

    assert r.state == ABERTA and roles(r) == ["anterior", MANTIDO]  # nada apagado
    again = env.reopen().session.index.folder(r.id)
    assert again is not None and again.state == ABERTA
    assert mgr.view(r).issue == "versao_anterior_ilegivel"  # a cópia em dúvida não some
    assert tree_digest(p) == before
    out = mgr.lock(r.id)  # a pasta volta a poder ser trancada
    assert out.complete and r.state == TRANCADA and MANTIDO in roles(r)
    assert mgr.unlock(r.id).complete
    assert tree_digest(p) == before
    with pytest.raises(StateError):
        mgr.leave_open(r.id)  # só vale para um trancamento interrompido


# --- estados-8: uma pasta sem permissão de listar não derruba a lista -------------------------


def test_pasta_sem_permissao_de_listar_nao_esconde_as_outras(env: Env) -> None:
    sid = acl.current_user_sid()
    if sid is None:
        pytest.skip("SID da conta atual indisponível")
    a = make_folder(env.base, "Normal A", {"a.txt": b"a" * 50})
    blocked = make_folder(env.base, "Bloqueada", {"b.txt": b"b" * 50})
    c = make_folder(env.base, "Normal C", {"c.txt": b"c" * 50})
    for f in (a, blocked, c):
        protect(env.mgr, f)
    if icacls(str(blocked), "/deny", f"*{sid}:(RD)") != 0:
        pytest.skip("icacls indisponível")
    try:
        views = env.mgr.views()  # antes: PermissionError e lista inteira escondida
        by_name = {v.record.name: v for v in views}
    finally:
        icacls(str(blocked), "/remove:d", f"*{sid}")
    assert set(by_name) == {"Normal A", "Bloqueada", "Normal C"}
    assert by_name["Normal A"].issue == "" and by_name["Normal C"].issue == ""
    bad = by_name["Bloqueada"]
    assert bad.issue == SEM_ACESSO and bad.action == "resolver"
    assert "\\\\?\\" not in bad.attention and "WinError" not in bad.attention


def test_view_nunca_levanta_erro_de_disco(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    p = make_folder(env.base, spec={"a.txt": b"a"})
    rec = protect(env.mgr, p).record

    def broken(_self: LockerManager, _rec: object) -> str:
        raise OSError(5, "O dispositivo não está pronto", str(p))

    monkeypatch.setattr(LockerManager, "_locked_content_problem", broken)
    view = env.mgr.view(rec)
    assert view.issue == lockers.ERRO_LEITURA and view.action == "resolver"
    assert str(p) not in view.attention


def test_nota_do_inicio_sem_caminho_cru(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    p = make_folder(env.base, spec={"a.txt": b"a"})
    protect(env.mgr, p)

    def denied(_self: LockerManager, _rec: object) -> list[str]:
        raise PermissionError(13, "Acesso negado", str(p / "desktop.ini"))

    monkeypatch.setattr(LockerManager, "_write_placeholder", denied)
    notes = env.mgr.reconcile_on_start()
    assert notes == ["'Particular': Acesso negado"]


# --- estados-9: .owlvault trocado por uma cópia mais velha -----------------------------------


def test_cofre_trocado_por_copia_antiga_e_detectado(env: Env) -> None:
    p = make_folder(env.base, spec={"um.txt": b"1" * 40})
    rec = protect(env.mgr, p).record
    backup = env.root / "bk"
    shutil.copytree(p / VAULT_DIR, backup / VAULT_DIR)
    env.mgr.unlock(rec.id)
    (p / "dois.txt").write_bytes(b"2" * 40)
    assert env.mgr.lock(rec.id).complete
    guardado = env.root / "cofre certo"
    os.rename(p / VAULT_DIR, guardado)
    shutil.copytree(backup / VAULT_DIR, p / VAULT_DIR)  # backup restaurado no lugar
    inner = winfs.join(rec.path, VAULT_DIR)

    view = env.mgr.view(rec)
    assert view.issue == COFRE_DIFERENTE and view.action == "resolver"
    assert view.base_action == ""  # 'Abrir' não aparece no ⋯ (recusaria)
    with pytest.raises(StateError, match="não são os que o Owl Vault guardou"):
        env.mgr.keys_for_vault(inner)  # 'Verificar arquivos' não diz "Tudo certo"
    with pytest.raises(StateError):
        env.mgr.unlock(rec.id)
    assert "Recuperar uma pasta protegida" in env.mgr.forget_warning(rec.id)

    wipe(p / VAULT_DIR)
    os.rename(guardado, p / VAULT_DIR)  # a cópia certa de volta
    assert env.mgr.view(rec).issue == ""
    assert env.mgr.keys_for_vault(inner) is not None


# --- estados-10: pasta escondida que não chega a abrir continua escondida ---------------------


def test_pasta_escondida_que_nao_abre_continua_escondida(env: Env) -> None:
    p = make_folder(env.base, spec={"um.txt": b"1" * 40})
    before = tree_digest(p)
    rec = protect(env.mgr, p).record
    env.mgr.hide(rec.id)
    staging = env.base / f".owlvault-{rec.id}"
    staging.write_bytes(b"x")  # um ARQUIVO com o nome da área temporária

    with pytest.raises(UnsafePathError, match="arquivo chamado"):
        env.mgr.unlock(rec.id)

    assert rec.state == TRANCADA and rec.hidden
    assert attrs(p) & HIDE == HIDE
    again = env.reopen().session.index.folder(rec.id)
    assert again is not None and again.hidden and again.state == TRANCADA
    assert env.mgr.view(rec).label == "Escondida"
    staging.unlink()
    assert env.mgr.unlock(rec.id).complete
    assert not attrs(p) & HIDDEN and not rec.hidden
    assert tree_digest(p) == before


# --- estados-14: pasta escondida cuja pasta-mãe foi renomeada ---------------------------------


def test_procurar_pasta_escondida_pela_pasta_mae(env: Env) -> None:
    mae = env.base / "Mãe"
    mae.mkdir()
    p = make_folder(mae, "Escondida", {"um.txt": b"1" * 40})
    before = tree_digest(p)
    rec = protect(env.mgr, p).record
    env.mgr.hide(rec.id)
    nova = env.base / "Mãe renomeada"
    os.rename(mae, nova)
    view = env.mgr.view(rec)
    assert view.issue == "nao_encontrada" and "escondida" in view.attention

    env.mgr.relocate(rec.id, str(nova))  # o seletor só mostra a pasta-mãe

    assert winfs.strip_extended(rec.path) == str(nova / "Escondida")
    assert env.mgr.view(rec).label == "Escondida"
    assert attrs(nova / "Escondida") & HIDE == HIDE  # continua oculta E de sistema
    env.reopen().reconcile_on_start()  # refazer o espaço reservado não a mostra de novo
    assert attrs(nova / "Escondida") & HIDE == HIDE
    assert env.mgr.unlock(rec.id).complete
    assert tree_digest(nova / "Escondida") == before


def test_procurar_pela_pasta_mae_prefere_a_mesma_pasta_ao_backup(env: Env) -> None:
    mae = env.base / "Mãe"
    mae.mkdir()
    p = make_folder(mae, "Particular", {"um.txt": b"1" * 40})
    rec = protect(env.mgr, p).record
    shutil.copytree(p, mae / "Particular - backup")  # mesmo cofre, outra pasta
    env.mgr.hide(rec.id)
    nova = env.base / "Mãe renomeada"
    os.rename(mae, nova)

    env.mgr.relocate(rec.id, str(nova))

    assert winfs.strip_extended(rec.path) == str(nova / "Particular")  # pela identidade
    outra = make_folder(env.base, "Outra", {"x.txt": b"x"})
    protect(env.mgr, outra)
    with pytest.raises(StateError, match="mesma"):
        env.mgr.relocate(rec.id, str(outra))  # outra pasta protegida: recusada
    assert winfs.strip_extended(rec.path) == str(nova / "Particular")


# --- fluxos-6: item novo posto durante o trancamento --------------------------------------------


def test_item_novo_durante_o_trancamento_tem_texto_proprio(env: Env) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    intruso = p / "Planilha nova.xlsx"
    aninhado = p / "sub" / "fundo" / "rascunho.txt"

    def drop() -> None:
        intruso.write_bytes(b"novo")
        aninhado.write_bytes(b"novo aninhado")

    out = protect(env.mgr, p, progress=OnStage("Apagando", drop))
    rec = out.record

    assert not out.complete and rec.state == APAGANDO
    assert sorted(x.split(":", 1)[0] for x in out.pending) == [
        "Planilha nova.xlsx",
        "sub\\fundo\\rascunho.txt",
    ]
    att = rec.attention
    assert "NÃO estão guardados" in att and "Mova-os" in att and "Planilha nova.xlsx" in att
    assert "Feche-os" not in att  # nada estava aberto
    assert env.mgr.view(rec).attention == att
    assert not env.mgr.continue_lock(rec.id).complete  # o item continua lá: mesma pendência
    moved = env.root / "movidos"
    moved.mkdir()
    os.rename(intruso, moved / intruso.name)
    os.rename(aninhado, moved / aninhado.name)

    assert env.mgr.continue_lock(rec.id).complete
    assert env.mgr.unlock(rec.id).complete
    assert tree_digest(p) == before


def test_textos_de_pendencia_separam_em_uso_e_alterado(env: Env) -> None:
    p = make_folder(env.base)
    target = p / "notas.bin"

    def rewrite() -> None:
        target.write_bytes(b"conteudo novo, gravado depois da cifragem")

    with contextlib.ExitStack() as stack:

        def hold_and_rewrite() -> None:
            stack.enter_context(open(p / "relatório.txt", "rb"))
            rewrite()

        rec = protect(env.mgr, p, progress=OnStage("Apagando", hold_and_rewrite)).record
        att = rec.attention
    assert "Feche-os" in att and "relatório.txt" in att  # em uso
    assert "A versão nova deles NÃO está guardada" in att and "notas.bin" in att  # mudou
    assert "item novo" not in att


# --- estados-3 / fluxos-7: aviso de 'Tirar da lista' verdadeiro em todo estado ----------------


def test_aviso_de_tirar_da_lista_em_cada_estado(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    p = make_folder(env.base)
    rec = protect(env.mgr, p).record
    assert env.mgr.forget_warning(rec.id) == ""  # trancada com tudo dentro: 'Recuperar' acha

    env.mgr.unlock(rec.id)
    aberta = env.mgr.forget_warning(rec.id)
    assert "legíveis continuam na pasta" in aberta and "NÃO aparece" in aberta

    stack, sink = _held(p / "notas.bin")
    with stack:
        env.mgr.lock(rec.id, sink)
    assert rec.state == APAGANDO
    apagando = env.mgr.forget_warning(rec.id)
    assert "legíveis continuam" not in apagando
    assert "parou no meio" in apagando and "só existe na cópia criptografada" in apagando
    assert f".owlvault-{rec.id}" in apagando and "NÃO aparece" in apagando
    assert "Abrir uma cópia" in apagando
    assert env.mgr.continue_lock(rec.id).complete

    with monkeypatch.context() as m:
        m.setattr(LockerManager, "_finish_unlock", _crash)
        with pytest.raises(Crash):
            env.mgr.unlock(rec.id)
    assert rec.state == ABRINDO and os.listdir(p) == []
    abrindo = env.mgr.forget_warning(rec.id)
    assert "legíveis continuam" not in abrindo
    assert "não voltaram" in abrindo and "NÃO aparece" in abrindo
    assert env.mgr.unlock(rec.id).complete

    assert rec.state == ABERTA and env.mgr.lock(rec.id).complete
    with monkeypatch.context() as m:
        m.setattr(LockerManager, "_move_vault_out", _crash)
        with pytest.raises(Crash):
            env.mgr.unlock(rec.id)
    assert rec.state == ABRINDO and VAULT_DIR in os.listdir(p)  # o cofre ainda está na pasta
    dentro = env.mgr.forget_warning(rec.id)
    assert "continuam criptografados dentro da pasta" in dentro
    assert "Recuperar uma pasta protegida" in dentro


def test_aviso_de_tirar_da_lista_nunca_vira_recuperar_por_erro_de_disco(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = make_folder(env.base, spec={"um.txt": b"1"})
    rec = protect(env.mgr, p).record

    def broken(_self: LockerManager, _rec: object) -> bool:
        raise OSError(21, "O dispositivo não está pronto", str(p))

    monkeypatch.setattr(LockerManager, "_inner_differs", broken)
    warning = env.mgr.forget_warning(rec.id)  # antes: o erro subia e a janela dizia "Recuperar"
    assert warning != "" and "NÃO aparecem" in warning and str(p) not in warning


def test_aviso_de_tirar_da_lista_sem_os_dados_na_pasta(env: Env) -> None:
    p = make_folder(env.base, spec={"um.txt": b"1"})
    rec = protect(env.mgr, p).record
    os.rename(p / VAULT_DIR, env.root / "cofre movido")
    assert env.mgr.view(rec).issue == "sem_dados"
    warning = env.mgr.forget_warning(rec.id)  # antes: "" ⇒ "use Recuperar" (que não acharia)
    assert "não estão na pasta" in warning and "coloque-a de volta" in warning


def test_aviso_de_tirar_da_lista_com_versao_mantida(env: Env) -> None:
    p = make_folder(env.base)
    rec = protect(env.mgr, p).record
    env.mgr.unlock(rec.id)
    os.remove(p / "Fotos de família" / "praia.jpg")  # a foto fica só na versão mantida
    assert env.mgr.lock(rec.id).kept_previous
    warning = env.mgr.forget_warning(rec.id)
    assert "versão anterior mantida só existem lá" in warning
    assert "Recuperar uma pasta protegida" in warning


# --- vd2-1: falha ao gravar o perfil num trancamento que não apagou nada ----------------------


def _no_new_vault(env: Env, folder_id: str) -> bool:
    """A área temporária da pasta não guarda nenhum cofre 'novo' (só o 'anterior', se houver)."""
    staging = env.base / f".owlvault-{folder_id}"
    return not staging.exists() or not any(n.startswith("novo-") for n in os.listdir(staging))


class _SaveFailsOnce:
    """``session.save`` que falha UMA vez depois de armado (perfil travado, disco cheio)."""

    def __init__(self, session: Any) -> None:
        self.real = session.save
        self.armed = False
        self.fired = 0

    def __call__(self) -> None:
        if self.armed:
            self.armed = False
            self.fired += 1
            raise OSError(32, "perfil em uso por outro processo (simulado)")
        self.real()


@pytest.mark.parametrize("acao", ["renomear", "apagar"])
@pytest.mark.parametrize("primeira", [True, False])
def test_divergencia_com_falha_ao_gravar_volta_a_aberta(
    env: Env, monkeypatch: pytest.MonkeyPatch, acao: str, primeira: bool
) -> None:
    p = make_folder(env.base)
    rid = ""
    if not primeira:
        rid = protect(env.mgr, p).record.id
        assert env.mgr.unlock(rid).complete
    save = _SaveFailsOnce(env.session)

    def user() -> None:
        if acao == "renomear":
            os.rename(p / "notas.bin", p / "notas2.bin")
        else:
            os.remove(p / "notas.bin")
        save.armed = True  # a próxima gravação do perfil (a do descarte do 'novo') falha

    sink = OnStage("Teste de restauração", user)
    with monkeypatch.context() as m:
        m.setattr(env.session, "save", save)
        with pytest.raises(OwlVaultError, match="nada foi apagado"):
            if primeira:
                env.mgr.protect(env.mgr.check_protect(str(p)), sink)
            else:
                env.mgr.lock(rid, sink)
    assert save.fired == 1
    after = tree_digest(p)
    if primeira:
        assert env.mgr.folders == [] and env.reopen().folders == []  # antes: TRANCANDO
        assert staging_dirs(env.base) == []
        out = protect(env.mgr, p)  # "Tente de novo"
        assert out.complete and env.mgr.unlock(out.record.id).complete
        assert tree_digest(p) == after
        return
    rec = env.mgr.session.index.folder(rid)
    assert rec is not None
    assert rec.state == ABERTA and roles(rec) == ["anterior"]  # antes: TRANCANDO com 'novo'
    assert _no_new_vault(env, rid)
    notes = env.mgr.reconcile_on_start()  # o 'Resolver' da janela
    assert rec.state == ABERTA and not any("começar a apagar" in n for n in notes)
    disk = env.reopen().session.index.folder(rid)
    assert disk is not None and disk.state == ABERTA
    out = env.mgr.lock(rid, accept_missing=["notas.bin"])  # antes: "Só uma pasta aberta…"
    assert out.complete and rec.state == TRANCADA
    assert env.mgr.unlock(rid).complete
    assert tree_digest(p) == after  # nada ressuscitado nem duplicado


@pytest.mark.parametrize("primeira", [True, False])
def test_falha_ao_gravar_trancando_deixa_tentar_de_novo(
    env: Env, monkeypatch: pytest.MonkeyPatch, primeira: bool
) -> None:
    p = make_folder(env.base)
    before = tree_digest(p)
    rid = ""
    if not primeira:
        rid = protect(env.mgr, p).record.id
        assert env.mgr.unlock(rid).complete
    real = env.session.save
    failed: list[int] = []

    def save() -> None:
        if not failed and any(r.state == TRANCANDO for r in env.mgr.folders):
            failed.append(1)
            raise OSError(28, "Não há espaço suficiente no disco (simulado)")
        real()

    with monkeypatch.context() as m:
        m.setattr(env.session, "save", save)
        with pytest.raises(OSError):
            if primeira:
                protect(env.mgr, p)
            else:
                env.mgr.lock(rid)
    assert failed and tree_digest(p) == before
    if primeira:
        assert env.mgr.folders == [] and env.reopen().folders == []  # antes: TRANCANDO
        assert staging_dirs(env.base) == []
        out = protect(env.mgr, p)
    else:
        rec = env.mgr.session.index.folder(rid)
        assert rec is not None and rec.state == ABERTA and roles(rec) == ["anterior"]
        assert _no_new_vault(env, rid)
        out = env.mgr.lock(rid)  # antes: "Só uma pasta aberta pode ser trancada."
    assert out.complete and out.record.state == TRANCADA
    assert env.mgr.unlock(out.record.id).complete
    assert tree_digest(p) == before


# --- vd2-2: queda REAL no meio do 'Desfazer' deixa um temporário '.part' na pasta -------------

_UNDO_SPEC: dict[str, Any] = {
    "a.txt": b"A" * 300,
    "b.txt": b"B" * 200,
    "notas.bin": bytes(range(256)) * 3,
    "sub": {"c.txt": b"C" * 120, "d.txt": b"D" * 90},
}


def _undo_dies_mid_file(
    env: Env, monkeypatch: pytest.MonkeyPatch, nth: int
) -> tuple[Path, str, dict[str, Any]]:
    """Tranca (parando em 'apagando' com b.txt aberto) e derruba o 'Desfazer' no meio do
    ``nth``-ésimo arquivo decifrado: numa queda de verdade o 'apagar ao fechar' do ``.part``
    nunca roda. Devolve a pasta, o id e o conteúdo original da pasta."""
    p = make_folder(env.base, spec=_UNDO_SPEC)
    before = tree_digest(p)
    stack, sink = _held(p / "b.txt")
    with stack:
        rec = protect(env.mgr, p, progress=sink).record
    assert rec.state == APAGANDO
    dead = [False]
    real_mark = winfs.Win32File.mark_delete

    def mark_delete(self: winfs.Win32File) -> None:
        if dead[0]:
            raise Crash  # o processo já morreu
        real_mark(self)

    def die() -> BaseException:
        dead[0] = True
        return Crash()

    with monkeypatch.context() as m:
        m.setattr(winfs.Win32File, "mark_delete", mark_delete)
        faults.fail_at("restore.write", nth, die)
        try:
            with pytest.raises(Crash):
                env.mgr.undo_lock(rec.id)
        finally:
            faults.reset()
    assert list(p.rglob("*.part"))  # sobrou um pedaço já decifrado na pasta
    return p, rec.id, before


@pytest.mark.parametrize("nth", [1, 3])  # o pedaço na raiz da pasta / numa subpasta
def test_continuar_depois_de_queda_real_no_desfazer_apaga_o_pedaco(
    env: Env, monkeypatch: pytest.MonkeyPatch, nth: int
) -> None:
    p, rid, before = _undo_dies_mid_file(env, monkeypatch, nth)
    mgr = env.reopen()
    rec = mgr.session.index.folder(rid)
    assert rec is not None and rec.state == APAGANDO
    mgr.reconcile_on_start()

    out = mgr.continue_lock(rid)  # antes: ".owl-….part: item novo…", e nunca terminava

    assert out.complete and rec.state == TRANCADA, out.pending
    assert not list(p.rglob("*.part"))
    assert mgr.unlock(rid).complete
    assert tree_digest(p) == before


def test_pedaco_do_desfazer_que_nao_sai_tem_texto_proprio(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    p, rid, _before = _undo_dies_mid_file(env, monkeypatch, 1)
    [part] = list(p.glob("*.part"))
    alheio = p / (".owl-" + "ab" * 16 + "-" + "cd" * 16 + ".part")  # mesmo formato, outro id
    alheio.write_bytes(b"arquivo do usuario com nome parecido")
    mgr = env.reopen()
    rec = mgr.session.index.folder(rid)
    assert rec is not None
    mgr.reconcile_on_start()

    with open(part, "rb"):  # outro programa (antivírus) segura o pedaço
        out = mgr.continue_lock(rid)

    assert not out.complete
    assert sorted(out.pending) == sorted(
        [f"{part.name}: {lockers._UNDO_LEFTOVER}", f"{alheio.name}: {lockers._NEW_ITEM}"]
    )
    assert "'Desfazer' interrompido" in rec.attention and "não mova esses pedaços" in rec.attention
    assert alheio.read_bytes() == b"arquivo do usuario com nome parecido"  # nunca apagado
    alheio.unlink()

    out = mgr.continue_lock(rid)

    assert out.complete and rec.state == TRANCADA and not part.exists()


# --- vd3-1: queda entre o 'novo' COM divergência ficar pronto e a gravação de DESCARTANDO -----

_DIV_SPEC: dict[str, Any] = {
    "a.txt": b"A" * 300,
    "notas.bin": bytes(range(256)) * 3,
    "sub": {"c.txt": b"C" * 120},
}


def _user_touches_notas(p: Path, acao: str, got: dict[str, Any]) -> OnStage:
    """No 'Teste de restauração' o usuário renomeia ou apaga ``notas.bin`` (divergência)."""

    def user() -> None:
        if acao == "renomear":
            os.rename(p / "notas.bin", p / "notas2.bin")
        else:
            os.remove(p / "notas.bin")
        got["depois"] = tree_digest(p)

    return OnStage("Teste de restauração", user)


def _novo_concluido(rec: FolderRecord) -> bool:
    """O 'novo' do trancamento interrompido existe e tem o registro de conclusão gravado."""
    novo = rec.vault("novo")
    return novo is not None and os.path.lexists(winfs.join(novo.location, COMPLETE_NAME))


def _assert_inicio_volta_a_aberta(env: Env, mgr: LockerManager, rec: FolderRecord) -> None:
    """O início descarta o 'novo' com divergência: pasta ABERTA, nada apagado nem trazido."""
    notes = mgr.reconcile_on_start()  # início do app (ou o 'Resolver' da linha)
    assert not any("começar a apagar" in n for n in notes), notes  # antes: APAGANDO (falso)
    assert len(notes) == 1 and "antes de apagar arquivos" in notes[0], notes
    assert rec.state == ABERTA and "novo" not in roles(rec) and rec.attention == ""
    assert _no_new_vault(env, rec.id)
    disk = env.reopen().session.index.folder(rec.id)
    assert disk is not None and disk.state == ABERTA


class _DiesOnDiscardSave:
    """O processo morre (``Crash``) ao gravar o papel DESCARTANDO do 'novo', ANTES de gravar."""

    def __init__(self, env: Env) -> None:
        self.real = env.session.save
        self.mgr = env.mgr
        self.fired = 0

    def __call__(self) -> None:
        if any(v.role == lockers.DESCARTANDO for r in self.mgr.folders for v in r.vaults):
            self.fired += 1
            raise Crash
        self.real()


@pytest.mark.parametrize("acao", ["renomear", "apagar"])
@pytest.mark.parametrize("primeira", [True, False])
def test_queda_antes_de_descartar_novo_com_divergencia_volta_a_aberta(
    env: Env, monkeypatch: pytest.MonkeyPatch, acao: str, primeira: bool
) -> None:
    p = make_folder(env.base, spec=_DIV_SPEC)
    rid = ""
    if not primeira:
        rid = protect(env.mgr, p).record.id
        assert env.mgr.unlock(rid).complete
    got: dict[str, Any] = {}
    sink = _user_touches_notas(p, acao, got)
    save = _DiesOnDiscardSave(env)
    with monkeypatch.context() as m:
        m.setattr(env.session, "save", save)
        with pytest.raises(Crash):
            if primeira:
                env.mgr.protect(env.mgr.check_protect(str(p)), sink)
            else:
                env.mgr.lock(rid, sink)
    assert save.fired == 1
    assert tree_digest(p) == got["depois"]  # nada foi apagado por este trancamento

    mgr = env.reopen()  # o processo morreu: relê o perfil do disco
    [rec] = mgr.folders
    assert rec.state == TRANCANDO and _novo_concluido(rec)
    assert MARKER_NAME not in os.listdir(p)

    _assert_inicio_volta_a_aberta(env, mgr, rec)

    assert tree_digest(p) == got["depois"]
    # "Tente de novo": tranca e abre sem trazer de volta (nem duplicar) notas.bin
    out = mgr.lock(rec.id, accept_missing=[] if primeira else ["notas.bin"])
    assert out.complete and rec.state == TRANCADA
    assert mgr.unlock(rec.id).complete
    assert tree_digest(p) == got["depois"]  # antes: notas.bin e notas2.bin / notas.bin de volta


class _DeadAfterCompletion:
    """Queda FIEL: a ``n``-ésima operação de disco (ponto de falha ou gravação do perfil) depois
    de ``complete.owl`` do 'novo' ser gravado morre, e todas as seguintes também."""

    def __init__(self, n: int, env: Env) -> None:
        self.n = n
        self.real_checkpoint = faults.checkpoint
        self.real_save = env.session.save
        self.after: list[str] = []
        self.armed = False
        self.dead = False

    def _tick(self, op: str) -> None:
        if self.dead:
            raise Crash
        if self.armed:
            self.after.append(op)
            if len(self.after) == self.n:
                self.dead = True
                raise Crash
        elif op == "complete.rename":
            self.armed = True  # o registro de conclusão é renomeado logo depois deste ponto

    def checkpoint(self, op: str) -> None:
        self._tick(op)
        self.real_checkpoint(op)

    def save(self) -> None:
        self._tick("perfil")
        self.real_save()


# 1..5: a limpeza do diário/teste dentro de create_vault; 6: a gravação de DESCARTANDO
@pytest.mark.parametrize("n", range(1, 7))
def test_queda_na_janela_depois_do_novo_com_divergencia(
    env: Env, monkeypatch: pytest.MonkeyPatch, n: int
) -> None:
    p = make_folder(env.base, spec=_DIV_SPEC)
    rid = protect(env.mgr, p).record.id
    assert env.mgr.unlock(rid).complete
    got: dict[str, Any] = {}
    dies = _DeadAfterCompletion(n, env)
    with monkeypatch.context() as m:
        m.setattr(faults, "checkpoint", dies.checkpoint)
        m.setattr(env.session, "save", dies.save)
        with pytest.raises(Crash):
            env.mgr.lock(rid, _user_touches_notas(p, "apagar", got))
    assert dies.dead and dies.after[-1] in ("remove", "perfil"), dies.after
    assert tree_digest(p) == got["depois"]

    mgr = env.reopen()
    rec = mgr.session.index.folder(rid)
    assert rec is not None and rec.state == TRANCANDO and _novo_concluido(rec)

    _assert_inicio_volta_a_aberta(env, mgr, rec)

    assert tree_digest(p) == got["depois"]  # notas.bin continua apagada, como o usuário quis
