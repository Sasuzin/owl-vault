"""Criar cofre de ponta a ponta (application/create.py).

Cobre (TEST_PLAN): arquivo alterado/em uso durante a cifragem (mensagem clara + retomada),
trava de escritor único, teste de restauração com divergência de origem (b), falha do
cofre (a) e leitura instável (c), nome/layout genérico do cofre, ``state.json`` sem nomes,
limpeza da pasta de teste, senha mínima e aceite de mídia FAT/exFAT.

Somente pastas temporárias com dados sintéticos.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from owl_vault.application import create as create_mod
from owl_vault.application.common import default_vault_name
from owl_vault.application.create import CreateResult, inspect_vault_dir, resume_create
from owl_vault.application.progress import NullProgress
from owl_vault.application.protection import ProtectedPaths
from owl_vault.crypto.kdf import TESTING_POLICY
from owl_vault.domain.errors import (
    FileInUseError,
    IntegrityError,
    OwlVaultError,
    PreflightError,
    SourceChangedError,
    VaultLockedError,
)
from owl_vault.storage import faults, winfs
from owl_vault.storage.layout import CHK_RE, TEST_DIR_RE, TEST_PART_RE
from tests.conftest import (
    PASSWORD,
    SMALL_CHUNK,
    Area,
    do_restore,
    do_verify,
    make_vault,
    tree_digest,
    write_tree,
)

# Nomes "sensíveis" usados na origem: nunca podem aparecer em claro fora da origem.
_NAMES = [
    "extrato-bancario-2024.csv",
    "diario intimo",
    "capitulo 1.txt",
    "Relatório Médico.pdf",
    "fotos-família",
    "praia.jpg",
    "vazio.txt",
    "pasta-vazia",
]

_STATE_KEYS = {
    "app",
    "format_version",
    "vault_id",
    "phase",
    "files_total",
    "files_done",
    "test_dir_name",
}
_STATE_PHASES = {
    "encrypting",
    "manifest_written",
    "verified",
    "restore_tested",
    "complete",
    "interrupted",
}
_FINAL_VAULT_NAMES = {
    "vault.owl",
    "vault.owl.bak",
    "manifest.owl",
    "manifest.owl.bak",
    "complete.owl",
    "state.json",
    "LEIA-ME.txt",
    "data",
}


class _Crash(BaseException):
    """Queda simulada: atravessa o tratamento normal de erros."""


def _sample(area: Area) -> None:
    write_tree(
        area.src,
        {
            "extrato-bancario-2024.csv": os.urandom(3 * SMALL_CHUNK + 5),
            "diario intimo": {"capitulo 1.txt": b"querido diario " * 300, "pasta-vazia": {}},
            "Relatório Médico.pdf": os.urandom(SMALL_CHUNK),
            "fotos-família": {"praia.jpg": os.urandom(2 * SMALL_CHUNK + 1)},
            "vazio.txt": b"",
        },
    )


def _resume(area: Area, name: str = "cofre", **kw: Any) -> CreateResult:
    return resume_create(
        str(area.vault(name)),
        str(area.src),
        PASSWORD,
        kdf_policy=TESTING_POLICY,
        protected=ProtectedPaths.none(),
        **kw,
    )


def _lock_path(vault: Path) -> str:
    return winfs.join(winfs.to_extended(str(vault)), ".owlvault.lock")


def _encodings(text: str) -> list[bytes]:
    forms = {text.encode("utf-8"), text.encode("utf-16-le")}
    escaped = json.dumps(text)[1:-1].encode("ascii")  # forma \uXXXX (ensure_ascii)
    forms.add(escaped)
    return sorted(forms)


def _assert_no_plain_names(data: bytes, names: list[str]) -> None:
    for name in names:
        for form in _encodings(name):
            assert form not in data, f"nome em claro encontrado: {name!r}"


def _vault_bytes(vault: Path) -> bytes:
    return b"".join(p.read_bytes() for p in vault.rglob("*") if p.is_file())


def _files_under(folder: Path) -> list[Path]:
    return [p for p in folder.rglob("*") if p.is_file()]


def _patch_before_restore_test(
    monkeypatch: pytest.MonkeyPatch, hook: Callable[[], None]
) -> list[bool]:
    """Executa ``hook`` depois da cifragem/verificação e ANTES do teste de restauração."""
    original = create_mod._Session.restore_test
    called: list[bool] = []

    def wrapper(self: Any, opened: Any, mread: Any) -> list[str]:
        hook()
        called.append(True)
        return original(self, opened, mread)

    monkeypatch.setattr(create_mod._Session, "restore_test", wrapper)
    return called


def _shift_mtime(path: Path, seconds: int = -3600) -> None:
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + seconds * 1_000_000_000))


# --------------------------------------------------------------------------------------
# Arquivo alterado / em uso durante a cifragem
# --------------------------------------------------------------------------------------


def test_concurrent_writer_is_denied_while_file_is_being_encrypted(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    """open_source usa FILE_SHARE_READ: outro programa não consegue escrever no meio da leitura."""
    write_tree(
        area.src,
        {"grande.bin": os.urandom(5 * SMALL_CHUNK + 3), "pequeno.txt": b"abc", "vazio.txt": b""},
    )
    before = tree_digest(area.src)
    original = create_mod.encrypt_source_to_blob
    attempts: list[tuple[str, str, object]] = []

    def wrapper(src: winfs.Win32File, before_fp: Any, *args: Any) -> Any:
        on_bytes = args[-1]
        target = src.path
        fired = False

        def spy(n: int) -> None:
            nonlocal fired
            on_bytes(n)
            if fired or not n:
                return
            fired = True  # depois do 1º chunk lido: arquivo está aberto pelo motor
            try:
                with open(target, "ab") as fh:
                    fh.write(b"ESCRITA CONCORRENTE")
                attempts.append((winfs.name_of(target), "python-append", "OPENED"))
            except PermissionError as exc:
                attempts.append((winfs.name_of(target), "python-append", exc.errno))
            try:
                h = winfs.Win32File.open(
                    target,
                    winfs.GENERIC_WRITE,
                    winfs.FILE_SHARE_READ | winfs.FILE_SHARE_WRITE | winfs.FILE_SHARE_DELETE,
                    winfs.OPEN_EXISTING,
                    0,
                )
                h.close()
                attempts.append((winfs.name_of(target), "win32-write", "OPENED"))
            except OSError as exc:
                attempts.append((winfs.name_of(target), "win32-write", winfs.winerror_of(exc)))

        return original(src, before_fp, *args[:-1], spy)

    monkeypatch.setattr(create_mod, "encrypt_source_to_blob", wrapper)
    result = make_vault(area)
    assert result.status == "success", result.divergences
    # uma tentativa de cada tipo por arquivo não vazio, todas negadas
    assert sorted({a[0] for a in attempts}) == ["grande.bin", "pequeno.txt"]
    for name, kind, outcome in attempts:
        assert outcome != "OPENED", (name, kind)
        if kind == "win32-write":
            assert outcome == winfs.ERROR_SHARING_VIOLATION, (name, outcome)
    # a origem não foi alterada e o cofre tem exatamente a versão lida
    assert tree_digest(area.src) == before
    monkeypatch.undo()
    assert do_verify(area).fully_ok
    assert do_restore(area).ok
    assert tree_digest(area.dest()) == before


def test_source_changed_during_read_is_clear_and_resumable(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Metadados alterados no meio da leitura (mtime) ⇒ SourceChangedError clara; retomável."""
    _sample(area)
    target_name = "extrato-bancario-2024.csv"
    original = create_mod.encrypt_source_to_blob
    hits: list[int] = []

    def wrapper(src: winfs.Win32File, before_fp: Any, *args: Any) -> Any:
        if winfs.name_of(src.path) != target_name:
            return original(src, before_fp, *args)
        on_bytes = args[-1]

        def spy(n: int) -> None:
            on_bytes(n)
            if not hits:
                hits.append(n)
                # FILE_WRITE_ATTRIBUTES não é barrado pelo modo de compartilhamento
                _shift_mtime(Path(src.path))

        return original(src, before_fp, *args[:-1], spy)

    monkeypatch.setattr(create_mod, "encrypt_source_to_blob", wrapper)
    with pytest.raises(SourceChangedError) as ei:
        make_vault(area)
    msg = str(ei.value)
    assert hits, "o arquivo alvo não chegou a ser lido"
    assert target_name in msg
    assert "modificado durante a leitura" in msg
    assert "retome" in msg
    vault = area.vault()
    status = inspect_vault_dir(str(vault))
    assert status.kind == "vault-incomplete"
    assert status.phase == "interrupted"
    assert not (vault / "complete.owl").exists()
    # o temporário do blob interrompido foi apagado pelo handle
    assert not [p for p in vault.rglob("*.tmp")]

    monkeypatch.undo()
    before = tree_digest(area.src)
    result = _resume(area)
    assert result.status == "success", result.divergences
    assert result.files == 5
    report = do_verify(area)
    assert report.fully_ok, (report.bad, report.anomalies, report.notes)
    assert do_restore(area).ok
    assert tree_digest(area.dest()) == before


class _WriterAtEncryption(NullProgress):
    """Simula outro programa que abre um arquivo para escrita logo após a pré-verificação."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle: Any = None

    def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
        if name.startswith("Criptografando") and self.handle is None:
            self.handle = open(self.path, "r+b")  # noqa: SIM115 - fechado pelo teste
            self.handle.write(b"versao nova escrita por outro programa")
            self.handle.flush()

    def close(self) -> None:
        if self.handle is not None:
            self.handle.close()


def test_file_in_use_during_encryption_is_clear_and_resumable(area: Area) -> None:
    _sample(area)
    target = area.src / "extrato-bancario-2024.csv"
    sink = _WriterAtEncryption(target)
    try:
        with pytest.raises(FileInUseError) as ei:
            make_vault(area, progress=sink)  # type: ignore[arg-type]
        assert sink.handle is not None
        msg = str(ei.value)
        assert target.name in msg
        assert "em uso" in msg
        status = inspect_vault_dir(str(area.vault()))
        assert status.kind == "vault-incomplete"
        assert status.phase == "interrupted"
        assert not (area.vault() / "complete.owl").exists()
    finally:
        sink.close()
    # o outro programa terminou: a retomada cifra a versão atual
    before = tree_digest(area.src)
    result = _resume(area)
    assert result.status == "success", result.divergences
    assert do_verify(area).fully_ok
    rest = do_restore(area)
    assert rest.ok, (rest.failed, rest.conflicts)
    assert tree_digest(area.dest()) == before
    assert list(area.testarea.iterdir()) == []


# --------------------------------------------------------------------------------------
# Trava de escritor único
# --------------------------------------------------------------------------------------


def test_lock_held_blocks_create(area: Area) -> None:
    _sample(area)
    vault = area.vault()
    vault.mkdir()
    with winfs.ExclusiveLock(_lock_path(vault), "O cofre"):
        with pytest.raises(VaultLockedError):
            make_vault(area)
        assert os.listdir(vault) == [".owlvault.lock"]  # nada foi gravado
    # trava liberada (DELETE_ON_CLOSE) ⇒ segue normalmente
    assert not (vault / ".owlvault.lock").exists()
    assert make_vault(area).status == "success"
    assert do_verify(area).fully_ok


def test_lock_held_blocks_resume_and_verify(area: Area) -> None:
    _sample(area)
    faults.fail_at("blob.write", 2, _Crash)
    with pytest.raises(_Crash):
        make_vault(area)
    faults.reset()
    vault = area.vault()
    assert inspect_vault_dir(str(vault)).kind == "vault-incomplete"
    snapshot = sorted(p.relative_to(vault).as_posix() for p in vault.rglob("*"))
    with winfs.ExclusiveLock(_lock_path(vault), "O cofre"):
        with pytest.raises(VaultLockedError):
            _resume(area)
        with pytest.raises(VaultLockedError):
            do_verify(area)
    after = sorted(p.relative_to(vault).as_posix() for p in vault.rglob("*"))
    assert after == snapshot  # a instância barrada não mexeu em nada
    before = tree_digest(area.src)
    assert _resume(area).status == "success"
    assert do_restore(area).ok
    assert tree_digest(area.dest()) == before


def test_second_instance_is_refused_while_creation_runs(area: Area) -> None:
    _sample(area)
    outcomes: dict[str, str] = {}

    class _SecondInstance(NullProgress):
        def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
            if not name.startswith("Criptografando") or outcomes:
                return
            calls: dict[str, Callable[[], object]] = {
                "resume": lambda: _resume(area),
                "verify": lambda: do_verify(area),
                "create": lambda: make_vault(area),
            }
            for label, fn in calls.items():
                try:
                    fn()
                    outcomes[label] = "ran"
                except VaultLockedError:
                    outcomes[label] = "locked"
                except OwlVaultError as exc:
                    outcomes[label] = type(exc).__name__

    result = make_vault(area, progress=_SecondInstance())  # type: ignore[arg-type]
    assert result.status == "success"
    assert outcomes["resume"] == "locked"
    assert outcomes["verify"] == "locked"
    # uma segunda criação no mesmo cofre é recusada (pasta não vazia / trava)
    assert outcomes["create"] in ("locked", "PreflightError")
    assert do_verify(area).fully_ok


# --------------------------------------------------------------------------------------
# Teste de restauração: divergências de origem (b), falha do cofre (a), leitura instável (c)
# --------------------------------------------------------------------------------------


def _modify_content(area: Area) -> None:
    p = area.src / "Relatório Médico.pdf"
    data = bytearray(p.read_bytes())
    data[0] ^= 0xFF
    p.write_bytes(bytes(data))
    _shift_mtime(p)  # garante impressão digital diferente mesmo com relógio grosso


def _grow_content(area: Area) -> None:
    p = area.src / "fotos-família" / "praia.jpg"
    with open(p, "ab") as fh:
        fh.write(b"mais bytes")
    _shift_mtime(p)


def _add_file(area: Area) -> None:
    (area.src / "diario intimo" / "novo.txt").write_bytes(b"adicionado depois")


def _add_dir(area: Area) -> None:
    (area.src / "album-secreto").mkdir()


def _remove_file(area: Area) -> None:
    (area.src / "vazio.txt").unlink()


def _replace_file(area: Area) -> None:
    p = area.src / "diario intimo" / "capitulo 1.txt"
    data = p.read_bytes()
    p.unlink()
    p.write_bytes(data)  # mesmo conteúdo, outro FileId


def _touch(area: Area) -> None:
    _shift_mtime(area.src / "Relatório Médico.pdf")  # só a data de modificação muda


_DIVERGENCE_CASES: dict[str, tuple[Callable[[Area], None], str, str]] = {
    "conteudo-alterado": (
        _modify_content,
        "Relatório Médico.pdf",
        "alterado na origem após a cifragem",
    ),
    "arquivo-cresceu": (_grow_content, "fotos-família\\praia.jpg", "alterado na origem"),
    "arquivo-adicionado": (
        _add_file,
        "diario intimo\\novo.txt",
        "adicionado na origem após a cifragem",
    ),
    "pasta-adicionada": (_add_dir, "album-secreto", "adicionado na origem após a cifragem"),
    "arquivo-removido": (_remove_file, "vazio.txt", "removido"),
    "arquivo-substituido": (_replace_file, "diario intimo\\capitulo 1.txt", "substituído"),
    # ARCHITECTURE §4.1 passo 6: a nova varredura compara "tipo, tamanho, mtime e FileId";
    # impressão digital diferente ⇒ (b) "origem alterada após a cifragem".
    "so-mtime-alterado": (_touch, "Relatório Médico.pdf", "alterado"),
}


@pytest.mark.parametrize("case", sorted(_DIVERGENCE_CASES))
def test_restore_test_reports_source_divergence(
    area: Area, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    mutate, shown, fragment = _DIVERGENCE_CASES[case]
    _sample(area)
    as_encrypted = tree_digest(area.src)
    called = _patch_before_restore_test(monkeypatch, lambda: mutate(area))
    result = make_vault(area)
    assert called == [True]
    assert result.status == "divergences", f"{case}: esperava divergência, veio {result.status}"
    mine = [d for d in result.divergences if d.split(":", 1)[0] == shown]
    assert mine, result.divergences
    assert any(fragment in d for d in mine), result.divergences
    # nunca "criada e verificada" quando há divergências
    assert "DIVERGÊNCIAS" in result.message
    assert "criada e verificada" not in result.message
    # o cofre foi concluído (com divergências) e corresponde à origem como foi lida
    monkeypatch.undo()
    report = do_verify(area)
    assert report.completed, report.creation_status
    assert report.fully_ok, (report.bad, report.anomalies, report.notes)
    assert "divergência" in report.creation_status
    rest = do_restore(area)
    assert rest.ok, (rest.failed, rest.conflicts)
    assert tree_digest(area.dest()) == as_encrypted
    # pasta de teste removida; divergências só na tela (nunca gravadas no cofre)
    assert list(area.testarea.iterdir()) == []
    _assert_no_plain_names(_vault_bytes(area.vault()), [shown, *_NAMES, "novo.txt"])


def test_restore_test_failure_when_vault_content_is_bad(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(a) restaurado ≠ manifesto ⇒ a criação FALHA e não há complete.owl."""
    _sample(area)

    def corrupt_one_blob() -> None:
        blobs = sorted((area.vault() / "data").rglob("*.owlb"), key=lambda p: p.stat().st_size)
        victim = blobs[-1]
        with open(victim, "r+b") as fh:
            fh.seek(64 + 10)
            b = fh.read(1)
            fh.seek(64 + 10)
            fh.write(bytes([b[0] ^ 0x01]))

    _patch_before_restore_test(monkeypatch, corrupt_one_blob)
    with pytest.raises(IntegrityError) as ei:
        make_vault(area)
    assert "teste de restauração FALHOU" in str(ei.value)
    vault = area.vault()
    assert not (vault / "complete.owl").exists()
    monkeypatch.undo()
    report = do_verify(area)
    assert not report.completed
    assert "NÃO concluída" in report.creation_status
    assert report.bad
    # nenhum texto claro (.chk/.part) ficou na pasta de teste
    assert _files_under(area.testarea) == []


class _FlakyReader:
    """Proxy de handle de origem que devolve um byte trocado (leitura instável)."""

    def __init__(self, inner: winfs.Win32File) -> None:
        self._inner = inner
        self._first = True

    def read(self, size: int) -> bytes:
        data = self._inner.read(size)
        if self._first and data:
            self._first = False
            data = bytes([data[0] ^ 0x01]) + data[1:]
        return data

    def info(self) -> winfs.HandleInfo:
        return self._inner.info()

    def close(self) -> None:
        self._inner.close()

    def __enter__(self) -> _FlakyReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def test_restore_test_unstable_source_read_fails_creation(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(c) impressão digital igual mas hash diferente ⇒ "leitura instável" ⇒ FALHA."""
    _sample(area)
    target = "Relatório Médico.pdf"
    real_open = winfs.open_source
    original = create_mod._Session.restore_test

    def flaky_open(path: str, expected: Any = None) -> tuple[Any, winfs.HandleInfo]:
        f, info = real_open(path, expected)
        if winfs.name_of(path) == target:
            return _FlakyReader(f), info
        return f, info

    def wrapper(self: Any, opened: Any, mread: Any) -> list[str]:
        with monkeypatch.context() as m:
            m.setattr(winfs, "open_source", flaky_open)
            return original(self, opened, mread)

    monkeypatch.setattr(create_mod._Session, "restore_test", wrapper)
    with pytest.raises(IntegrityError) as ei:
        make_vault(area)
    msg = str(ei.value)
    assert "leitura instável" in msg
    assert target in msg
    assert not (area.vault() / "complete.owl").exists()
    assert _files_under(area.testarea) == []


# --------------------------------------------------------------------------------------
# Nome e layout genéricos; state.json sem nomes; pasta de teste
# --------------------------------------------------------------------------------------


def test_default_vault_name_is_generic() -> None:
    name = default_vault_name()
    assert re.fullmatch(r"Cofre-\d{8}-\d{4}", name), name


def test_vault_layout_is_generic_and_has_no_names(area: Area) -> None:
    _sample(area)
    name = default_vault_name()
    result = make_vault(area, name=name)
    assert result.status == "success"
    vault = area.vault(name)
    # layout final: só os nomes do FORMAT §1 (sem journal, sem trava, sem temporários)
    assert set(os.listdir(vault)) == _FINAL_VAULT_NAMES
    assert (vault / "vault.owl").stat().st_size == 144
    assert (vault / "vault.owl").read_bytes() == (vault / "vault.owl.bak").read_bytes()
    assert (vault / "manifest.owl").read_bytes() == (vault / "manifest.owl.bak").read_bytes()
    blobs = [p for p in (vault / "data").rglob("*") if p.is_file()]
    assert len(blobs) == result.files == 5
    for b in blobs:
        assert re.fullmatch(r"[0-9a-f]{32}\.owlb", b.name), b.name
        assert b.parent.name == b.name[:2]
        assert b.parent.parent == vault / "data"
    # nenhum nome nem caminho da origem em claro em nenhum arquivo do cofre
    everything = _vault_bytes(vault)
    _assert_no_plain_names(everything, [*_NAMES, str(area.src)])
    readme = (vault / "LEIA-ME.txt").read_text(encoding="utf-8")
    for n in _NAMES:
        assert n not in readme
    # file_id aleatório: outro cofre da mesma origem tem blobs com nomes diferentes
    make_vault(area, name="outro")
    other = {p.name for p in (area.vault("outro") / "data").rglob("*.owlb")}
    assert other.isdisjoint({b.name for b in blobs})


def _check_state(raw: bytes, forbidden: list[str]) -> dict[str, Any]:
    text = raw.decode("ascii")  # ensure_ascii: nada além de ASCII
    obj = json.loads(text)
    assert isinstance(obj, dict)
    assert set(obj) == _STATE_KEYS, obj
    assert obj["app"] == "Owl Vault"
    assert obj["format_version"] == 1
    assert re.fullmatch(r"[0-9a-f]{32}", obj["vault_id"])
    assert obj["phase"] in _STATE_PHASES
    for k in ("files_total", "files_done"):
        assert type(obj[k]) is int and obj[k] >= 0
    assert TEST_DIR_RE.fullmatch(obj["test_dir_name"]), obj["test_dir_name"]
    for name in forbidden:
        for form in _encodings(name):
            assert form.decode("latin-1") not in text, name
    return obj


class _StateSnapshots(NullProgress):
    def __init__(self, state_path: Path) -> None:
        self.path = state_path
        self.snaps: list[tuple[str, bytes]] = []

    def _grab(self, label: str) -> None:
        try:
            self.snaps.append((label, self.path.read_bytes()))
        except OSError:
            pass

    def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
        self._grab(name)

    def advance(self, nbytes: int = 0, nitems: int = 0) -> None:
        if nitems:
            self._grab("advance")


def test_state_json_never_contains_source_names(area: Area) -> None:
    _sample(area)
    vault = area.vault()
    state = vault / "state.json"
    forbidden = [*_NAMES, str(area.src), area.src.name, "origem"]
    # 1) execução interrompida no meio da cifragem
    faults.fail_at("blob.write", 4, _Crash)
    sink1 = _StateSnapshots(state)
    with pytest.raises(_Crash):
        make_vault(area, progress=sink1)  # type: ignore[arg-type]
    faults.reset()
    obj = _check_state(state.read_bytes(), forbidden)
    assert obj["phase"] == "interrupted"
    # 2) retomada até o fim
    sink2 = _StateSnapshots(state)
    result = _resume(area, progress=sink2)
    assert result.status == "success"
    snaps = sink1.snaps + sink2.snaps
    assert len(snaps) >= 5
    phases = {_check_state(raw, forbidden)["phase"] for _, raw in snaps}
    assert "encrypting" in phases
    final = _check_state(state.read_bytes(), forbidden)
    assert final["phase"] == "complete"
    assert final["files_total"] == final["files_done"] == 5


def test_restore_test_dir_holds_only_anonymous_files_and_is_removed(area: Area) -> None:
    _sample(area)
    seen_dirs: set[str] = set()
    seen_files: set[str] = set()

    class _Watch(NullProgress):
        in_test = False

        def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
            self.in_test = name.startswith("Teste de restauração")

        def advance(self, nbytes: int = 0, nitems: int = 0) -> None:
            if not self.in_test:
                return
            for d in area.testarea.iterdir():
                seen_dirs.add(d.name)
                for f in d.iterdir():
                    seen_files.add(f.name)

    result = make_vault(area, progress=_Watch())  # type: ignore[arg-type]
    assert result.status == "success"
    assert len(seen_dirs) == 1
    assert TEST_DIR_RE.fullmatch(next(iter(seen_dirs)))
    assert seen_files, "nenhum temporário observado durante o teste de restauração"
    for n in seen_files:
        assert CHK_RE.fullmatch(n) or TEST_PART_RE.fullmatch(n), n
    _assert_no_plain_names("|".join(seen_files).encode("utf-8"), _NAMES)
    # ao final a pasta de teste foi removida (e nada ficou na pasta-pai)
    assert list(area.testarea.iterdir()) == []


# --------------------------------------------------------------------------------------
# Senha, aceite FAT/exFAT, pasta de cofre não vazia
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "password",
    ["", "curta", "12345678901", "ççççççççççç", " espaco no inicio", "espaco no fim "],
)
def test_weak_password_rejected_before_anything_is_written(area: Area, password: str) -> None:
    _sample(area)
    with pytest.raises(OwlVaultError) as ei:
        make_vault(area, password=password)
    assert not isinstance(ei.value, PreflightError)
    assert not area.vault().exists()
    assert list(area.testarea.iterdir()) == []
    if len(password) < 12:
        assert "12" in str(ei.value)


def test_twelve_character_password_is_accepted(area: Area) -> None:
    _sample(area)
    pw = "abcdefghijkl"
    assert len(pw) == 12
    assert make_vault(area, password=pw).status == "success"
    assert do_verify(area, password=pw).fully_ok


def _fake_fat_vault_volume(
    monkeypatch: pytest.MonkeyPatch, vault: Path, fs_name: str = "exFAT"
) -> None:
    """Faz o volume do cofre parecer FAT/exFAT (somente para caminhos do cofre)."""
    real = winfs.resolve
    vault_parts = real(str(vault)).parts

    def fake(path: str) -> winfs.Resolved:
        r = real(path)
        if r.parts[: len(vault_parts)] == vault_parts:
            return dataclasses.replace(r, fs_name=fs_name)
        return r

    monkeypatch.setattr(winfs, "resolve", fake)


def test_fat_destination_requires_acknowledgement(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sample(area)
    _fake_fat_vault_volume(monkeypatch, area.vault())
    with pytest.raises(PreflightError) as ei:
        make_vault(area)
    assert "FAT" in str(ei.value)
    assert any("exFAT" in w for w in ei.value.blockers)
    assert not area.vault().exists()  # nada gravado sem o aceite
    result = make_vault(area, fat_acknowledged=True)
    assert result.status == "success"
    assert result.removable_media
    assert "Remover hardware com segurança" in result.message
    assert "Verificar cofre" in result.message
    assert any("exFAT" in w for w in result.warnings)


def test_fat_acknowledgement_also_required_on_resume(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sample(area)
    _fake_fat_vault_volume(monkeypatch, area.vault())
    faults.fail_at("blob.write", 3, _Crash)
    with pytest.raises(_Crash):
        make_vault(area, fat_acknowledged=True)
    faults.reset()
    with pytest.raises(PreflightError):
        _resume(area)
    assert not (area.vault() / "complete.owl").exists()
    result = _resume(area, fat_acknowledged=True)
    assert result.status == "success"
    assert result.removable_media


def test_existing_nonempty_vault_folder_is_refused_untouched(area: Area) -> None:
    _sample(area)
    vault = area.vault()
    vault.mkdir()
    (vault / "meu-arquivo.txt").write_bytes(b"importante")
    with pytest.raises(PreflightError):
        make_vault(area)
    assert os.listdir(vault) == ["meu-arquivo.txt"]
    assert (vault / "meu-arquivo.txt").read_bytes() == b"importante"
    assert list(area.testarea.iterdir()) == []
