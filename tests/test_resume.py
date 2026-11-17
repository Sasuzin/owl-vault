"""Retomada da criação (ARCHITECTURE §4.2) e cancelamento (§3).

TEST_PLAN: "Cancelamento + retomada"; "Retomada: arquivo alterado, removido, adicionado;
blob ausente/truncado; órfão"; "file_id sempre novo em retry/retomada"; "Teste de
restauração: ... limpeza após queda".

Regras verificadas:
* fase ``encrypting``: impressão digital da origem igual E blob íntegro ⇒ mantém; senão ⇒
  cifra de novo com ``file_id`` NOVO (FORMAT §4.3); arquivo removido ⇒ entrada e blob somem;
  arquivo novo ⇒ cifrado; órfãos/temporários que casam o padrão ⇒ apagados; o resto é
  relatado e mantido; segmentos após uma quebra do diário ⇒ removidos;
* fases ``manifest_written``/``verified``/``restore_tested``: apenas etapas 5–7, nunca
  recifra nem reescreve o manifesto;
* um blob existente nunca é aberto para escrita.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from owl_vault.application import create as create_mod
from owl_vault.application.create import CreateResult, inspect_vault_dir, resume_create
from owl_vault.application.progress import CancelToken, RecordingProgress
from owl_vault.application.protection import ProtectedPaths
from owl_vault.application.vault import open_vault, read_manifest
from owl_vault.crypto.kdf import TESTING_POLICY
from owl_vault.domain.errors import CancelledError, OwlVaultError, UnsafePathError
from owl_vault.domain.models import Phase
from owl_vault.storage import faults, winfs
from owl_vault.storage.blob import encrypt_source_to_blob
from owl_vault.storage.journal import read_journal
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

# --------------------------------------------------------------------------------------
# Utilidades (privadas deste módulo)


class Crash(BaseException):
    """Queda simulada (não capturada pelos tratadores de erro comuns)."""


def _crash() -> BaseException:
    return Crash("queda simulada")


@pytest.fixture(autouse=True)
def _deterministic_checkpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sem checkpoint por tempo (5 s): a contagem de segmentos do diário fica determinística."""
    monkeypatch.setattr(create_mod, "_CHECKPOINT_SECONDS", 1e9)


NFILES = 7


def _sample(area: Area) -> None:
    c = SMALL_CHUNK
    write_tree(
        area.src,
        {
            "vazio.txt": b"",
            "pequeno.txt": b"ola mundo",
            "multi.bin": os.urandom(3 * c + 17),
            "exato.bin": os.urandom(2 * c),
            "pasta vazia": {},
            "sub": {"a.txt": b"A" * 100, "mais": {"b.bin": os.urandom(c + 1)}},
            "Ação 日本語 😀.txt": b"acentos e emoji",
        },
    )


def _vext(area: Area, name: str = "cofre") -> str:
    return winfs.to_extended(str(area.vault(name)))


def _resume(area: Area, source: Path | None = None, **kw: Any) -> CreateResult:
    return resume_create(
        str(area.vault()),
        str(source or area.src),
        PASSWORD,
        kdf_policy=TESTING_POLICY,
        protected=ProtectedPaths.none(),
        **kw,
    )


def _blob_paths(area: Area) -> dict[str, Path]:
    data = area.vault() / "data"
    return {p.name[:32]: p for p in data.glob("*/*.owlb")} if data.is_dir() else {}


def _blob_ids(area: Area) -> set[str]:
    return set(_blob_paths(area))


def _journal(area: Area) -> Any:
    opened = open_vault(_vext(area), PASSWORD, TESTING_POLICY)
    return read_journal(opened.layout, opened.master_key, opened.vault_id)


def _journal_ids(area: Area) -> dict[tuple[str, ...], str]:
    return {e.path: e.file_id.hex() for e, _ in _journal(area).files.values()}


def _manifest_ids(area: Area) -> dict[tuple[str, ...], str]:
    opened = open_vault(_vext(area), PASSWORD, TESTING_POLICY)
    return {f.path: f.file_id.hex() for f in read_manifest(opened).manifest.files}


def _sha(p: Path) -> str | None:
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


def _segments(area: Area) -> list[str]:
    j = area.vault() / "journal"
    return sorted(p.name for p in j.iterdir()) if j.is_dir() else []


def _test_dir(area: Area) -> Path:
    found = [p for p in area.testarea.iterdir() if p.name.startswith("OwlVault-teste-")]
    assert len(found) == 1, found
    return found[0]


_DATA_TMP = re.compile(r"\\data\\([0-9a-f]{2})\\([0-9a-f]{32})\.tmp$", re.IGNORECASE)
_WRITE_MASK = winfs.GENERIC_WRITE | 0x2 | 0x4 | 0x10000000  # WRITE_DATA|APPEND_DATA|GENERIC_ALL


class IoSpy:
    """Registra aberturas Win32 com escrita e cada ``file_id`` cifrado com sucesso."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.created: list[str] = []
        self.write_opens: list[str] = []
        self.encrypted: list[str] = []
        orig_open = winfs.Win32File.__dict__["open"].__func__
        spy = self

        def _open(cls: Any, path: str, access: int, share: int, disp: int, flags: int) -> Any:
            if access & _WRITE_MASK:
                spy.write_opens.append(path)
                if disp == winfs.CREATE_NEW:
                    spy.created.append(path)
            return orig_open(cls, path, access, share, disp, flags)

        monkeypatch.setattr(winfs.Win32File, "open", classmethod(_open))
        orig_enc = encrypt_source_to_blob

        def _enc(*a: Any, **k: Any) -> Any:
            res = orig_enc(*a, **k)
            spy.encrypted.append(res.file_id.hex())
            return res

        monkeypatch.setattr(create_mod, "encrypt_source_to_blob", _enc)

    def new_blob_ids(self) -> list[str]:
        out = []
        for p in self.created:
            m = _DATA_TMP.search(p)
            if m:
                assert m.group(2)[:2] == m.group(1).lower(), p
                out.append(m.group(2).lower())
        return out

    def assert_blob_rules(self, seen_before: set[str]) -> None:
        """FORMAT §4.3: nenhum blob existente aberto para escrita; todo file_id é inédito."""
        owlb = [p for p in self.write_opens if p.lower().endswith(".owlb")]
        assert owlb == [], f"blob existente aberto para escrita: {owlb}"
        ids = self.new_blob_ids()
        assert len(ids) == len(set(ids)), "file_id repetido"
        assert not (set(ids) & seen_before), "file_id reutilizado"
        assert set(self.encrypted) <= set(ids)


class Trap(RecordingProgress):
    """Sink de progresso que executa ``action`` numa etapa (``stage``) escolhida.

    ``after == 0``: ao entrar na etapa. Senão: no ``after``-ésimo ``advance`` da etapa que
    conta bytes (``unit="bytes"``) ou itens (``unit="items"``).
    """

    def __init__(
        self, prefix: str, after: int, action: Callable[[], None], unit: str = "bytes"
    ) -> None:
        super().__init__()
        self.prefix = prefix
        self.after = after
        self.action = action
        self.unit = unit
        self.current = ""
        self.hits = 0
        self.fired = False

    def _fire(self) -> None:
        self.fired = True
        self.action()

    def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
        super().stage(name, total_bytes, total_items)
        self.current = name
        if not self.fired and self.after == 0 and name.startswith(self.prefix):
            self._fire()

    def advance(self, nbytes: int = 0, nitems: int = 0) -> None:
        if self.fired or not self.current.startswith(self.prefix):
            return
        if (self.unit == "bytes" and nbytes > 0) or (self.unit == "items" and nitems > 0):
            self.hits += 1
            if self.hits >= self.after:
                self._fire()


def _assert_interrupted(area: Area, before: dict[str, Any]) -> None:
    assert tree_digest(area.src) == before, "a origem foi alterada"
    assert not (area.vault() / "complete.owl").exists()
    assert inspect_vault_dir(str(area.vault())).kind == "vault-incomplete"
    assert list(area.vault().rglob("*.tmp")) == []


def _assert_complete(area: Area, expected_tree: dict[str, Any], result: CreateResult) -> None:
    """Concluído, verificado e restaurado fielmente para ``expected_tree``."""
    assert (area.vault() / "complete.owl").is_file()
    assert not (area.vault() / "journal").exists()
    assert list(area.vault().rglob("*.tmp")) == []
    rep = do_verify(area)
    assert rep.fully_ok, (rep.bad, rep.anomalies, rep.notes, rep.creation_status)
    assert rep.files_ok == result.files
    assert _blob_ids(area) == set(_manifest_ids(area).values())
    rest = do_restore(area)
    assert rest.ok, (rest.failed, rest.conflicts)
    assert tree_digest(area.dest()) == expected_tree


def _all_encrypted_then_crash(area: Area) -> None:
    """Todos os blobs gravados e registrados; queda antes do manifesto (fase encrypting)."""
    faults.fail_at("manifest.write", 1, _crash)
    with pytest.raises(Crash):
        make_vault(area)
    faults.reset()
    assert len(_journal_ids(area)) == NFILES
    assert _journal(area).phase == Phase.ENCRYPTING


# --------------------------------------------------------------------------------------
# Cancelamento


@pytest.mark.parametrize(("unit", "after"), [("bytes", 5), ("items", 2)])
def test_cancel_mid_encryption_then_resume(
    area: Area, monkeypatch: pytest.MonkeyPatch, unit: str, after: int
) -> None:
    _sample(area)
    before = tree_digest(area.src)
    spy = IoSpy(monkeypatch)
    token = CancelToken()
    trap = Trap("Criptografando", after, token.cancel, unit)
    with pytest.raises(CancelledError):
        make_vault(area, cancel=token, progress=trap)
    assert trap.fired
    _assert_interrupted(area, before)
    # o que já foi promovido a .owlb ficou registrado no diário (checkpoint no cancelamento)
    kept = _blob_ids(area)
    assert kept == set(_journal_ids(area).values())
    assert 0 < len(kept) < NFILES if unit == "items" else len(kept) < NFILES
    spy.encrypted.clear()

    result = _resume(area)

    assert result.status == "success", result.divergences
    final = set(_manifest_ids(area).values())
    assert kept <= final, "blobs íntegros e inalterados devem ser mantidos"
    assert len(spy.encrypted) == NFILES - len(kept)
    spy.assert_blob_rules(seen_before=set())
    assert tree_digest(area.src) == before
    _assert_complete(area, before, result)


def test_cancel_during_resume_then_resume_again(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sample(area)
    before = tree_digest(area.src)
    spy = IoSpy(monkeypatch)
    token = CancelToken()
    with pytest.raises(CancelledError):
        make_vault(area, cancel=token, progress=Trap("Criptografando", 1, token.cancel, "items"))
    token2 = CancelToken()
    with pytest.raises(CancelledError):
        _resume(area, cancel=token2, progress=Trap("Criptografando", 2, token2.cancel, "items"))
    _assert_interrupted(area, before)
    kept = _blob_ids(area)
    assert kept == set(_journal_ids(area).values())
    result = _resume(area)
    assert result.status == "success"
    assert kept <= set(_manifest_ids(area).values())
    spy.assert_blob_rules(seen_before=set())
    _assert_complete(area, before, result)


# --------------------------------------------------------------------------------------
# Fases posteriores: nunca recifrar nem reescrever o manifesto


def _raise_crash() -> None:
    raise Crash("queda simulada")


@pytest.mark.parametrize(
    ("prefix", "after", "action", "phase"),
    [
        ("Verificando blocos", 2, "crash", Phase.MANIFEST_WRITTEN),
        ("Teste de restauração", 3, "crash", Phase.VERIFIED),
        ("Teste de restauração", 1, "cancel", Phase.VERIFIED),
        ("Comparando a origem", 0, "crash", Phase.VERIFIED),
        ("Finalizando", 0, "crash", Phase.RESTORE_TESTED),
    ],
    ids=[
        "verify-crash",
        "restoretest-crash",
        "restoretest-cancel",
        "rescan-crash",
        "finalize-crash",
    ],
)
def test_resume_from_later_phase_does_not_reencrypt(
    area: Area,
    monkeypatch: pytest.MonkeyPatch,
    prefix: str,
    after: int,
    action: str,
    phase: Phase,
) -> None:
    _sample(area)
    before = tree_digest(area.src)
    token = CancelToken()
    trap = Trap(prefix, after, token.cancel if action == "cancel" else _raise_crash)
    with pytest.raises(CancelledError if action == "cancel" else Crash):
        make_vault(area, cancel=token, progress=trap)
    assert trap.fired
    _assert_interrupted(area, before)
    assert _journal(area).phase == phase
    manifest_sha = _sha(area.vault() / "manifest.owl")
    assert manifest_sha is not None
    assert _sha(area.vault() / "manifest.owl.bak") == manifest_sha
    blobs = _blob_ids(area)
    assert len(blobs) == NFILES
    spy = IoSpy(monkeypatch)

    result = _resume(area)

    assert result.status == "success", result.divergences
    assert spy.encrypted == [], "a retomada de fase posterior não pode recifrar"
    assert spy.new_blob_ids() == []
    assert _sha(area.vault() / "manifest.owl") == manifest_sha, "manifesto reescrito"
    assert _sha(area.vault() / "manifest.owl.bak") == manifest_sha
    assert _blob_ids(area) == blobs
    assert list(area.testarea.iterdir()) == [], "resíduos do teste de restauração"
    _assert_complete(area, before, result)


def test_cancel_while_verifying_last_file_is_a_cancellation(area: Area) -> None:
    """ARCHITECTURE §3: cancelar entre chunks é um cancelamento (retomável), não uma falha
    de integridade. Com um único arquivo de 4 chunks, o cancelamento cai dentro do último
    (e único) arquivo verificado."""
    area.src.joinpath("unico.bin").write_bytes(os.urandom(4 * SMALL_CHUNK))
    before = tree_digest(area.src)
    token = CancelToken()
    with pytest.raises(CancelledError):
        make_vault(area, cancel=token, progress=Trap("Verificando blocos", 1, token.cancel))
    _assert_interrupted(area, before)
    result = _resume(area)
    assert result.status == "success"
    _assert_complete(area, before, result)


def test_later_phase_with_changed_source_reports_divergence_without_reencrypting(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Origem muda depois de manifest_written: etapas 5–7 apenas ⇒ divergência, sem recifrar."""
    _sample(area)
    before = tree_digest(area.src)
    with pytest.raises(Crash):
        make_vault(area, progress=Trap("Verificando blocos", 1, _raise_crash))
    assert _journal(area).phase == Phase.MANIFEST_WRITTEN
    manifest_sha = _sha(area.vault() / "manifest.owl")
    (area.src / "pequeno.txt").write_bytes(b"conteudo novo, maior que antes")
    spy = IoSpy(monkeypatch)

    result = _resume(area)

    assert spy.encrypted == []
    assert _sha(area.vault() / "manifest.owl") == manifest_sha
    assert result.status == "divergences"
    assert any("pequeno.txt" in d for d in result.divergences), result.divergences
    # o cofre corresponde à origem como estava na cifragem
    rest = do_restore(area)
    assert rest.ok
    assert tree_digest(area.dest()) == before


# --------------------------------------------------------------------------------------
# Fase encrypting: origem alterada, removida, adicionada


def _modify_bigger(src: Path) -> list[tuple[str, ...]]:
    (src / "pequeno.txt").write_bytes(b"agora com outro tamanho")
    return [("pequeno.txt",)]


def _modify_same_size_same_mtime(src: Path) -> list[tuple[str, ...]]:
    """Mesmo tamanho e mesmo LastWriteTime: só o ChangeTime denuncia a alteração."""
    p = src / "exato.bin"
    st = p.stat()
    p.write_bytes(os.urandom(st.st_size))
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert p.stat().st_mtime_ns == st.st_mtime_ns and p.stat().st_size == st.st_size
    return [("exato.bin",)]


def _replace_file(src: Path) -> list[tuple[str, ...]]:
    """Mesmo nome, mesmo conteúdo, arquivo novo (FileId diferente)."""
    p = src / "sub" / "a.txt"
    data = p.read_bytes()
    st = p.stat()
    p.unlink()
    p.write_bytes(data)
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
    return [("sub", "a.txt")]


@pytest.mark.parametrize(
    "change",
    [_modify_bigger, _modify_same_size_same_mtime, _replace_file],
    ids=["content-and-size", "same-size-same-mtime", "replaced-same-content"],
)
def test_resume_reencrypts_changed_file_with_new_file_id(
    area: Area, monkeypatch: pytest.MonkeyPatch, change: Callable[[Path], list[tuple[str, ...]]]
) -> None:
    _sample(area)
    _all_encrypted_then_crash(area)
    old = _journal_ids(area)
    old_blobs = _blob_paths(area)
    changed = change(area.src)
    expected = tree_digest(area.src)
    spy = IoSpy(monkeypatch)

    result = _resume(area)

    assert result.status == "success", result.divergences
    assert result.notes, "a retomada deve informar o que será recifrado"
    new = _manifest_ids(area)
    assert set(new) == set(old)
    for path in changed:
        assert new[path] != old[path], f"{path}: file_id reutilizado para conteúdo alterado"
        assert new[path] not in set(old.values()) | set(old_blobs)
        assert not old_blobs[old[path]].exists(), "blob antigo do arquivo alterado não foi apagado"
    for path in set(old) - set(changed):
        assert new[path] == old[path], f"{path}: arquivo inalterado foi recifrado"
    assert sorted(spy.encrypted) == sorted(new[p] for p in changed)
    spy.assert_blob_rules(seen_before=set(old.values()) | set(old_blobs))
    _assert_complete(area, expected, result)


def test_resume_drops_deleted_file_and_encrypts_added_ones(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sample(area)
    _all_encrypted_then_crash(area)
    old = _journal_ids(area)
    old_blobs = _blob_paths(area)
    gone = ("sub", "mais", "b.bin")
    (area.src / "sub" / "mais" / "b.bin").unlink()
    (area.src / "novo.txt").write_bytes(b"arquivo novo")
    (area.src / "nova pasta").mkdir()
    (area.src / "nova pasta" / "x.bin").write_bytes(os.urandom(SMALL_CHUNK * 2 + 5))
    (area.src / "nova vazia").mkdir()
    expected = tree_digest(area.src)
    spy = IoSpy(monkeypatch)

    result = _resume(area)

    assert result.status == "success", result.divergences
    assert result.notes, "a retomada deve informar os arquivos novos"
    new = _manifest_ids(area)
    assert gone not in new
    assert not old_blobs[old[gone]].exists(), "blob do arquivo removido não foi apagado"
    added = {("novo.txt",), ("nova pasta", "x.bin")}
    assert added <= set(new)
    for p in set(old) - {gone}:
        assert new[p] == old[p]
    assert sorted(spy.encrypted) == sorted(new[p] for p in added)
    spy.assert_blob_rules(seen_before=set(old.values()))
    assert result.files == NFILES - 1 + 2
    _assert_complete(area, expected, result)


# --------------------------------------------------------------------------------------
# Fase encrypting: blob ausente / truncado / estendido / cabeçalho errado


def _damage_missing(p: Path) -> None:
    p.unlink()


def _damage_truncated(p: Path) -> None:
    data = p.read_bytes()
    p.write_bytes(data[: len(data) - 7])


def _damage_header_file_id(p: Path) -> None:
    data = bytearray(p.read_bytes())
    data[32:48] = os.urandom(16)  # file_id do cabeçalho (FORMAT §4.1) não confere
    p.write_bytes(bytes(data))


def _damage_header_vault_id(p: Path) -> None:
    data = bytearray(p.read_bytes())
    data[16:32] = os.urandom(16)  # vault_id de outro cofre
    p.write_bytes(bytes(data))


@pytest.mark.parametrize(
    "damage",
    [_damage_missing, _damage_truncated, _damage_header_file_id, _damage_header_vault_id],
    ids=["missing", "truncated", "wrong-file-id", "wrong-vault-id"],
)
def test_resume_reencrypts_bad_blob_with_new_file_id(
    area: Area, monkeypatch: pytest.MonkeyPatch, damage: Callable[[Path], None]
) -> None:
    _sample(area)
    before = tree_digest(area.src)
    _all_encrypted_then_crash(area)
    old = _journal_ids(area)
    target = ("multi.bin",)
    blob = _blob_paths(area)[old[target]]
    damage(blob)
    spy = IoSpy(monkeypatch)

    result = _resume(area)

    assert result.status == "success", result.divergences
    new = _manifest_ids(area)
    assert new[target] != old[target], "file_id reutilizado após blob ausente/danificado"
    assert new[target] not in set(old.values())
    assert not blob.exists(), "o blob danificado deveria ter sido apagado"
    for p in set(old) - {target}:
        assert new[p] == old[p]
    assert spy.encrypted == [new[target]]
    spy.assert_blob_rules(seen_before=set(old.values()))
    assert tree_digest(area.src) == before
    _assert_complete(area, before, result)


# --------------------------------------------------------------------------------------
# Órfãos, temporários e resíduos


def test_orphan_blobs_after_crash_before_journal_checkpoint(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Queda entre o rename dos blobs e o checkpoint do diário: todos viram órfãos."""
    _sample(area)
    before = tree_digest(area.src)
    spy = IoSpy(monkeypatch)
    faults.fail_at("journal.write", 2, _crash)  # checkpoint final da cifragem
    with pytest.raises(Crash):
        make_vault(area)
    faults.reset()
    _assert_interrupted(area, before)
    orphans = _blob_paths(area)
    assert len(orphans) == NFILES
    assert _journal_ids(area) == {}
    spy.encrypted.clear()

    result = _resume(area)

    assert result.status == "success"
    assert all(not p.exists() for p in orphans.values()), "órfãos não foram apagados"
    final = set(_manifest_ids(area).values())
    assert not (final & set(orphans)), "um órfão foi reaproveitado"
    assert len(spy.encrypted) == NFILES
    spy.assert_blob_rules(seen_before=set())
    _assert_complete(area, before, result)


def test_orphans_created_by_crash_during_resume(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sample(area)
    before = tree_digest(area.src)
    spy = IoSpy(monkeypatch)
    faults.fail_at("blob.rename", 3, _crash)
    with pytest.raises(Crash):
        make_vault(area)
    faults.reset()
    kept = _blob_ids(area)
    faults.fail_at("journal.write", 1, _crash)  # 1º segmento da retomada = checkpoint da cifragem
    with pytest.raises(Crash):
        _resume(area)
    faults.reset()
    orphans = _blob_ids(area) - kept
    assert orphans and kept == set(_journal_ids(area).values())
    result = _resume(area)
    final = set(_manifest_ids(area).values())
    assert kept <= final and not (final & orphans)
    spy.assert_blob_rules(seen_before=set())
    _assert_complete(area, before, result)


def test_resume_cleans_planted_crash_residues(area: Area) -> None:
    """Resíduos de uma queda real (sem o tratamento por handle) são apagados se casam o padrão."""
    _sample(area)
    before = tree_digest(area.src)
    faults.fail_at("blob.rename", 4, _crash)
    with pytest.raises(Crash):
        make_vault(area)
    faults.reset()
    vault = area.vault()
    kept = _blob_ids(area)
    some_blob = next(iter(_blob_paths(area).values()))
    planted: list[Path] = []

    def plant(p: Path, data: bytes) -> None:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        planted.append(p)

    fid = secrets.token_hex(16)
    plant(vault / "data" / fid[:2] / f"{fid}.tmp", os.urandom(200))  # blob parcial
    fid = secrets.token_hex(16)
    plant(vault / "data" / fid[:2] / f"{fid}.owlb", some_blob.read_bytes())  # .owlb órfão
    plant(vault / f"manifest.owl.{secrets.token_hex(16)}.tmp", os.urandom(100))
    plant(vault / f"complete.owl.{secrets.token_hex(16)}.tmp", os.urandom(100))
    plant(vault / f"vault.owl.bak.{secrets.token_hex(16)}.tmp", os.urandom(144))
    plant(vault / f".owlvault-probe-{secrets.token_hex(16)}.tmp", b"probe")
    plant(vault / "journal" / f"{99:016x}.owlj.{secrets.token_hex(16)}.tmp", os.urandom(90))
    test_dir = _test_dir(area)
    plant(test_dir / f"{secrets.token_hex(16)}.chk", b"texto claro restaurado")
    plant(test_dir / f".owl-test-{secrets.token_hex(16)}.part", b"texto claro parcial")

    result = _resume(area)

    assert result.status == "success", result.divergences
    leftover = [p for p in planted if p.exists()]
    assert leftover == [], leftover
    assert kept <= set(_manifest_ids(area).values())
    assert list(area.testarea.iterdir()) == []
    _assert_complete(area, before, result)


def test_unknown_item_in_test_dir_is_kept_and_reported(area: Area) -> None:
    _sample(area)
    before = tree_digest(area.src)
    _all_encrypted_then_crash(area)
    stranger = _test_dir(area) / "anotacoes.txt"
    stranger.write_bytes(b"nao e do Owl Vault")

    result = _resume(area)

    assert result.status == "success"
    assert stranger.read_bytes() == b"nao e do Owl Vault", "item desconhecido foi alterado"
    assert any("anotacoes.txt" in w for w in result.warnings), result.warnings
    rep = do_verify(area)
    assert rep.fully_ok, (rep.bad, rep.anomalies)
    rest = do_restore(area)
    assert rest.ok and tree_digest(area.dest()) == before


@pytest.mark.parametrize("where", ["unknown-name", "wrong-hh"])
def test_unknown_item_in_data_is_kept_and_blocks_completion(area: Area, where: str) -> None:
    """ARCHITECTURE §4.2: só apaga o que casa o padrão na pasta hh correta; o resto é
    relatado e mantido — e o invariante de COMPLETE (data/ == blobs do manifesto) impede
    a conclusão."""
    _sample(area)
    before = tree_digest(area.src)
    _all_encrypted_then_crash(area)
    some = next(iter(_blob_paths(area).values()))
    if where == "unknown-name":
        stranger = some.parent / "leia.txt"
    else:
        fid = secrets.token_hex(16)
        wrong = "00" if fid[:2] != "00" else "01"
        (area.vault() / "data" / wrong).mkdir(exist_ok=True)
        stranger = area.vault() / "data" / wrong / f"{fid}.owlb"
    stranger.write_bytes(b"conteudo estranho")

    with pytest.raises(OwlVaultError):
        _resume(area)

    assert stranger.read_bytes() == b"conteudo estranho"
    assert not (area.vault() / "complete.owl").exists()
    assert tree_digest(area.src) == before


# --------------------------------------------------------------------------------------
# Diário: segmento corrompido ⇒ segmentos posteriores removidos


def test_stale_segments_after_corrupted_segment_are_removed(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(create_mod, "_CHECKPOINT_FILES", 2)
    _sample(area)
    before = tree_digest(area.src)
    _all_encrypted_then_crash(area)
    segs = _segments(area)
    # 0: init; 1..3: 2 arquivos cada; 4: último arquivo (checkpoint final)
    assert segs == [f"{i:016x}.owlj" for i in range(5)], segs
    all_blobs = _blob_ids(area)
    bad = area.vault() / "journal" / segs[2]
    raw = bytearray(bad.read_bytes())
    raw[70] ^= 0x01  # bit no texto cifrado ⇒ não autentica
    bad.write_bytes(bytes(raw))

    st = _journal(area)
    assert st.broken_at == 2
    valid = {e.file_id.hex() for e, _ in st.files.values()}
    assert len(valid) == 2
    lost = all_blobs - valid
    spy = IoSpy(monkeypatch)

    # 1ª retomada cai na primeira cifragem: o estado intermediário fica observável
    faults.fail_at("blob.write", 1, _crash)
    with pytest.raises(Crash):
        _resume(area)
    faults.reset()
    assert _segments(area) == segs[:2], "segmentos após a quebra deveriam ter sido removidos"
    assert _blob_ids(area) == valid, "blobs registrados só em segmentos descartados ficam órfãos"

    result = _resume(area)

    final = set(_manifest_ids(area).values())
    assert valid <= final
    assert not (final & lost), "file_id de segmento descartado reutilizado"
    spy.assert_blob_rules(seen_before=all_blobs)
    _assert_complete(area, before, result)


def test_corrupted_segment_zero_is_incomplete_init(area: Area) -> None:
    _sample(area)
    _all_encrypted_then_crash(area)
    seg0 = area.vault() / "journal" / f"{0:016x}.owlj"
    raw = bytearray(seg0.read_bytes())
    raw[-1] ^= 0x01  # tag
    seg0.write_bytes(bytes(raw))
    names = sorted(str(p.relative_to(area.vault())) for p in area.vault().rglob("*"))
    with pytest.raises(OwlVaultError):
        _resume(area)
    assert not (area.vault() / "complete.owl").exists()
    # nada é apagado automaticamente
    assert sorted(str(p.relative_to(area.vault())) for p in area.vault().rglob("*")) == names


# --------------------------------------------------------------------------------------
# Identidade da origem


@pytest.mark.parametrize("how", ["other-folder", "recreated-folder"])
def test_resume_refuses_a_different_source(area: Area, how: str) -> None:
    _sample(area)
    before = tree_digest(area.src)
    faults.fail_at("blob.rename", 3, _crash)
    with pytest.raises(Crash):
        make_vault(area)
    faults.reset()
    blobs = _blob_ids(area)
    segs = _segments(area)
    if how == "other-folder":
        other = area.root / "copia"
        shutil.copytree(area.src, other)
        with pytest.raises(UnsafePathError):
            _resume(area, source=other)
    else:
        moved = area.root / "origem-antiga"
        area.src.rename(moved)
        shutil.copytree(moved, area.src)  # mesmo caminho, outra pasta (FileId diferente)
        with pytest.raises(UnsafePathError):
            _resume(area)
        shutil.rmtree(area.src)
        moved.rename(area.src)
    assert _blob_ids(area) == blobs and _segments(area) == segs, "cofre alterado na recusa"
    result = _resume(area)
    assert result.status == "success"
    assert tree_digest(area.src) == before
    _assert_complete(area, before, result)


# --------------------------------------------------------------------------------------
# complete.owl inválido (ex.: corrompido) não pode travar a retomada para sempre


def test_resume_with_unauthentic_completion_record(area: Area) -> None:
    """FORMAT §5.4/§4.2: complete.owl que não autentica não conta como concluído; a retomada
    refaz as etapas 5–7 e deve conseguir terminar com um registro de conclusão autêntico."""
    _sample(area)
    before = tree_digest(area.src)
    faults.fail_at("complete.write", 1, _crash)
    with pytest.raises(Crash):
        make_vault(area)
    faults.reset()
    (area.vault() / "complete.owl").write_bytes(os.urandom(200))  # registro corrompido
    rep = do_verify(area)
    assert not rep.completed

    result = _resume(area)

    assert result.status == "success"
    rep = do_verify(area)
    assert rep.completed, rep.creation_status
    rest = do_restore(area)
    assert rest.ok and tree_digest(area.dest()) == before
