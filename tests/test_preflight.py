"""Pré-verificação da criação (preflight), varredura segura da origem e pastas protegidas.

Cobre o TEST_PLAN: symlinks (skip sem privilégio) / junctions (``_winapi.CreateJunction``);
aliases de caminho (8.3, junction); cofre dentro da origem / origem dentro do cofre / pastas
protegidas; arquivo em uso; bloqueio FAT32 > 4 GiB (FS simulado); limites de espaço e de
tamanho do manifesto; regra do volume da pasta de teste.

Regra transversal (ARCHITECTURE §4.1 passo 1, "Preflight (sem escrita)"): toda chamada de
preflight feita aqui passa por :func:`_preflight`, que compara uma listagem completa da área
temporária (tipo, tamanho, mtime, atributos — sem seguir pontos de reparse) antes e depois.

Somente pastas temporárias do pytest com dados sintéticos.
"""

from __future__ import annotations

import _winapi
import ctypes
import dataclasses
import json
import os
import stat as stat_mod
import subprocess
import tempfile
from collections.abc import Callable, Iterator, Sequence
from ctypes import wintypes
from pathlib import Path
from typing import Any

import pytest

from owl_vault.application import preflight as preflight_mod
from owl_vault.application.create import create_vault
from owl_vault.application.preflight import CreatePlan, default_test_parent, preflight_create
from owl_vault.application.progress import CancelToken
from owl_vault.application.protection import (
    ProtectedPaths,
    destination_location_problems,
    source_location_problems,
)
from owl_vault.crypto.kdf import TESTING_PARAMS, TESTING_POLICY
from owl_vault.domain.errors import CancelledError, PreflightError, UnsafePathError
from owl_vault.domain.limits import FAT32_MAX_FILE_SIZE, GIB, MIB
from owl_vault.storage import scan as scan_mod
from owl_vault.storage import winfs
from owl_vault.storage.scan import scan_tree
from tests.conftest import PASSWORD, SMALL_CHUNK, Area, make_vault, write_tree

# --- Win32 auxiliares (instância própria de kernel32: não mexe nos protótipos do motor) ---

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_GetShortPathNameW = _k32.GetShortPathNameW
_GetShortPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
_GetShortPathNameW.restype = wintypes.DWORD
_SetFileAttributesW = _k32.SetFileAttributesW
_SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
_SetFileAttributesW.restype = wintypes.BOOL

_ATTR_HIDDEN = 0x2
_ATTR_SYSTEM = 0x4
_ATTR_ARCHIVE = 0x20
_ATTR_REPARSE_POINT = 0x400
_ATTR_OFFLINE = 0x1000
_ERROR_PRIVILEGE_NOT_HELD = 1314
_MARGIN = 64 * MIB  # margem documentada (ARCHITECTURE §4.1 "Espaço")

_REAL_SCANDIR = os.scandir  # capturado antes de qualquer monkeypatch
_UNSET: Any = object()


# --- helpers ------------------------------------------------------------------------------


def _ext(path: Path | str) -> str:
    return "\\\\?\\" + str(path)


def _snapshot(root: Path) -> dict[str, tuple[int, int, int, int]]:
    """Listagem completa sob ``root`` sem seguir reparse points: caminho → (modo, tamanho, mtime, attrs).

    Os dados vêm de ``os.lstat`` do próprio item (valor autoritativo), não da cópia
    "duplicada" que o NTFS guarda no índice da pasta-pai: essa cópia é atualizada de forma
    preguiçosa (ao fechar um handle da pasta) e mudaria só porque o preflight LISTOU a pasta.
    """
    base = _ext(root)
    st = os.lstat(base)
    out: dict[str, tuple[int, int, int, int]] = {
        "": (st.st_mode, 0, st.st_mtime_ns, st.st_file_attributes)
    }
    stack = [(base, "")]
    while stack:
        folder, rel = stack.pop()
        with _REAL_SCANDIR(folder) as it:
            for entry in it:
                est = os.lstat(entry.path)
                key = f"{rel}\\{entry.name}" if rel else entry.name
                is_dir = stat_mod.S_ISDIR(est.st_mode)
                out[key] = (
                    est.st_mode,
                    0 if is_dir else est.st_size,
                    est.st_mtime_ns,
                    est.st_file_attributes,
                )
                if is_dir and not est.st_file_attributes & _ATTR_REPARSE_POINT:
                    stack.append((entry.path, key))
    return out


def _diff(before: dict[str, Any], after: dict[str, Any]) -> str:
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(k for k in set(before) & set(after) if before[k] != after[k])
    return f"preflight escreveu algo: novos={added} removidos={removed} alterados={changed}"


def _preflight(
    area: Area,
    source: Path | str | None = None,
    vault: Path | str | None = None,
    *,
    test_parent: Any = _UNSET,
    protected: ProtectedPaths | None = None,
    chunk_size: int = SMALL_CHUNK,
    **kw: Any,
) -> CreatePlan:
    """Roda o preflight e garante que NADA foi escrito na área temporária."""
    if test_parent is _UNSET:
        tp: str | None = str(area.testarea)
    else:
        tp = None if test_parent is None else str(test_parent)
    before = _snapshot(area.root)
    plan = preflight_create(
        str(area.src if source is None else source),
        str(area.vault() if vault is None else vault),
        test_parent=tp,
        chunk_size=chunk_size,
        protected=ProtectedPaths.none() if protected is None else protected,
        **kw,
    )
    after = _snapshot(area.root)
    assert after == before, _diff(before, after)
    return plan


def _tree(root: Path, spec: dict[str, Any]) -> Path:
    """``write_tree`` criando a pasta raiz (e as acima) se preciso."""
    root.mkdir(parents=True, exist_ok=True)
    write_tree(root, spec)
    return root


def _has(messages: Sequence[str], *needles: str) -> bool:
    """Alguma mensagem contém TODOS os trechos."""
    return any(all(n in m for n in needles) for m in messages)


def _short(path: Path) -> str:
    """Alias 8.3 do caminho (GetShortPathNameW); skip se o volume não gera nomes curtos."""
    buf = ctypes.create_unicode_buffer(32768)
    n = _GetShortPathNameW(str(path), buf, len(buf))
    if n == 0 or n >= len(buf):
        raise ctypes.WinError(ctypes.get_last_error())
    short = buf.value
    if winfs.name_of(short).lower() == path.name.lower():
        pytest.skip("o volume não gera nomes curtos 8.3 (8dot3name desativado)")
    assert short.lower() != str(path).lower()
    return short


def _set_attrs(path: Path, attrs: int) -> None:
    if not _SetFileAttributesW(str(path), attrs):
        raise ctypes.WinError(ctypes.get_last_error())


def _spec_blob_size(plaintext: int, chunk: int) -> int:
    """FORMAT §4.2: ``64 + P + 16·n`` com ``n = max(1, ceil(P / c))`` (cálculo independente)."""
    n = max(1, -(-plaintext // chunk))
    return 64 + plaintext + 16 * n


def _round_up(value: int, unit: int) -> int:
    return -(-value // unit) * unit


def _max_plaintext_with_blob_at_most(limit: int, chunk: int) -> int:
    lo, hi = 0, limit
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if _spec_blob_size(mid, chunk) <= limit:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _plenty_space(monkeypatch: pytest.MonkeyPatch, cluster: int = 4096) -> None:
    monkeypatch.setattr(
        winfs, "volume_space", lambda d: winfs.VolumeSpace(free_bytes=1 << 50, cluster_size=cluster)
    )


def _fake_vault_fs(monkeypatch: pytest.MonkeyPatch, vault: Path, fs_name: str) -> None:
    """Simula o sistema de arquivos do volume do cofre (só o resultado de resolve do cofre)."""
    real = winfs.resolve
    target = winfs.to_extended(str(vault)).lower()

    def fake(path: str) -> winfs.Resolved:
        res = real(path)
        if winfs.to_extended(path).lower() == target:
            res = dataclasses.replace(res, fs_name=fs_name)
        return res

    monkeypatch.setattr(winfs, "resolve", fake)


def _fake_sizes(monkeypatch: pytest.MonkeyPatch, sizes: dict[str, int]) -> None:
    """Simula o tamanho lido do handle (impressão digital) de arquivos pelo nome."""
    real = winfs.open_source

    def fake(path: str, expected: Any = None) -> Any:
        fh, info = real(path, expected)
        name = winfs.name_of(path)
        if name in sizes:
            info = dataclasses.replace(info, size=sizes[name])
        return fh, info

    monkeypatch.setattr(winfs, "open_source", fake)


def _fake_volume(
    monkeypatch: pytest.MonkeyPatch,
    prefix: Path,
    volume: str = "VOLUME{0BADC0DE-0000-0000-0000-00000000F00D}",
) -> None:
    """Faz ``resolve`` reportar ``prefix`` (e o que estiver abaixo) em outro volume."""
    real = winfs.resolve
    target = winfs.to_extended(str(prefix)).lower()

    def fake(path: str) -> winfs.Resolved:
        res = real(path)
        e = winfs.to_extended(path).lower()
        if e == target or e.startswith(target + "\\"):
            res = dataclasses.replace(res, parts=(volume, *res.parts[1:]))
        return res

    monkeypatch.setattr(winfs, "resolve", fake)


class _Listing:
    def __init__(self, entries: list[Any]) -> None:
        self._entries = entries

    def __enter__(self) -> Iterator[Any]:
        return iter(self._entries)

    def __exit__(self, *exc: object) -> None:
        return None

    def __iter__(self) -> Iterator[Any]:
        return iter(self._entries)


def _patch_scandir(
    monkeypatch: pytest.MonkeyPatch, transform: Callable[[str, list[Any]], list[Any]]
) -> None:
    def fake(path: Any = None) -> _Listing:
        with _REAL_SCANDIR(path) as it:
            entries = list(it)
        return _Listing(transform(str(path), entries))

    monkeypatch.setattr(os, "scandir", fake)


class _RenamedEntry:
    """DirEntry falso: mesmo arquivo real, outro nome (simula colisão de caixa no NTFS)."""

    def __init__(self, real: os.DirEntry[str], name: str) -> None:
        self._real = real
        self.name = name
        self.path = real.path[: len(real.path) - len(real.name)] + name

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        return self._real.stat(follow_symlinks=follow_symlinks)

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        return self._real.is_dir(follow_symlinks=follow_symlinks)

    def is_file(self, *, follow_symlinks: bool = True) -> bool:
        return self._real.is_file(follow_symlinks=follow_symlinks)

    def is_symlink(self) -> bool:
        return self._real.is_symlink()

    def is_junction(self) -> bool:
        return self._real.is_junction()


class _BrokenStatEntry(_RenamedEntry):
    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        raise PermissionError(13, "Acesso negado", self.path)


class _FakeStatEntry(_RenamedEntry):
    """DirEntry real com atributos/tag/modo simulados na listagem (OneDrive, WOF, ...)."""

    def __init__(
        self, real: os.DirEntry[str], *, attrs: int, tag: int = 0, mode: int | None = None
    ) -> None:
        super().__init__(real, real.name)
        self._attrs = attrs
        self._tag = tag
        self._mode = mode

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        base = self._real.stat(follow_symlinks=False)
        seq = list(base[:10])
        if self._mode is not None:
            seq[0] = self._mode
        return os.stat_result(
            seq,
            {
                "st_file_attributes": self._attrs,
                "st_reparse_tag": self._tag,
                "st_atime_ns": base.st_atime_ns,
                "st_mtime_ns": base.st_mtime_ns,
                "st_ctime_ns": base.st_ctime_ns,
            },
        )


class _FsExtras:
    """Cria links/nomes especiais e os remove no teardown (com caminhos estendidos)."""

    def __init__(self) -> None:
        self._items: list[tuple[str, str]] = []

    def junction(self, target: Path, link: Path) -> Path:
        _winapi.CreateJunction(str(target), str(link))
        self._items.append(("rmdir", str(link)))
        return link

    def symlink(self, target: Path, link: Path, *, is_dir: bool) -> Path:
        try:
            os.symlink(str(target), str(link), target_is_directory=is_dir)
        except OSError as exc:
            if getattr(exc, "winerror", None) == _ERROR_PRIVILEGE_NOT_HELD:
                pytest.skip(
                    "sem privilégio para criar link simbólico (WinError 1314): "
                    "ative o Modo de Desenvolvedor ou rode como administrador"
                )
            raise
        self._items.append(("rmdir" if is_dir else "unlink", str(link)))
        return link

    def ext_file(self, folder: Path, name: str, data: bytes = b"x") -> str:
        p = _ext(folder) + "\\" + name
        with open(p, "xb") as fh:
            fh.write(data)
        self._items.append(("unlink", p))
        return p

    def ext_dir(self, folder: Path, name: str) -> str:
        p = _ext(folder) + "\\" + name
        os.mkdir(p)
        self._items.append(("rmdir", p))
        return p

    def close(self) -> None:
        for kind, p in reversed(self._items):
            try:
                if kind == "rmdir":
                    os.rmdir(p)
                else:
                    os.unlink(p)
            except FileNotFoundError:
                pass


@pytest.fixture
def fsx() -> Iterator[_FsExtras]:
    extras = _FsExtras()
    yield extras
    extras.close()


def _sample(area: Area) -> None:
    _tree(
        area.src,
        {
            "a.txt": b"conteudo a",
            "Ação 日本語 😀.txt": b"unicode",
            "vazio.bin": b"",
            "pasta vazia": {},
            "sub": {"b.bin": os.urandom(3 * SMALL_CHUNK + 5), "mais": {"c.txt": b"c" * 100}},
        },
    )


# =========================================================================================
# Plano básico e "nenhuma escrita"
# =========================================================================================


def test_clean_source_plan_ok_and_nothing_written(area: Area) -> None:
    _sample(area)
    plan = _preflight(area)
    assert plan.ok, plan.blockers
    assert {f.path for f in plan.files} == {
        ("a.txt",),
        ("Ação 日本語 😀.txt",),
        ("vazio.bin",),
        ("sub", "b.bin"),
        ("sub", "mais", "c.txt"),
    }
    # toda pasta aparece, inclusive as vazias
    assert {d.path for d in plan.dirs} == {("pasta vazia",), ("sub",), ("sub", "mais")}
    sizes = {f.path: f.fingerprint.size for f in plan.files}
    assert sizes[("sub", "b.bin")] == 3 * SMALL_CHUNK + 5
    assert sizes[("vazio.bin",)] == 0
    assert plan.total_bytes == sum(sizes.values())
    assert plan.largest_file == 3 * SMALL_CHUNK + 5
    assert all(f.links == 1 for f in plan.files)
    assert plan.source_res is not None and plan.source_res.identity is not None
    assert plan.vault_res is not None and not plan.vault_res.exists
    assert plan.manifest_size > 0
    assert plan.estimated_vault_bytes > plan.total_bytes
    assert not plan.needs_fat_ack  # volume de teste é NTFS
    assert _has(plan.warnings, "Não são preservados")
    assert plan.summary_lines()
    # o cofre não foi criado e a pasta de teste continua vazia
    assert not area.vault().exists()
    assert list(area.testarea.iterdir()) == []


def test_empty_source_is_ok(area: Area) -> None:
    plan = _preflight(area)
    assert plan.ok, plan.blockers
    assert plan.files == [] and plan.dirs == []
    assert plan.total_bytes == 0 and plan.largest_file == 0


def test_cancelled_preflight_raises_and_writes_nothing(area: Area) -> None:
    _sample(area)
    token = CancelToken()
    token.cancel()
    before = _snapshot(area.root)
    with pytest.raises(CancelledError):
        preflight_create(
            str(area.src),
            str(area.vault()),
            test_parent=str(area.testarea),
            chunk_size=SMALL_CHUNK,
            protected=ProtectedPaths.none(),
            cancel=token,
        )
    assert _snapshot(area.root) == before


def test_trailing_backslash_and_forward_slashes_are_accepted(area: Area) -> None:
    _sample(area)
    plan = _preflight(area, str(area.src) + "\\", str(area.vault()).replace("\\", "/"))
    assert plan.ok, plan.blockers
    assert len(plan.files) == 5


# =========================================================================================
# winfs.to_extended: caminhos relativos, ponto/espaço final, rede
# =========================================================================================


@pytest.mark.parametrize(
    "path",
    ["origem", "pasta\\sub", ".\\pasta", "..\\pasta", "\\sem\\unidade", "C:pasta", "C:", "", "   "],
)
def test_to_extended_rejects_relative_paths(path: str) -> None:
    with pytest.raises(UnsafePathError):
        winfs.to_extended(path)


@pytest.mark.parametrize("suffix", [".", " ", "..", ". ", " ."])
def test_to_extended_rejects_trailing_dot_or_space(area: Area, suffix: str) -> None:
    with pytest.raises(UnsafePathError, match="ponto ou espaço"):
        winfs.to_extended(str(area.src) + suffix)


@pytest.mark.parametrize(
    "path",
    [
        "\\\\servidor\\compartilhamento\\pasta",
        "//servidor/compartilhamento/pasta",
        "\\\\?\\UNC\\servidor\\compartilhamento\\pasta",
        "\\\\.\\C:\\pasta",
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\pasta",
    ],
)
def test_to_extended_rejects_network_and_device_paths(path: str) -> None:
    with pytest.raises(UnsafePathError):
        winfs.to_extended(path)


def test_to_extended_normalizes_absolute_forms() -> None:
    assert winfs.to_extended("C:/x/y") == "\\\\?\\C:\\x\\y"
    assert winfs.to_extended("C:\\x\\y\\") == "\\\\?\\C:\\x\\y"
    assert winfs.to_extended("C:\\") == "\\\\?\\C:\\"
    assert winfs.to_extended("\\\\?\\C:\\x\\y\\") == "\\\\?\\C:\\x\\y"


@pytest.mark.parametrize("which", ["source", "vault"])
@pytest.mark.parametrize("bad", ["origem", "C:origem", "pasta\\sub"])
def test_relative_source_or_vault_is_blocker(area: Area, which: str, bad: str) -> None:
    _sample(area)
    plan = _preflight(area, source=bad) if which == "source" else _preflight(area, vault=bad)
    assert not plan.ok
    assert _has(plan.blockers, "caminho absoluto"), plan.blockers
    assert plan.files == [] and plan.dirs == []


@pytest.mark.parametrize("suffix", [".", " "])
def test_trailing_dot_source_never_resolves_to_real_folder(area: Area, suffix: str) -> None:
    # "origem." / "origem " seriam silenciosamente trocados pelo Windows por "origem" (que existe)
    _sample(area)
    plan = _preflight(area, source=str(area.src) + suffix)
    assert not plan.ok
    assert _has(plan.blockers, "ponto ou espaço"), plan.blockers
    assert plan.files == []


@pytest.mark.parametrize("suffix", [".", " "])
def test_trailing_dot_vault_is_blocker(area: Area, suffix: str) -> None:
    _sample(area)
    plan = _preflight(area, vault=str(area.vault()) + suffix)
    assert not plan.ok
    assert _has(plan.blockers, "ponto ou espaço"), plan.blockers


@pytest.mark.parametrize("which", ["source", "vault"])
@pytest.mark.parametrize("component", [".", ".."])
def test_extended_path_with_dot_components_is_refused(
    area: Area, which: str, component: str
) -> None:
    # "\\?\" não é normalizado: "." / ".." literais não podem driblar a checagem de sobreposição.
    _sample(area)
    if which == "vault":
        path = _ext(area.vaults) + f"\\{component}\\origem\\cofre"
        plan = _preflight(area, vault=path)
    else:
        path = _ext(area.vaults) + f"\\{component}\\origem"
        plan = _preflight(area, source=path)
    assert not plan.ok, "caminho estendido com '.'/'..' deveria ser recusado"
    assert plan.files == []
    assert not (area.src / "cofre").exists()


@pytest.mark.parametrize(
    "vault_rel",
    ["cofres\\..\\origem\\cofre", "origem.\\cofre", "cofres\\.\\..\\origem\\sub\\cofre"],
)
def test_plain_path_normalization_cannot_hide_overlap(area: Area, vault_rel: str) -> None:
    _sample(area)
    plan = _preflight(area, vault=str(area.root) + "\\" + vault_rel)
    assert not plan.ok
    # "origem.\cofre": o Windows trocaria 'origem.' por 'origem' (outra pasta); desde a
    # revisão de segurança isso é recusado já na normalização do caminho.
    assert _has(plan.blockers, "não pode ficar dentro da origem") or _has(
        plan.blockers, "termina com ponto ou espaço"
    ), plan.blockers


@pytest.mark.parametrize("kind", ["relativo", "relativo_a_unidade", "ponto_final", "espaco_final"])
def test_relative_or_trailing_dot_test_parent_is_refused(area: Area, kind: str) -> None:
    # Aceita as duas formas de recusa: bloqueio no relatório ou UnsafePathError.
    _sample(area)
    bad = {
        "relativo": "teste-relativo",
        "relativo_a_unidade": "C:teste",
        "ponto_final": str(area.testarea) + ".",
        "espaco_final": str(area.testarea) + " ",
    }[kind]
    before = _snapshot(area.root)
    try:
        plan = preflight_create(
            str(area.src),
            str(area.vault()),
            test_parent=bad,
            chunk_size=SMALL_CHUNK,
            protected=ProtectedPaths.none(),
        )
    except UnsafePathError:
        refused = True
    else:
        refused = not plan.ok
    assert refused
    assert _snapshot(area.root) == before


# =========================================================================================
# Origem: inexistente, arquivo, raiz de volume, link
# =========================================================================================


def test_nonexistent_source_is_blocker(area: Area) -> None:
    plan = _preflight(area, source=area.root / "nao-existe" / "nem-isto")
    assert not plan.ok
    assert _has(plan.blockers, "Origem", "não existe"), plan.blockers
    assert plan.files == []


def test_source_that_is_a_file_is_blocker(area: Area) -> None:
    f = area.root / "arquivo.txt"
    f.write_bytes(b"nao sou pasta")
    plan = _preflight(area, source=f)
    assert not plan.ok
    assert _has(plan.blockers, "Origem", "não existe"), plan.blockers


@pytest.mark.parametrize("form", ["plain", "extended"])
def test_volume_root_source_is_blocker(
    area: Area, monkeypatch: pytest.MonkeyPatch, form: str
) -> None:
    # Guardas: mesmo com bug, o teste nunca varre/abre arquivos reais da unidade.
    def no_scan(*a: object, **k: object) -> None:
        raise AssertionError("a raiz do volume não pode ser varrida")

    def no_open(*a: object, **k: object) -> None:
        raise AssertionError("a raiz do volume não pode ter arquivos abertos")

    monkeypatch.setattr(preflight_mod, "scan_tree", no_scan)
    monkeypatch.setattr(winfs, "open_source", no_open)
    drive = os.path.splitdrive(str(area.root))[0]
    root = drive + "\\" if form == "plain" else "\\\\?\\" + drive + "\\"
    plan = _preflight(area, source=root)
    assert not plan.ok
    assert _has(plan.blockers, "raiz de uma unidade"), plan.blockers
    assert plan.files == []


def test_source_itself_junction_is_blocker(area: Area, fsx: _FsExtras) -> None:
    _sample(area)
    alias = fsx.junction(area.src, area.root / "alias-da-origem")
    plan = _preflight(area, source=alias)
    assert not plan.ok
    assert _has(plan.blockers, "Origem", "junction"), plan.blockers
    assert plan.files == []


def test_source_itself_symlink_is_blocker(area: Area, fsx: _FsExtras) -> None:
    _sample(area)
    alias = fsx.symlink(area.src, area.root / "symlink-da-origem", is_dir=True)
    plan = _preflight(area, source=alias)
    assert not plan.ok
    assert _has(plan.blockers, "Origem", "link"), plan.blockers
    assert plan.files == []


# =========================================================================================
# Junctions / symlinks DENTRO da origem: bloqueio e nunca seguidos
# =========================================================================================


def _outside_tree(area: Area) -> Path:
    fora = area.root / "fora"
    _tree(fora, {"segredo.txt": b"NAO PODE ENTRAR NO PLANO", "dentro": {"mais.txt": b"m"}})
    return fora


def test_junction_inside_source_is_blocker_and_never_followed(
    area: Area, fsx: _FsExtras, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(area.src, {"normal.txt": b"ok", "sub": {"b.txt": b"b"}})
    fora = _outside_tree(area)
    fsx.junction(fora, area.src / "atalho")
    fsx.junction(fora / "dentro", area.src / "sub" / "atalho2")

    listed: list[str] = []
    opened: list[str] = []

    def spy_scandir(path: Any = None) -> Any:
        listed.append(winfs.strip_extended(str(path)))
        return _REAL_SCANDIR(path)

    real_open = winfs.open_source

    def spy_open(path: str, expected: Any = None) -> Any:
        opened.append(path)
        return real_open(path, expected)

    monkeypatch.setattr(os, "scandir", spy_scandir)
    monkeypatch.setattr(winfs, "open_source", spy_open)

    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "atalho", "junction"), plan.blockers
    assert _has(plan.blockers, "sub\\atalho2", "junction"), plan.blockers
    # nada de trás da junction entra no plano
    every = {f.path for f in plan.files} | {d.path for d in plan.dirs}
    assert every == {("normal.txt",), ("sub",), ("sub", "b.txt")}
    assert not any("segredo.txt" in f.path or "mais.txt" in f.path for f in plan.files)
    # e a junction nunca foi listada nem teve arquivos abertos através dela
    assert listed, "a varredura deveria ter listado a origem"
    assert not [p for p in listed if "atalho" in p or "\\fora" in p], listed
    assert not [p for p in opened if "atalho" in p or "segredo" in p or "mais.txt" in p], opened


def test_junction_loop_inside_source_is_blocked_once(area: Area, fsx: _FsExtras) -> None:
    write_tree(area.src, {"a.txt": b"a"})
    fsx.junction(area.src, area.src / "laco")
    plan = _preflight(area)
    assert not plan.ok
    assert [b for b in plan.blockers if "laco" in b] == [
        next(b for b in plan.blockers if "laco" in b)
    ]
    assert {f.path for f in plan.files} == {("a.txt",)}
    assert plan.dirs == []


def test_dangling_junction_inside_source_is_blocker(area: Area, fsx: _FsExtras) -> None:
    write_tree(area.src, {"a.txt": b"a"})
    alvo = area.root / "alvo-removido"
    alvo.mkdir()
    fsx.junction(alvo, area.src / "quebrada")
    alvo.rmdir()
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "quebrada", "junction"), plan.blockers
    assert {f.path for f in plan.files} == {("a.txt",)}


def test_create_vault_refuses_source_with_junction(area: Area, fsx: _FsExtras) -> None:
    write_tree(area.src, {"a.txt": b"a"})
    fsx.junction(_outside_tree(area), area.src / "atalho")
    before = _snapshot(area.root)
    with pytest.raises(PreflightError) as info:
        make_vault(area)
    assert _has(info.value.blockers, "atalho", "junction"), info.value.blockers
    assert not area.vault().exists()
    assert _snapshot(area.root) == before


@pytest.mark.parametrize("is_dir", [False, True], ids=["arquivo", "pasta"])
def test_symlink_inside_source_is_blocker_and_never_followed(
    area: Area, fsx: _FsExtras, is_dir: bool
) -> None:
    write_tree(area.src, {"a.txt": b"a"})
    fora = _outside_tree(area)
    target = fora / "dentro" if is_dir else fora / "segredo.txt"
    fsx.symlink(target, area.src / "link", is_dir=is_dir)
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "link", "link simbólico"), plan.blockers
    assert {f.path for f in plan.files} == {("a.txt",)}
    assert plan.dirs == []


# =========================================================================================
# Cofre × origem (inclusive via aliases 8.3 e junction)
# =========================================================================================

_OVERLAP = "não pode ficar dentro da origem"


@pytest.mark.parametrize("exists", [False, True])
def test_vault_inside_source_is_blocker(area: Area, exists: bool) -> None:
    _sample(area)
    vault = area.src / "sub" / "cofre"
    if exists:
        vault.mkdir()
    plan = _preflight(area, vault=vault)
    assert not plan.ok
    assert _has(plan.blockers, _OVERLAP), plan.blockers


def test_vault_equal_to_source_is_blocker(area: Area) -> None:
    _sample(area)
    plan = _preflight(area, vault=area.src)
    assert not plan.ok
    assert _has(plan.blockers, _OVERLAP), plan.blockers


@pytest.mark.parametrize("depth", [1, 3])
def test_source_inside_vault_is_blocker(area: Area, depth: int) -> None:
    vault = area.vault()
    src = vault
    for i in range(depth):
        src = src / f"nivel{i}"
    src.mkdir(parents=True)
    (src / "a.txt").write_bytes(b"a")
    plan = _preflight(area, source=src, vault=vault)
    assert not plan.ok
    assert _has(plan.blockers, _OVERLAP), plan.blockers


@pytest.mark.parametrize(
    "case", ["vault_in_source", "source_via_alias", "vault_equals_source", "source_in_vault"]
)
def test_overlap_detected_through_8dot3_alias(area: Area, case: str) -> None:
    long_src = area.root / "Pasta de Origem Longa"
    _tree(long_src, {"a.txt": b"a"})
    short_src = _short(long_src)
    if case == "vault_in_source":
        source, vault = str(long_src), short_src + "\\cofre"
    elif case == "source_via_alias":
        source, vault = short_src, str(long_src / "cofre")
    elif case == "vault_equals_source":
        source, vault = str(long_src), short_src
    else:
        long_vault = area.vaults / "Cofre Com Nome Longo"
        _tree(long_vault, {"dados": {"b.txt": b"b"}})
        source, vault = str(long_vault / "dados"), _short(long_vault)
    plan = _preflight(area, source=source, vault=vault)
    assert not plan.ok
    assert _has(plan.blockers, _OVERLAP), plan.blockers


@pytest.mark.parametrize(
    "case",
    [
        "vault_via_junction_into_source",
        "source_via_junction_into_vault",
        "vault_is_junction_to_source",
    ],
)
def test_overlap_detected_through_junction_alias(area: Area, fsx: _FsExtras, case: str) -> None:
    _sample(area)
    if case == "vault_via_junction_into_source":
        j = fsx.junction(area.src / "sub", area.root / "atalho")
        source, vault = str(area.src), str(j / "cofre")
    elif case == "source_via_junction_into_vault":
        real_vault = area.vault()
        _tree(real_vault, {"dados": {"b.txt": b"b"}})
        j = fsx.junction(real_vault, area.root / "atalho")
        source, vault = str(j / "dados"), str(real_vault)
    else:
        j = fsx.junction(area.src, area.vaults / "atalho")
        source, vault = str(area.src), str(j)
    plan = _preflight(area, source=source, vault=vault)
    assert not plan.ok
    assert _has(plan.blockers, _OVERLAP), plan.blockers


def test_vault_path_that_is_a_junction_is_blocker(area: Area, fsx: _FsExtras) -> None:
    _sample(area)
    empty = area.root / "vazia-fora"
    empty.mkdir()
    j = fsx.junction(empty, area.vault())
    plan = _preflight(area, vault=j)
    assert not plan.ok
    assert _has(plan.blockers, "Cofre", "não é uma pasta comum"), plan.blockers


# =========================================================================================
# Pasta do cofre: vazia / não vazia / arquivo / pai inexistente
# =========================================================================================


def test_nonempty_vault_dir_is_blocker(area: Area) -> None:
    _sample(area)
    area.vault().mkdir()
    (area.vault() / "qualquer.txt").write_bytes(b"x")
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "Cofre", "não está vazia"), plan.blockers


def test_nonempty_vault_dir_with_only_subfolder_is_blocker(area: Area) -> None:
    _sample(area)
    (area.vault() / "data").mkdir(parents=True)
    plan = _preflight(area)
    assert _has(plan.blockers, "Cofre", "não está vazia"), plan.blockers


def test_existing_empty_vault_dir_is_ok(area: Area) -> None:
    _sample(area)
    area.vault().mkdir()
    plan = _preflight(area)
    assert plan.ok, plan.blockers
    assert plan.vault_res is not None and plan.vault_res.exists


def test_vault_dir_with_only_stale_lock_is_ok(area: Area) -> None:
    _sample(area)
    area.vault().mkdir()
    (area.vault() / ".owlvault.lock").write_bytes(b"")
    plan = _preflight(area)
    assert plan.ok, plan.blockers


def test_nonempty_vault_dir_allowed_when_resuming(area: Area) -> None:
    _sample(area)
    area.vault().mkdir()
    (area.vault() / "vault.owl").write_bytes(b"x" * 144)
    plan = _preflight(area, resume=True)
    assert not _has(plan.blockers, "não está vazia"), plan.blockers
    assert plan.ok, plan.blockers


def test_vault_path_that_is_a_file_is_blocker(area: Area) -> None:
    _sample(area)
    area.vault().write_bytes(b"sou um arquivo")
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "Cofre", "não é uma pasta comum"), plan.blockers


def test_vault_parent_missing_is_blocker(area: Area) -> None:
    _sample(area)
    plan = _preflight(area, vault=area.vaults / "nao" / "existe" / "cofre")
    assert not plan.ok
    assert _has(plan.blockers, "Cofre", "não existe"), plan.blockers


# =========================================================================================
# Pasta do teste de restauração: fora da origem e do cofre, existente, volume
# =========================================================================================


def test_test_parent_inside_source_is_blocker(area: Area) -> None:
    _sample(area)
    plan = _preflight(area, test_parent=area.src / "sub")
    assert not plan.ok
    assert _has(plan.blockers, "Teste de restauração", "dentro da origem"), plan.blockers


def test_test_parent_equal_to_source_is_blocker(area: Area) -> None:
    _sample(area)
    plan = _preflight(area, test_parent=area.src)
    assert _has(plan.blockers, "Teste de restauração", "dentro da origem"), plan.blockers


def test_test_parent_inside_vault_is_blocker(area: Area) -> None:
    _sample(area)
    area.vault().mkdir()
    plan = _preflight(area, test_parent=area.vault())
    assert not plan.ok
    assert _has(plan.blockers, "Teste de restauração", "dentro do cofre"), plan.blockers


def test_test_parent_inside_source_via_junction_alias(area: Area, fsx: _FsExtras) -> None:
    _sample(area)
    j = fsx.junction(area.src / "sub", area.root / "atalho-teste")
    plan = _preflight(area, test_parent=j)
    assert not plan.ok
    assert _has(plan.blockers, "Teste de restauração", "dentro da origem"), plan.blockers


def test_test_parent_inside_source_via_8dot3_alias(area: Area) -> None:
    long_src = area.root / "Pasta de Origem Longa"
    _tree(long_src, {"a.txt": b"a", "subpasta": {}})
    plan = _preflight(area, source=long_src, test_parent=_short(long_src) + "\\subpasta")
    assert not plan.ok
    assert _has(plan.blockers, "Teste de restauração", "dentro da origem"), plan.blockers


def test_missing_test_parent_is_blocker(area: Area) -> None:
    _sample(area)
    plan = _preflight(area, test_parent=area.root / "nao-existe")
    assert not plan.ok
    assert _has(plan.blockers, "Teste de restauração", "não existe"), plan.blockers


def test_test_parent_that_is_a_file_is_blocker(area: Area) -> None:
    _sample(area)
    f = area.root / "arquivo-teste.txt"
    f.write_bytes(b"x")
    plan = _preflight(area, test_parent=f)
    assert not plan.ok
    assert _has(plan.blockers, "Teste de restauração", "não existe"), plan.blockers


def test_test_parent_on_vault_volume_blocked_when_source_on_other_volume(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ARCHITECTURE §4.1: "Nunca no volume do cofre, a menos que seja também o volume da origem".
    _sample(area)
    _fake_volume(monkeypatch, area.src)
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "Teste de restauração", "volume da ORIGEM"), plan.blockers


def test_test_parent_on_source_volume_ok_when_vault_on_other_volume(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sample(area)
    _fake_volume(monkeypatch, area.vault())
    plan = _preflight(area)
    assert not _has(plan.blockers, "volume da ORIGEM"), plan.blockers
    assert plan.ok, plan.blockers


def test_default_test_parent_prefers_temp_on_source_volume(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(area.testarea))
    got = default_test_parent(winfs.resolve(str(area.src)))
    assert winfs.resolve(got).same(winfs.resolve(str(area.testarea)))


def test_default_test_parent_falls_back_to_source_parent_when_temp_inside_source(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    inside = area.src / "tmp"
    inside.mkdir()
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(inside))
    got = default_test_parent(winfs.resolve(str(area.src)))
    assert winfs.resolve(got).same(winfs.resolve(str(area.root)))


def test_default_test_parent_falls_back_to_source_parent_when_temp_on_other_volume(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(area.testarea))
    real = winfs.resolve(str(area.src))
    src_other_volume = dataclasses.replace(real, parts=("VOLUME{OUTRO}", *real.parts[1:]))
    got = default_test_parent(src_other_volume)
    assert winfs.resolve(got).same(winfs.resolve(str(area.root)))


def test_preflight_without_test_parent_uses_default(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sample(area)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(area.testarea))
    plan = _preflight(area, test_parent=None)
    assert plan.ok, plan.blockers
    assert winfs.resolve(plan.test_parent_ext).same(winfs.resolve(str(area.testarea)))


# =========================================================================================
# Pastas protegidas (ProtectedPaths customizado)
# =========================================================================================


@dataclasses.dataclass
class _Prot:
    pai: Path
    critical: Path
    users: Path
    profile: Path
    paths: ProtectedPaths


@pytest.fixture
def prot(area: Area) -> _Prot:
    pai = area.root / "pai"
    critical = pai / "Sistema Critico Falso"
    _tree(critical, {"sub": {"x.txt": b"x"}, "tmp": {}})
    users = area.root / "Usuarios"
    profile = users / "fulano"
    _tree(profile, {"Documentos": {"Projeto": {"p.txt": b"p"}}})
    paths = ProtectedPaths(
        critical=[winfs.resolve(str(critical))],
        no_ancestor=[winfs.resolve(str(profile)), winfs.resolve(str(users))],
        dest_forbidden=[winfs.resolve(str(critical))],
    )
    return _Prot(pai, critical, users, profile, paths)


@pytest.mark.parametrize(
    "case", ["equal", "inside", "ancestor", "upper_case", "short_alias", "junction_alias"]
)
def test_source_overlapping_critical_folder_is_blocker(
    area: Area, prot: _Prot, fsx: _FsExtras, case: str
) -> None:
    if case == "equal":
        source = str(prot.critical)
    elif case == "inside":
        source = str(prot.critical / "sub")
    elif case == "ancestor":
        source = str(prot.pai)
    elif case == "upper_case":
        source = str(prot.critical / "sub").upper()
    elif case == "short_alias":
        source = _short(prot.critical) + "\\sub"
    else:
        j = fsx.junction(prot.critical, area.root / "atalho-sistema")
        source = str(j / "sub")
    plan = _preflight(area, source=source, protected=prot.paths)
    assert not plan.ok
    assert _has(plan.blockers, "Origem", "pasta protegida"), plan.blockers
    assert plan.files == []


@pytest.mark.parametrize("case", ["profile", "users_root"])
def test_source_equal_or_ancestor_of_profile_is_blocker(area: Area, prot: _Prot, case: str) -> None:
    source = prot.profile if case == "profile" else prot.users
    plan = _preflight(area, source=source, protected=prot.paths)
    assert not plan.ok
    assert _has(plan.blockers, "Origem", "perfil do usuário"), plan.blockers


def test_source_inside_profile_is_allowed(area: Area, prot: _Prot) -> None:
    plan = _preflight(area, source=prot.profile / "Documentos" / "Projeto", protected=prot.paths)
    assert plan.ok, plan.blockers
    assert {f.path for f in plan.files} == {("p.txt",)}


@pytest.mark.parametrize("via_alias", [False, True])
def test_vault_inside_forbidden_destination_is_blocker(
    area: Area, prot: _Prot, via_alias: bool
) -> None:
    _sample(area)
    base = _short(prot.critical) if via_alias else str(prot.critical)
    plan = _preflight(area, vault=base + "\\cofre", protected=prot.paths)
    assert not plan.ok
    assert _has(plan.blockers, "O cofre", "pasta do sistema"), plan.blockers


def test_test_parent_inside_forbidden_destination_is_blocker(area: Area, prot: _Prot) -> None:
    _sample(area)
    plan = _preflight(area, test_parent=prot.critical / "tmp", protected=prot.paths)
    assert not plan.ok
    assert _has(plan.blockers, "teste de restauração", "pasta do sistema"), plan.blockers


def test_vault_inside_profile_is_allowed(area: Area, prot: _Prot) -> None:
    _sample(area)
    plan = _preflight(area, vault=prot.profile / "Cofre-novo", protected=prot.paths)
    assert plan.ok, plan.blockers


@pytest.mark.parametrize("top", ["$Recycle.Bin", "System Volume Information"])
def test_system_areas_are_refused_for_source_and_destinations(area: Area, top: str) -> None:
    # Resolved sintético (não toca a Lixeira/SVI reais do volume).
    real = winfs.resolve(str(area.src))
    fake = dataclasses.replace(real, parts=(real.parts[0], top.upper(), "S-1-5-21", "X"))
    assert any(
        "área de sistema" in p for p in source_location_problems(fake, ProtectedPaths.none())
    )
    assert any(
        "área de sistema" in p
        for p in destination_location_problems(fake, ProtectedPaths.none(), "O cofre")
    )
    # o mesmo nome mais fundo (não no topo do volume) não é área de sistema
    deeper = dataclasses.replace(real, parts=(*real.parts, top.upper()))
    assert source_location_problems(deeper, ProtectedPaths.none()) == []


def test_protected_paths_from_environment_with_synthetic_env(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = area.root / "env"
    folders = {
        "SystemRoot": "Windows",
        "ProgramFiles": "Program Files",
        "ProgramFiles(x86)": "Program Files (x86)",
        "ProgramData": "ProgramData",
        "APPDATA": "Users\\fulano\\AppData\\Roaming",
        "LOCALAPPDATA": "Users\\fulano\\AppData\\Local",
    }
    for var, rel in folders.items():
        (env / rel).mkdir(parents=True)
        monkeypatch.setenv(var, str(env / rel))
    monkeypatch.setenv("ProgramW6432", str(env / "inexistente"))  # inexistente ⇒ ignorada
    profile = env / "Users" / "fulano"
    monkeypatch.setenv("USERPROFILE", str(profile))
    (profile / "Documentos").mkdir()

    p = ProtectedPaths.from_environment()
    assert len(p.critical) == 6  # SystemRoot, PF, PF(x86), ProgramData, Roaming, Local
    assert len(p.no_ancestor) == 2  # perfil e C:\Users
    assert len(p.dest_forbidden) == 4  # sistema (sem AppData)

    def src_problems(path: Path) -> list[str]:
        return source_location_problems(winfs.resolve(str(path)), p)

    def dst_problems(path: Path) -> list[str]:
        return destination_location_problems(winfs.resolve(str(path)), p, "O cofre")

    assert src_problems(env / "Windows" / "System32")
    assert src_problems(profile / "AppData" / "Local" / "Programa")
    assert src_problems(profile)  # perfil
    assert src_problems(env / "Users")  # C:\Users
    assert src_problems(env)  # ancestral de pastas críticas
    assert src_problems(profile / "Documentos") == []
    assert dst_problems(env / "ProgramData" / "cofre")
    assert dst_problems(env / "Program Files (x86)" / "cofre")
    assert dst_problems(profile / "AppData" / "Local" / "cofre") == []
    assert dst_problems(profile / "Documentos" / "cofre") == []


# =========================================================================================
# Arquivo em uso
# =========================================================================================


@pytest.mark.parametrize("how", ["python-r+b", "win32-sem-compartilhamento"])
def test_file_in_use_is_blocker(area: Area, how: str) -> None:
    _sample(area)
    target = area.src / "sub" / "aberto.txt"
    target.write_bytes(b"alguem esta editando")
    if how == "python-r+b":
        holder: Any = open(target, "r+b")  # noqa: SIM115
    else:
        holder = winfs.Win32File.open(_ext(target), winfs.GENERIC_READ, 0, winfs.OPEN_EXISTING, 0)
    try:
        plan = _preflight(area)
    finally:
        holder.close()
    assert not plan.ok
    assert _has(plan.blockers, "aberto.txt", "em uso"), plan.blockers
    assert ("sub", "aberto.txt") not in {f.path for f in plan.files}
    # os outros arquivos continuam no plano
    assert ("a.txt",) in {f.path for f in plan.files}


def test_file_open_read_only_elsewhere_is_ok(area: Area) -> None:
    _sample(area)
    with open(area.src / "a.txt", "rb"):
        plan = _preflight(area)
    assert plan.ok, plan.blockers


# =========================================================================================
# Varredura: colisões de caixa (fold), nomes inválidos, atributos, limites, erros
# =========================================================================================


def test_case_collision_in_case_sensitive_directory(area: Area) -> None:
    cs = area.src / "cs"
    cs.mkdir()
    r = subprocess.run(  # noqa: S603
        ["fsutil.exe", "file", "setCaseSensitiveInfo", str(cs), "enable"],  # noqa: S607
        capture_output=True,
        check=False,
    )
    if r.returncode != 0:
        pytest.skip("não foi possível habilitar diferenciação de maiúsculas na pasta (fsutil)")
    (cs / "foto.txt").write_bytes(b"1")
    try:
        with open(cs / "FOTO.TXT", "xb") as fh:
            fh.write(b"2")
    except FileExistsError:
        pytest.skip("a pasta não ficou sensível a maiúsculas")
    assert len(os.listdir(cs)) == 2
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "maiúsculas/minúsculas"), plan.blockers
    assert len([f for f in plan.files if f.path[0] == "cs"]) == 1


@pytest.mark.parametrize(
    ("real_name", "alias", "collides"),
    [
        ("foto.txt", "FOTO.TXT", True),
        ("ação.txt", "AÇÃO.TXT", True),
        ("ωmega.txt", "Ωmega.txt", True),
        ("😀a.txt", "😀A.txt", True),  # não-BMP fica igual, o resto dobra
        ("straße.txt", "STRASSE.TXT", False),  # ß não vira SS
        ("ﬁm.txt", "FIM.txt", False),  # ligadura não expande
        ("𐐨.txt", "𐐀.txt", False),  # não-BMP não dobra
    ],
)
def test_fold_collision_rules_in_scan(
    area: Area, monkeypatch: pytest.MonkeyPatch, real_name: str, alias: str, collides: bool
) -> None:
    (area.src / real_name).write_bytes(b"x")
    root = winfs.to_extended(str(area.src))

    def transform(path: str, entries: list[Any]) -> list[Any]:
        if path == root:
            real = next(e for e in entries if e.name == real_name)
            return [*entries, _RenamedEntry(real, alias)]
        return entries

    _patch_scandir(monkeypatch, transform)
    result = scan_tree(root, lambda: None)
    names = {f.path for f in result.files}
    if collides:
        assert _has(result.blockers, alias, real_name, "maiúsculas/minúsculas"), result.blockers
        assert names == {(real_name,)}
    else:
        assert result.blockers == []
        assert names == {(real_name,), (alias,)}


def test_fold_collision_between_folder_and_file(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(area.src, {"Docs": {"a.txt": b"a"}, "outro.txt": b"o"})
    root = winfs.to_extended(str(area.src))

    def transform(path: str, entries: list[Any]) -> list[Any]:
        if path == root:
            real = next(e for e in entries if e.name == "outro.txt")
            return [*entries, _RenamedEntry(real, "DOCS")]
        return entries

    _patch_scandir(monkeypatch, transform)
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "DOCS", "maiúsculas/minúsculas"), plan.blockers


def test_names_distinct_under_ntfs_upcase_are_not_collisions(area: Area) -> None:
    # Pares que o NTFS aceita lado a lado (sem truques): não podem ser bloqueados.
    pairs = [("straße.txt", "STRASSE.TXT"), ("𐐨.txt", "𐐀.txt")]
    for a, b in pairs:
        (area.src / a).write_bytes(b"1")
        try:
            with open(area.src / b, "xb") as fh:
                fh.write(b"2")
        except FileExistsError:
            pytest.skip(f"o volume considera {a!r} e {b!r} o mesmo nome")
    plan = _preflight(area)
    assert plan.ok, plan.blockers
    assert {f.path for f in plan.files} == {(n,) for pair in pairs for n in pair}


def test_invalid_names_created_with_extended_paths_are_blocked(area: Area, fsx: _FsExtras) -> None:
    write_tree(area.src, {"ok.txt": b"ok"})
    fsx.ext_file(area.src, "fim.")
    fsx.ext_file(area.src, "espaco ")
    fsx.ext_file(area.src, "CON")
    fsx.ext_file(area.src, "NUL .txt")
    aux = fsx.ext_dir(area.src, "aux")
    with open(aux + "\\dentro.txt", "xb") as fh:
        fh.write(b"d")
    fsx._items.append(("unlink", aux + "\\dentro.txt"))
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "fim.", "termina com espaço ou ponto"), plan.blockers
    assert _has(plan.blockers, "espaco ", "termina com espaço ou ponto"), plan.blockers
    assert _has(plan.blockers, "CON", "reservado"), plan.blockers
    assert _has(plan.blockers, "NUL .txt", "reservado"), plan.blockers
    assert _has(plan.blockers, "aux", "reservado"), plan.blockers
    assert {f.path for f in plan.files} == {("ok.txt",)}
    assert plan.dirs == []


def test_lone_surrogate_name_is_blocked(area: Area, fsx: _FsExtras) -> None:
    write_tree(area.src, {"ok.txt": b"ok"})
    try:
        fsx.ext_file(area.src, "ruim\ud800.txt")
    except (OSError, UnicodeError) as exc:
        pytest.skip(f"não foi possível criar nome com UTF-16 malformado: {exc}")
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "UTF-16"), plan.blockers
    assert {f.path for f in plan.files} == {("ok.txt",)}


def test_offline_attribute_is_blocker(area: Area) -> None:
    write_tree(area.src, {"ok.txt": b"ok", "nuvem.txt": b"n"})
    _set_attrs(area.src / "nuvem.txt", _ATTR_OFFLINE | _ATTR_ARCHIVE)
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "nuvem.txt", "offline"), plan.blockers
    assert {f.path for f in plan.files} == {("ok.txt",)}


def test_hidden_system_and_hard_link_warnings(area: Area) -> None:
    write_tree(area.src, {"a.txt": b"a", "oculto.txt": b"o", "sub": {}})
    _set_attrs(area.src / "oculto.txt", _ATTR_HIDDEN | _ATTR_SYSTEM | _ATTR_ARCHIVE)
    os.link(area.src / "a.txt", area.src / "sub" / "a-link.txt")
    plan = _preflight(area)
    assert plan.ok, plan.blockers
    assert {f.path for f in plan.files} == {("a.txt",), ("oculto.txt",), ("sub", "a-link.txt")}
    assert _has(plan.warnings, "oculto"), plan.warnings
    assert _has(plan.warnings, "hard links"), plan.warnings
    links = {f.path: f.links for f in plan.files}
    assert links[("a.txt",)] == 2 and links[("sub", "a-link.txt")] == 2


@pytest.mark.parametrize("where", ["subpasta", "raiz"])
def test_listing_error_is_blocker_never_skipped(
    area: Area, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    write_tree(area.src, {"ok.txt": b"1", "trancada": {"x.txt": b"2"}, "outra": {"y.txt": b"3"}})
    root = winfs.to_extended(str(area.src))

    def transform(path: str, entries: list[Any]) -> list[Any]:
        if (where == "raiz" and path == root) or (
            where == "subpasta" and winfs.name_of(path) == "trancada"
        ):
            raise PermissionError(13, "Acesso negado", path)
        return entries

    _patch_scandir(monkeypatch, transform)
    plan = _preflight(area)
    assert not plan.ok
    if where == "raiz":
        assert _has(plan.blockers, "pasta de origem", "não foi possível listar"), plan.blockers
    else:
        assert _has(plan.blockers, "trancada", "não foi possível listar"), plan.blockers
        assert {f.path for f in plan.files} == {("ok.txt",), ("outra", "y.txt")}


def test_attribute_read_error_is_blocker(area: Area, monkeypatch: pytest.MonkeyPatch) -> None:
    write_tree(area.src, {"ok.txt": b"1", "ruim.txt": b"2"})
    root = winfs.to_extended(str(area.src))

    def transform(path: str, entries: list[Any]) -> list[Any]:
        if path != root:
            return entries
        return [_BrokenStatEntry(e, e.name) if e.name == "ruim.txt" else e for e in entries]

    _patch_scandir(monkeypatch, transform)
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "ruim.txt", "não foi possível ler atributos"), plan.blockers
    assert {f.path for f in plan.files} == {("ok.txt",)}


_ATTR_PINNED = 0x80000


@pytest.mark.parametrize(
    ("attrs", "tag", "needle"),
    [
        # OneDrive/Arquivos sob Demanda, inclusive "Sempre manter neste dispositivo" (PINNED)
        (_ATTR_REPARSE_POINT | _ATTR_ARCHIVE, 0x9000001A, "OneDrive"),
        (_ATTR_REPARSE_POINT | _ATTR_ARCHIVE | _ATTR_PINNED, 0x9000701A, "OneDrive"),
        (_ATTR_REPARSE_POINT | _ATTR_ARCHIVE, 0x80000017, "compactado"),  # WOF
        (_ATTR_REPARSE_POINT | _ATTR_ARCHIVE, 0x80000013, "deduplicado"),  # dedup
        (_ATTR_REPARSE_POINT | _ATTR_ARCHIVE, 0x8000001B, "atalho de aplicativo"),
        (_ATTR_REPARSE_POINT | _ATTR_ARCHIVE, 0xA000000C, "link simbólico"),
        (_ATTR_REPARSE_POINT | _ATTR_ARCHIVE, 0xA0000003, "junction"),
        (_ATTR_REPARSE_POINT | _ATTR_ARCHIVE, 0x12345678, "0x12345678"),
        (0x40000 | _ATTR_ARCHIVE, 0, "nuvem/offline"),  # RECALL_ON_OPEN
        (0x400000 | _ATTR_ARCHIVE, 0, "nuvem/offline"),  # RECALL_ON_DATA_ACCESS
    ],
)
def test_reparse_and_recall_entries_blocked_from_listing_attributes(
    area: Area, monkeypatch: pytest.MonkeyPatch, attrs: int, tag: int, needle: str
) -> None:
    write_tree(area.src, {"ok.txt": b"1", "especial.txt": b"2"})
    root = winfs.to_extended(str(area.src))
    opened: list[str] = []
    real_open = winfs.open_source

    def spy_open(path: str, expected: Any = None) -> Any:
        opened.append(winfs.name_of(path))
        return real_open(path, expected)

    def transform(path: str, entries: list[Any]) -> list[Any]:
        if path != root:
            return entries
        return [
            _FakeStatEntry(e, attrs=attrs, tag=tag) if e.name == "especial.txt" else e
            for e in entries
        ]

    _patch_scandir(monkeypatch, transform)
    monkeypatch.setattr(winfs, "open_source", spy_open)
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "especial.txt", needle), plan.blockers
    assert {f.path for f in plan.files} == {("ok.txt",)}
    # classificado pela listagem ANTES de qualquer abertura
    assert "especial.txt" not in opened


def test_special_file_type_is_blocker(area: Area, monkeypatch: pytest.MonkeyPatch) -> None:
    write_tree(area.src, {"ok.txt": b"1", "dispositivo": b"2"})
    root = winfs.to_extended(str(area.src))

    def transform(path: str, entries: list[Any]) -> list[Any]:
        if path != root:
            return entries
        return [
            _FakeStatEntry(e, attrs=_ATTR_ARCHIVE, mode=stat_mod.S_IFCHR | 0o666)
            if e.name == "dispositivo"
            else e
            for e in entries
        ]

    _patch_scandir(monkeypatch, transform)
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "dispositivo", "tipo de arquivo especial"), plan.blockers
    assert {f.path for f in plan.files} == {("ok.txt",)}


def test_file_vanished_between_scan_and_open_is_blocker(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(area.src, {"ok.txt": b"1"})
    root = winfs.to_extended(str(area.src))

    def transform(path: str, entries: list[Any]) -> list[Any]:
        if path != root:
            return entries
        return [*entries, _RenamedEntry(entries[0], "fantasma.txt")]

    _patch_scandir(monkeypatch, transform)
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "fantasma.txt"), plan.blockers
    assert {f.path for f in plan.files} == {("ok.txt",)}


def test_many_scan_blockers_are_summarized_not_dropped(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_mod, "_MAX_DETAILED", 3)
    write_tree(area.src, {"ok.txt": b"1", **{f"off{i}.txt": b"o" for i in range(5)}})
    for i in range(5):
        _set_attrs(area.src / f"off{i}.txt", _ATTR_OFFLINE | _ATTR_ARCHIVE)
    plan = _preflight(area)
    assert not plan.ok
    assert len([b for b in plan.blockers if "offline" in b]) == 3
    assert _has(plan.blockers, "omitidos"), plan.blockers
    assert _has(plan.warnings, "Total de bloqueios na varredura: 5"), plan.warnings


@pytest.mark.parametrize(("entries", "blocked"), [(5, False), (6, True)])
def test_entry_count_limit(
    area: Area, monkeypatch: pytest.MonkeyPatch, entries: int, blocked: bool
) -> None:
    monkeypatch.setattr(scan_mod, "MAX_ENTRIES", 5)
    (area.src / "pasta").mkdir()  # pastas contam como entradas
    for i in range(entries - 1):
        (area.src / "pasta" / f"f{i}.txt").write_bytes(b"x")
    plan = _preflight(area)
    if blocked:
        assert _has(plan.blockers, "mais de 5 itens"), plan.blockers
    else:
        assert plan.ok, plan.blockers
        assert len(plan.files) + len(plan.dirs) == 5


@pytest.mark.parametrize(("depth", "blocked"), [(3, False), (4, True)])
def test_depth_limit(
    area: Area, monkeypatch: pytest.MonkeyPatch, depth: int, blocked: bool
) -> None:
    monkeypatch.setattr(scan_mod, "MAX_DEPTH", 3)
    p = area.src
    for i in range(depth - 1):
        p = p / f"n{i}"
    p.mkdir(parents=True, exist_ok=True)
    (p / "f.txt").write_bytes(b"x")
    plan = _preflight(area)
    if blocked:
        assert _has(plan.blockers, "mais de 3 níveis"), plan.blockers
    else:
        assert plan.ok, plan.blockers
        assert max(len(f.path) for f in plan.files) == 3


@pytest.mark.parametrize(("size", "blocked"), [(10, False), (11, True)])
def test_file_size_limit(
    area: Area, monkeypatch: pytest.MonkeyPatch, size: int, blocked: bool
) -> None:
    monkeypatch.setattr(scan_mod, "MAX_FILE_SIZE", 10)
    write_tree(area.src, {"pequeno.txt": b"x", "limite.bin": b"y" * size})
    plan = _preflight(area)
    if blocked:
        assert _has(plan.blockers, "limite.bin", "limite da v1"), plan.blockers
        assert {f.path for f in plan.files} == {("pequeno.txt",)}
    else:
        assert plan.ok, plan.blockers


# =========================================================================================
# Sistema de arquivos do cofre: FAT32 > 4 GiB − 1 e aceite FAT/exFAT (FS simulado)
# =========================================================================================


@pytest.mark.parametrize("fs_name", ["FAT32", "FAT"])
def test_fat32_blocks_blob_over_4gib(
    area: Area, monkeypatch: pytest.MonkeyPatch, fs_name: str
) -> None:
    write_tree(area.src, {"grande.bin": b"g", "pequeno.bin": b"p"})
    _plenty_space(monkeypatch)
    _fake_vault_fs(monkeypatch, area.vault(), fs_name)
    _fake_sizes(monkeypatch, {"grande.bin": 5 * GIB})
    plan = _preflight(area)
    assert plan.vault_fs == fs_name
    assert not plan.ok
    assert _has(plan.blockers, "grande.bin", "4 GiB"), plan.blockers
    assert not _has(plan.blockers, "pequeno.bin"), plan.blockers
    assert plan.needs_fat_ack
    assert _has(plan.warnings, "journaling"), plan.warnings


@pytest.mark.parametrize("over", [False, True])
def test_fat32_limit_applies_to_blob_size_exactly(
    area: Area, monkeypatch: pytest.MonkeyPatch, over: bool
) -> None:
    # FORMAT §4.2 + ARCHITECTURE §4.1: bloqueia BLOBS > 4 GiB − 1 (cabeçalho + tags contam).
    p_max = _max_plaintext_with_blob_at_most(FAT32_MAX_FILE_SIZE, SMALL_CHUNK)
    assert _spec_blob_size(p_max, SMALL_CHUNK) <= FAT32_MAX_FILE_SIZE
    assert _spec_blob_size(p_max + 1, SMALL_CHUNK) > FAT32_MAX_FILE_SIZE
    assert p_max < FAT32_MAX_FILE_SIZE  # o texto claro sozinho caberia: o limite é do blob
    write_tree(area.src, {"borda.bin": b"b"})
    _plenty_space(monkeypatch)
    _fake_vault_fs(monkeypatch, area.vault(), "FAT32")
    _fake_sizes(monkeypatch, {"borda.bin": p_max + 1 if over else p_max})
    plan = _preflight(area)
    if over:
        assert _has(plan.blockers, "borda.bin", "4 GiB"), plan.blockers
    else:
        assert plan.ok, plan.blockers
        assert plan.needs_fat_ack


def test_exfat_needs_ack_but_has_no_4gib_limit(area: Area, monkeypatch: pytest.MonkeyPatch) -> None:
    write_tree(area.src, {"grande.bin": b"g"})
    _plenty_space(monkeypatch)
    _fake_vault_fs(monkeypatch, area.vault(), "exFAT")
    _fake_sizes(monkeypatch, {"grande.bin": 5 * GIB})
    plan = _preflight(area)
    assert plan.ok, plan.blockers
    assert plan.needs_fat_ack
    assert _has(plan.warnings, "exFAT", "journaling"), plan.warnings


@pytest.mark.parametrize("fs_name", ["NTFS", "ReFS"])
def test_journaled_fs_needs_no_ack(
    area: Area, monkeypatch: pytest.MonkeyPatch, fs_name: str
) -> None:
    write_tree(area.src, {"grande.bin": b"g"})
    _plenty_space(monkeypatch)
    _fake_vault_fs(monkeypatch, area.vault(), fs_name)
    _fake_sizes(monkeypatch, {"grande.bin": 5 * GIB})
    plan = _preflight(area)
    assert plan.ok, plan.blockers
    assert not plan.needs_fat_ack
    assert not _has(plan.warnings, "journaling")


def test_create_vault_requires_fat_acknowledgement(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(area.src, {"a.txt": b"a"})
    _plenty_space(monkeypatch)
    _fake_vault_fs(monkeypatch, area.vault(), "FAT32")
    plan = _preflight(area)
    assert plan.ok and plan.needs_fat_ack
    before = _snapshot(area.root)
    with pytest.raises(PreflightError):
        create_vault(
            str(area.src),
            str(area.vault()),
            PASSWORD,
            test_parent=str(area.testarea),
            kdf_params=TESTING_PARAMS,
            kdf_policy=TESTING_POLICY,
            chunk_size=SMALL_CHUNK,
            protected=ProtectedPaths.none(),
            plan=plan,
            fat_acknowledged=False,
        )
    assert not area.vault().exists()
    assert _snapshot(area.root) == before


# =========================================================================================
# Espaço livre (volume_space simulado)
# =========================================================================================


def _space_tree(area: Area) -> None:
    _tree(
        area.src,
        {
            "a.bin": os.urandom(100_000),
            "vazio.bin": b"",
            "pasta vazia": {},
            "sub": {"c.bin": os.urandom(3 * SMALL_CHUNK), "d.txt": b"d" * 4097},
        },
    )


def test_space_estimate_follows_documented_formula(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    _space_tree(area)
    cluster = 4096
    _plenty_space(monkeypatch, cluster)
    plan = _preflight(area)
    assert plan.ok, plan.blockers
    # ARCHITECTURE §4.1: Σ arredonda(blob, cluster) + ~1 KiB/entrada + 3 × manifesto + 64 MiB
    blobs = sum(
        _round_up(_spec_blob_size(f.fingerprint.size, SMALL_CHUNK), cluster) for f in plan.files
    )
    entries = len(plan.files) + len(plan.dirs)
    lower = blobs + 1024 * entries + 3 * plan.manifest_size + _MARGIN
    assert lower <= plan.estimated_vault_bytes <= lower + 2 * MIB


@pytest.mark.parametrize(("delta", "blocked"), [(-1, True), (0, False)])
def test_vault_space_blocker(
    area: Area, monkeypatch: pytest.MonkeyPatch, delta: int, blocked: bool
) -> None:
    _space_tree(area)
    cluster = 4096
    _plenty_space(monkeypatch, cluster)
    need = _preflight(area).estimated_vault_bytes
    vault_anc = winfs.resolve(str(area.vault())).existing_ancestor.lower()

    def fake(d: str) -> winfs.VolumeSpace:
        free = need + delta if d.lower() == vault_anc else 1 << 50
        return winfs.VolumeSpace(free_bytes=free, cluster_size=cluster)

    monkeypatch.setattr(winfs, "volume_space", fake)
    plan = _preflight(area)
    if blocked:
        assert _has(plan.blockers, "Espaço insuficiente para o cofre"), plan.blockers
    else:
        assert plan.ok, plan.blockers


@pytest.mark.parametrize(("enough", "blocked"), [(False, True), (True, False)])
def test_test_folder_space_blocker(
    area: Area, monkeypatch: pytest.MonkeyPatch, enough: bool, blocked: bool
) -> None:
    _space_tree(area)
    cluster = 4096
    test_anc = winfs.resolve(str(area.testarea)).existing_ancestor.lower()
    largest = 3 * SMALL_CHUNK
    # pasta de teste: pelo menos "maior arquivo + margem"
    free_test = (1 << 50) if enough else _round_up(largest, cluster) + _MARGIN - 1

    def fake(d: str) -> winfs.VolumeSpace:
        free = free_test if d.lower() == test_anc else 1 << 50
        return winfs.VolumeSpace(free_bytes=free, cluster_size=cluster)

    monkeypatch.setattr(winfs, "volume_space", fake)
    plan = _preflight(area)
    assert plan.largest_file == largest
    if blocked:
        assert _has(plan.blockers, "Espaço insuficiente na pasta do teste"), plan.blockers
    else:
        assert plan.ok, plan.blockers


def test_vault_space_query_failure_is_blocker(area: Area, monkeypatch: pytest.MonkeyPatch) -> None:
    _space_tree(area)

    def boom(d: str) -> winfs.VolumeSpace:
        raise OSError(21, "O dispositivo não está pronto")

    monkeypatch.setattr(winfs, "volume_space", boom)
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "Cofre", "espaço livre"), plan.blockers


# =========================================================================================
# Tamanho do manifesto
# =========================================================================================


def test_manifest_size_cap_blocker(area: Area, monkeypatch: pytest.MonkeyPatch) -> None:
    _sample(area)
    _plenty_space(monkeypatch)
    assert vars(preflight_mod)["MAX_MANIFEST_PLAINTEXT"] == 256 * MIB
    size = _preflight(area).manifest_size
    monkeypatch.setattr(preflight_mod, "MAX_MANIFEST_PLAINTEXT", size)
    plan = _preflight(area)
    assert plan.ok, plan.blockers
    monkeypatch.setattr(preflight_mod, "MAX_MANIFEST_PLAINTEXT", size - 1)
    plan = _preflight(area)
    assert not plan.ok
    assert _has(plan.blockers, "lista de nomes"), plan.blockers


def test_manifest_size_estimate_covers_real_serialization(
    area: Area, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Nomes não-ASCII: o tamanho deve contar BYTES UTF-8 (ensure_ascii=False), não caracteres.
    _tree(
        area.src,
        {
            "日本語のファイル名.txt": b"a",
            "😀😀😀 emoji.bin": b"b" * 5000,
            "Ação": {"ç" * 100 + ".txt": b"c", "vazia": {}},
            "x" * 100 + ".txt": b"d",
        },
    )
    _plenty_space(monkeypatch)
    plan = _preflight(area)
    assert plan.ok, plan.blockers
    entries: list[dict[str, Any]] = [{"type": "dir", "path": list(d.path)} for d in plan.dirs]
    entries += [
        {
            "type": "file",
            "path": list(f.path),
            "size": f.fingerprint.size,
            "mtime_ns": f.fingerprint.mtime_ns,
            "file_id": os.urandom(16).hex(),
            "sha256": os.urandom(32).hex(),
        }
        for f in plan.files
    ]
    manifest = {
        "kind": "manifest",
        "format_version": 1,
        "vault_id": os.urandom(16).hex(),
        "chunk_size": SMALL_CHUNK,
        "entries": entries,
    }
    # serializador canônico do FORMAT §5
    actual = len(
        json.dumps(
            manifest, ensure_ascii=False, separators=(",", ":"), allow_nan=False, sort_keys=True
        ).encode("utf-8")
    )
    assert actual <= plan.manifest_size
    # e é um limite justo (só a largura dos campos numéricos pode sobrar)
    assert plan.manifest_size - actual <= 32 * len(plan.files) + 16
