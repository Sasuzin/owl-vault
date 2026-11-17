"""Criar → verificar → restaurar: restauração fiel (conteúdo, árvore, mtime, pastas vazias)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from owl_vault.domain.errors import AuthenticationError
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


def _sample(area: Area) -> None:
    write_tree(
        area.src,
        {
            "vazio.txt": b"",
            "pequeno.txt": b"ola mundo",
            "binario.bin": os.urandom(3 * SMALL_CHUNK + 17),
            "exato.bin": os.urandom(2 * SMALL_CHUNK),
            "um-chunk-menos-1.bin": os.urandom(SMALL_CHUNK - 1),
            "Ação çãõ 日本語 😀.txt": b"acentos e emoji",
            "pasta vazia": {},
            "sub": {"a.txt": b"A", "mais": {"b.txt": b"B" * 1000}},
            "outra": {"a.txt": b"mesmo nome, outra pasta"},
        },
    )


def test_roundtrip_faithful(area: Area) -> None:
    _sample(area)
    before = tree_digest(area.src)
    result = make_vault(area)
    assert result.status == "success", result.divergences
    assert result.files == 9
    # origem intacta
    assert tree_digest(area.src) == before
    report = do_verify(area)
    assert report.fully_ok, (report.bad, report.anomalies, report.notes)
    assert report.files_ok == 9
    rest = do_restore(area)
    assert rest.ok, (rest.failed, rest.conflicts)
    assert tree_digest(area.dest()) == before
    # nenhum resíduo do teste de restauração
    assert list(area.testarea.iterdir()) == []
    # nomes originais não aparecem em claro em nenhum arquivo do cofre
    blob = b"".join(p.read_bytes() for p in area.vault().rglob("*") if p.is_file())
    for name in ("pequeno", "binario", "pasta vazia", "日本語".encode().decode()):
        assert name.encode("utf-8") not in blob
        assert name.encode("utf-16-le") not in blob


def test_wrong_password(area: Area) -> None:
    _sample(area)
    make_vault(area)
    with pytest.raises(AuthenticationError):
        do_verify(area, password="senha errada errada")
    with pytest.raises(AuthenticationError):
        do_restore(area, password="senha errada errada")
    assert not area.dest().exists()


def test_deep_and_long_paths(area: Area) -> None:
    deep = area.src
    parts = ["nivel" + str(i) + "x" * 40 for i in range(8)]
    p = "\\\\?\\" + str(deep)
    for comp in parts:
        p = p + "\\" + comp
        os.mkdir(p)
    with open(p + "\\arquivo final.txt", "wb") as fh:
        fh.write(b"fundo")
    assert len(p) > 300
    before = tree_digest(Path("\\\\?\\" + str(area.src)))
    assert make_vault(area).status == "success"
    assert do_restore(area).ok
    assert tree_digest(Path("\\\\?\\" + str(area.dest()))) == before


def test_source_never_modified_and_password_not_stored(area: Area) -> None:
    _sample(area)
    stats_before = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in area.src.rglob("*")}
    make_vault(area)
    stats_after = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in area.src.rglob("*")}
    assert stats_before == stats_after
    everything = b"".join(
        p.read_bytes() for p in area.root.rglob("*") if p.is_file() and "origem" not in p.parts
    )
    assert PASSWORD.encode() not in everything
