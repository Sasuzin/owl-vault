"""Arquivos grandes sintéticos (TEST_PLAN: "Vídeos grandes sintéticos").

Os dados são gerados em streaming (blocos de 1 MiB, nunca o arquivo inteiro em memória) e
conferidos por hash também em streaming. Usa o chunk padrão de 1 MiB (FORMAT §4.1).
"""

from __future__ import annotations

import hashlib
import os
import struct
import tracemalloc
from pathlib import Path

import pytest

from owl_vault.domain.limits import MIB
from tests.conftest import Area, do_restore, do_verify, make_vault

CHUNK = 1048576  # padrão do formato (1 MiB)
_GEN_BLOCK = 1 * MIB


def _write_streaming(path: Path, size: int) -> str:
    """Grava ``size`` bytes pseudoaleatórios em blocos; devolve o SHA-256 (hex)."""
    sha = hashlib.sha256()
    remaining = size
    with open(path, "wb") as fh:
        while remaining:
            block = os.urandom(min(_GEN_BLOCK, remaining))
            fh.write(block)
            sha.update(block)
            remaining -= len(block)
    return sha.hexdigest()


def _sha_streaming(path: Path) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        while block := fh.read(4 * MIB):
            sha.update(block)
    return sha.hexdigest()


def _expected_blob_size(p: int, c: int) -> int:
    n = max(1, -(-p // c))
    return 64 + p + 16 * n


def _roundtrip_large(area: Area, big_size: int, *, memory_bound: int | None) -> None:
    files = {
        "video-sintetico.mp4": big_size,
        "exato-3-chunks.bin": 3 * CHUNK,  # múltiplo exato: último chunk cheio
        "um-chunk-menos-1.bin": CHUNK - 1,
    }
    expected: dict[str, tuple[str, int]] = {}
    for name, size in files.items():
        sha = _write_streaming(area.src / name, size)
        expected[name] = (sha, (area.src / name).stat().st_mtime_ns)

    if memory_bound is not None:
        tracemalloc.start()
    try:
        result = make_vault(area, chunk_size=CHUNK)
        peak = tracemalloc.get_traced_memory()[1] if memory_bound is not None else 0
    finally:
        if memory_bound is not None:
            tracemalloc.stop()
    assert result.status == "success", result.divergences
    assert result.files == len(files)
    assert result.total_bytes == sum(files.values())
    if memory_bound is not None:
        # cifragem/verificação/teste em chunks: o pico fica muito abaixo do tamanho do arquivo
        assert peak < memory_bound, f"pico de memória {peak / MIB:.1f} MiB"

    # cada blob tem o tamanho EXATO 64 + P + 16·n e chunk_size = 1 MiB no cabeçalho
    blobs = sorted((area.vault() / "data").rglob("*.owlb"))
    assert sorted(b.stat().st_size for b in blobs) == sorted(
        _expected_blob_size(s, CHUNK) for s in files.values()
    )
    for b in blobs:
        with open(b, "rb") as fh:
            head = fh.read(64)
        chunk_size, plaintext_size = struct.unpack(">IQ", head[48:60])
        assert chunk_size == CHUNK
        assert b.stat().st_size == _expected_blob_size(plaintext_size, CHUNK)

    report = do_verify(area)
    assert report.fully_ok, (report.bad, report.anomalies, report.notes)
    assert report.files_ok == len(files)
    rest = do_restore(area)
    assert rest.ok, (rest.failed, rest.conflicts)
    for name, (sha, mtime_ns) in expected.items():
        out = area.dest() / name
        assert out.stat().st_size == files[name]
        assert _sha_streaming(out) == sha, name
        assert out.stat().st_mtime_ns == mtime_ns, name
        assert _sha_streaming(area.src / name) == sha  # origem intacta
    # nenhum texto claro remanescente do teste de restauração
    assert list(area.testarea.iterdir()) == []


def test_large_file_roundtrip_200mib_default_chunk(area: Area) -> None:
    """~200 MiB (não múltiplo do chunk), chunk padrão de 1 MiB, memória limitada."""
    _roundtrip_large(area, 200 * MIB + 12_345, memory_bound=48 * MIB)


@pytest.mark.slow
def test_large_file_roundtrip_over_1gib_default_chunk(area: Area) -> None:
    """> 1 GiB (TEST_PLAN: marcado ``slow``)."""
    _roundtrip_large(area, 1024 * MIB + 100 * MIB + 7, memory_bound=None)
