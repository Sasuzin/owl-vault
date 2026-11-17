"""Salvamento de emergência sem manifesto (ARCHITECTURE §4.5): cada blob autenticável é
decifrado para ``recuperado-NNNNN.bin`` numa pasta nova e vazia (conteúdo, sem nomes).

Somente pastas temporárias com dados sintéticos.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
from collections import Counter
from pathlib import Path

import pytest

from owl_vault.application.protection import ProtectedPaths
from owl_vault.application.salvage import SalvageReport, salvage_vault
from owl_vault.application.vault import open_vault, read_manifest
from owl_vault.crypto.kdf import TESTING_POLICY
from owl_vault.domain.errors import AuthenticationError, UnsafePathError
from tests.conftest import PASSWORD, SMALL_CHUNK, Area, make_vault, tree_digest, write_tree

_RECOVERED_RE = re.compile(r"recuperado-\d{5}\.bin")


def _salvage(
    area: Area, dest: Path, *, name: str = "cofre", password: str = PASSWORD
) -> SalvageReport:
    return salvage_vault(
        str(area.vault(name)),
        password,
        str(dest),
        policy=TESTING_POLICY,
        protected=ProtectedPaths.none(),
    )


def _sample(area: Area) -> None:
    same = os.urandom(SMALL_CHUNK + 1)
    write_tree(
        area.src,
        {
            "vazio.txt": b"",
            "outro-vazio.txt": b"",
            "pequeno.txt": b"ola",
            "exato.bin": os.urandom(2 * SMALL_CHUNK),
            "grande.bin": os.urandom(3 * SMALL_CHUNK + 17),
            "copia1.bin": same,
            "sub": {"copia2.bin": same, "mais": {"b.txt": b"B" * 1000}, "vazia": {}},
        },
    )


def _source_hashes(area: Area) -> Counter[str]:
    return Counter(v[1] for v in tree_digest(area.src).values() if v[0] == "file")


def _recovered_hashes(dest: Path) -> Counter[str]:
    return Counter(hashlib.sha256(p.read_bytes()).hexdigest() for p in dest.iterdir())


def _drop_manifests(vault: Path) -> None:
    (vault / "manifest.owl").unlink()
    (vault / "manifest.owl.bak").unlink()


def _blob_to_sha(area: Area, name: str = "cofre") -> dict[str, str]:
    """nome do blob → sha256 do conteúdo (lido do manifesto ANTES de removê-lo)."""
    opened = open_vault(str(area.vault(name)), PASSWORD, TESTING_POLICY)
    m = read_manifest(opened).manifest
    return {f"{e.file_id.hex()}.owlb": e.sha256.hex() for e in m.files}


def test_salvage_without_manifests_recovers_every_file_content(area: Area) -> None:
    _sample(area)
    expected = _source_hashes(area)
    n = sum(expected.values())
    assert make_vault(area).status == "success"
    vault = area.vault()
    _drop_manifests(vault)
    vault_digest = tree_digest(vault)
    dest = area.dest("salvos")

    rep = _salvage(area, dest)
    assert rep.failed == []
    assert rep.recovered == n
    names = sorted(os.listdir(dest))
    # exatamente recuperado-00001.bin .. recuperado-0000N.bin; sem temporários nem trava
    assert names == [f"recuperado-{i:05d}.bin" for i in range(1, n + 1)]
    assert all(_RECOVERED_RE.fullmatch(x) for x in names)
    # o multiconjunto de conteúdos é idêntico ao da origem (inclui vazios e duplicados)
    assert _recovered_hashes(dest) == expected
    # o cofre não foi alterado
    assert tree_digest(vault) == vault_digest
    # nenhum nome original aparece no destino
    for original in ("pequeno", "grande", "copia", "sub", "vazio"):
        assert not any(original in x for x in names)


def test_salvage_into_existing_empty_destination(area: Area) -> None:
    write_tree(area.src, {"a.txt": b"A", "b.txt": b"BB"})
    expected = _source_hashes(area)
    make_vault(area)
    _drop_manifests(area.vault())
    dest = area.dest("salvos")
    dest.mkdir()
    rep = _salvage(area, dest)
    assert rep.recovered == 2 and rep.failed == []
    assert _recovered_hashes(dest) == expected


@pytest.mark.parametrize(
    "content",
    [{"ja-existe.txt": b"dados"}, {"pasta": {}}],
    ids=["file", "empty-subfolder"],
)
def test_salvage_nonempty_destination_refused(area: Area, content: dict[str, object]) -> None:
    write_tree(area.src, {"a.txt": b"A"})
    make_vault(area)
    _drop_manifests(area.vault())
    dest = area.dest("salvos")
    dest.mkdir()
    write_tree(dest, content)
    before = tree_digest(dest)
    listing = sorted(os.listdir(dest))
    with pytest.raises(UnsafePathError):
        _salvage(area, dest)
    assert sorted(os.listdir(dest)) == listing
    assert tree_digest(dest) == before


def test_salvage_destination_inside_vault_refused(area: Area) -> None:
    write_tree(area.src, {"a.txt": b"A"})
    make_vault(area)
    vault = area.vault()
    _drop_manifests(vault)
    listing = sorted(str(p.relative_to(vault)) for p in vault.rglob("*"))
    dest = vault / "salvos"
    with pytest.raises(UnsafePathError):
        _salvage(area, dest)
    assert not dest.exists()
    assert sorted(str(p.relative_to(vault)) for p in vault.rglob("*")) == listing


def test_salvage_wrong_password_writes_nothing(area: Area) -> None:
    write_tree(area.src, {"a.txt": b"A"})
    make_vault(area)
    _drop_manifests(area.vault())
    dest = area.dest("salvos")
    with pytest.raises(AuthenticationError):
        _salvage(area, dest, password="senha totalmente errada")
    assert not dest.exists() or os.listdir(dest) == []


def test_salvage_skips_corrupt_and_foreign_blobs_and_keeps_going(area: Area) -> None:
    _sample(area)
    make_vault(area)
    make_vault(area, name="outro")
    vault = area.vault()
    blob_sha = _blob_to_sha(area)
    _drop_manifests(vault)
    blobs = sorted((vault / "data").rglob("*.owlb"))
    assert len(blobs) == len(blob_sha)

    # (1) blob corrompido (tamanho inalterado)
    corrupt = next(p for p in blobs if p.stat().st_size > 64 + 16 + 10)
    data = bytearray(corrupt.read_bytes())
    data[64 + 5] ^= 0x01
    corrupt.write_bytes(bytes(data))
    # (2) blob de outro cofre, com nome de blob válido
    foreign_src = next(iter(sorted((area.vault("outro") / "data").rglob("*.owlb"))))
    while True:
        h = secrets.token_hex(16)
        if not (vault / "data" / h[:2] / f"{h}.owlb").exists():
            break
    (vault / "data" / h[:2]).mkdir(exist_ok=True)
    shutil.copyfile(foreign_src, vault / "data" / h[:2] / f"{h}.owlb")
    # (3) blob íntegro deslocado para outra pasta hh: ainda autenticável, deve ser salvo
    moved = next(p for p in blobs if p != corrupt)
    wrong_hh = "00" if moved.parent.name != "00" else "ff"
    (vault / "data" / wrong_hh).mkdir(exist_ok=True)
    os.replace(moved, vault / "data" / wrong_hh / moved.name)

    dest = area.dest("salvos")
    rep = _salvage(area, dest)
    assert len(rep.failed) == 2, rep.failed
    assert any(corrupt.name in f for f in rep.failed), rep.failed
    assert any(f"{h}.owlb" in f for f in rep.failed), rep.failed
    assert rep.recovered == len(blob_sha) - 1

    expected = Counter(sha for name, sha in blob_sha.items() if name != corrupt.name)
    assert _recovered_hashes(dest) == expected
    names = os.listdir(dest)
    assert len(names) == rep.recovered
    assert all(_RECOVERED_RE.fullmatch(x) for x in names), names
