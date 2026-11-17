"""Validação do manifesto e JSON estrito (FORMAT §5, §5.1, §5.2).

Cobre ``storage/manifest.py`` (``manifest_from_obj``, ``validate_entries``,
``build_manifest``, ``estimate_manifest_size``) e o JSON canônico/estrito de
``storage/container.py``. Testes puros, em memória; nenhum toca pastas reais.

O caminho de leitura real é ``strict_json_loads(texto) -> manifest_from_obj(obj, vault_id)``;
os testes passam pelo mesmo caminho sempre que o caso é expressável em JSON.
"""

from __future__ import annotations

import json
import os
import random
import struct
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from owl_vault.crypto.keys import derive_subkey
from owl_vault.domain.errors import (
    AuthenticationError,
    FormatError,
    LimitError,
    OwlVaultError,
    UnsafePathError,
)
from owl_vault.domain.limits import (
    MAX_CHUNK_SIZE,
    MAX_DEPTH,
    MAX_ENTRIES,
    MAX_FILE_SIZE,
    MAX_MANIFEST_PLAINTEXT,
    MAX_MTIME_NS,
    MIN_CHUNK_SIZE,
    MIN_MTIME_NS,
)
from owl_vault.domain.models import DirEntryRecord, FileEntryRecord
from owl_vault.domain.names import component_problem, fold_path
from owl_vault.storage import manifest as manifest_mod
from owl_vault.storage.container import (
    ContainerKind,
    canonical_json,
    open_sealed,
    seal,
    strict_json_loads,
)
from owl_vault.storage.manifest import (
    Manifest,
    build_manifest,
    entry_from_obj,
    estimate_manifest_size,
    manifest_from_obj,
    manifest_to_obj,
    validate_entries,
)

VID = bytes.fromhex("00112233445566778899aabbccddeeff")
OTHER_VID = bytes.fromhex("ffeeddccbbaa99887766554433221100")
MASTER = bytes(range(32))
MIB = 1024 * 1024
BS = chr(92)  # barra invertida
EMOJI = chr(0x1F600)
SHARP_S = "\N{LATIN SMALL LETTER SHARP S}"
LIG_FI = "\N{LATIN SMALL LIGATURE FI}"
E_ACUTE = "\N{LATIN SMALL LETTER E WITH ACUTE}"
E_ACUTE_UP = "\N{LATIN CAPITAL LETTER E WITH ACUTE}"
COMBINING_ACUTE = "\N{COMBINING ACUTE ACCENT}"
DESERET_SMALL = chr(0x10428)
DESERET_CAPITAL = chr(0x10400)
SUP1 = "\N{SUPERSCRIPT ONE}"

#: rejeição genérica: estrutura (FormatError/LimitError) ou caminho (UnsafePathError)
REJECT = (FormatError, UnsafePathError)


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _hexid(n: int) -> str:
    return f"{n:032x}"


def _dir(*path: Any) -> dict[str, Any]:
    return {"type": "dir", "path": list(path)}


_counter = iter(range(1, 10**9))


def _file(
    *path: Any,
    n: int | None = None,
    size: Any = 3,
    mtime_ns: Any = 1_700_000_000_000_000_000,
    sha256: Any = "ab" * 32,
) -> dict[str, Any]:
    return {
        "type": "file",
        "path": list(path),
        "size": size,
        "mtime_ns": mtime_ns,
        "file_id": _hexid(next(_counter) if n is None else n),
        "sha256": sha256,
    }


def _mobj(entries: list[Any] | None = None, **over: Any) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "kind": "manifest",
        "format_version": 1,
        "vault_id": VID.hex(),
        "chunk_size": 1 * MIB,
        "entries": [] if entries is None else entries,
    }
    obj.update(over)
    return obj


def _text(obj: Any) -> bytes:
    """JSON válido (ASCII, com escapes) — o leitor não exige a forma canônica."""
    return json.dumps(obj, ensure_ascii=True).encode("ascii")


def _load_bytes(data: bytes, vault_id: bytes = VID) -> Manifest:
    return manifest_from_obj(strict_json_loads(data), vault_id)


def _load(obj: Any, vault_id: bytes = VID) -> Manifest:
    return _load_bytes(_text(obj), vault_id)


def _valid_entries() -> list[dict[str, Any]]:
    return [
        _dir("Fotos"),
        _dir("Fotos", "2024"),
        _file("Fotos", "2024", "praia.jpg", size=123456),
        _file("leia-me.txt", size=0),
        _dir("vazia"),
    ]


def _frec(*path: str, n: int, size: int = 1, mtime_ns: int = 0) -> FileEntryRecord:
    return FileEntryRecord(
        path=tuple(path),
        size=size,
        mtime_ns=mtime_ns,
        file_id=n.to_bytes(16, "big"),
        sha256=bytes(32),
    )


def _drec(*path: str) -> DirEntryRecord:
    return DirEntryRecord(tuple(path))


# --------------------------------------------------------------------------------------
# manifestos válidos
# --------------------------------------------------------------------------------------


def test_valid_manifest_parses() -> None:
    m = _load(_mobj(_valid_entries()))
    assert m.vault_id == VID
    assert m.chunk_size == 1 * MIB
    assert len(m.entries) == 5
    assert [e.path for e in m.dirs] == [("Fotos",), ("Fotos", "2024"), ("vazia",)]
    assert [e.path for e in m.files] == [("Fotos", "2024", "praia.jpg"), ("leia-me.txt",)]
    praia = m.files[0]
    assert praia.size == 123456
    assert praia.mtime_ns == 1_700_000_000_000_000_000
    assert len(praia.file_id) == 16
    assert praia.sha256 == bytes.fromhex("ab" * 32)
    assert m.total_bytes() == 123456


def test_parsed_manifest_reserializes_identically() -> None:
    obj = _mobj(
        [
            _dir("Ação"),
            _file("Ação", "日本語 " + EMOJI + ".txt"),
            _file(E_ACUTE + ".txt"),
            _file("e" + COMBINING_ACUTE + ".txt"),  # NFD ≠ NFC: nomes diferentes
            _file(SHARP_S),
            _file("SS"),  # ß não colide com SS
        ]
    )
    m = _load(obj)
    assert canonical_json(manifest_to_obj(m)) == canonical_json(obj)
    # e a forma canônica também é aceita pelo leitor
    assert _load_bytes(canonical_json(obj)) == m


def test_empty_manifest_is_valid() -> None:
    m = _load(_mobj([]))
    assert m.entries == ()


@pytest.mark.parametrize("size", [0, 1, MAX_FILE_SIZE])
def test_size_boundaries_accepted(size: int) -> None:
    assert MAX_FILE_SIZE == 2**40
    assert _load(_mobj([_file("a", size=size)])).files[0].size == size


@pytest.mark.parametrize("mtime_ns", [MIN_MTIME_NS, -1, 0, MAX_MTIME_NS])
def test_mtime_boundaries_accepted(mtime_ns: int) -> None:
    assert MIN_MTIME_NS == -11_644_473_600 * 10**9
    assert MAX_MTIME_NS == 2**63 - 1
    assert _load(_mobj([_file("a", mtime_ns=mtime_ns)])).files[0].mtime_ns == mtime_ns


@pytest.mark.parametrize("chunk", [MIN_CHUNK_SIZE, 128 * 1024, 1 * MIB, MAX_CHUNK_SIZE])
def test_chunk_size_boundaries_accepted(chunk: int) -> None:
    assert _load(_mobj([], chunk_size=chunk)).chunk_size == chunk


# --------------------------------------------------------------------------------------
# JSON estrito / canônico
# --------------------------------------------------------------------------------------


def test_canonical_json_is_the_documented_serializer() -> None:
    obj = {"b": 1, "a": [E_ACUTE, {"z": None, "y": True}], "c": "x"}
    expected = json.dumps(
        obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False, sort_keys=True
    ).encode("utf-8")
    assert canonical_json(obj) == expected
    assert canonical_json(obj) == (
        '{"a":["' + E_ACUTE + '",{"y":true,"z":null}],"b":1,"c":"x"}'
    ).encode("utf-8")
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


@pytest.mark.parametrize(
    "text",
    [
        b'{"a":1,"a":2}',
        b'{"a":1,"a":1}',
        b'{"x":{"k":1,"k":2}}',
        b'[{"k":1},{"k":1,"j":2,"k":3}]',
        # mesma chave depois de decodificar o escape k ("k")
        b'{"k":1,"' + BS.encode() + b'u006b":2}',
    ],
)
def test_strict_json_rejects_duplicate_keys(text: bytes) -> None:
    with pytest.raises(FormatError):
        strict_json_loads(text)


@pytest.mark.parametrize(
    "text", [b"NaN", b"Infinity", b"-Infinity", b'{"size":NaN}', b"[1,Infinity]"]
)
def test_strict_json_rejects_nan_and_infinity(text: bytes) -> None:
    with pytest.raises(FormatError):
        strict_json_loads(text)


@pytest.mark.parametrize(
    "data",
    [
        b'{"a":"\xff"}',  # UTF-8 inválido
        b'{"a":"\xc3"}',  # sequência truncada
        b'{"a":"\xed\xa0\x80"}',  # surrogate codificado em UTF-8 (proibido no UTF-8 estrito)
        b'{"a":"\xc0\xaf"}',  # forma longa (overlong)
        b"\xef\xbb\xbf{}",  # BOM
        b"",
        b"{",
        b'{"a":1',
        b'{"a":1}x',
        b'{"a":1} {"b":2}',
        b"{'a':1}",
        b'{"a":01}',
        b'{"a":1,}',
    ],
)
def test_strict_json_rejects_malformed(data: bytes) -> None:
    with pytest.raises(FormatError):
        strict_json_loads(data)


def test_duplicate_key_in_manifest_text_rejected() -> None:
    good = canonical_json(_mobj([_file("a.txt", n=1)])).decode("utf-8")
    assert _load_bytes(good.encode("utf-8")).files[0].path == ("a.txt",)
    variants = [
        good.replace('"kind":"manifest"', '"kind":"manifest","kind":"manifest"'),
        good.replace('"chunk_size":', '"chunk_size":65536,"chunk_size":'),
        good.replace('"file_id":', '"file_id":"' + _hexid(9) + '","file_id":'),
        good.replace('"size":3', '"size":3,"size":3'),
        good.replace('"type":"file"', '"type":"dir","type":"file"'),
        good.replace('"path":["a.txt"]', '"path":["a.txt"],"path":["b.txt"]'),
    ]
    for text in variants:
        assert text != good
        with pytest.raises(FormatError):
            _load_bytes(text.encode("utf-8"))


# --------------------------------------------------------------------------------------
# esquema: campos ausentes/desconhecidos, tipos, kind
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["kind", "format_version", "vault_id", "chunk_size", "entries"])
def test_missing_top_level_field_rejected(field: str) -> None:
    obj = _mobj(_valid_entries())
    del obj[field]
    with pytest.raises(FormatError):
        _load(obj)


@pytest.mark.parametrize("extra", ["extra", "Kind", "version", "files", ""])
def test_unknown_top_level_field_rejected(extra: str) -> None:
    obj = _mobj(_valid_entries())
    obj[extra] = 1
    with pytest.raises(FormatError):
        _load(obj)


@pytest.mark.parametrize("field", ["type", "path", "size", "mtime_ns", "file_id", "sha256"])
def test_missing_file_field_rejected(field: str) -> None:
    f = _file("a.txt")
    del f[field]
    with pytest.raises(FormatError):
        _load(_mobj([f]))


@pytest.mark.parametrize(
    ("extra", "value"),
    [
        ("fp", {"vol": 1, "fid": _hexid(1), "size": 3, "mtime_ns": 0, "ctime_ns": 0}),
        ("extra", 1),
        ("mode", 0o644),
        ("Size", 3),
        ("ctime_ns", 0),
    ],
)
def test_unknown_file_field_rejected(extra: str, value: Any) -> None:
    f = _file("a.txt")
    f[extra] = value
    with pytest.raises(FormatError):
        _load(_mobj([f]))


@pytest.mark.parametrize(("extra", "value"), [("size", 0), ("file_id", _hexid(5)), ("x", None)])
def test_unknown_dir_field_rejected(extra: str, value: Any) -> None:
    d = _dir("a")
    d[extra] = value
    with pytest.raises(FormatError):
        _load(_mobj([d]))


def test_dir_without_path_rejected() -> None:
    with pytest.raises(FormatError):
        _load(_mobj([{"type": "dir"}]))


@pytest.mark.parametrize("etype", ["symlink", "DIR", "File", "", None, 1, True, ["dir"]])
def test_unknown_entry_type_rejected(etype: Any) -> None:
    e = _file("a.txt")
    e["type"] = etype
    with pytest.raises(FormatError):
        _load(_mobj([e]))


@pytest.mark.parametrize("entry", [[], "dir", 1, None, True, ["type", "dir"]])
def test_entry_not_object_rejected(entry: Any) -> None:
    with pytest.raises(FormatError):
        _load(_mobj([entry]))


@pytest.mark.parametrize("entries", [{}, "[]", None, 1, {"type": "dir", "path": ["a"]}])
def test_entries_not_list_rejected(entries: Any) -> None:
    obj = _mobj([])
    obj["entries"] = entries
    with pytest.raises(FormatError):
        _load(obj)


@pytest.mark.parametrize("top", [[], "manifest", None, 1, True])
def test_top_level_not_object_rejected(top: Any) -> None:
    with pytest.raises(FormatError):
        _load(top)


@pytest.mark.parametrize("kind", ["journal", "completion", "Manifest", "MANIFEST", "", None, 1])
def test_wrong_kind_rejected(kind: Any) -> None:
    with pytest.raises(FormatError):
        _load(_mobj(_valid_entries(), kind=kind))


@pytest.mark.parametrize("version", [0, 2, 65535, 65536, 2**16 + 1, -1])
def test_unsupported_format_version_rejected(version: int) -> None:
    with pytest.raises(FormatError):
        _load(_mobj([], format_version=version))


# --- bool onde se espera inteiro (True == 1 em Python!) ---------------------------------


def test_bool_format_version_rejected() -> None:
    # json.loads("true") é True, e True == 1 em Python: o leitor precisa recusar mesmo assim
    with pytest.raises(FormatError):
        _load(_mobj([], format_version=True))


@pytest.mark.parametrize("field", ["size", "mtime_ns"])
@pytest.mark.parametrize("value", [True, False])
def test_bool_file_ints_rejected(field: str, value: bool) -> None:
    f = _file("a.txt")
    f[field] = value
    with pytest.raises(FormatError):
        _load(_mobj([f]))


def test_bool_chunk_size_rejected() -> None:
    with pytest.raises(FormatError):
        _load(_mobj([], chunk_size=True))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("size", 3.0),
        ("size", "3"),
        ("size", None),
        ("size", [3]),
        ("mtime_ns", 1.5),
        ("mtime_ns", "0"),
        ("mtime_ns", None),
        ("file_id", 12345),
        ("file_id", None),
        ("sha256", ["ab"]),
    ],
)
def test_wrong_value_types_in_file_rejected(field: str, value: Any) -> None:
    f = _file("a.txt")
    f[field] = value
    with pytest.raises(FormatError):
        _load(_mobj([f]))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("format_version", "1"),
        ("format_version", 1.0),
        ("format_version", None),
        ("chunk_size", float(MIB)),
        ("chunk_size", str(MIB)),
        ("vault_id", 1),
        ("vault_id", None),
        ("vault_id", list(VID)),
    ],
)
def test_wrong_value_types_top_level_rejected(field: str, value: Any) -> None:
    with pytest.raises(FormatError):
        _load(_mobj([], **{field: value}))


def test_float_from_json_exponent_rejected() -> None:
    # 1e3 vira float no JSON — não é inteiro
    text = canonical_json(_mobj([_file("a", n=1, size=1000)])).replace(
        b'"size":1000', b'"size":1e3'
    )
    with pytest.raises(FormatError):
        _load_bytes(text)


# --- limites numéricos -----------------------------------------------------------------


@pytest.mark.parametrize("size", [-1, MAX_FILE_SIZE + 1, 2**63, 2**64, 10**30])
def test_size_out_of_range_rejected(size: int) -> None:
    with pytest.raises(LimitError):
        _load(_mobj([_file("a", size=size)]))


@pytest.mark.parametrize(
    "mtime_ns", [MIN_MTIME_NS - 1, MAX_MTIME_NS + 1, MIN_MTIME_NS * 2, 2**64, -(10**30)]
)
def test_mtime_out_of_range_rejected(mtime_ns: int) -> None:
    with pytest.raises(LimitError):
        _load(_mobj([_file("a", mtime_ns=mtime_ns)]))


@pytest.mark.parametrize(
    "chunk",
    [
        0,
        -1,
        1,
        4096,
        MIN_CHUNK_SIZE - 1,
        MIN_CHUNK_SIZE + 1,
        3 * MIN_CHUNK_SIZE,
        MIB + 1,
        2 * MAX_CHUNK_SIZE,
        2**32,
        2**33,
    ],
)
def test_invalid_chunk_size_rejected(chunk: int) -> None:
    with pytest.raises(FormatError):
        _load(_mobj([], chunk_size=chunk))


# --- hex: minúsculo, comprimento exato --------------------------------------------------


def _hex_variants(nbytes: int) -> list[str]:
    good = "a1" * nbytes
    return [
        good.upper(),
        "A1" + "a1" * (nbytes - 1),  # caixa mista
        good[:-1],  # 1 dígito a menos
        good + "a",  # 1 dígito a mais
        good[:-2],  # 1 byte a menos
        good + "a1",  # 1 byte a mais
        "",
        "g" + good[1:],  # não hex
        "0x" + good[2:],  # prefixo
        "-" + good[1:],
        "\N{FULLWIDTH DIGIT ONE}" + good[1:],  # dígito não ASCII
    ]


@pytest.mark.parametrize("field,nbytes", [("file_id", 16), ("sha256", 32)])
def test_bad_hex_in_file_entry_rejected(field: str, nbytes: int) -> None:
    for bad in _hex_variants(nbytes):
        f = _file("a.txt")
        f[field] = bad
        with pytest.raises(FormatError):
            _load(_mobj([f]))


def test_bad_hex_vault_id_rejected() -> None:
    for bad in _hex_variants(16):
        with pytest.raises(FormatError):
            _load(_mobj([], vault_id=bad))


def test_uppercase_vault_id_rejected_even_if_bytes_match() -> None:
    with pytest.raises(FormatError):
        _load(_mobj([], vault_id=VID.hex().upper()))


def _whitespace_padded(nbytes: int) -> list[str]:
    # Mesmo número de CARACTERES que o hex correto, mas com espaço em branco ASCII (que
    # ``bytes.fromhex`` ignora) ⇒ decodifica para nbytes-1 bytes. Não é "<32 hex>"/"<64 hex>".
    body = "a1" * (nbytes - 1)
    return [" " + body + " ", "\t" + body + "\n", body[:4] + "  " + body[4:], body + "\r\n"]


@pytest.mark.parametrize("field,nbytes", [("file_id", 16), ("sha256", 32)])
def test_whitespace_in_hex_rejected(field: str, nbytes: int) -> None:
    for bad in _whitespace_padded(nbytes):
        assert len(bad) == 2 * nbytes
        f = _file("a.txt")
        f[field] = bad
        with pytest.raises(FormatError):
            _load(_mobj([f]))


def test_whitespace_in_vault_id_rejected() -> None:
    for bad in _whitespace_padded(16):
        with pytest.raises(FormatError):
            _load(_mobj([], vault_id=bad))


# --- vault_id ---------------------------------------------------------------------------


def test_manifest_of_other_vault_rejected() -> None:
    obj = _mobj(_valid_entries())
    assert _load(obj, VID)
    with pytest.raises(FormatError):
        _load(obj, OTHER_VID)
    with pytest.raises(FormatError):
        _load(_mobj(_valid_entries(), vault_id=OTHER_VID.hex()), VID)


# --------------------------------------------------------------------------------------
# caminhos (FORMAT §5.2)
# --------------------------------------------------------------------------------------

BAD_COMPONENTS = [
    "..",
    ".",
    "",
    "C:",
    "c:",
    "a:b",  # ADS
    "file.txt:Zone.Identifier",
    "a:b:$DATA",
    "::$DATA",
    BS,
    "/",
    "a" + BS + "b",
    "a/b",
    ".." + BS + "x",
    "../x",
    BS + BS + "?" + BS + "C:",
    "C:" + BS + "Windows",
    "C:" + BS,
    "/etc",
    BS + "Windows",
    BS + BS + "server" + BS + "share",
    "CON",
    "con.txt",
    "CON.tar.gz",
    "NUL .txt",
    "COM" + SUP1,
    "lpt3",
    "CONIN$",
    "conout$.log",
    "a.",
    "a ",
    "...",
    "a\x00b",
    "a\x1fb",
    "a\tb",
    "a\nb",
    "a<b",
    "a>b",
    'a"b',
    "a|b",
    "a?b",
    "a*b",
    "x" * 256,
    EMOJI * 128,
    chr(0xD800),
    "a" + chr(0xDC00),
]


@pytest.mark.parametrize("comp", BAD_COMPONENTS)
def test_bad_component_as_file_rejected(comp: str) -> None:
    assert component_problem(comp) is not None
    with pytest.raises(UnsafePathError):
        _load(_mobj([_file(comp)]))


@pytest.mark.parametrize("comp", BAD_COMPONENTS)
def test_bad_component_in_middle_of_path_rejected(comp: str) -> None:
    entries = [_dir("a"), _dir("a", comp), _file("a", comp, "x.txt")]
    with pytest.raises(UnsafePathError):
        _load(_mobj(entries))


@pytest.mark.parametrize(
    "path",
    [
        ["C:", "Windows", "x.txt"],
        ["", "etc", "passwd"],
        [BS + BS + "server", "share", "x"],
        [BS + BS + "?" + BS + "C:" + BS, "x"],
        ["C:" + BS + "Users", "x"],
        ["/", "x"],
        [BS, "x"],
        ["a", "..", "..", "x"],
        ["..", "x"],
    ],
)
def test_absolute_or_traversal_paths_rejected(path: list[str]) -> None:
    dirs = [_dir(*path[:i]) for i in range(1, len(path))]
    with pytest.raises(UnsafePathError):
        _load(_mobj([*dirs, _file(*path)]))


@pytest.mark.parametrize("path", ["a/b", "a" + BS + "b", "x.txt", None, 1, {"0": "a"}, []])
def test_path_must_be_nonempty_list(path: Any) -> None:
    f = _file("x")
    f["path"] = path
    with pytest.raises(REJECT):
        _load(_mobj([f]))
    d = {"type": "dir", "path": path}
    with pytest.raises(REJECT):
        _load(_mobj([d]))


@pytest.mark.parametrize("comp", [1, None, True, ["a"], {"a": 1}, 1.5])
def test_non_string_component_rejected(comp: Any) -> None:
    f = _file("a", "x")
    f["path"] = ["a", comp]
    with pytest.raises(REJECT):
        _load(_mobj([_dir("a"), f]))
    with pytest.raises(REJECT):
        _load(_mobj([_dir(comp)]))


def test_depth_limit() -> None:
    assert MAX_DEPTH == 256
    ok_entries = [_dir(*(["d"] * i)) for i in range(1, MAX_DEPTH)]
    ok_entries.append(_file(*(["d"] * (MAX_DEPTH - 1)), "f"))
    m = _load(_mobj(ok_entries))
    assert max(len(e.path) for e in m.entries) == MAX_DEPTH

    too_deep = [_dir(*(["d"] * i)) for i in range(1, MAX_DEPTH + 1)]
    too_deep.append(_file(*(["d"] * MAX_DEPTH), "f"))
    with pytest.raises(REJECT):
        _load(_mobj(too_deep))
    with pytest.raises(REJECT):
        _load(_mobj([_dir(*(["d"] * i)) for i in range(1, MAX_DEPTH + 2)]))


def test_lone_surrogate_escape_in_json_rejected() -> None:
    # "\ud800" sozinho no JSON vira surrogate órfão ⇒ não é UTF-16 estrito
    esc_lone = BS + "ud800"
    text = canonical_json(_mobj([_file("PLACEHOLDER", n=1)])).replace(
        b"PLACEHOLDER", ("x" + esc_lone + "y").encode("ascii")
    )
    with pytest.raises(UnsafePathError):
        _load_bytes(text)


def test_valid_surrogate_pair_escape_in_json_accepted() -> None:
    esc_pair = BS + "ud83d" + BS + "ude00"  # 😀 escrito como par de escapes
    text = canonical_json(_mobj([_file("PLACEHOLDER", n=1)])).replace(
        b"PLACEHOLDER", ("x" + esc_pair + "y").encode("ascii")
    )
    m = _load_bytes(text)
    assert m.files[0].path == ("x" + EMOJI + "y",)


def test_max_length_component_accepted() -> None:
    names = ["a" * 255, EMOJI * 127 + "b", E_ACUTE * 255]
    m = _load(_mobj([_file(n) for n in names]))
    assert [f.path[0] for f in m.files] == names


# --------------------------------------------------------------------------------------
# regras de conjunto (sobre caminhos dobrados)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entries",
    [
        [_dir("Fotos"), _dir("FOTOS")],
        [_dir("fotos"), _dir("Fotos")],
        [_file("a.txt"), _file("A.TXT")],
        [_file("ação.txt"), _file("AÇÃO.TXT")],
        [_file(E_ACUTE), _file(E_ACUTE_UP)],
        [_dir("Fotos"), _file("Fotos", "Praia.jpg"), _file("Fotos", "praia.JPG")],
        [_dir("x"), _file("X")],  # arquivo e pasta com o mesmo caminho dobrado
        [_file("x"), _dir("X")],
        [_file("same"), _file("same")],  # duplicata exata
        [_dir("same"), _dir("same")],
        [_dir("a"), _dir("a", "b"), _dir("A", "B")],
    ],
)
def test_case_fold_duplicates_rejected(entries: list[dict[str, Any]]) -> None:
    with pytest.raises(UnsafePathError):
        _load(_mobj(entries))


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (SHARP_S, "SS"),
        (SHARP_S, "ss"),
        ("Straße", "STRASSE"),
        (LIG_FI, "FI"),
        (LIG_FI + "le", "file"),
        (E_ACUTE, "e" + COMBINING_ACUTE),  # NFC × NFD
        (DESERET_SMALL, DESERET_CAPITAL),  # fora do BMP não é dobrado
    ],
)
def test_no_false_case_collisions(a: str, b: str) -> None:
    m = _load(_mobj([_file(a), _file(b)]))
    assert [f.path[0] for f in m.files] == [a, b]


def test_parent_matched_by_folded_path() -> None:
    # FORMAT §5.2: as regras de conjunto usam listas de componentes DOBRADAS
    m = _load(_mobj([_dir("Fotos"), _file("FOTOS", "a.jpg"), _dir("fotos", "Sub")]))
    assert len(m.entries) == 3


@pytest.mark.parametrize(
    "entries",
    [
        [_file("a"), _file("a", "b")],
        [_file("a"), _dir("a", "b")],
        [_file("a"), _dir("A", "b")],
        [_file("a"), _dir("a", "b"), _file("a", "b", "c")],
        [_dir("d"), _file("d", "f"), _file("d", "f", "g")],
        [_dir("d"), _file("d", "f"), _dir("d", "f", "g"), _file("d", "f", "g", "h")],
    ],
)
def test_file_as_parent_rejected(entries: list[dict[str, Any]]) -> None:
    with pytest.raises(UnsafePathError):
        _load(_mobj(entries))


@pytest.mark.parametrize(
    "entries",
    [
        [_file("x", "y")],
        [_dir("a", "b")],
        [_dir("a"), _file("a", "b", "c")],
        [_dir("a"), _dir("a", "b", "c")],
        [_dir("a"), _dir("b", "c")],
    ],
)
def test_missing_parent_dir_rejected(entries: list[dict[str, Any]]) -> None:
    with pytest.raises(UnsafePathError):
        _load(_mobj(entries))


def test_parent_listed_after_child_is_still_present() -> None:
    m = _load(_mobj([_file("a", "b", "c"), _dir("a", "b"), _dir("a")]))
    assert len(m.entries) == 3


def test_duplicate_file_id_rejected() -> None:
    with pytest.raises(FormatError):
        _load(_mobj([_file("a", n=7), _file("b", n=7)]))
    with pytest.raises(FormatError):
        _load(_mobj([_dir("d"), _file("a", n=7), _file("d", "a", n=7)]))
    # ids diferentes ⇒ ok
    assert len(_load(_mobj([_file("a", n=7), _file("b", n=8)])).files) == 2


def test_too_many_entries_real_limit() -> None:
    assert MAX_ENTRIES == 1_000_000
    entry = _dir("a")
    with pytest.raises(LimitError):
        manifest_from_obj(_mobj([entry] * (MAX_ENTRIES + 1)), VID)
    with pytest.raises(LimitError):
        validate_entries((DirEntryRecord(("a",)),) * (MAX_ENTRIES + 1))


def test_too_many_entries_small_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(manifest_mod, "MAX_ENTRIES", 3)
    three = [_dir("a"), _file("a", "b"), _file("c")]
    assert len(_load(_mobj(three)).entries) == 3
    with pytest.raises(LimitError):
        _load(_mobj([*three, _file("d")]))
    recs = [_drec("a"), _frec("a", "b", n=1), _frec("c", n=2), _frec("d", n=3)]
    with pytest.raises(LimitError):
        validate_entries(recs)
    with pytest.raises(LimitError):
        build_manifest(VID, MIB, recs)
    assert len(build_manifest(VID, MIB, recs[:3]).entries) == 3


def test_validator_rejects_whole_manifest_on_single_bad_entry() -> None:
    good = [_dir(f"d{i}") for i in range(50)] + [_file(f"d{i}", "f.txt") for i in range(50)]
    assert len(_load(_mobj(good)).entries) == 100
    for bad in (_file("CON"), _file("d3", "F.TXT"), _file("nada", "x"), _file("d7", "..")):
        with pytest.raises(UnsafePathError):
            _load(_mobj([*good, bad]))


# --- entry_from_obj com impressão digital (formato do diário) ---------------------------


def test_entry_from_obj_with_fp_is_strict() -> None:
    fp = {"vol": 7, "fid": "ab" * 16, "size": 3, "mtime_ns": 0, "ctime_ns": 0}
    e = {**_file("a.txt"), "fp": fp}
    entry, got = entry_from_obj(e, with_fp=True)
    assert isinstance(entry, FileEntryRecord)
    assert got is not None and got.identity.volume_serial == 7
    with pytest.raises(FormatError):
        entry_from_obj(_file("a.txt"), with_fp=True)  # fp ausente
    for bad_fp in (
        {**fp, "extra": 1},
        {k: v for k, v in fp.items() if k != "ctime_ns"},
        {**fp, "vol": True},
        {**fp, "fid": "AB" * 16},
        {**fp, "size": -1},
        [],
    ):
        with pytest.raises(FormatError):
            entry_from_obj({**_file("a.txt"), "fp": bad_fp}, with_fp=True)


# --------------------------------------------------------------------------------------
# build_manifest (escritor)
# --------------------------------------------------------------------------------------


def _sample_records() -> list[DirEntryRecord | FileEntryRecord]:
    return [
        _frec("b", "z.txt", n=1, size=10),
        _drec("b"),
        _frec("A.txt", n=2),
        _drec("Ação"),
        _frec("Ação", EMOJI + ".bin", n=3, size=2**40, mtime_ns=MIN_MTIME_NS),
        _frec("c", n=4, mtime_ns=MAX_MTIME_NS),
    ]


def test_build_manifest_sorts_deterministically_and_roundtrips() -> None:
    recs = _sample_records()
    m1 = build_manifest(VID, MIB, recs)
    m2 = build_manifest(VID, MIB, list(reversed(recs)))
    rng = random.Random(3)  # noqa: S311 (semente fixa, sem uso criptográfico)
    shuffled = list(recs)
    rng.shuffle(shuffled)
    m3 = build_manifest(VID, MIB, shuffled)
    assert m1 == m2 == m3
    keys = [fold_path(e.path) for e in m1.entries]
    assert keys == sorted(keys)
    raw = canonical_json(manifest_to_obj(m1))
    assert _load_bytes(raw) == m1


@pytest.mark.parametrize(
    "recs",
    [
        [_frec("a.txt", n=1), _frec("A.TXT", n=2)],
        [_drec("d"), _drec("D")],
        [_frec("CON", n=1)],
        [_frec("NUL .txt", n=1)],
        [_frec("x", "y", n=1)],  # pai ausente
        [_frec("f", n=1), _frec("f", "g", n=2)],  # arquivo como pai
        [_frec("a", n=1), _frec("b", n=1)],  # file_id duplicado
        [_frec("a.", n=1)],
        [_frec("..", n=1)],
        [_frec("a:b", n=1)],
        [_frec(chr(0xD800), n=1)],
        [DirEntryRecord(())],
    ],
)
def test_build_manifest_runs_reader_validator(recs: list[Any]) -> None:
    with pytest.raises(REJECT):
        build_manifest(VID, MIB, recs)


@pytest.mark.parametrize(
    "rec",
    [
        _frec("a", n=1, size=-1),
        _frec("a", n=1, size=MAX_FILE_SIZE + 1),
        _frec("a", n=1, mtime_ns=MIN_MTIME_NS - 1),
        _frec("a", n=1, mtime_ns=MAX_MTIME_NS + 1),
    ],
)
def test_build_manifest_rejects_out_of_range_numbers(rec: FileEntryRecord) -> None:
    with pytest.raises(LimitError):
        build_manifest(VID, MIB, [rec])


def test_build_manifest_enforces_serialized_size_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    assert MAX_MANIFEST_PLAINTEXT == 256 * MIB
    recs = _sample_records()
    exact = len(canonical_json(manifest_to_obj(build_manifest(VID, MIB, recs))))
    monkeypatch.setattr(manifest_mod, "MAX_MANIFEST_PLAINTEXT", exact)
    assert len(build_manifest(VID, MIB, recs).entries) == len(recs)  # no limite: ok
    monkeypatch.setattr(manifest_mod, "MAX_MANIFEST_PLAINTEXT", exact - 1)
    with pytest.raises(LimitError):
        build_manifest(VID, MIB, recs)


def test_build_manifest_cap_counts_utf8_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    # nomes com caracteres de 3/4 bytes em UTF-8: o limite é sobre BYTES serializados
    recs = [_frec("日" * 200, n=1), _frec(EMOJI * 100, n=2)]
    obj = manifest_to_obj(build_manifest(VID, MIB, recs))
    exact = len(canonical_json(obj))
    code_points = len(
        json.dumps(obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False, sort_keys=True)
    )
    assert exact - code_points == 200 * 2 + 100 * 3  # 日 = 3 bytes, 😀 = 4 bytes
    monkeypatch.setattr(manifest_mod, "MAX_MANIFEST_PLAINTEXT", exact - 1)
    with pytest.raises(LimitError):
        build_manifest(VID, MIB, recs)
    monkeypatch.setattr(manifest_mod, "MAX_MANIFEST_PLAINTEXT", code_points)
    with pytest.raises(LimitError):
        build_manifest(VID, MIB, recs)


# --------------------------------------------------------------------------------------
# estimate_manifest_size
# --------------------------------------------------------------------------------------

_NAME_ALPHABET = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    " ._-'&#%{}~$@!+=,;()[]"
    "áéíóúâêôãõçÁÉÍÓÚÂÊÔÃÕÇàüñ"
    + SHARP_S
    + LIG_FI
    + COMBINING_ACUTE
    + "日本語中文한국어Ελληνικάрусский"
    + "\N{EURO SIGN}\N{NO-BREAK SPACE}\N{LINE SEPARATOR}\N{ZERO WIDTH JOINER}\x7f"
    + EMOJI
    + chr(0x1F680)
    + DESERET_SMALL
    + DESERET_CAPITAL
    + chr(0x20000)
)


def _random_name(rng: random.Random) -> str:
    while True:
        n = "".join(rng.choice(_NAME_ALPHABET) for _ in range(rng.randint(1, 40)))
        if component_problem(n) is None:
            return n


def _random_tree(
    rng: random.Random, n_dirs: int, n_files: int
) -> list[DirEntryRecord | FileEntryRecord]:
    dirs: list[tuple[str, ...]] = []
    taken: set[tuple[str, ...]] = set()

    def fresh(parent: tuple[str, ...]) -> tuple[str, ...]:
        while True:
            p = (*parent, _random_name(rng))
            if fold_path(p) not in taken:
                taken.add(fold_path(p))
                return p

    for _ in range(n_dirs):
        parent = rng.choice([(), *dirs]) if dirs else ()
        if len(parent) >= 20:
            parent = ()
        dirs.append(fresh(parent))
    recs: list[DirEntryRecord | FileEntryRecord] = [DirEntryRecord(d) for d in dirs]
    for _ in range(n_files):
        parent = rng.choice([(), *dirs])
        recs.append(
            FileEntryRecord(
                path=fresh(parent),
                size=rng.choice([0, 1, rng.randrange(0, MAX_FILE_SIZE + 1), MAX_FILE_SIZE]),
                mtime_ns=rng.choice(
                    [0, MIN_MTIME_NS, MAX_MTIME_NS, rng.randrange(MIN_MTIME_NS, MAX_MTIME_NS + 1)]
                ),
                file_id=rng.randbytes(16),
                sha256=rng.randbytes(32),
            )
        )
    return recs


def _paths(recs: list[Any]) -> list[tuple[tuple[str, ...], bool]]:
    return [(e.path, isinstance(e, FileEntryRecord)) for e in recs]


@pytest.mark.parametrize("seed", range(12))
@pytest.mark.parametrize("chunk", [MIN_CHUNK_SIZE, MIB, MAX_CHUNK_SIZE])
def test_estimate_is_upper_bound_for_random_unicode_trees(seed: int, chunk: int) -> None:
    rng = random.Random(seed * 1000 + chunk)  # noqa: S311 (semente fixa, sem uso criptográfico)
    recs = _random_tree(rng, n_dirs=rng.randint(0, 40), n_files=rng.randint(0, 120))
    m = build_manifest(VID, chunk, recs)
    actual = len(canonical_json(manifest_to_obj(m)))
    est = estimate_manifest_size(_paths(recs))
    assert est >= actual
    # A folga é exatamente a diferença de largura dos campos numéricos (o resto é idêntico):
    slack = len(str(MAX_CHUNK_SIZE)) - len(str(chunk))
    for f in m.files:
        slack += len(str(MAX_FILE_SIZE)) - len(str(f.size))
        slack += len(str(MIN_MTIME_NS)) - len(str(f.mtime_ns))
    assert est - actual == slack
    # a ordem de entrada não importa
    shuffled = _paths(recs)
    rng.shuffle(shuffled)
    assert estimate_manifest_size(shuffled) == est


def test_estimate_is_exact_with_widest_values() -> None:
    rng = random.Random(99)  # noqa: S311 (semente fixa, sem uso criptográfico)
    recs = _random_tree(rng, n_dirs=30, n_files=80)
    widest = [
        FileEntryRecord(e.path, MAX_FILE_SIZE, MIN_MTIME_NS, e.file_id, e.sha256)
        if isinstance(e, FileEntryRecord)
        else e
        for e in recs
    ]
    m = build_manifest(VID, MAX_CHUNK_SIZE, widest)
    assert estimate_manifest_size(_paths(widest)) == len(canonical_json(manifest_to_obj(m)))


@pytest.mark.parametrize(
    "paths",
    [
        [],
        [(("a",), False)],
        [(("a",), True)],
        [(("pasta",), False), (("pasta", "日本語 " + EMOJI + ".txt"), True)],
    ],
)
def test_estimate_small_cases(paths: list[tuple[tuple[str, ...], bool]]) -> None:
    recs: list[Any] = []
    for i, (p, is_file) in enumerate(paths, start=1):
        recs.append(
            FileEntryRecord(p, MAX_FILE_SIZE, MIN_MTIME_NS, i.to_bytes(16, "big"), bytes(32))
            if is_file
            else DirEntryRecord(p)
        )
    m = Manifest(VID, MAX_CHUNK_SIZE, tuple(recs))
    assert estimate_manifest_size(paths) == len(canonical_json(manifest_to_obj(m)))


def test_estimate_scales_with_utf8_bytes_not_code_points() -> None:
    ascii_est = estimate_manifest_size([(("a" * 100,), True)])
    cjk_est = estimate_manifest_size([(("日" * 100,), True)])  # 3 bytes cada
    emoji_est = estimate_manifest_size([((EMOJI * 100,), True)])  # 4 bytes cada
    assert cjk_est - ascii_est == 200
    assert emoji_est - ascii_est == 300


# --------------------------------------------------------------------------------------
# contêiner: JSON estrito depois da autenticação (FORMAT §5)
# --------------------------------------------------------------------------------------

_HDR = struct.Struct(">8sHHI16s16s12sI")


def _seal_plaintext(kind: ContainerKind, plaintext: bytes, vault_id: bytes = VID) -> bytes:
    """Contêiner AUTÊNTICO com texto claro arbitrário (simula um escritor com a chave)."""
    key_id = os.urandom(16)
    nonce = os.urandom(12)
    header = _HDR.pack(kind.magic, 1, 64, 0, vault_id, key_id, nonce, 0)
    key = derive_subkey(MASTER, vault_id, kind.purpose, key_id)
    return header + AESGCM(key).encrypt(nonce, plaintext, header)


def test_seal_and_open_roundtrip() -> None:
    obj = manifest_to_obj(build_manifest(VID, MIB, _sample_records()))
    raw = seal(ContainerKind.MANIFEST, MASTER, VID, obj)
    assert open_sealed(ContainerKind.MANIFEST, MASTER, VID, raw) == obj
    # o helper de teste produz o mesmo formato
    raw2 = _seal_plaintext(ContainerKind.MANIFEST, canonical_json(obj))
    assert manifest_from_obj(open_sealed(ContainerKind.MANIFEST, MASTER, VID, raw2), VID)


@pytest.mark.parametrize(
    "plaintext",
    [
        b'{"kind":"manifest","kind":"manifest"}',
        b'{"kind":"manifest","format_version":1,"format_version":1}',
        b'{"kind":"manifest","x":NaN}',
        b'{"kind":"manifest","x":-Infinity}',
        b'{"kind":"manifest","x":"\xff"}',
        b'{"kind":"manifest"',
        b"",
    ],
)
def test_authentic_container_with_hostile_json_rejected(plaintext: bytes) -> None:
    raw = _seal_plaintext(ContainerKind.MANIFEST, plaintext)
    with pytest.raises(FormatError):
        open_sealed(ContainerKind.MANIFEST, MASTER, VID, raw)


@pytest.mark.parametrize(
    "obj",
    [
        {"kind": "journal"},
        {"kind": "completion"},
        {"kind": "Manifest"},
        {"no_kind": 1},
        [{"kind": "manifest"}],
        "manifest",
        None,
    ],
)
def test_authentic_container_with_wrong_kind_rejected(obj: Any) -> None:
    raw = _seal_plaintext(ContainerKind.MANIFEST, canonical_json(obj))
    with pytest.raises(FormatError):
        open_sealed(ContainerKind.MANIFEST, MASTER, VID, raw)


def test_authentic_container_with_duplicate_keys_in_entry_rejected() -> None:
    good = canonical_json(_mobj([_file("a.txt", n=1)]))
    bad = good.replace(b'"size":3', b'"size":3,"size":4')
    assert bad != good
    raw_good = _seal_plaintext(ContainerKind.MANIFEST, good)
    assert manifest_from_obj(open_sealed(ContainerKind.MANIFEST, MASTER, VID, raw_good), VID)
    with pytest.raises(FormatError):
        open_sealed(
            ContainerKind.MANIFEST, MASTER, VID, _seal_plaintext(ContainerKind.MANIFEST, bad)
        )


def test_container_of_other_vault_or_wrong_magic_rejected() -> None:
    obj = _mobj([])
    raw = seal(ContainerKind.MANIFEST, MASTER, VID, obj)
    with pytest.raises(FormatError):
        open_sealed(ContainerKind.MANIFEST, MASTER, OTHER_VID, raw)
    with pytest.raises(FormatError):
        open_sealed(ContainerKind.JOURNAL, MASTER, VID, raw)
    tampered = bytearray(raw)
    tampered[-1] ^= 1
    with pytest.raises(AuthenticationError):
        open_sealed(ContainerKind.MANIFEST, MASTER, VID, bytes(tampered))


def test_writer_checks_plaintext_limit_before_encrypting() -> None:
    # Mesmo limite do leitor (FORMAT §5): conclusão = 1 MiB de texto claro.
    limit = ContainerKind.COMPLETE.max_plaintext
    assert limit == 1 * MIB
    base = canonical_json({"kind": "completion", "pad": ""})
    fits = {"kind": "completion", "pad": "x" * (limit - len(base))}
    assert len(canonical_json(fits)) == limit
    raw = seal(ContainerKind.COMPLETE, MASTER, VID, fits)
    assert len(raw) == ContainerKind.COMPLETE.max_file_size
    assert open_sealed(ContainerKind.COMPLETE, MASTER, VID, raw) == fits
    too_big = {"kind": "completion", "pad": "x" * (limit - len(base) + 1)}
    with pytest.raises(LimitError):
        seal(ContainerKind.COMPLETE, MASTER, VID, too_big)


def test_reader_checks_file_size_before_decrypting() -> None:
    limit = ContainerKind.COMPLETE.max_plaintext
    raw = _seal_plaintext(ContainerKind.COMPLETE, b"x" * (limit + 1))
    assert len(raw) == ContainerKind.COMPLETE.max_file_size + 1
    with pytest.raises(LimitError):
        open_sealed(ContainerKind.COMPLETE, MASTER, VID, raw)


def test_limits_are_owl_vault_errors() -> None:
    # A camada de aplicação trata OwlVaultError; nada aqui deve escapar como outro tipo.
    for exc in (FormatError, LimitError, UnsafePathError, AuthenticationError):
        assert issubclass(exc, OwlVaultError)
    assert issubclass(LimitError, FormatError)
