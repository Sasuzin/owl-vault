"""Nomes Windows e dobra de caixa (FORMAT §5.2) — ``owl_vault.domain.names``.

Funções puras: nenhum teste aqui toca o disco.

Diferenças intencionais documentadas em relação a ``ntpath.isreserved`` (Python 3.13):

* ``COM0``/``LPT0`` são reservados no Owl Vault (FORMAT §5.2 lista ``COM0–COM9`` e
  ``LPT0–LPT9``), mas não no Python. O Owl Vault é mais conservador.
* ``is_reserved_name`` cobre apenas nomes de DISPOSITIVO. Caracteres proibidos e ponto/espaço
  final (que ``isreserved`` também considera "reservados") são recusados por
  ``component_problem``, que é a função usada na validação.
* ``.`` e ``..`` não são "reservados" para o Python, mas ``component_problem`` os recusa.
"""

from __future__ import annotations

import ntpath
import random

import pytest

from owl_vault.domain.errors import UnsafePathError
from owl_vault.domain.limits import MAX_COMPONENT_UTF16, MAX_DEPTH
from owl_vault.domain.names import (
    component_problem,
    display_path,
    fold,
    fold_path,
    is_reserved_name,
    is_short_name_legal,
    utf16_len,
    validate_component,
    validate_relative_path,
)

BS = chr(92)  # barra invertida (evita escapes ambíguos no código-fonte)
SUP0 = "\N{SUPERSCRIPT ZERO}"
SUP1 = "\N{SUPERSCRIPT ONE}"
SUP2 = "\N{SUPERSCRIPT TWO}"
SUP3 = "\N{SUPERSCRIPT THREE}"
SUP4 = "\N{SUPERSCRIPT FOUR}"
SHARP_S = "\N{LATIN SMALL LETTER SHARP S}"
LIG_FI = "\N{LATIN SMALL LIGATURE FI}"
E_ACUTE = "\N{LATIN SMALL LETTER E WITH ACUTE}"
E_ACUTE_UP = "\N{LATIN CAPITAL LETTER E WITH ACUTE}"
COMBINING_ACUTE = "\N{COMBINING ACUTE ACCENT}"
EMOJI = chr(0x1F600)  # fora do BMP: 2 unidades UTF-16
DESERET_SMALL = chr(0x10428)  # minúscula fora do BMP cujo upper() existe (U+10400)
DESERET_CAPITAL = chr(0x10400)
HIGH_SURROGATE = chr(0xD83D)
LOW_SURROGATE = chr(0xDE00)


# --------------------------------------------------------------------------------------
# nomes reservados
# --------------------------------------------------------------------------------------

RESERVED = [
    "CON",
    "con",
    "Con",
    "cOn",
    "PRN",
    "prn",
    "AUX",
    "aux",
    "NUL",
    "nul",
    "CONIN$",
    "conin$",
    "CONOUT$",
    "Conout$",
    *[f"COM{d}" for d in "0123456789"],
    *[f"LPT{d}" for d in "0123456789"],
    "com1",
    "lpt9",
    "Com0",
    "lPt0",
    f"COM{SUP1}",
    f"COM{SUP2}",
    f"COM{SUP3}",
    f"com{SUP1}",
    f"LPT{SUP1}",
    f"LPT{SUP2}",
    f"LPT{SUP3}",
    f"lpt{SUP3}",
    # com extensão(ões) — exemplos do FORMAT §5.2
    "CON.tar.gz",
    "NUL .txt",
    "nul.txt",
    "NUL  .txt",
    "AUX.c",
    "PRN.anything.else",
    "COM1.txt",
    "LPT1 .log",
    "CONIN$.txt",
    "conout$.dat",
    f"COM{SUP1}.txt",
    "con.",
    "NUL..txt",
    "cOn.TxT",
]

NOT_RESERVED = [
    "CONSOLE",
    "CON1",
    "CONX",
    "XCON",
    "NULL",
    "AUXX",
    "PRNT",
    "COM",
    "LPT",
    "COM10",
    "LPT10",
    "COM00",
    f"COM{SUP4}",
    f"COM{SUP0}",
    f"LPT{SUP4}",
    f"COM1{SUP1}",
    "CONIN",
    "CONOUT",
    "CONIN$$",
    "CON_",
    "CON-1",
    ".CON",
    "my CON",
    "aux2",
    "nul_",
    "CO N",
    "C0N",
    "COM1x",
    "COM 1",
    "CON~1",
    "\N{FULLWIDTH LATIN CAPITAL LETTER C}\N{FULLWIDTH LATIN CAPITAL LETTER O}"
    "\N{FULLWIDTH LATIN CAPITAL LETTER N}",
    "readme.txt",
    "a",
]


@pytest.mark.parametrize("name", RESERVED)
def test_reserved_names_detected(name: str) -> None:
    assert is_reserved_name(name)
    assert component_problem(name) is not None
    with pytest.raises(UnsafePathError):
        validate_component(name)


@pytest.mark.parametrize("name", NOT_RESERVED)
def test_non_reserved_names_accepted(name: str) -> None:
    assert not is_reserved_name(name)
    assert component_problem(name) is None
    assert validate_component(name) == name


@pytest.mark.parametrize("base", ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM1", "LPT3"])
def test_reserved_is_case_insensitive(base: str) -> None:
    for variant in (base, base.lower(), base.capitalize(), base.swapcase()):
        assert is_reserved_name(variant), variant
        assert is_reserved_name(variant + ".txt"), variant
        assert is_reserved_name(variant + " .txt"), variant


def test_reserved_rule_matches_format_formula() -> None:
    """``base = componente.split(".", 1)[0].rstrip(" ").upper()`` (FORMAT §5.2)."""
    reserved_bases = (
        {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
        | {f"COM{d}" for d in "0123456789"}
        | {f"LPT{d}" for d in "0123456789"}
        | {f"COM{s}" for s in (SUP1, SUP2, SUP3)}
        | {f"LPT{s}" for s in (SUP1, SUP2, SUP3)}
    )
    rng = random.Random(1234)  # noqa: S311 (semente fixa, sem uso criptográfico)
    alphabet = "cConNuUlLpPrRaAxXiItTmMoO$ ." + SUP1 + SUP2 + SUP3 + SUP4 + "0123459" + E_ACUTE
    samples = list(RESERVED) + list(NOT_RESERVED)
    for _ in range(5000):
        samples.append("".join(rng.choice(alphabet) for _ in range(rng.randint(1, 10))))
    for name in samples:
        expected = name.split(".", 1)[0].rstrip(" ").upper() in reserved_bases
        assert is_reserved_name(name) == expected, repr(name)


# --- comparação com ntpath.isreserved (Python 3.13+) -------------------------------------

_needs_isreserved = pytest.mark.skipif(
    not hasattr(ntpath, "isreserved"), reason="ntpath.isreserved exige Python 3.13+"
)

_ZERO_BASES = {"COM0", "LPT0"}  # diferença intencional: reservados só no Owl Vault


def _python_device_check_applies(name: str) -> bool:
    """Para estes nomes ``ntpath.isreserved`` decide APENAS pela regra de dispositivo."""
    if not name or name[-1] in ". ":
        return False
    return not any(c in '<>:"/|?*' or c == BS or ord(c) < 0x20 for c in name)


def _cross_check_candidates() -> list[str]:
    bases = [
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CONIN$",
        "CONOUT$",
        "COM",
        "LPT",
        "CONSOLE",
        "NULL",
        "AUXX",
        "CO",
        "COM10",
        "LPT10",
        "XCON",
        "CONIN",
        "CONOUT",
        "C0N",
        *[f"COM{d}" for d in "0123456789"],
        *[f"LPT{d}" for d in "0123456789"],
        *[f"COM{s}" for s in (SUP0, SUP1, SUP2, SUP3, SUP4)],
        *[f"LPT{s}" for s in (SUP0, SUP1, SUP2, SUP3, SUP4)],
    ]
    suffixes = [
        "",
        ".txt",
        ".tar.gz",
        " .txt",
        "  .txt",
        ". txt",
        "..txt",
        ".",
        " ",
        "x",
        " x",
        ":",
        ":x",
        "/x",
        BS + "x",
        "?",
        "\x00",
        "\x1f",
    ]
    out = []
    for b in bases:
        for variant in {b, b.lower(), b.capitalize()}:
            for s in suffixes:
                out.append(variant + s)
    return out


@_needs_isreserved
def test_is_reserved_name_agrees_with_ntpath_isreserved() -> None:
    """Igualdade com ``ntpath.isreserved`` quando só a regra de dispositivo se aplica.

    Única diferença aceita: ``COM0``/``LPT0`` (reservados no Owl Vault, não no Python).
    """
    checked = 0
    for name in _cross_check_candidates():
        if not _python_device_check_applies(name):
            continue
        checked += 1
        ours = is_reserved_name(name)
        theirs = ntpath.isreserved(name)
        base = name.split(".", 1)[0].rstrip(" ").upper()
        if base in _ZERO_BASES:
            assert ours and not theirs, repr(name)
        else:
            assert ours == theirs, repr(name)
    assert checked > 100


@_needs_isreserved
def test_everything_python_reserves_is_rejected() -> None:
    """``ntpath.isreserved(n)`` ⇒ ``component_problem(n)`` recusa (nunca aceitamos menos)."""
    rng = random.Random(42)  # noqa: S311 (semente fixa, sem uso criptográfico)
    alphabet = (
        "cConNuUlLpPrRaAxXiIoOtT$ ."
        + SUP1
        + SUP2
        + SUP3
        + "0129"
        + ':/<>|?*"'
        + BS
        + "\x00\x1f\t"
        + E_ACUTE
        + EMOJI
    )
    samples = _cross_check_candidates()
    for _ in range(20000):
        samples.append("".join(rng.choice(alphabet) for _ in range(rng.randint(0, 9))))
    for name in samples:
        if ntpath.isreserved(name):
            assert component_problem(name) is not None, repr(name)
        if (
            _python_device_check_applies(name)
            and name.split(".", 1)[0].rstrip(" ").upper() not in _ZERO_BASES
        ):
            assert is_reserved_name(name) == ntpath.isreserved(name), repr(name)


# --------------------------------------------------------------------------------------
# outras regras de componente
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("ch", [*'<>:"/|?*', BS])
def test_invalid_windows_chars_rejected(ch: str) -> None:
    for name in (ch, "a" + ch, ch + "a", "a" + ch + "b.txt"):
        assert component_problem(name) is not None, repr(name)
        with pytest.raises(UnsafePathError):
            validate_component(name)


@pytest.mark.parametrize("code", range(0x20))
def test_control_chars_rejected(code: int) -> None:
    name = "a" + chr(code) + "b"
    assert component_problem(name) is not None
    assert component_problem(chr(code)) is not None


def test_del_and_other_printables_allowed() -> None:
    # FORMAT §5.2 proíbe só 0x00–0x1F; 0x7F e demais imprimíveis são permitidos.
    for name in (
        "a\x7fb",
        "a&b",
        "#hash",
        "100%",
        "{x}",
        "~tilde",
        "it's",
        "[1]",
        "a,b;c=d",
        "a+b",
        "@at",
        "$dollar",
        "!bang",
        "^caret",
        "`tick`",
        "\N{EURO SIGN}5",
    ):
        assert component_problem(name) is None, repr(name)


@pytest.mark.parametrize("name", ["a.", "a ", "a. ", "a .", "...", "   ", " ", "x..", "dir.  "])
def test_trailing_dot_or_space_rejected(name: str) -> None:
    assert component_problem(name) is not None
    with pytest.raises(UnsafePathError):
        validate_component(name)


@pytest.mark.parametrize("name", [".gitignore", " leading", ".a", "a.b", "a..b", ". a", "a b"])
def test_leading_or_inner_dot_space_allowed(name: str) -> None:
    assert component_problem(name) is None


@pytest.mark.parametrize("name", [".", ".."])
def test_dot_and_dotdot_rejected(name: str) -> None:
    assert component_problem(name) is not None
    with pytest.raises(UnsafePathError):
        validate_component(name)


def test_empty_rejected() -> None:
    assert component_problem("") is not None
    with pytest.raises(UnsafePathError):
        validate_component("")


@pytest.mark.parametrize("value", [None, 1, 1.5, b"abc", ["a"], ("a",), {"a": 1}, True])
def test_non_string_rejected(value: object) -> None:
    assert component_problem(value) is not None
    with pytest.raises(UnsafePathError):
        validate_component(value)


@pytest.mark.parametrize(
    ("name", "units", "ok"),
    [
        ("a" * 255, 255, True),
        ("a" * 256, 256, False),
        (E_ACUTE * 255, 255, True),  # 2 bytes UTF-8, mas 1 unidade UTF-16
        (E_ACUTE * 256, 256, False),
        ("\N{CJK UNIFIED IDEOGRAPH-65E5}" * 255, 255, True),
        (EMOJI * 127 + "a", 255, True),  # 128 code points, 255 unidades
        (EMOJI * 128, 256, False),  # só 128 code points, mas 256 unidades
        ("a" * 254 + EMOJI, 256, False),
        ("a" * 253 + EMOJI, 255, True),
        (DESERET_SMALL * 127 + "b", 255, True),
    ],
)
def test_length_counted_in_utf16_units(name: str, units: int, ok: bool) -> None:
    assert MAX_COMPONENT_UTF16 == 255
    assert utf16_len(name) == units
    assert (component_problem(name) is None) is ok


def test_utf16_len_basics() -> None:
    assert utf16_len("") == 0
    assert utf16_len("abc") == 3
    assert utf16_len(EMOJI) == 2
    assert utf16_len("a" + EMOJI + "b") == 4
    assert utf16_len(HIGH_SURROGATE) == 1  # surrogate órfão conta 1 unidade


@pytest.mark.parametrize(
    "name",
    [
        HIGH_SURROGATE,
        LOW_SURROGATE,
        chr(0xD800),
        chr(0xDFFF),
        "a" + chr(0xDC00) + "b",
        "foto" + HIGH_SURROGATE + ".jpg",
        LOW_SURROGATE + HIGH_SURROGATE,  # ordem invertida: nunca é um par válido
    ],
)
def test_lone_surrogates_rejected(name: str) -> None:
    assert component_problem(name) is not None
    with pytest.raises(UnsafePathError):
        validate_component(name)


@pytest.mark.parametrize(
    "name",
    [
        "Ação çãõ \N{CJK UNIFIED IDEOGRAPH-65E5}\N{CJK UNIFIED IDEOGRAPH-672C} " + EMOJI + ".txt",
        EMOJI,
        DESERET_SMALL + DESERET_CAPITAL,
        E_ACUTE,  # NFC
        "e" + COMBINING_ACUTE,  # NFD
        SHARP_S,
        LIG_FI + "le",
        "\N{ZERO WIDTH JOINER}",
        "\N{NO-BREAK SPACE}x",
    ],
)
def test_unicode_names_accepted(name: str) -> None:
    assert component_problem(name) is None


# --------------------------------------------------------------------------------------
# validate_relative_path
# --------------------------------------------------------------------------------------


def test_validate_relative_path_ok() -> None:
    assert validate_relative_path(["a", "b", "c.txt"]) == ("a", "b", "c.txt")
    assert validate_relative_path(("x",)) == ("x",)
    deep = ["d"] * MAX_DEPTH
    assert validate_relative_path(deep) == tuple(deep)


@pytest.mark.parametrize(
    "path",
    [
        [],
        (),
        "a/b",
        "a" + BS + "b",
        "abc",
        None,
        {"a": 1},
        ["d"] * (MAX_DEPTH + 1),
        ["a", "..", "b"],
        ["..", "x"],
        ["a", ".", "b"],
        ["C:", "Windows"],
        ["", "etc", "passwd"],
        [BS + BS + "server", "share"],
        [BS + BS + "?" + BS + "C:", "x"],
        ["a", "b:stream"],
        ["a", "b/c"],
        ["a", "CON"],
        ["NUL .txt"],
        ["a", "b."],
        ["a", 1],
        ["a", None],
    ],
)
def test_validate_relative_path_rejects(path: object) -> None:
    with pytest.raises(UnsafePathError):
        validate_relative_path(path)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------
# fold (FORMAT §5.2 "Dobra de caixa")
# --------------------------------------------------------------------------------------


def _units(text: str) -> bytes:
    return text.encode("utf-16-le", "surrogatepass")


def _fold_reference(component: str) -> bytes:
    """Implementação literal da FORMAT §5.2, unidade UTF-16 por unidade UTF-16.

    Devolve as unidades UTF-16-LE (comparar em unidades evita que dois surrogates órfãos
    adjacentes, que em UTF-16 formam um par, sejam vistos como diferentes de um code point).
    """
    data = _units(component)
    units = [int.from_bytes(data[i : i + 2], "little") for i in range(0, len(data), 2)]
    out = []
    for u in units:
        if 0xD800 <= u <= 0xDFFF:
            out.append(u)
            continue
        up = chr(u).upper()
        if len(up) == 1 and ord(up) < 0x10000:
            out.append(ord(up))
        else:
            out.append(u)
    return b"".join(u.to_bytes(2, "little") for u in out)


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("abc", "ABC"),
        ("ABC", "ABC"),
        ("Fotos 2024.JPG", "FOTOS 2024.JPG"),
        ("ação", "AÇÃO"),
        ("éèêëàâäôöûüçñõãíú", "ÉÈÊËÀÂÄÔÖÛÜÇÑÕÃÍÚ"),
        ("\N{LATIN SMALL LETTER Y WITH DIAERESIS}", "\N{LATIN CAPITAL LETTER Y WITH DIAERESIS}"),
        (
            "\N{GREEK SMALL LETTER ALPHA}\N{GREEK SMALL LETTER OMEGA}",
            "\N{GREEK CAPITAL LETTER ALPHA}\N{GREEK CAPITAL LETTER OMEGA}",
        ),
        ("\N{CYRILLIC SMALL LETTER ZHE}", "\N{CYRILLIC CAPITAL LETTER ZHE}"),
        # upper() com mais de um caractere ⇒ mantém
        (SHARP_S, SHARP_S),
        ("straße", "STRA" + SHARP_S + "E"),
        (LIG_FI, LIG_FI),
        (LIG_FI + "le", LIG_FI + "LE"),
        (
            "\N{LATIN SMALL LETTER N PRECEDED BY APOSTROPHE}",
            "\N{LATIN SMALL LETTER N PRECEDED BY APOSTROPHE}",
        ),
        (
            "\N{GREEK SMALL LETTER IOTA WITH DIALYTIKA AND TONOS}",
            "\N{GREEK SMALL LETTER IOTA WITH DIALYTIKA AND TONOS}",
        ),
        # fora do BMP ⇒ mantém (mesmo com maiúscula existente)
        (DESERET_SMALL, DESERET_SMALL),
        (EMOJI, EMOJI),
        ("a" + EMOJI + "b" + DESERET_SMALL, "A" + EMOJI + "B" + DESERET_SMALL),
        # surrogates órfãos ⇒ mantém
        (HIGH_SURROGATE, HIGH_SURROGATE),
        ("x" + LOW_SURROGATE, "X" + LOW_SURROGATE),
        # sem caixa
        ("123 _-.~", "123 _-.~"),
        ("\N{CJK UNIFIED IDEOGRAPH-65E5}", "\N{CJK UNIFIED IDEOGRAPH-65E5}"),
        ("", ""),
    ],
)
def test_fold_examples(given: str, expected: str) -> None:
    assert fold(given) == expected
    assert _units(fold(given)) == _fold_reference(given)


def test_fold_never_uses_whole_string_upper() -> None:
    assert fold(SHARP_S) != "SS"
    assert fold(SHARP_S) != fold("SS")
    assert fold("ss") == "SS"
    assert fold(LIG_FI) != fold("FI")
    assert fold(DESERET_SMALL) != fold(DESERET_CAPITAL)
    # casefold() também colapsaria ß → ss; fold não pode fazer isso
    assert fold("Straße") != fold("STRASSE")


def test_fold_does_not_normalize_unicode() -> None:
    nfc = E_ACUTE
    nfd = "e" + COMBINING_ACUTE
    assert fold(nfc) == E_ACUTE_UP
    assert fold(nfd) == "E" + COMBINING_ACUTE
    assert fold(nfc) != fold(nfd)


def test_fold_is_case_insensitive_key() -> None:
    assert fold("Fotos") == fold("FOTOS") == fold("fotos") == fold("fOtOs")
    assert fold("ação.TXT") == fold("AÇÃO.txt")
    assert fold_path(("Fotos", "Praia.JPG")) == fold_path(("FOTOS", "praia.jpg"))
    assert fold_path(["a", "b"]) == ("A", "B")


def test_fold_matches_reference_for_every_bmp_code_point() -> None:
    mismatches = []
    for cp in range(0x10000):
        ch = chr(cp)
        got = fold(ch)
        if _units(got) != _fold_reference(ch):
            mismatches.append(hex(cp))
            continue
        # preserva exatamente uma unidade UTF-16 e é idempotente
        assert utf16_len(got) == 1, hex(cp)
        assert fold(got) == got, hex(cp)
    assert mismatches == []


def test_fold_matches_reference_on_random_strings() -> None:
    rng = random.Random(7)  # noqa: S311 (semente fixa, sem uso criptográfico)
    pools = [
        (0x20, 0x7F),
        (0xA0, 0x250),
        (0x370, 0x500),
        (0x1E00, 0x2000),
        (0x2C00, 0x2D30),
        (0xA640, 0xA800),
        (0xFB00, 0xFB07),
        (0xFF21, 0xFF5B),
        (0xD800, 0xE000),  # surrogates órfãos
        (0x10400, 0x10450),  # Deseret
        (0x1F600, 0x1F650),  # emoji
        (0x1E900, 0x1E944),  # Adlam (tem caixa, fora do BMP)
    ]
    for _ in range(3000):
        chars = []
        for _ in range(rng.randint(0, 12)):
            lo, hi = rng.choice(pools)
            chars.append(chr(rng.randrange(lo, hi)))
        s = "".join(chars)
        f = fold(s)
        assert _units(f) == _fold_reference(s), [hex(ord(c)) for c in s]
        assert utf16_len(f) == utf16_len(s)
        assert f == "".join(fold(c) for c in s)  # por unidade, nunca na string inteira


def test_fold_path_returns_tuple() -> None:
    assert fold_path(iter(["x", "y"])) == ("X", "Y")
    assert fold_path(()) == ()


# --------------------------------------------------------------------------------------
# utilitários
# --------------------------------------------------------------------------------------


def test_display_path_joins_with_backslash() -> None:
    assert display_path(("a", "b", "c.txt")) == "a" + BS + "b" + BS + "c.txt"
    assert display_path(("só",)) == "só"


@pytest.mark.parametrize(
    ("name", "legal"),
    [
        ("README.TXT", True),
        ("A", True),
        ("FILE1234.ABC", True),
        ("NOEXT", True),
        ("LONGFILENAME.TXT", False),  # base com mais de 8
        ("A.HTML", False),  # extensão com mais de 3
        ("A.B.C", False),  # mais de um ponto
        ("NAME.", False),  # ponto sem extensão
        ("AÇÃO.TXT", False),  # não ASCII
        ("WITH SPACE.TXT", False),
        (".HIDDEN", False),  # base vazia
    ],
)
def test_is_short_name_legal(name: str, legal: bool) -> None:
    assert is_short_name_legal(name) is legal
