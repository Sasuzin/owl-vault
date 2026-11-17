"""Validação de nomes de arquivos/pastas do Windows e dobra de caixa (FORMAT §5.2).

Funções puras, sem E/S. Usadas na varredura da origem, na validação do manifesto e na
restauração.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from owl_vault.domain.errors import UnsafePathError
from owl_vault.domain.limits import MAX_COMPONENT_UTF16, MAX_DEPTH

_INVALID_CHARS = frozenset('<>:"/\\|?*') | frozenset(chr(c) for c in range(0x20))

_RESERVED_BASES = frozenset(
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
    + [f"COM{d}" for d in "0123456789"]
    + [f"LPT{d}" for d in "0123456789"]
    + ["COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"]
)

# Caracteres aceitos em nomes curtos 8.3 (além de letras e dígitos ASCII).
_SHORT_NAME_EXTRA = frozenset("!#$%&'()-@^_`{}~")


def utf16_len(text: str) -> int:
    """Comprimento em unidades de código UTF-16 (o que o Windows conta)."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def is_reserved_name(component: str) -> bool:
    """Nome reservado de dispositivo do Windows, com ou sem extensão(ões).

    ``base = componente.split(".", 1)[0].rstrip(" ").upper()`` — pega ``CON.tar.gz`` e
    ``NUL .txt``.
    """
    base = component.split(".", 1)[0].rstrip(" ").upper()
    return base in _RESERVED_BASES


def component_problem(component: object) -> str | None:
    """Retorna a descrição do problema do componente, ou ``None`` se for válido."""
    if not isinstance(component, str):
        return "componente de caminho não é texto"
    if component == "":
        return "nome vazio"
    if component in (".", ".."):
        return "nome '.' ou '..' não é permitido"
    try:
        encoded = component.encode("utf-16-le", "strict")
    except UnicodeEncodeError:
        return "nome com caracteres Unicode inválidos (UTF-16 malformado)"
    if len(encoded) // 2 > MAX_COMPONENT_UTF16:
        return f"nome com mais de {MAX_COMPONENT_UTF16} caracteres"
    bad = sorted({c for c in component if c in _INVALID_CHARS})
    if bad:
        shown = ", ".join(repr(c) for c in bad[:5])
        return f"nome contém caracteres não permitidos no Windows ({shown})"
    if component[-1] in (" ", "."):
        return "nome termina com espaço ou ponto"
    if is_reserved_name(component):
        return "nome reservado do Windows (CON, NUL, COM1, LPT1...)"
    return None


def validate_component(component: object) -> str:
    """Valida um componente; levanta :class:`UnsafePathError` se inválido."""
    problem = component_problem(component)
    if problem is not None:
        raise UnsafePathError(problem)
    assert isinstance(component, str)
    return component


def validate_relative_path(components: Sequence[object]) -> tuple[str, ...]:
    """Valida um caminho relativo como lista de componentes."""
    if not isinstance(components, (list, tuple)):
        raise UnsafePathError("caminho deve ser uma lista de componentes")
    if len(components) == 0:
        raise UnsafePathError("caminho vazio")
    if len(components) > MAX_DEPTH:
        raise UnsafePathError(f"caminho com mais de {MAX_DEPTH} níveis")
    return tuple(validate_component(c) for c in components)


def fold(component: str) -> str:
    """Dobra de caixa que aproxima a tabela ``$UpCase`` do NTFS.

    Para cada unidade UTF-16: se não é surrogate e ``upper()`` resulta em um único
    caractere BMP, usa-o; senão mantém. Nunca aplica ``upper()``/``casefold()`` na string
    inteira (``ß`` → ``SS`` geraria colisões falsas).
    """
    out: list[str] = []
    for ch in component:
        cp = ord(ch)
        if cp >= 0x10000 or 0xD800 <= cp <= 0xDFFF:
            out.append(ch)
            continue
        up = ch.upper()
        if len(up) == 1 and ord(up) < 0x10000:
            out.append(up)
        else:
            out.append(ch)
    return "".join(out)


def fold_path(components: Iterable[str]) -> tuple[str, ...]:
    return tuple(fold(c) for c in components)


def is_short_name_legal(component: str) -> bool:
    """Aproximação: o nome já é um nome curto 8.3 legal (não gera alias curto)."""
    if component.count(".") > 1:
        return False
    base, _, ext = component.partition(".")
    if not (1 <= len(base) <= 8) or len(ext) > 3:
        return False
    if "." in component and not ext:
        return False
    return all(ch.isascii() and (ch.isalnum() or ch in _SHORT_NAME_EXTRA) for ch in base + ext)


def display_path(components: Sequence[str]) -> str:
    """Caminho relativo para exibição na tela (nunca gravar em disco)."""
    return "\\".join(components)
