"""Tema "Cofre" (Claude Design): tokens, contraste WCAG e "nenhuma cor literal fora do tema"."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from owl_vault.ui.tema import theme_cofre
from owl_vault.ui.tema.theme_cofre import TEMAS, montar_qss

UI = Path(theme_cofre.__file__).resolve().parent.parent


def _lum(hex_color: str) -> float:
    h = hex_color.lstrip("#")[-6:]
    r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))

    def ch(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast(a: str, b: str) -> float:
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


# (frente, fundo, mínimo) — texto 4,5:1; contornos, indicadores e foco 3:1 (WCAG 2.1)
PARES = [
    ("ink", "app-bg", 4.5),
    ("ink", "panel", 4.5),
    ("ink", "panel-alt", 4.5),
    ("ink", "field", 4.5),
    ("ink-muted", "app-bg", 4.5),
    ("ink-muted", "panel", 4.5),
    ("ink-muted", "panel-alt", 4.5),
    ("ink-muted", "field", 4.5),
    ("accent-ink", "accent", 4.5),
    ("accent-ink", "accent-hover", 4.5),
    ("accent-text", "panel", 4.5),
    ("accent-text", "panel-alt", 4.5),
    ("accent-text", "app-bg", 4.5),
    ("accent-text", "accent-soft", 4.5),
    ("ink", "accent-soft", 4.5),
    ("notice-ink", "notice-bg", 4.5),
    ("log-ink", "log-bg", 4.5),
    ("ok", "panel", 4.5),
    ("warn", "panel", 4.5),
    ("warn", "panel-alt", 4.5),
    ("danger", "panel", 4.5),
    ("danger", "panel-alt", 4.5),
    ("border-strong", "panel", 3.0),
    ("border-strong", "field", 3.0),
    ("border-strong", "panel-alt", 2.4),  # contorno das linhas (o fundo da linha já separa)
    ("focus", "field", 3.0),
    ("focus", "panel", 3.0),
    ("accent", "panel", 3.0),
]


@pytest.mark.parametrize("tema", sorted(TEMAS))
@pytest.mark.parametrize(("frente", "fundo", "minimo"), PARES)
def test_contraste(tema: str, frente: str, fundo: str, minimo: float) -> None:
    t = TEMAS[tema]
    assert contrast(t[frente], t[fundo]) >= minimo, (
        tema,
        frente,
        fundo,
        contrast(t[frente], t[fundo]),
    )


def test_temas_tem_os_mesmos_tokens() -> None:
    assert set(TEMAS["dark"]) == set(TEMAS["light"])


def test_tema_escuro_e_o_do_design() -> None:
    """Os valores do Claude Design (visual/theme_cofre.py) não foram alterados."""
    design = UI.parent.parent.parent / "visual" / "theme_cofre.py"
    if not design.exists():
        pytest.skip("pasta visual/ ausente")
    texto = design.read_text(encoding="utf-8")
    for nome, valor in re.findall(r'"([a-z0-9-]+)":\s*"([^"]+)"', texto):
        assert TEMAS["dark"][nome] == valor, nome


@pytest.mark.parametrize("tema", sorted(TEMAS))
def test_qss_casa_com_tokens(tema: str) -> None:
    qss = montar_qss(tema=tema)
    assert "{" in qss and "}" in qss
    assert not re.search(r"\{[a-z][a-z0-9-]*\}", qss), "token sem valor"


def test_nenhuma_cor_literal_fora_do_tema() -> None:
    """Regra 1 do design: toda cor sai de theme_cofre.TOKENS (via QSS ou current_tokens())."""
    cor = re.compile(r"#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{8}\b|\brgba?\(|QColor\(\s*\d")
    ofensores = []
    for py in UI.rglob("*.py"):
        if py.parent.name == "tema" or py.name == "icon.py":  # icon.py desenha a LOGO (marca)
            continue
        for n, linha in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            if cor.search(linha):
                ofensores.append(f"{py.name}:{n}: {linha.strip()}")
    assert not ofensores, "\n".join(ofensores)


def test_qss_sem_cor_literal() -> None:
    bruto = (UI / "tema" / "owlvault.qss").read_text(encoding="utf-8")
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", bruto)
