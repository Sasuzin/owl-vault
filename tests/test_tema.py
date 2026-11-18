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
    # contorno das linhas: o fundo panel-alt da linha já separa (QFrame#cartao QFrame#linhaPasta)
    ("border-strong", "panel-alt", 2.4),
    ("focus", "field", 3.0),
    ("focus", "panel", 3.0),
    ("focus", "log-bg", 3.0),  # foco no registro (QPlainTextEdit#log:focus)
    ("accent", "panel", 3.0),
    ("ink", "border", 4.5),  # hover dos botões dentro da linha da lista
    ("notice-ink", "notice-bg", 3.0),  # ícone ⚠ desenhado com notice-ink
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


# --------------------------------------------------------------- regras da folha (ordem importa)


def _regras(tema: str = "dark") -> list[tuple[list[str], dict[str, str]]]:
    """``[(seletores, {propriedade: valor}), ...]`` na ordem do arquivo (sem comentários)."""
    qss = re.sub(r"/\*.*?\*/", "", montar_qss(tema=tema), flags=re.S)
    regras = []
    for seletor, corpo in re.findall(r"([^{}]+)\{([^{}]*)\}", qss):
        props = {}
        for decl in corpo.split(";"):
            if ":" in decl:
                k, v = decl.split(":", 1)
                props[k.strip()] = v.strip()
        regras.append(([s.strip() for s in seletor.split(",") if s.strip()], props))
    return regras


def _especificidade(seletor: str) -> tuple[int, int, int]:
    ids = seletor.count("#")
    pseudo = len(re.findall(r":[a-z!-]+|\[", seletor))
    tipos = len(re.findall(r"(?:^|\s)[A-Za-z]", seletor))
    return ids, pseudo, tipos


def _vencedor(seletores: list[str], prop: str, tema: str = "dark") -> str:
    """Valor de ``prop`` dado pela regra mais específica (e mais tardia) entre ``seletores``."""
    melhor: tuple[tuple[int, int, int], int] | None = None
    valor = ""
    for i, (sels, props) in enumerate(_regras(tema)):
        if prop not in props:
            continue
        for s in sels:
            if s in seletores:
                chave = (_especificidade(s), i)
                if melhor is None or chave > melhor:
                    melhor, valor = chave, props[prop]
    return valor


def test_todo_conteiner_transparente_devolve_o_fundo_dos_menus() -> None:
    """visual-1: "QFrame#x QWidget { background: transparent }" também pega o QMenu cujo pai está
    dentro de x (menu ⋯ da linha, botão direito em campos): ele saía sem fundo (preto)."""
    regras = _regras()
    ultimo_transparente: dict[str, int] = {}
    for i, (sels, props) in enumerate(regras):
        if props.get("background") == "transparent":
            for s in sels:
                m = re.fullmatch(r"QFrame#(\w+) QWidget", s)
                if m:
                    ultimo_transparente[m.group(1)] = i
    assert {"cartao", "cartaoLateral", "dica", "aviso", "rodape", "linhaPasta"} <= set(
        ultimo_transparente
    )
    painel = TEMAS["dark"]["panel"]
    for nome, i in ultimo_transparente.items():
        depois = [
            j
            for j, (sels, props) in enumerate(regras)
            if f"QFrame#{nome} QMenu" in sels and props.get("background") == painel
        ]
        assert depois and max(depois) > i, (
            f"falta 'QFrame#{nome} QMenu' depois da regra transparente"
        )


def test_linha_da_lista_pinta_panel_alt_e_hover_diferente() -> None:
    """visual-7: o fundo da linha (panel-alt) e o hover dos botões dentro dela não se confundem."""
    t = TEMAS["dark"]
    linha = ["QFrame#linhaPasta", "QFrame#cartao QWidget", "QFrame#cartao QFrame#linhaPasta"]
    assert _vencedor(linha, "background") == t["panel-alt"]
    botao = [
        "QPushButton:hover",
        "QFrame#cartao QWidget",
        "QFrame#linhaPasta QWidget",
        "QFrame#cartao QPushButton:hover",
        "QFrame#linhaPasta QPushButton:hover",
    ]
    assert _vencedor(botao, "background") not in (t["panel-alt"], "transparent")
    mais = [
        "QToolButton#mais:hover",
        "QFrame#linhaPasta QWidget",
        "QFrame#linhaPasta QToolButton#mais:hover",
    ]
    assert _vencedor(mais, "background") not in (t["panel-alt"], "transparent")
    primario = [
        "QPushButton#primario:hover",
        "QFrame#cartao QPushButton#primario:hover",
        "QFrame#linhaPasta QPushButton:hover",
        "QFrame#linhaPasta QPushButton#primario:hover",
    ]
    assert _vencedor(primario, "background") == t["accent-hover"]


def test_icone_do_aviso_nao_perde_para_a_regra_do_aviso() -> None:
    """visual-8: "QFrame#aviso QLabel" (13px) vencia "QLabel#avisoIcone" (16px)."""
    sels = ["QFrame#aviso QLabel", "QLabel#avisoIcone", "QFrame#aviso QLabel#avisoIcone"]
    assert _vencedor(sels, "font-size") == "16px"
    assert _vencedor(sels, "color") == TEMAS["dark"]["notice-ink"]


@pytest.mark.parametrize("tema", sorted(TEMAS))
@pytest.mark.parametrize(
    "seletores",
    [
        ["QPlainTextEdit", "QPlainTextEdit:focus"],
        ["QListWidget", "QListWidget:focus"],
        [
            "QPlainTextEdit",
            "QPlainTextEdit:focus",
            "QPlainTextEdit#log",
            "QPlainTextEdit#log:focus",
        ],
    ],
)
def test_foco_visivel_em_listas_e_no_registro(tema: str, seletores: list[str]) -> None:
    """visual-12: a lista de "Detalhes" e o registro entram no Tab e não mostravam o foco."""
    borda = _vencedor(seletores, "border", tema)
    assert borda == f"2px solid {TEMAS[tema]['focus']}", seletores
