"""Owl Vault — tema "Cofre" (Estilo 5, Claude Design).

Único lugar onde as cores vivem. O QSS (``owlvault.qss``) usa ``{nome-do-token}`` e
``montar_qss`` troca pelos valores abaixo. Nunca cole uma cor direto no QSS nem no código:
se precisar de uma cor nova, acrescente um token com nome e comentário — nos DOIS conjuntos.

``TOKENS`` é o tema escuro original do design ("Cofre"). ``TOKENS_CLARO`` é a variante clara
derivada dele (mesmos nomes; contraste WCAG conferido por ``tests/test_tema.py``).
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from PySide6.QtWidgets import QApplication, QWidget

TOKENS: dict[str, str] = {
    # --- fundo e estrutura ---
    "app-bg": "#241834",  # fundo da janela
    "panel": "#2f2245",  # cartão
    "panel-alt": "#3a2b53",  # segundo nível (passo futuro, trilho de barra, linha da lista)
    "field": "#271b3b",  # fundo de campo editável
    "border": "#4a3866",  # divisor decorativo
    "border-strong": "#8873b0",  # contorno de controle (passa 3:1 sobre o cartão)
    # --- texto ---
    "ink": "#f7f1ff",
    "ink-muted": "#c6b7dd",
    # --- roxo ---
    "accent": "#a479ff",  # preenchimento do botão primário / passo atual
    "accent-hover": "#bb99ff",
    "accent-ink": "#1b1028",  # texto SOBRE o roxo
    "accent-text": "#d6bbff",  # roxo COMO texto/ícone sobre o cartão
    "accent-soft": "#3d2c5e",  # fundo roxo discreto (cartão de dica, passo feito)
    "focus": "#d6bbff",
    # --- sinal ---
    "ok": "#7ee2b0",
    "warn": "#f3c489",
    "danger": "#ff93a6",
    "notice-bg": "#40301f",
    "notice-ink": "#ffd5ab",
    "log-bg": "#1c1328",
    "log-ink": "#cfc2e4",
    # --- sombra dos cartões (QGraphicsDropShadowEffect; formato #AARRGGBB, preto a 45%) ---
    "sombra": "#73000000",
    # --- marca (ícone do .exe, splash, material de apoio — não é cor de interface) ---
    "brand-violet": "#7c3aed",
    "brand-lilac": "#c4a7ff",
    "brand-deep": "#2b1b4d",
    "brand-ink": "#120d1f",
    "brand-mint": "#5fe3a3",
    # --- espaçamento (escala de 4 em 4) ---
    "space-1": "4px",
    "space-2": "8px",
    "space-3": "12px",
    "space-4": "16px",
    "space-5": "20px",
    "space-6": "24px",
    "space-8": "32px",
    "space-10": "40px",
    # --- raio ---
    "radius-0": "0px",
    "radius-sm": "4px",
    "radius-md": "8px",
    "radius-lg": "12px",
    "radius-xl": "18px",
    "radius-pill": "24px",
    # --- tipografia ---
    "font-ui": "Segoe UI",
    "font-mono": "Cascadia Code",
}

#: Variante clara (mesmos papéis; valores escolhidos para o mesmo contraste mínimo).
TOKENS_CLARO: dict[str, str] = {
    **TOKENS,
    "app-bg": "#f3eefa",
    "panel": "#ffffff",
    "panel-alt": "#ebe3f7",
    "field": "#fbf9fe",
    "border": "#dccff0",
    "border-strong": "#7a64ad",
    "ink": "#1d1430",
    "ink-muted": "#584a72",
    "accent": "#6a3bd2",
    "accent-hover": "#5a2ec0",
    "accent-ink": "#ffffff",
    "accent-text": "#5b2fc4",
    "accent-soft": "#efe6ff",
    "focus": "#5b2fc4",
    "ok": "#1b7a4f",
    "warn": "#875000",
    "danger": "#b42345",
    "notice-bg": "#fff1df",
    "notice-ink": "#683b06",
    "log-bg": "#f7f3fd",
    "log-ink": "#3a2d52",
    "sombra": "#2e1d1430",  # sombra suave no claro (tinta a 18%)
}

TEMAS = {"dark": TOKENS, "light": TOKENS_CLARO}

# Alturas do Estilo 5 (maiores que o padrão: é um assistente, não um formulário denso)
ALTURA_CAMPO = 48
ALTURA_BOTAO = 48
TAMANHO_PASSO = 26  # diâmetro do contador de passo
LARGURA_LATERAL = 272


def tokens(tema: str = "dark") -> dict[str, str]:
    return TEMAS.get(tema, TOKENS)


def _folha_padrao() -> str:
    return resources.files("owl_vault.ui.tema").joinpath("owlvault.qss").read_text(encoding="utf-8")


def montar_qss(caminho: str | Path | None = None, tema: str = "dark") -> str:
    """Lê owlvault.qss e troca os {tokens} pelos valores do tema."""
    folha = Path(caminho).read_text(encoding="utf-8") if caminho else _folha_padrao()
    return folha.format(**tokens(tema))


def aplicar_tema(app: QApplication, caminho: str | Path | None = None, tema: str = "dark") -> None:
    """Aplica a folha de estilo no QApplication."""
    app.setStyleSheet(montar_qss(caminho, tema))


def repintar(widget: QWidget) -> None:
    """Chame depois de mudar uma propriedade dinâmica (estado, caminho, ativo...).

    O Qt não reavalia o seletor sozinho::

        rotulo.setProperty("estado", "atual")
        repintar(rotulo)
    """
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


if __name__ == "__main__":
    # Confere se a folha casa com os tokens antes de subir o app
    for nome in TEMAS:
        try:
            montar_qss(tema=nome)
        except KeyError as erro:
            raise SystemExit(f"Token faltando no theme_cofre.py ({nome}): {erro}") from erro
    print("owlvault.qss e theme_cofre.py estão casados.")
