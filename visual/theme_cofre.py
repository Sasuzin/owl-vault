"""
Owl Vault — tema "Cofre" (Estilo 5).

Único lugar onde as cores vivem. O QSS (owlvault.qss) usa {nome-do-token}
e esta função troca pelos valores abaixo. Nunca cole uma cor direto no QSS.

Uso:

    from theme_cofre import aplicar_tema
    app = QApplication(sys.argv)
    aplicar_tema(app)

Funciona igual em PyQt5, PyQt6 e PySide6 — o QSS é o mesmo, só muda o import.
"""

from pathlib import Path

PASTA = Path(__file__).resolve().parent

TOKENS = {
    # --- fundo e estrutura ---
    "app-bg":        "#241834",  # fundo da janela
    "panel":         "#2f2245",  # cartão
    "panel-alt":     "#3a2b53",  # segundo nível (passo futuro, trilho de barra)
    "field":         "#271b3b",  # fundo de campo editável
    "border":        "#4a3866",  # divisor decorativo
    "border-strong": "#8873b0",  # contorno de controle (passa 3:1 sobre o cartão)

    # --- texto ---
    "ink":           "#f7f1ff",
    "ink-muted":     "#c6b7dd",

    # --- roxo ---
    "accent":        "#a479ff",  # preenchimento do botão primário / passo atual
    "accent-hover":  "#bb99ff",
    "accent-ink":    "#1b1028",  # texto SOBRE o roxo
    "accent-text":   "#d6bbff",  # roxo COMO texto/ícone sobre o cartão
    "accent-soft":   "#3d2c5e",  # fundo roxo discreto (cartão de dica, passo feito)
    "focus":         "#d6bbff",

    # --- sinal ---
    "ok":            "#7ee2b0",
    "warn":          "#f3c489",
    "danger":        "#ff93a6",
    "notice-bg":     "#40301f",
    "notice-ink":    "#ffd5ab",
    "log-bg":        "#1c1328",
    "log-ink":       "#cfc2e4",

    # --- marca (ícone do .exe, splash, material de apoio — não é cor de interface) ---
    "brand-violet":  "#7c3aed",
    "brand-lilac":   "#c4a7ff",
    "brand-deep":    "#2b1b4d",
    "brand-ink":     "#120d1f",
    "brand-mint":    "#5fe3a3",

    # --- espaçamento (escala de 4 em 4) ---
    "space-1": "4px", "space-2": "8px", "space-3": "12px", "space-4": "16px",
    "space-5": "20px", "space-6": "24px", "space-8": "32px", "space-10": "40px",

    # --- raio ---
    "radius-0": "0px", "radius-sm": "4px", "radius-md": "8px",
    "radius-lg": "12px", "radius-xl": "18px", "radius-pill": "24px",

    # --- tipografia ---
    "font-ui":   "Segoe UI",
    "font-mono": "Cascadia Code",
}

# Alturas do Estilo 5 (maiores que o padrão: é um assistente, não um formulário denso)
ALTURA_CAMPO = 48
ALTURA_BOTAO = 48
TAMANHO_PASSO = 26  # diâmetro do contador de passo


def montar_qss(caminho: str | Path = None) -> str:
    """Lê owlvault.qss e troca os {tokens} pelos valores do tema."""
    folha = Path(caminho) if caminho else PASTA / "owlvault.qss"
    return folha.read_text(encoding="utf-8").format(**TOKENS)


def aplicar_tema(app, caminho: str | Path = None) -> None:
    """Aplica a folha de estilo no QApplication."""
    app.setStyleSheet(montar_qss(caminho))


def repintar(widget) -> None:
    """
    Chame depois de mudar uma propriedade dinâmica (estado, caminho, papel...).
    O Qt não reavalia o seletor sozinho.

        rotulo.setProperty("estado", "atual")
        repintar(rotulo)
    """
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()


if __name__ == "__main__":
    # Confere se a folha casa com os tokens antes de subir o app
    try:
        montar_qss()
    except KeyError as erro:
        raise SystemExit(f"Token faltando no theme_cofre.py: {erro}")
    print("owlvault.qss e theme_cofre.py estão casados.")
