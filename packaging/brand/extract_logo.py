"""Extrai o escudo da coruja da logo original e gera o asset com transparência.

Entrada:  packaging/brand/owl-vault-logo-original.webp (1312x1199, SEM canal alfa: o xadrez
          de "transparência" está pintado nos pixels).
Saída:    src/owl_vault/ui/assets/owl-shield.png (escudo isolado, fundo transparente).

Passos:
1. recorta a área do escudo; a letra "V" do texto cobre a ponta do escudo, então a ponta
   é reconstruída estreitando o perfil da última linha intacta até um vértice;
2. remove o xadrez por preenchimento a partir das bordas: só pixels claros e sem cor
   (o roxo do contorno do escudo funciona como barreira);
3. recalcula o alfa dos pixels de borda ("desmistura" do fundo claro) para não sobrar halo
   branco sobre fundos escuros.

Uso: .venv\\Scripts\\python.exe packaging\\brand\\extract_logo.py
"""

from __future__ import annotations

import os
import sys
from collections import deque
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QGuiApplication, QImage

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SRC = HERE / "owl-vault-logo-original.webp"
OUT = ROOT / "src" / "owl_vault" / "ui" / "assets" / "owl-shield.png"

CROP = QRect(200, 0, 912, 940)  # x, y, largura, altura (contém o escudo inteiro)
TEMPLATE_Y = 883  # última linha do escudo antes da letra "V" (que começa em ~886)
OUT_HEIGHT = 512


def is_background(r: int, g: int, b: int) -> bool:
    """Xadrez: branco (#fefefe) e cinza claro (#e5e5e5), sem saturação."""
    return min(r, g, b) >= 168 and (max(r, g, b) - min(r, g, b)) <= 26


def main() -> None:
    _app = QGuiApplication(sys.argv)
    src = QImage(str(SRC))
    if src.isNull():
        raise SystemExit(f"não foi possível abrir {SRC}")
    img = src.copy(CROP).convertToFormat(QImage.Format.Format_ARGB32)
    w, h = img.width(), img.height()
    px = [[img.pixel(x, y) for x in range(w)] for y in range(h)]

    def rgb(v: int) -> tuple[int, int, int]:
        return (v >> 16) & 255, (v >> 8) & 255, v & 255

    removed = [[False] * w for _ in range(h)]

    # 1) ponta do escudo: a letra "V" do texto fica NA FRENTE da ponta (a ponta original não
    #    existe na imagem). Reconstrói a ponta a partir da última linha intacta: o perfil da
    #    linha (borda roxa | interior escuro | borda roxa) é estreitado até um vértice, no
    #    mesmo ritmo em que o escudo já vinha afinando.
    def extent(y: int) -> tuple[int, int]:
        xs = [x for x in range(250, 750) if not is_background(*rgb(px[y][x]))]
        return min(xs), max(xs)

    left0, right0 = extent(TEMPLATE_Y)
    left1, right1 = extent(TEMPLATE_Y - 20)
    width0 = right0 - left0
    rate = ((right1 - left1) - width0) / 20.0  # quanto a largura diminui por linha
    extra = max(4.0, width0 / max(rate, 1.0))
    apex_x = (left0 + right0) / 2
    template = list(px[TEMPLATE_Y])
    for y in range(TEMPLATE_Y + 1, h):
        t = (y - TEMPLATE_Y) / extra
        if t >= 1.0:
            removed[y] = [True] * w
            continue
        lo = left0 + (apex_x - left0) * t
        hi = right0 + (apex_x - right0) * t
        for x in range(w):
            if x < lo or x > hi:
                removed[y][x] = True
            else:
                sx = left0 + (x - lo) / max(hi - lo, 1e-6) * width0
                px[y][x] = template[min(w - 1, max(0, round(sx)))]

    # 2) preenchimento a partir das bordas sobre pixels de fundo
    queue: deque[tuple[int, int]] = deque()
    for x in range(w):
        queue.extend([(x, 0), (x, h - 1)])
    for y in range(h):
        queue.extend([(0, y), (w - 1, y)])
    seen = [[False] * w for _ in range(h)]
    while queue:
        x, y = queue.popleft()
        if seen[y][x]:
            continue
        seen[y][x] = True
        if not removed[y][x] and not is_background(*rgb(px[y][x])):
            continue
        removed[y][x] = True
        for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nx, ny = x + dx, y + dy
            if 0 <= nx < w and 0 <= ny < h and not seen[ny][nx]:
                queue.append((nx, ny))

    # 3) alfa da borda: desmistura do fundo claro usando a cor de um vizinho interno
    out = QImage(w, h, QImage.Format.Format_ARGB32)
    out.fill(Qt.GlobalColor.transparent)
    bg = 243.0
    for y in range(h):
        for x in range(w):
            if removed[y][x]:
                continue
            r, g, b = rgb(px[y][x])
            edge = any(
                0 <= x + dx < w and 0 <= y + dy < h and removed[y + dy][x + dx]
                for dx in (-1, 0, 1)
                for dy in (-1, 0, 1)
            )
            if not edge:
                out.setPixel(x, y, 0xFF000000 | (r << 16) | (g << 8) | b)
                continue
            # cor "verdadeira": o vizinho mais escuro num raio de 3 px que não é fundo
            best = (r, g, b)
            for dy in range(-3, 4):
                for dx in range(-3, 4):
                    nx, ny = x + dx, y + dy
                    if 0 <= nx < w and 0 <= ny < h and not removed[ny][nx]:
                        c = rgb(px[ny][nx])
                        if sum(c) < sum(best):
                            best = c
            alphas = [
                (bg - p) / (bg - c) for p, c in zip((r, g, b), best, strict=True) if bg - c > 24
            ]
            a = max(0.0, min(1.0, max(alphas) if alphas else 1.0))
            if a <= 0.02:
                continue
            col = [max(0, min(255, round((p - (1 - a) * bg) / a))) for p in (r, g, b)]
            out.setPixel(x, y, (round(a * 255) << 24) | (col[0] << 16) | (col[1] << 8) | col[2])

    # recorta ao conteúdo e reduz para o tamanho do asset
    min_x = min(x for y in range(h) for x in range(w) if not removed[y][x])
    max_x = max(x for y in range(h) for x in range(w) if not removed[y][x])
    min_y = min(y for y in range(h) if not all(removed[y]))
    max_y = max(y for y in range(h) if not all(removed[y]))
    trimmed = out.copy(QRect(min_x, min_y, max_x - min_x + 1, max_y - min_y + 1))
    final = trimmed.scaledToHeight(OUT_HEIGHT, Qt.TransformationMode.SmoothTransformation)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    if not final.save(str(OUT), "PNG"):
        raise SystemExit("falha ao salvar o PNG")
    print(f"asset gerado: {OUT} ({final.width()}x{final.height()})")


if __name__ == "__main__":
    main()
