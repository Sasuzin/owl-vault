"""Honestidade da interface: textos sobre a pasta de origem nunca sugerem proteção."""

from __future__ import annotations

import re

import pytest

from owl_vault.ui import strings as S

FORBIDDEN = re.compile(r"protegid|segur|bloquead|criptografad", re.IGNORECASE)


@pytest.mark.parametrize("text", S.ORIGIN_STATUS_TEXTS)
def test_origin_texts_do_not_claim_protection(text: str) -> None:
    assert not FORBIDDEN.search(text), text


def test_banner_says_copy_and_origin_readable() -> None:
    assert "CÓPIA" in S.BANNER
    assert S.ORIGIN_STILL_READABLE in S.BANNER
    assert "legível" in S.ORIGIN_STILL_READABLE


def test_required_warnings_present() -> None:
    assert "malware" in S.LIMITS_TEXT
    assert "memória" in S.LIMITS_TEXT
    assert "exclusão segura" in S.LIMITS_TEXT
    assert "backup" in S.BACKUP_TEXT
    assert "senha" in S.PASSWORD_LOSS_TEXT


def test_no_string_calls_origin_protected() -> None:
    for name in dir(S):
        if name.startswith("__"):
            continue  # a docstring do módulo descreve a própria regra
        value = getattr(S, name)
        if isinstance(value, str):
            assert not re.search(r"(pasta (original|de origem)[^.]*protegid)", value, re.I), name


# --- assistente "Cópia criptografada" (visual Cofre, Estilo 5) ------------------------------


def _textos_do_modulo() -> list[tuple[str, str]]:
    """Todas as strings de ``strings.py`` (inclusive dentro de tuplas), com o nome."""
    out: list[tuple[str, str]] = []

    def add(name: str, value: object) -> None:
        if isinstance(value, str):
            out.append((name, value))
        elif isinstance(value, tuple):
            for i, v in enumerate(value):
                add(f"{name}[{i}]", v)

    for name in dir(S):
        if not name.startswith("__"):
            add(name, getattr(S, name))
    return out


def test_textos_do_design_sao_exatos() -> None:
    """Os textos da seção "Textos" de visual/ESTILO5-COFRE.md estão em strings.py, sem mudar
    uma vírgula (espaços e quebras de linha do .md não contam)."""
    from pathlib import Path

    doc = Path(__file__).resolve().parent.parent / "visual" / "ESTILO5-COFRE.md"
    if not doc.exists():
        pytest.skip("pasta visual/ ausente")
    secao = doc.read_text(encoding="utf-8").split("## Textos", 1)[1].split("## Medidas", 1)[0]
    citados = [" ".join(t.split()) for t in re.findall(r'\*"(.+?)"\*', secao, re.S)]
    assert len(citados) == 5
    nossos = {" ".join(v.split()) for _n, v in _textos_do_modulo()}
    for texto in citados:
        assert texto in nossos, texto
    assert citados == [S.AVISO_COPIA, S.SENHA_TEXTO, S.NOME_DICA, S.TESTE_NOTA, S.FIM_TEXTO]


def test_aviso_da_copia_diz_que_e_copia_e_que_a_origem_continua_legivel() -> None:
    assert S.AVISO_COPIA.startswith("O cofre é uma cópia criptografada.")
    sobre_a_origem = S.AVISO_COPIA.split(". ", 1)[1]
    assert "legível" in sobre_a_origem
    assert not FORBIDDEN.search(sobre_a_origem), sobre_a_origem
    for rastro in ("Lixeira", "Versões anteriores", "OneDrive", "backups", "índice do Windows"):
        assert rastro in S.AVISO_COPIA


def test_texto_final_tem_data_hora_e_pede_backup() -> None:
    fim = S.FIM_TEXTO.format(data="17/11/2026", hora="14:13")
    assert "(cópia da pasta como estava em 17/11/2026 14:13)" in fim
    assert "backup externo" in fim and "outro computador" in fim
    assert "{" not in fim


def test_textos_do_assistente_sobre_a_origem_nunca_dizem_protegida() -> None:
    frases_sobre_origem = [
        (name, frase)
        for name, value in _textos_do_modulo()
        for frase in re.split(r"(?<=[.!?])\s+", value)
        if re.search(r"\borigem\b|\boriginal\b", frase, re.I)
    ]
    assert frases_sobre_origem
    for name, frase in frases_sobre_origem:
        assert not re.search(r"protegid", frase, re.I), (name, frase)


def test_botoes_e_passos_do_assistente() -> None:
    assert S.COPIA_PASSOS == ("Pastas", "Senha", "Conferência", "Criar")
    assert S.COPIA_PRIMARIO == (
        "Continuar para a senha",
        "Continuar para a conferência",
        "Criar cofre agora",
    )
    assert S.COPIA_PRIMARIO_FIM == "Abrir a pasta do cofre"
    assert S.COPIA_CRIAR_OUTRO == "Criar outro cofre"
    assert S.COPIA_RETOMAR == "Retomar criação interrompida"
