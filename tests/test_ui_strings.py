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


# --- regressões da revisão: textos verdadeiros para cada situação ---------------------------


def test_so_manda_retomar_quando_ha_o_que_retomar() -> None:
    """copia-3/copia-8: a conferência, a conferência de uma cópia e a restauração não têm
    "Retomar criação"; a criação parada antes de existir um cofre incompleto também não."""
    for texto in (
        S.COPIA_CANCELADA_SEM_RETOMADA,
        S.COPIA_CONFERENCIA_CANCELADA,
        S.COPIA_VERIFICACAO_CANCELADA,
        S.COPIA_RESTAURACAO_PARADA,
        S.COPIA_RESTAURACAO_PARADA_ANTES,
        S.COPIA_RESTAURACAO_INCOMPLETA,
        S.COPIA_RESTAURACAO_TALVEZ,
        S.COPIA_NAO_CRIOU,
        S.COPIA_FECHAR_CONFERENCIA,
        S.COPIA_FECHAR_CONFERIR,
        S.COPIA_FECHAR_ABRIR,
    ):
        assert "Retomar" not in texto, texto
    assert S.COPIA_RETOMAR in S.COPIA_CANCELADA
    # "Nada foi gravado" só onde é verdade (a conferência do passo 3 não grava nada)
    assert "Nada foi gravado" in S.COPIA_CONFERENCIA_CANCELADA
    assert "Nada" not in S.COPIA_RESTAURACAO_PARADA + S.COPIA_RESTAURACAO_INCOMPLETA
    assert S.COPIA_FECHAR_TEXTOS == {
        "criar": S.COPIA_FECHAR_TEXTO,
        "conferencia": S.COPIA_FECHAR_CONFERENCIA,
        "conferir": S.COPIA_FECHAR_CONFERIR,
        "abrir": S.COPIA_FECHAR_ABRIR,
    }
    assert "Se já houver um cofre incompleto" in S.COPIA_FECHAR_TEXTO


def test_destino_gravavel_nao_finge_teste_de_gravacao() -> None:
    """copia-3: a linha diz que a gravação ainda não foi testada (e quando será)."""
    texto = S.COPIA_DESTINO_NAO_TESTADO.format(fs="NTFS")
    assert "(NTFS)" in texto
    assert "ainda não foi testada" in texto and "início da criação" in texto
    assert "de novo" not in texto


def test_textos_com_campos_sao_preenchidos() -> None:
    assert "{" not in S.COPIA_RESTAURACAO_INCOMPLETA.format(nome="Volta")
    assert "'Volta'" in S.COPIA_RESTAURACAO_TALVEZ.format(nome="Volta")
    assert S.COPIA_NOME_INVALIDO.format(problema="x").endswith(": x.")
    assert S.COPIA_NOME_NOVO_INVALIDO.format(problema="x").endswith(": x.")
    fim = S.COPIA_FIM_CONCLUIDO.format(data="17/11/2026", hora="12:03")
    assert "(concluída em 17/11/2026 12:03)" in fim
    assert "backup externo" in fim and "backup externo" in S.COPIA_FIM_SEM_DATA


def test_rodape_da_conferencia_acompanha_os_aceites() -> None:
    """visual-14: um texto para "faltam os avisos" e outro para "pronto"."""
    assert "Marque os avisos" in S.COPIA_MARQUE_AVISOS
    assert "Marque" not in S.COPIA_PRONTO_CRIAR and "Marque" not in S.COPIA_PRONTO_RETOMAR


def test_textos_do_bloqueio_nao_dizem_que_nada_aconteceu() -> None:
    """Com o app bloqueado no meio de um trabalho, o texto não promete o que não sabe."""
    for texto in (S.COPIA_BLOQUEIO_PAROU, S.COPIA_BLOQUEIO_TERMINOU, S.COPIA_DIGITE_DE_NOVO):
        assert "nada foi" not in texto.lower()
        assert "{" not in texto
