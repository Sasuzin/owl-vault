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
