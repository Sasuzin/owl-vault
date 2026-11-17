"""Ponto de injeção de falhas para testes (ARCHITECTURE §5).

O código de produção chama :func:`checkpoint` antes de cada escrita/flush/rename
relevante. Por padrão nada acontece. Os testes registram falhas com :func:`fail_at`
(ex.: simular disco cheio na 3ª escrita de blob, ou queda antes de um rename).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class _Rule:
    op: str
    nth: int
    make_exc: Callable[[], BaseException]
    seen: int = 0
    fired: bool = False


@dataclass
class _Registry:
    rules: list[_Rule] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


_REG = _Registry()


def checkpoint(op: str) -> None:
    """Chamado pelo código de produção em pontos de E/S nomeados."""
    if not _REG.rules:
        return
    with _REG.lock:
        _REG.counts[op] = _REG.counts.get(op, 0) + 1
        for rule in _REG.rules:
            if rule.fired or not _matches(rule.op, op):
                continue
            rule.seen += 1
            if rule.seen == rule.nth:
                rule.fired = True
                raise rule.make_exc()


def _matches(pattern: str, op: str) -> bool:
    if pattern.endswith("*"):
        return op.startswith(pattern[:-1])
    return pattern == op


def fail_at(op: str, nth: int, make_exc: Callable[[], BaseException]) -> None:
    """Faz a ``nth``-ésima passagem por ``op`` levantar ``make_exc()``."""
    with _REG.lock:
        _REG.rules.append(_Rule(op, nth, make_exc))


def reset() -> None:
    with _REG.lock:
        _REG.rules.clear()
        _REG.counts.clear()


def count(op: str) -> int:
    with _REG.lock:
        return _REG.counts.get(op, 0)
