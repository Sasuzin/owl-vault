"""Contratos de progresso e cancelamento (ARCHITECTURE §3)."""

from __future__ import annotations

import threading
from typing import Protocol

from owl_vault.domain.errors import CancelledError


class CancelToken:
    """Sinal de cancelamento verificado em fronteiras consistentes (entre chunks/arquivos)."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def check(self) -> None:
        if self._event.is_set():
            raise CancelledError("Operação cancelada pelo usuário.")


class ProgressSink(Protocol):
    def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None: ...

    def advance(self, nbytes: int = 0, nitems: int = 0) -> None: ...

    def info(self, message: str) -> None: ...

    def warning(self, message: str) -> None: ...


class NullProgress:
    def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
        pass

    def advance(self, nbytes: int = 0, nitems: int = 0) -> None:
        pass

    def info(self, message: str) -> None:
        pass

    def warning(self, message: str) -> None:
        pass


class RecordingProgress(NullProgress):
    """Guarda mensagens em memória (útil para CLI/testes)."""

    def __init__(self) -> None:
        self.stages: list[str] = []
        self.infos: list[str] = []
        self.warnings: list[str] = []

    def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
        self.stages.append(name)

    def info(self, message: str) -> None:
        self.infos.append(message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)
