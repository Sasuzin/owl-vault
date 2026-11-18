"""Execução de operações longas em QThread com sinais de progresso/cancelamento."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal, Slot

from owl_vault.application.progress import CancelToken


class Bridge(QObject):
    """Vive na thread da UI; os sinais emitidos pela thread de trabalho chegam enfileirados."""

    stage = Signal(str, object, object)  # nome, total_bytes, total_itens
    advance = Signal(object, object)  # bytes, itens (acumulados desde o último sinal)
    info = Signal(str)
    warning = Signal(str)


class QtProgress:
    """ProgressSink que emite sinais Qt, com limitação de frequência."""

    def __init__(self, bridge: Bridge) -> None:
        self._b = bridge
        self._pending_bytes = 0
        self._pending_items = 0
        self._last = 0.0

    def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
        self._flush()
        self._b.stage.emit(name, total_bytes, total_items)

    def advance(self, nbytes: int = 0, nitems: int = 0) -> None:
        self._pending_bytes += nbytes
        self._pending_items += nitems
        now = time.monotonic()
        if now - self._last >= 0.1:
            self._flush()
            self._last = now

    def _flush(self) -> None:
        if self._pending_bytes or self._pending_items:
            self._b.advance.emit(self._pending_bytes, self._pending_items)
            self._pending_bytes = 0
            self._pending_items = 0

    def info(self, message: str) -> None:
        self._b.info.emit(message)

    def warning(self, message: str) -> None:
        self._b.warning.emit(message)

    def close(self) -> None:
        self._flush()


Job = Callable[[QtProgress, CancelToken], Any]


class _Worker(QObject):
    finished = Signal(object)
    failed = Signal(object)

    def __init__(self, job: Job, progress: QtProgress, cancel: CancelToken) -> None:
        super().__init__()
        self._job: Job | None = job
        self._progress = progress
        self._cancel = cancel

    @Slot()
    def run(self) -> None:
        # O objeto solta o trabalho antes de rodá-lo: a closure (que pode guardar senha, PIN ou
        # caminhos) não fica presa a ele depois que o trabalho termina.
        job, self._job = self._job, None
        if job is None:
            return
        try:
            result = job(self._progress, self._cancel)
        except BaseException as exc:  # entregue à UI; nada é registrado em disco
            del job
            self._progress.close()
            self.failed.emit(exc)
            return
        del job
        self._progress.close()
        self.finished.emit(result)


class JobRunner(QObject):
    """Roda um job por vez numa QThread dedicada."""

    started = Signal()
    done = Signal(object)
    error = Signal(object)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.bridge = Bridge(self)
        self._thread: QThread | None = None
        self._worker: _Worker | None = None
        self.cancel_token: CancelToken | None = None

    @property
    def busy(self) -> bool:
        return self._thread is not None

    def start(self, job: Job) -> None:
        if self.busy:
            raise RuntimeError("já existe uma operação em andamento")
        self.cancel_token = CancelToken()
        progress = QtProgress(self.bridge)
        thread = QThread()
        worker = _Worker(job, progress, self.cancel_token)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        # O worker vive na thread do trabalho: só ela pode destruí-lo. Depois de "finished" a
        # thread ainda atende os pedidos de destruição, então nenhum worker sobra por trabalho.
        thread.finished.connect(worker.deleteLater)
        worker.finished.connect(self._on_finished)
        worker.failed.connect(self._on_failed)
        self._thread, self._worker = thread, worker
        thread.start()
        self.started.emit()

    def cancel(self) -> None:
        if self.cancel_token is not None:
            self.cancel_token.cancel()

    def _cleanup(self) -> None:
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait()  # ao voltar, o worker já foi destruído pela própria thread
            self._thread.deleteLater()
        self._thread = None
        self._worker = None

    @Slot(object)
    def _on_finished(self, result: object) -> None:
        self._cleanup()
        self.done.emit(result)

    @Slot(object)
    def _on_failed(self, exc: object) -> None:
        self._cleanup()
        self.error.emit(exc)
