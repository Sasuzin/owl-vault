"""JobRunner (workers.py): o trabalho e o worker não sobrevivem ao fim de cada operação.

JAN-8 (parte de workers.py): o ``_Worker`` guardava o trabalho (e a closure dele, que pode ter
senha, PIN ou caminhos) e nunca era destruído — o ``deleteLater`` ia para uma thread que já
tinha terminado. Um worker ficava vivo por operação. Dados sintéticos; nenhum acesso a disco.
"""

from __future__ import annotations

import gc
import os
import time
import weakref
from collections.abc import Iterator

import pytest
import shiboken6
from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication

from owl_vault.application.progress import CancelToken
from owl_vault.ui import workers
from owl_vault.ui.workers import JobRunner, QtProgress

pytestmark = pytest.mark.gui

SEGREDO = "segredo-do-trabalho-" + "7f3a9c"


@pytest.fixture(scope="module")
def qapp() -> Iterator[QApplication]:
    anterior = os.environ.get("QT_QPA_PLATFORM")
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance() or QApplication(["owl-vault-testes-workers"])
    assert isinstance(app, QApplication)
    yield app
    if anterior is None:
        os.environ.pop("QT_QPA_PLATFORM", None)
    else:
        os.environ["QT_QPA_PLATFORM"] = anterior


def _descarta() -> None:
    for _ in range(3):
        QCoreApplication.processEvents()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def _workers_vivos() -> int:
    gc.collect()
    return sum(1 for o in gc.get_objects() if isinstance(o, workers._Worker))


def _roda(runner: JobRunner, falha: bool) -> tuple[str, weakref.ref[object], object]:
    """Roda um trabalho cuja closure guarda o segredo; devolve o que chegou à UI (só o tipo),
    uma referência fraca ao trabalho e o worker que o rodou."""
    chegou: list[str] = []
    runner.done.connect(lambda r: chegou.append(type(r).__name__))
    runner.error.connect(lambda e: chegou.append(type(e).__name__))
    segredo = SEGREDO

    def trabalho(progress: QtProgress, cancel: CancelToken) -> int:
        if falha:
            raise ValueError("falhou")
        return len(segredo)

    ref: weakref.ref[object] = weakref.ref(trabalho)
    runner.start(trabalho)
    worker = runner._worker
    del trabalho
    limite = time.monotonic() + 10
    while not chegou and time.monotonic() < limite:
        QCoreApplication.processEvents()
        time.sleep(0.005)
    runner.done.disconnect()
    runner.error.disconnect()
    _descarta()
    assert chegou, "o trabalho não terminou"
    return chegou[0], ref, worker


@pytest.mark.parametrize("falha", [False, True], ids=["ok", "falha"])
def test_trabalho_e_worker_nao_sobrevivem_ao_fim(qapp: QApplication, falha: bool) -> None:
    runner = JobRunner()
    antes = _workers_vivos()
    for _ in range(3):
        chegou, ref, worker = _roda(runner, falha)
        assert chegou == ("ValueError" if falha else "int")
        assert not runner.busy
        # o worker foi destruído pela própria thread (não sobra um por operação)
        assert not shiboken6.isValid(worker)
        del worker
        gc.collect()
        # nada mais guarda o trabalho nem, por ele, o segredo da closure
        assert ref() is None
    assert _workers_vivos() <= antes
    runner.deleteLater()
    _descarta()


def test_runner_continua_rodando_um_trabalho_por_vez(qapp: QApplication) -> None:
    """A destruição do worker não muda o resto: dá para rodar de novo e 'busy' segue certo."""
    runner = JobRunner()
    resultados: list[object] = []
    runner.done.connect(resultados.append)
    for i in range(3):
        runner.start(lambda _p, _c, i=i: i * 2)
        assert runner.busy
        with pytest.raises(RuntimeError):
            runner.start(lambda _p, _c: None)
        limite = time.monotonic() + 10
        while runner.busy and time.monotonic() < limite:
            QCoreApplication.processEvents()
            time.sleep(0.005)
    assert resultados == [0, 2, 4]
    runner.deleteLater()
    _descarta()
