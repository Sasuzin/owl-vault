"""Instalação por usuário (``install.py``) e instância única (``single_instance.py``).

Achados perfil-4 (``versao.txt`` ligado ao conteúdo do exe instalado) e perfil-5 (o pedido
"abrir <id>" do atalho nunca se perde em silêncio). Só pastas temporárias e dados sintéticos:
``LOCALAPPDATA``/``APPDATA`` apontam para ``tmp_path``, os "executáveis" são bytes aleatórios
(sem Menu Iniciar, nenhum atalho é criado) e o canal da instância única usa nomes aleatórios —
nada fala com um Owl Vault de verdade.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from owl_vault.application import install
from owl_vault.application.install import InstallStamp

PY = sys.executable  # guardado antes de qualquer teste trocar sys.executable
ID_OK = "0123456789abcdef0123456789abcdef"
DATA = "2026-11-17"
V20 = (0, 3, 0, 20)
V19 = (0, 3, 0, 19)
V21 = (0, 3, 0, 21)
#: o leitor de ``versao.txt`` das versões anteriores (fullmatch do arquivo inteiro)
LEITOR_ANTIGO = r"\s*(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?\s*"


# =========================================================================== instalação


@dataclass
class Instalacao:
    baixado: Path
    alvo: Path
    pasta: Path
    build: dict[str, Any] = field(default_factory=dict)

    def roda(self, conteudo: bytes, versao: tuple[int, int, int, int], data: str = DATA) -> str:
        """Roda um "OwlVault.exe" baixado com ``conteudo``, ``versao`` e data de build."""
        self.baixado.write_bytes(conteudo)
        self.build["versao"], self.build["data"] = versao, data
        exe, args = install.ensure_installed()
        assert args == ""
        return exe

    def instalado(self) -> bytes:
        return self.alvo.read_bytes()

    def versao_txt(self) -> str:
        return (self.pasta / install.VERSION_FILE).read_text(encoding="ascii")

    def troca_por_fora(self, conteudo: bytes) -> None:
        """O que um Owl Vault 0.2.0 faz: troca o exe instalado e não mexe nas marcas."""
        tmp = self.pasta / "troca.tmp"
        tmp.write_bytes(conteudo)
        os.replace(tmp, self.alvo)


def _exe(rotulo: str) -> bytes:
    return rotulo.encode("ascii") + b"|" + os.urandom(8192)


def _marca(conteudo: bytes, versao: tuple[int, int, int, int], data: str = DATA) -> InstallStamp:
    return InstallStamp(versao, len(conteudo), hashlib.sha256(conteudo).hexdigest(), data)


@pytest.fixture
def inst(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Instalacao:
    local = tmp_path / "LocalAppData sintético"
    local.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming sem Menu Iniciar"))
    baixado = tmp_path / "Downloads sintéticos" / "OwlVault.exe"
    baixado.parent.mkdir()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(baixado))
    pasta = local / "Programs" / "Owl Vault"
    i = Instalacao(baixado, pasta / install.EXE_NAME, pasta, {"versao": V20, "data": DATA})
    monkeypatch.setattr(install, "current_version", lambda: i.build["versao"])
    monkeypatch.setattr(install, "current_build_date", lambda: i.build["data"])
    return i


def test_instala_e_grava_as_marcas_ligadas_ao_exe(inst: Instalacao) -> None:
    a = _exe("A")
    exe = inst.roda(a, V20)
    assert os.path.normcase(exe) == os.path.normcase(str(inst.alvo))
    assert inst.instalado() == a
    assert sorted(p.name for p in inst.pasta.iterdir()) == [
        "OwlVault.exe",
        "versao.sha256",
        "versao.txt",
    ]
    # versao.txt continua só com a versão: o leitor das versões anteriores entende
    assert inst.versao_txt() == "0.3.0.20\n"
    assert re.fullmatch(LEITOR_ANTIGO, inst.versao_txt())
    assert install.installed_stamp(inst.pasta) == _marca(a, V20)
    assert (inst.pasta / install.STAMP_FILE).read_text(encoding="ascii") == (
        f"0.3.0.20 {len(a)} {hashlib.sha256(a).hexdigest()} {DATA}\n"
    )


def test_exe_trocado_por_fora_e_reinstalado_pela_mesma_versao(inst: Instalacao) -> None:
    """Antes: um 0.2.0 trocava o exe, versao.txt continuava dizendo 0.3.0.N e o 0.3.0.N nunca
    mais corrigia (todos os atalhos abriam o código antigo)."""
    a = _exe("A")
    inst.roda(a, V20)
    inst.troca_por_fora(_exe("OLD-0.2.0"))
    inst.roda(a, V20)
    assert inst.instalado() == a
    assert install.installed_stamp(inst.pasta) == _marca(a, V20)


def test_exe_trocado_por_fora_nunca_abre_caminho_para_downgrade(inst: Instalacao) -> None:
    a, antigo, velho = _exe("A"), _exe("OLD-0.2.0"), _exe("V19")
    inst.roda(a, V20)
    inst.troca_por_fora(antigo)
    inst.roda(velho, V19)  # versão desconhecida no lugar, mas a registrada é 0.3.0.20
    assert inst.instalado() == antigo
    assert inst.versao_txt() == "0.3.0.20\n"
    inst.roda(a, V20)  # a versão registrada corrige
    assert inst.instalado() == a


def test_rebuild_com_o_mesmo_numero_substitui(inst: Instalacao) -> None:
    a, b = _exe("A"), _exe("B-rebuild")
    inst.roda(a, V20)
    inst.roda(b, V20)
    assert inst.instalado() == b
    assert install.installed_stamp(inst.pasta) == _marca(b, V20)


def test_rebuild_de_data_mais_antiga_com_o_mesmo_numero_nao_substitui(inst: Instalacao) -> None:
    novo, velho = _exe("novo"), _exe("velho")
    inst.roda(novo, V20, "2026-11-18")
    inst.roda(velho, V20, "2026-11-17")
    assert inst.instalado() == novo
    # sem data conhecida no atual não há como comparar: o rebuild substitui
    inst.roda(velho, V20, "")
    assert inst.instalado() == velho


def test_versao_mais_antiga_nunca_substitui_e_a_mais_nova_sim(inst: Instalacao) -> None:
    a, velho, novo = _exe("A"), _exe("V19"), _exe("V21")
    inst.roda(a, V20)
    inst.roda(velho, V19)
    assert inst.instalado() == a
    assert install.installed_stamp(inst.pasta) == _marca(a, V20)
    inst.roda(novo, V21)
    assert inst.instalado() == novo
    assert inst.versao_txt() == "0.3.0.21\n"
    assert install.installed_stamp(inst.pasta) == _marca(novo, V21)


def test_instalacao_sem_marca_do_conteudo_ganha_a_marca_sem_recopiar(inst: Instalacao) -> None:
    """Instalação feita por uma 0.3.0 de antes desta correção: só versao.txt."""
    a = _exe("A")
    inst.roda(a, V20)
    (inst.pasta / install.STAMP_FILE).unlink()
    antes = inst.alvo.stat()
    inst.roda(a, V20)
    depois = inst.alvo.stat()
    assert (depois.st_ino, depois.st_mtime_ns) == (antes.st_ino, antes.st_mtime_ns)
    assert install.installed_stamp(inst.pasta) == _marca(a, V20)


def test_segunda_execucao_igual_nao_regrava_nada(inst: Instalacao) -> None:
    a = _exe("A")
    inst.roda(a, V20)
    antes = {p.name: p.stat().st_mtime_ns for p in inst.pasta.iterdir()}
    inst.roda(a, V20)
    assert {p.name: p.stat().st_mtime_ns for p in inst.pasta.iterdir()} == antes


def test_marcas_voltam_se_a_troca_do_exe_falha(
    inst: Instalacao, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, novo = _exe("A"), _exe("V21")
    inst.roda(a, V20)
    original = os.replace

    def replace(src: Any, dst: Any) -> None:
        if os.path.normcase(str(dst)) == os.path.normcase(str(inst.alvo)):
            raise PermissionError(13, "exe instalado aberto (falha simulada)")
        original(src, dst)

    monkeypatch.setattr(install.os, "replace", replace)
    inst.roda(novo, V21)  # falha silenciosa: roda de onde está
    assert inst.instalado() == a
    assert inst.versao_txt() == "0.3.0.20\n"
    assert install.installed_stamp(inst.pasta) == _marca(a, V20)
    assert sorted(p.name for p in inst.pasta.iterdir()) == [
        "OwlVault.exe",
        "versao.sha256",
        "versao.txt",
    ]


def test_queda_entre_a_marca_e_o_exe_nao_permite_downgrade(inst: Instalacao) -> None:
    """As marcas vão antes do exe: uma queda no meio deixa a marca À FRENTE do exe."""
    a, novo, velho = _exe("A"), _exe("V21"), _exe("V19")
    inst.roda(a, V20)
    # queda: marcas do 0.3.0.21 gravadas, exe ainda o 0.3.0.20
    (inst.pasta / install.STAMP_FILE).write_text(_marca(novo, V21).text(), encoding="ascii")
    (inst.pasta / install.VERSION_FILE).write_text("0.3.0.21\n", encoding="ascii")
    inst.roda(velho, V19)
    assert inst.instalado() == a
    inst.roda(novo, V21)  # o exe não confere com a marca: a versão registrada corrige
    assert inst.instalado() == novo
    assert install.installed_stamp(inst.pasta) == _marca(novo, V21)


@pytest.mark.parametrize(
    "texto",
    [
        "",
        "0.3.0.20",
        "0.3.0.20 10 abc 2026-11-17",
        f"0.3.0 10 {'a' * 64} 2026-11-17",
        f"0.3.0.20 dez {'a' * 64} 2026-11-17",
        f"0.3.0.20 10 {'A' * 64} 2026-11-17",
        f"0.3.0.20 10 {'a' * 64} ontem",
    ],
)
def test_marca_ilegivel_e_ignorada(texto: str) -> None:
    assert install.parse_stamp(texto) is None


def test_marca_sem_data() -> None:
    m = install.parse_stamp(f"0.3.0.20 10 {'a' * 64} -\n")
    assert m == InstallStamp(V20, 10, "a" * 64, "")
    assert m is not None and m.text() == f"0.3.0.20 10 {'a' * 64} -\n"


def test_data_do_build_invalida_vira_desconhecida(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    for valor, esperado in [(DATA, DATA), ("17/11/2026", ""), ("", ""), (None, "")]:
        monkeypatch.setitem(sys.modules, "owl_vault._build", SimpleNamespace(BUILD=1, DATE=valor))
        assert install.current_build_date() == esperado
    monkeypatch.setitem(sys.modules, "owl_vault._build", SimpleNamespace(BUILD=1))
    assert install.current_build_date() == ""


# =========================================================================== instância única

gui = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp() -> Iterator[Any]:
    from PySide6.QtWidgets import QApplication

    anterior = os.environ.get("QT_QPA_PLATFORM")
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance() or QApplication(["owl-vault-testes"])
    yield app
    if anterior is None:
        os.environ.pop("QT_QPA_PLATFORM", None)
    else:
        os.environ["QT_QPA_PLATFORM"] = anterior


def _processa(cond: Callable[[], object], timeout: float) -> None:
    from PySide6.QtCore import QCoreApplication

    fim = time.monotonic() + timeout
    while not cond() and time.monotonic() < fim:
        QCoreApplication.processEvents()
        time.sleep(0.005)


def _descarta() -> None:
    from PySide6.QtCore import QCoreApplication, QEvent

    QCoreApplication.processEvents()
    QCoreApplication.sendPostedEvents(None, int(QEvent.Type.DeferredDelete.value))
    QCoreApplication.processEvents()


#: a 2ª execução, num processo à parte (como o atalho): espera "vai" e envia o pedido
_CLIENTE = r"""
import json, sys
from PySide6.QtCore import QCoreApplication
from owl_vault.ui import single_instance as si
app = QCoreApplication([])
si._key = lambda: sys.argv[1]
avisos = []
si._warn_user = avisos.append
s = si.SingleInstance()
print("pronto", flush=True)
sys.stdin.readline()
ok = s.send(sys.argv[2], patience=float(sys.argv[3]))
print(json.dumps({"ok": ok, "primaria": s.primary, "avisos": avisos}), flush=True)
"""


class Cliente:
    def __init__(self, nome: str, pedido: str, paciencia: float) -> None:
        self.proc = subprocess.Popen(  # noqa: S603 - o próprio Python do venv, script fixo
            [PY, "-c", _CLIENTE, nome, pedido, str(paciencia)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        assert self.proc.stdout is not None
        assert self.proc.stdout.readline().strip() == "pronto"

    def vai(self) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write("vai\n")
        self.proc.stdin.flush()

    def terminou(self) -> bool:
        return self.proc.poll() is not None

    def resultado(self) -> dict[str, Any]:
        out = self.proc.communicate(timeout=60)[0]
        return dict(json.loads(out.strip().splitlines()[-1]))

    def mata(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()


def _nome() -> str:
    return "OwlVault-teste-" + secrets.token_hex(12)  # nunca o nome real do usuário


@gui
def test_pedido_nao_se_perde_com_a_janela_principal_ocupada(
    qapp: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Antes: com a interface principal parada por mais de 3 s, a 2ª execução desistia, dizia
    que tinha enviado e saía calada — o pedido sumia."""
    from owl_vault.ui import single_instance

    nome = _nome()
    monkeypatch.setattr(single_instance, "_key", lambda: nome)
    primeira = single_instance.SingleInstance()
    recebidas: list[str] = []
    primeira.message.connect(recebidas.append)
    pedido = f"abrir {ID_OK}"
    cliente = Cliente(nome, pedido, single_instance.SEND_PATIENCE)
    try:
        assert primeira.primary and primeira.listening
        cliente.vai()
        time.sleep(4.0)  # interface principal ocupada (trabalho síncrono longo)
        _processa(lambda: recebidas and cliente.terminou(), timeout=30)
        r = cliente.resultado()
        assert r == {"ok": True, "primaria": False, "avisos": []}
        assert recebidas == [pedido]  # chegou, e uma vez só
    finally:
        cliente.mata()
        primeira.deleteLater()
        _descarta()


@gui
def test_janela_principal_confirma_que_leu(qapp: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from owl_vault.ui import single_instance

    nome = _nome()
    monkeypatch.setattr(single_instance, "_key", lambda: nome)
    primeira = single_instance.SingleInstance()
    recebidas: list[str] = []
    primeira.message.connect(recebidas.append)
    script = (
        "import sys\n"
        "from PySide6.QtCore import QCoreApplication\n"
        "from PySide6.QtNetwork import QLocalSocket\n"
        "app = QCoreApplication([])\n"
        "s = QLocalSocket()\n"
        "s.connectToServer(sys.argv[1])\n"
        "assert s.waitForConnected(10000)\n"
        "s.write(b'mostrar\\n')\n"
        "s.waitForBytesWritten(10000)\n"
        "while not s.canReadLine() and s.waitForReadyRead(10000):\n"
        "    pass\n"
        "print(bytes(s.readLine(64).data()).decode().strip())\n"
    )
    proc = subprocess.Popen(  # noqa: S603
        [PY, "-c", script, nome], stdout=subprocess.PIPE, text=True
    )
    try:
        _processa(lambda: proc.poll() is not None, timeout=30)
        out = proc.communicate(timeout=30)[0].strip()
        assert out == "ok"
        assert recebidas == ["mostrar"]
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        primeira.deleteLater()
        _descarta()


@gui
def test_pedido_lido_sem_confirmacao_avisa_e_nao_e_reenviado(qapp: Any) -> None:
    """A janela leu o pedido mas travou antes de confirmar: a 2ª execução avisa (sem dizer que
    o pedido se perdeu) e não reenvia — a janela não pode pedir o PIN duas vezes."""
    from PySide6.QtNetwork import QLocalServer

    from owl_vault.ui import single_instance

    nome = _nome()
    srv = QLocalServer()
    assert srv.listen(nome)
    lidas: list[bytes] = []
    socks: list[Any] = []

    def nova() -> None:
        sock = srv.nextPendingConnection()
        socks.append(sock)

        def ler() -> None:
            if sock.canReadLine():
                lidas.append(bytes(sock.readLine(512).data()))
                time.sleep(3.0)  # leu, mas a interface travou antes de confirmar

        sock.readyRead.connect(ler)
        if sock.bytesAvailable():
            ler()

    srv.newConnection.connect(nova)
    cliente = Cliente(nome, "mostrar", 1.5)
    try:
        cliente.vai()
        _processa(cliente.terminou, timeout=30)
        _processa(lambda: False, timeout=1.0)
        r = cliente.resultado()
        assert r["ok"] is False
        assert r["avisos"] == [single_instance._WARNINGS[single_instance._NO_REPLY]]
        assert "ocupado" in r["avisos"][0]
        assert lidas == [b"mostrar\n"]
    finally:
        cliente.mata()
        srv.close()
        _descarta()


@gui
def test_janela_principal_de_versao_anterior_conta_como_entregue(qapp: Any) -> None:
    """Uma janela principal de antes desta correção lê a linha e fecha, sem confirmar."""
    from PySide6.QtNetwork import QLocalServer

    nome = _nome()
    srv = QLocalServer()
    assert srv.listen(nome)
    lidas: list[bytes] = []
    socks: list[Any] = []

    def nova() -> None:
        sock = srv.nextPendingConnection()
        socks.append(sock)

        def ler() -> None:
            if sock.canReadLine():
                lidas.append(bytes(sock.readLine(512).data()))
                sock.disconnectFromServer()

        sock.readyRead.connect(ler)
        if sock.bytesAvailable():
            ler()

    srv.newConnection.connect(nova)
    cliente = Cliente(nome, f"abrir {ID_OK}", 5.0)
    try:
        cliente.vai()
        _processa(cliente.terminou, timeout=30)
        assert cliente.resultado()["ok"] is True
        assert lidas == [f"abrir {ID_OK}\n".encode()]
    finally:
        cliente.mata()
        srv.close()
        _descarta()


@gui
def test_sem_resposta_tenta_de_novo_e_avisa(qapp: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from owl_vault.ui import single_instance

    nome = _nome()
    monkeypatch.setattr(single_instance, "_key", lambda: nome)
    monkeypatch.setattr(single_instance, "claim_pipe_name", lambda _n: False)
    s = single_instance.SingleInstance()  # ninguém escuta neste nome
    assert not s.listening
    avisos: list[str] = []
    tentativas: list[float] = []
    original = single_instance.SingleInstance._send_once

    def conta(self: Any, payload: Any, deadline: float) -> str:
        tentativas.append(time.monotonic())
        return str(original(self, payload, deadline))

    monkeypatch.setattr(single_instance, "_warn_user", avisos.append)
    monkeypatch.setattr(single_instance.SingleInstance, "_send_once", conta)
    t0 = time.monotonic()
    assert s.send(f"abrir {ID_OK}", patience=1.0) is False
    assert time.monotonic() - t0 >= 0.9
    assert len(tentativas) >= 2  # tentou de novo enquanto havia tempo
    assert avisos == [single_instance._WARNINGS[single_instance._NOT_READ]]
    assert s.send("mostrar", patience=0.3, warn=False) is False
    assert len(avisos) == 1
    s.deleteLater()
    _descarta()


@gui
def test_canal_de_outra_conta_avisa_sem_enviar(qapp: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from owl_vault.ui import single_instance

    nome = _nome()
    monkeypatch.setattr(single_instance, "_key", lambda: nome)
    s = single_instance.SingleInstance()
    assert s.listening
    recebidas: list[str] = []
    s.message.connect(recebidas.append)
    avisos: list[str] = []
    monkeypatch.setattr(single_instance, "_warn_user", avisos.append)
    monkeypatch.setattr(single_instance, "peer_is_same_user", lambda *_a, **_k: False)
    t0 = time.monotonic()
    assert s.send(f"abrir {ID_OK}", patience=5.0) is False
    assert time.monotonic() - t0 < 4.0  # não fica tentando de novo
    assert avisos == [single_instance._WARNINGS[single_instance._REFUSED]]
    _processa(lambda: False, timeout=0.5)
    assert recebidas == []
    s.deleteLater()
    _descarta()


@gui
def test_aviso_aparece_numa_caixa_de_mensagem(qapp: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from PySide6.QtWidgets import QMessageBox

    from owl_vault import APP_NAME
    from owl_vault.ui import single_instance

    vistas: list[tuple[str, str]] = []

    def exec_(box: QMessageBox) -> int:
        vistas.append((box.windowTitle(), box.text()))
        return int(QMessageBox.StandardButton.Ok.value)

    monkeypatch.setattr(QMessageBox, "exec", exec_)
    texto = single_instance._WARNINGS[single_instance._NOT_READ]
    single_instance._warn_user(texto)
    assert vistas == [(APP_NAME, texto)]
    # sem interface gráfica (QCoreApplication), nada é mostrado
    monkeypatch.setattr(single_instance.QCoreApplication, "instance", staticmethod(lambda: None))
    single_instance._warn_user(texto)
    assert len(vistas) == 1


def test_avisos_curtos_e_sem_jargao() -> None:
    from owl_vault.ui import single_instance

    for texto in single_instance._WARNINGS.values():
        assert len(texto) <= 160
        for jargao in ("pipe", "socket", "instância", "processo", "servidor", "ack"):
            assert jargao not in texto.lower()
