"""Assistente "Cópia criptografada" (visual Cofre, Estilo 5) — ui/copy_window.py.

Regras destes testes: SOMENTE pastas temporárias (tmp_path) com dados sintéticos, política
de teste (TESTING_POLICY/TESTING_PARAMS) e nenhuma pasta protegida; nenhum diálogo modal é
aberto (``ask``/``inform`` e o Explorer são trocados por gravadores; os campos de pasta são
preenchidos direto, sem o seletor do Windows). A criação, a retomada, a conferência e a
restauração rodam de verdade (QThread) numa origem sintética.
"""

from __future__ import annotations

import itertools
import os
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtGui import QColor
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QFrame, QLabel, QPushButton

from owl_vault.application import restore as restore_mod
from owl_vault.application.create import create_vault, inspect_vault_dir
from owl_vault.application.preflight import CreatePlan, preflight_create
from owl_vault.application.progress import CancelToken, NullProgress
from owl_vault.application.protection import ProtectedPaths
from owl_vault.application.verify import verify_vault
from owl_vault.crypto.kdf import TESTING_PARAMS, TESTING_POLICY
from owl_vault.domain.errors import CancelledError
from owl_vault.ui import copy_window
from owl_vault.ui import strings as S
from owl_vault.ui.copy_window import (
    ABRIR,
    CONFERIR,
    CRIAR,
    TITULOS_CONFERENCIA,
    Checagem,
    CopyWindow,
    conferencia,
)
from owl_vault.ui.theme import current_tokens

SENHA = "cavalo correto bateria grampo 2026"
SENHA_ERRADA = "outra frase qualquer 9183"


# --------------------------------------------------------------------------------------
# infraestrutura


@pytest.fixture(scope="module")
def qapp() -> Iterator[QApplication]:
    """Uma QApplication por módulo, sem janela real (plataforma offscreen)."""
    anterior = os.environ.get("QT_QPA_PLATFORM")
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")
    app = QApplication.instance() or QApplication(["owl-vault-testes"])
    assert isinstance(app, QApplication)
    yield app
    _descarta()
    if anterior is None:
        os.environ.pop("QT_QPA_PLATFORM", None)
    else:
        os.environ["QT_QPA_PLATFORM"] = anterior


def _descarta() -> None:
    QCoreApplication.processEvents()
    QCoreApplication.sendPostedEvents(None, int(QEvent.Type.DeferredDelete.value))
    QCoreApplication.processEvents()


def _espera(cond: Callable[[], object], timeout: float = 60.0) -> None:
    fim = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > fim:
            raise AssertionError("tempo esgotado esperando a interface")
        QCoreApplication.processEvents()
        time.sleep(0.005)
    QCoreApplication.processEvents()


class Gravador:
    """Substitui ``ask``/``inform``/``open_in_explorer`` (nada de janela modal)."""

    def __init__(self) -> None:
        self.perguntas: list[tuple[str, str]] = []
        self.informes: list[tuple[str, str]] = []
        self.explorer: list[str] = []
        self.resposta = ""

    def ask(self, _parent: object, title: str, text: str, _buttons: object, **_kw: Any) -> str:
        self.perguntas.append((title, text))
        return self.resposta

    def inform(self, _parent: object, title: str, text: str, *_a: Any) -> None:
        self.informes.append((title, text))

    def abrir(self, path: str) -> None:
        self.explorer.append(path)


@pytest.fixture
def gravador(monkeypatch: pytest.MonkeyPatch) -> Gravador:
    g = Gravador()
    monkeypatch.setattr(copy_window, "ask", g.ask)
    monkeypatch.setattr(copy_window, "inform", g.inform)
    monkeypatch.setattr(copy_window, "open_in_explorer", g.abrir)
    return g


@pytest.fixture
def win(qapp: QApplication, gravador: Gravador) -> Iterator[CopyWindow]:
    w = CopyWindow(
        kdf_policy=TESTING_POLICY, kdf_params=TESTING_PARAMS, protected=ProtectedPaths.none()
    )
    w.resize(1040, 860)
    w.show()
    QCoreApplication.processEvents()
    yield w
    _espera(lambda: not w.runner.busy)
    w.close()
    w.deleteLater()
    _descarta()


@pytest.fixture
def pastas(tmp_path: Path) -> dict[str, Path]:
    origem = tmp_path / "origem sintética"
    (origem / "sub" / "vazia").mkdir(parents=True)
    (origem / "a.txt").write_bytes(b"ola mundo")
    (origem / "b.bin").write_bytes(os.urandom(70_000))
    (origem / "sub" / "c.txt").write_bytes(b"conteudo " * 100)
    out = {"origem": origem}
    for nome in ("cofres", "teste", "saida"):
        p = tmp_path / nome
        p.mkdir()
        out[nome] = p
    return out


def _arvore(raiz: Path) -> dict[str, bytes | None]:
    return {
        str(p.relative_to(raiz)): (p.read_bytes() if p.is_file() else None)
        for p in sorted(raiz.rglob("*"))
    }


def _estados_trilha(w: CopyWindow) -> list[str]:
    return [str(n.property("estado") or "") for n in w.trilha.findChildren(QLabel, "passoNumero")]


def _preenche_pastas(w: CopyWindow, p: dict[str, Path], nome: str = "Cofre-teste") -> None:
    w.c_origem.definir(str(p["origem"]))
    w.c_local.definir(str(p["cofres"]))
    w.c_teste.definir(str(p["teste"]))
    w.c_nome.setText(nome)


def _ate_conferencia(w: CopyWindow, p: dict[str, Path], nome: str = "Cofre-teste") -> None:
    _preenche_pastas(w, p, nome)
    w.rodape.primario.click()
    assert w.passo == 1
    w.c_senha.setText(SENHA)
    w.c_conf.setText(SENHA)
    w.rodape.primario.click()
    assert w.passo == 2
    _espera(lambda: not w.runner.busy)


def _marca_aceites(w: CopyWindow) -> None:
    for c in w.aceites_todos:
        if not c.isHidden():
            c.setChecked(True)


# --------------------------------------------------------------------------------------
# conferência (função pura)


def _plano(**kw: Any) -> CreatePlan:
    plan = CreatePlan("C:\\o", "C:\\c\\Cofre", "C:\\t", 64 * 1024)
    for k, v in kw.items():
        setattr(plan, k, v)
    return plan


def test_conferencia_classifica_bloqueios_e_avisos() -> None:
    plan = _plano(
        blockers=[
            "Espaço insuficiente para o cofre: necessário ~900 MiB, livre 10 MiB.",
            "fotos\\a.jpg: fotos\\a.jpg: arquivo em uso por outro programa. Feche-o e tente "
            "novamente.",
            "Origem: a origem não pode ser a raiz de uma unidade",
            "Cofre: a pasta já existe e não está vazia (escolha um nome novo; para continuar "
            "um cofre interrompido use 'Retomar').",
            "pasta\\aux.txt: nome reservado no Windows",
        ],
        warnings=["3 arquivo(s) com hard links: o conteúdo será copiado, os vínculos não."],
    )
    linhas = conferencia(plan, ["Pré-verificação: listando a origem"], None)
    por_titulo = {c.titulo: c for c in linhas}
    for t in TITULOS_CONFERENCIA:
        assert por_titulo[t].estado == "falhou", t
    assert "fotos\\a.jpg" in por_titulo["Arquivos em uso"].detalhe
    assert "raiz" in por_titulo["Tamanho e contagem da origem"].detalhe
    assert "não está vazia" in por_titulo["Destino gravável"].detalhe
    # cada outro bloqueio e cada aviso vira uma linha própria
    assert Checagem("pasta\\aux.txt", "falhou", "Nome reservado no Windows") in linhas
    assert (
        Checagem(
            "3 arquivo(s) com hard links", "aviso", "O conteúdo será copiado, os vínculos não."
        )
        in linhas
    )


def test_conferencia_sem_bloqueios_mostra_as_quatro_linhas_ok() -> None:
    plan = _plano(
        files=[object()] * 3,
        dirs=[object()],
        total_bytes=5000,
        estimated_vault_bytes=70 * 1024 * 1024,
        vault_res=object(),
        test_res=object(),
        vault_fs="NTFS",
    )
    etapas = ["Pré-verificação: listando a origem", "Pré-verificação: abrindo arquivos"]
    linhas = conferencia(plan, etapas, 2 * 1024**3)
    assert [c.titulo for c in linhas] == list(TITULOS_CONFERENCIA)
    assert all(c.estado == "ok" for c in linhas)
    assert "70,0 MB" in linhas[0].detalhe and "2,0 GB" in linhas[0].detalhe
    assert linhas[2].detalhe.startswith("3 arquivo(s) · 1 pasta(s)")
    assert "NTFS" in linhas[3].detalhe


def test_conferencia_que_parou_cedo_nao_finge_que_conferiu() -> None:
    plan = _plano(blockers=["Origem: a pasta não existe."])
    linhas = conferencia(plan, ["Pré-verificação: conferindo caminhos"], None)
    por_titulo = {c.titulo: c for c in linhas}
    assert por_titulo["Tamanho e contagem da origem"].estado == "falhou"
    for t in ("Espaço em disco", "Arquivos em uso", "Destino gravável"):
        assert por_titulo[t].estado == ""  # não rodou
        assert "Não conferido" in por_titulo[t].detalhe


# --------------------------------------------------------------------------------------
# janela: estrutura, textos e navegação


def test_abre_no_passo_pastas_com_trilha_rodape_e_dica(win: CopyWindow) -> None:
    assert win.windowTitle() == S.COPIA_TITULO_JANELA
    assert win.modo == CRIAR and win.passo == 0
    assert win.paginas.currentIndex() == 0
    assert win.trilha.isVisible()
    textos = [t.text() for t in win.trilha.findChildren(QLabel, "passoTexto")]
    assert textos == ["Pastas", "Senha", "Conferência", "Criar"]
    assert _estados_trilha(win) == ["atual", "", "", ""]
    assert win.rodape.primario.objectName() == "primario"
    assert win.rodape.primario.isDefault()
    assert win.rodape.primario.text() == "Continuar para a senha"
    assert win.rodape.voltar.isVisible() and not win.rodape.voltar.isEnabled()
    assert win.rodape.ponto.objectName() == "estadoPonto"
    assert win.rodape.texto.objectName() == "estadoTexto"
    assert win.rodape.texto.text() == "Pronto."
    # lateral: no passo 1 só a dica (o resumo aparece a partir do passo 2)
    assert not win.resumo.isVisible()
    assert win.dica.isVisible()
    assert S.NOME_DICA in [lbl.text() for lbl in win.dica.findChildren(QLabel)]
    assert win.c_retomar.objectName() == "discreto"
    assert win.c_retomar.text() == "Retomar criação interrompida"
    assert win.c_nome.text().startswith("Cofre-")
    assert win.c_origem.campo.property("caminho") == "sim"
    assert win.bt_criar.property("atual") == "sim"
    # páginas do assistente são QFrame#cartao; o log do passo 4 segue o design
    for i in range(4):
        assert win.paginas.widget(i).objectName() == "cartao"
    assert win.painel_criar.log.objectName() == "log"
    assert win.painel_criar.log.maximumBlockCount() == 5000
    assert win.lateral.width() == 272
    assert win.resumo.objectName() == "cartaoLateral" and win.dica.objectName() == "dica"
    assert win.rodape.objectName() == "rodape"


def test_passo_pastas_valida_antes_de_avancar(win: CopyWindow, pastas: dict[str, Path]) -> None:
    win.rodape.primario.click()
    assert win.passo == 0
    assert win.erro_pastas.isVisibleTo(win)
    assert win.erro_pastas.text() == "Escolha a pasta de origem."
    win.c_origem.definir(str(pastas["origem"]))
    win.rodape.primario.click()
    assert win.passo == 0
    assert win.erro_pastas.text() == "Informe o local e o nome do cofre."
    # retomar sem criação interrompida
    win.c_local.definir(str(pastas["cofres"]))
    win.c_retomar.click()
    assert win.passo == 0
    assert win.erro_pastas.text() == "Não há criação interrompida nessa pasta de cofre."
    win.rodape.primario.click()
    assert win.passo == 1
    assert not win.erro_pastas.isVisibleTo(win)


def test_teste_de_restauracao_e_sugerido_e_escolha_do_usuario_e_mantida(
    win: CopyWindow, pastas: dict[str, Path], tmp_path: Path
) -> None:
    win.c_origem.definir(str(pastas["origem"]))
    sugerida = win.c_teste.texto()
    assert sugerida, "a pasta do teste deve ser sugerida automaticamente"
    outra = tmp_path / "outra origem"
    outra.mkdir()
    win.c_origem.definir(str(outra))
    assert win.c_teste.texto()  # recalculada (ainda era a sugestão)
    win.c_teste.definir(str(pastas["teste"]))
    win.c_origem.definir(str(pastas["origem"]))
    assert win.c_teste.texto() == str(pastas["teste"])


def test_senha_valida_e_ir_e_voltar_nao_perde_o_que_foi_digitado(
    win: CopyWindow, pastas: dict[str, Path]
) -> None:
    _preenche_pastas(win, pastas)
    win.rodape.primario.click()
    assert win.passo == 1
    assert _estados_trilha(win) == ["feito", "atual", "", ""]
    numeros = win.trilha.findChildren(QLabel, "passoNumero")
    assert numeros[0].text() == "✓"
    ligacoes = win.trilha.findChildren(QFrame, "ligacao")
    assert [str(lg.property("estado") or "") for lg in ligacoes] == ["feito", "", ""]
    assert win.rodape.primario.text() == "Continuar para a conferência"
    assert win.rodape.voltar.isEnabled()
    assert win.p2_texto.text() == S.SENHA_TEXTO
    assert win.aviso_senha.isVisibleTo(win)
    assert "legível" in win.aviso_senha.texto() and "<b>cópia</b>" in win.aviso_senha.texto()
    # lateral com as escolhas do passo 1 e "alterar"
    QCoreApplication.processEvents()  # o layout mostra os itens novos no próximo giro
    assert win.resumo.isVisible()
    valores = [lbl.toolTip() for lbl in win.resumo.findChildren(QLabel, "resumoValor")]
    assert str(pastas["origem"]) in valores and "Cofre-teste" in valores
    alterar = [
        b
        for b in win.resumo.findChildren(QPushButton)
        if b.isVisibleTo(win) and b.text() == "alterar"
    ]
    assert len(alterar) == 4
    # regras de senha (as mesmas de antes)
    win.c_senha.setText("curta")
    win.rodape.primario.click()
    assert win.passo == 1
    assert win.erro_senha.text() == "A senha deve ter pelo menos 12 caracteres."
    win.c_senha.setText(SENHA)
    win.c_conf.setText(SENHA + "x")
    win.rodape.primario.click()
    assert win.erro_senha.text() == "As senhas não conferem."
    win.c_senha.setText(" " + SENHA)
    win.c_conf.setText(" " + SENHA)
    win.rodape.primario.click()
    assert win.passo == 1
    assert "espaço" in win.erro_senha.text()
    # medidor só informa
    win.c_senha.setText(SENHA)
    win.c_conf.setText(SENHA)
    veredito = win.medidor.findChildren(QLabel, "forcaTexto")[0]
    assert veredito.text() == "Forte"
    # voltar e ir de novo: nada se perde
    win.rodape.voltar.click()
    assert win.passo == 0
    assert win.c_origem.texto() == str(pastas["origem"])
    assert win.c_nome.text() == "Cofre-teste"
    win.rodape.primario.click()
    assert win.passo == 1
    assert win.c_senha.text() == SENHA and win.c_conf.text() == SENHA
    # "alterar" leva de volta ao passo 1
    QCoreApplication.processEvents()
    alterar = [
        b
        for b in win.resumo.findChildren(QPushButton)
        if b.isVisibleTo(win) and b.text() == "alterar"
    ]
    alterar[2].click()
    assert win.passo == 0


def test_fluxo_completo_cria_cofre_de_verdade(
    win: CopyWindow, pastas: dict[str, Path], gravador: Gravador
) -> None:
    antes = _arvore(pastas["origem"])
    _ate_conferencia(win, pastas)
    # passo 3: conferência rodou na QThread
    assert win.paginas.currentIndex() == 2
    assert _estados_trilha(win) == ["feito", "feito", "atual", ""]
    titulos = [lin.titulo.text() for lin in win.linhas]
    assert titulos[:4] == list(TITULOS_CONFERENCIA)
    estados = [str(lin.icone.property("estado") or "") for lin in win.linhas]
    assert estados[:4] == ["ok"] * 4
    assert "aviso" in estados  # "Não são preservados: ..." é sempre informado
    assert not win.aceite_fat.isVisibleTo(win)  # NTFS
    # primário só com os aceites
    assert win.rodape.primario.text() == "Criar cofre agora"
    assert not win.rodape.primario.isEnabled()
    win.aceite_limites.setChecked(True)
    win.aceite_backup.setChecked(True)
    assert not win.rodape.primario.isEnabled()
    win.aceite_senha.setChecked(True)
    assert win.rodape.primario.isEnabled()
    # passo 4: criação de verdade
    win.rodape.primario.click()
    assert win.passo == 3
    assert win.criacao == "rodando"
    assert win.c_senha.text() == "" and win.c_conf.text() == ""  # senha descartada dos campos
    assert win.aviso_criar.isVisibleTo(win)
    assert not win.rodape.voltar.isEnabled()
    assert win.cancelar.isVisibleTo(win)
    _espera(lambda: not win.runner.busy)
    assert win.criacao == "ok", win.erro_criar.text()
    assert win.p4_titulo.text() == "Cofre criado"
    assert _estados_trilha(win) == ["feito", "feito", "feito", "feito"]
    texto = win.resultado_criar.texto()
    assert "Cópia criptografada criada e verificada (cópia da pasta como estava em" in texto
    assert (
        "Mantenha a origem e um backup externo até verificar o cofre, de preferência em outro "
        "computador." in texto
    )
    assert win.rodape.primario.text() == "Abrir a pasta do cofre"
    assert win.criar_outro.isVisibleTo(win)
    assert win.criar_outro.text() == "Criar outro cofre"
    assert not win.rodape.voltar.isVisible()
    assert not win.cancelar.isVisibleTo(win)
    assert win.rodape.texto.text().startswith("Pronto. Último cofre verificado às")
    log = win.painel_criar.log.toPlainText()
    assert "Criptografando" in log and "Teste de restauração" in log
    # o cofre existe, está completo e confere; a origem não mudou
    cofre = pastas["cofres"] / "Cofre-teste"
    assert (cofre / "complete.owl").is_file()
    rep = verify_vault(str(cofre), SENHA, policy=TESTING_POLICY)
    assert rep.fully_ok
    assert _arvore(pastas["origem"]) == antes
    assert win.session_sources
    # "Abrir a pasta do cofre" e "Criar outro cofre"
    win.rodape.primario.click()
    assert gravador.explorer and gravador.explorer[-1].endswith("Cofre-teste")
    win.criar_outro.click()
    assert win.passo == 0 and win.criacao == ""
    assert _estados_trilha(win) == ["atual", "", "", ""]
    assert win.rodape.primario.text() == "Continuar para a senha"
    assert not any(c.isChecked() for c in win.aceites_todos)
    assert win.c_origem.texto() == str(pastas["origem"])


def test_conferencia_com_bloqueio_nao_habilita_criar(
    win: CopyWindow, pastas: dict[str, Path]
) -> None:
    _preenche_pastas(win, pastas)
    win.c_local.definir(str(pastas["origem"] / "sub"))  # cofre dentro da origem
    win.rodape.primario.click()
    win.c_senha.setText(SENHA)
    win.c_conf.setText(SENHA)
    win.rodape.primario.click()
    _espera(lambda: not win.runner.busy)
    destino = next(lin for lin in win.linhas if lin.titulo.text() == "Destino gravável")
    assert destino.icone.property("estado") == "falhou"
    assert "dentro da origem" in destino.detalhe.text()
    _marca_aceites(win)
    assert not win.rodape.primario.isEnabled()
    assert win.rodape.ponto.property("estado") == "erro"
    assert not (pastas["origem"] / "sub" / "Cofre-teste").exists()  # nada foi gravado


def test_falha_na_criacao_mostra_motivo_e_volta_as_pastas(
    win: CopyWindow, pastas: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    def falha(*_a: Any, **_kw: Any) -> Any:
        raise CancelledError("Operação cancelada pelo usuário.")

    _ate_conferencia(win, pastas)
    monkeypatch.setattr(copy_window, "create_vault", falha)
    _marca_aceites(win)
    win.rodape.primario.click()
    _espera(lambda: not win.runner.busy)
    assert win.criacao == "falhou"
    assert win.p4_titulo.text() == "A criação parou"
    assert win.erro_criar.isVisibleTo(win)
    assert win.erro_criar.text() == S.COPIA_CANCELADA
    assert win.rodape.ponto.property("estado") == "erro"
    assert win.rodape.primario.text() == "Voltar às pastas"  # nada a retomar
    assert win.rodape.voltar.isEnabled()
    win.rodape.primario.click()
    assert win.passo == 0
    assert win.c_origem.texto() == str(pastas["origem"])


def test_retomar_criacao_interrompida(win: CopyWindow, pastas: dict[str, Path]) -> None:
    cofre = pastas["cofres"] / "Cofre-interrompido"
    plan = preflight_create(
        str(pastas["origem"]),
        str(cofre),
        test_parent=str(pastas["teste"]),
        protected=ProtectedPaths.none(),
    )
    token = CancelToken()

    class Cancela(NullProgress):
        def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
            if name.startswith("Criptografando"):
                token.cancel()

    with pytest.raises(CancelledError):
        create_vault(
            str(pastas["origem"]),
            str(cofre),
            SENHA,
            plan=plan,
            kdf_params=TESTING_PARAMS,
            kdf_policy=TESTING_POLICY,
            progress=Cancela(),
            cancel=token,
        )
    assert inspect_vault_dir(str(cofre)).kind == "vault-incomplete"

    _preenche_pastas(win, pastas, "Cofre-interrompido")
    # criar com o mesmo nome é recusado, retomar é o caminho
    win.rodape.primario.click()
    assert win.passo == 0 and "Retomar criação interrompida" in win.erro_pastas.text()
    win.c_retomar.click()
    assert win.passo == 1 and win.retomando
    assert win.p2_titulo.text() == "Digite a senha do cofre"
    assert not win.g_conf.isVisibleTo(win) and not win.medidor.isVisibleTo(win)
    assert win.aviso_senha.isVisibleTo(win)
    win.rodape.primario.click()
    assert win.passo == 1 and win.erro_senha.text() == "Digite a senha do cofre."
    win.c_senha.setText(SENHA)
    win.rodape.primario.click()
    assert win.passo == 2
    assert win.linhas[0].titulo.text() == "Criação interrompida encontrada"
    assert win.linhas[0].icone.property("estado") == "ok"
    assert win.rodape.primario.text() == "Retomar a criação agora"
    assert not win.rodape.primario.isEnabled()  # aceites obrigatórios, como antes
    _marca_aceites(win)
    assert win.rodape.primario.isEnabled()
    win.rodape.primario.click()
    _espera(lambda: not win.runner.busy)
    assert win.criacao == "ok", win.erro_criar.text()
    assert (cofre / "complete.owl").is_file()
    assert verify_vault(str(cofre), SENHA, policy=TESTING_POLICY).fully_ok


# --------------------------------------------------------------------------------------
# conferir / abrir uma cópia


@pytest.fixture
def cofre_pronto(pastas: dict[str, Path]) -> Path:
    cofre = pastas["cofres"] / "Cofre-pronto"
    create_vault(
        str(pastas["origem"]),
        str(cofre),
        SENHA,
        test_parent=str(pastas["teste"]),
        kdf_params=TESTING_PARAMS,
        kdf_policy=TESTING_POLICY,
        protected=ProtectedPaths.none(),
    )
    return cofre


def test_conferir_uma_copia(win: CopyWindow, cofre_pronto: Path) -> None:
    win.bt_conferir.click()
    assert win.modo == CONFERIR
    assert win.paginas.currentWidget().objectName() == "cartao"
    assert not win.trilha.isVisible()
    assert win.bt_conferir.property("atual") == "sim"
    assert win.bt_criar.property("atual") == ""
    assert win.rodape.primario.text() == "Conferir a cópia"
    win.rodape.primario.click()
    assert win.erro_conferir.text() == "Informe o cofre e a senha."
    win.v_copia.definir(str(cofre_pronto))
    win.v_senha.setText(SENHA_ERRADA)
    win.rodape.primario.click()
    _espera(lambda: not win.runner.busy)
    assert win.erro_conferir.isVisibleTo(win)
    assert win.rodape.ponto.property("estado") == "erro"
    win.v_senha.setText(SENHA)
    win.rodape.primario.click()
    assert win.v_senha.text() == ""  # senha descartada do campo
    _espera(lambda: not win.runner.busy)
    assert win.resultado_conferir.linha is not None
    assert win.resultado_conferir.linha.icone.property("estado") == "ok"
    assert "Cofre íntegro" in win.resultado_conferir.texto()
    # Voltar leva ao assistente sem perder o passo
    win.rodape.voltar.click()
    assert win.modo == CRIAR and win.passo == 0


def test_abrir_uma_copia_numa_pasta_nova(
    win: CopyWindow, cofre_pronto: Path, pastas: dict[str, Path], gravador: Gravador
) -> None:
    win.bt_abrir.click()
    assert win.modo == ABRIR
    assert win.rodape.primario.text() == "Abrir numa pasta nova"
    win.r_copia.definir(str(cofre_pronto))
    win.r_senha.setText(SENHA)
    win.r_local.definir(str(pastas["saida"]))
    # destino existente e não vazio é recusado (sem rodar nada)
    ocupada = pastas["saida"] / "ocupada"
    ocupada.mkdir()
    (ocupada / "x.txt").write_bytes(b"x")
    win.r_nome.setText("ocupada")
    win.rodape.primario.click()
    assert not win.runner.busy
    assert "não está vazia" in win.erro_abrir.text()
    win.r_nome.setText("Restaurado-teste")
    win.rodape.primario.click()
    assert win.r_senha.text() == ""
    _espera(lambda: not win.runner.busy)
    assert win.resultado_abrir.linha is not None
    assert win.resultado_abrir.linha.icone.property("estado") == "ok", win.erro_abrir.text()
    assert _arvore(pastas["saida"] / "Restaurado-teste") == _arvore(pastas["origem"])
    assert win.r_nome.text().startswith("Restaurado-")  # novo nome sugerido
    mostrar = [
        b for b in win.resultado_abrir.findChildren(QPushButton) if b.text() == "Mostrar a pasta"
    ]
    mostrar[0].click()
    assert gravador.explorer[-1].endswith("Restaurado-teste")
    assert not gravador.perguntas


def test_abrir_restauracao_interrompida_pergunta_antes(
    win: CopyWindow, cofre_pronto: Path, pastas: dict[str, Path], gravador: Gravador
) -> None:
    dest = pastas["saida"] / "meio"
    dest.mkdir()
    (dest / restore_mod.MARKER_NAME).write_text("{}", encoding="utf-8")
    assert restore_mod.inspect_destination(str(dest)) == "resumable"
    win.bt_abrir.click()
    win.r_copia.definir(str(cofre_pronto))
    win.r_senha.setText(SENHA)
    win.r_local.definir(str(pastas["saida"]))
    win.r_nome.setText("meio")
    gravador.resposta = "nao"
    win.rodape.primario.click()
    assert gravador.perguntas and "restauração interrompida" in gravador.perguntas[-1][1]
    assert not win.runner.busy
    assert win.r_senha.text() == SENHA  # nada começou


# --------------------------------------------------------------------------------------
# teclado, log, fechar


def test_enter_aciona_o_primario_e_tab_segue_a_leitura(win: CopyWindow) -> None:
    win.c_nome.setFocus()
    QTest.keyClick(win.c_nome, Qt.Key.Key_Return)
    assert win.erro_pastas.text() == "Escolha a pasta de origem."  # o primário rodou
    ordem = [
        win.c_origem.campo,
        win.c_origem.botao,
        win.c_local.campo,
        win.c_local.botao,
        win.c_nome,
        win.c_teste.campo,
        win.c_teste.botao,
        win.c_retomar,
    ]
    for a, b in itertools.pairwise(ordem):
        assert a.nextInFocusChain() is b, (a, b)


def test_log_usa_cor_do_token(win: CopyWindow) -> None:
    painel = win.painel_criar
    painel.escrever("AVISO: teste", "aviso")
    painel.escrever("linha comum")
    doc = painel.log.document()
    ultimo = doc.lastBlock()
    aviso = ultimo.previous()
    cor = aviso.begin().fragment().charFormat().foreground().color()
    assert cor == QColor(current_tokens()["warn"])
    comum = ultimo.begin().fragment().charFormat().foreground()
    assert comum.style() == Qt.BrushStyle.NoBrush  # linha comum: cor do QSS (log-ink)


def test_limites_da_protecao_no_topo(win: CopyWindow, gravador: Gravador) -> None:
    win.bt_limites.click()
    assert gravador.informes and gravador.informes[-1][0] == S.LIMITS_TITLE
    assert S.LIMITS_TEXT in gravador.informes[-1][1]


def test_fechar_com_operacao_em_andamento_pergunta(win: CopyWindow, gravador: Gravador) -> None:
    liberar = threading.Event()

    def job(_p: Any, cancel: CancelToken) -> None:
        while not liberar.wait(0.01):
            cancel.check()

    win._rodar(job, lambda _r: None, lambda _e: None, None, "Trabalhando…")
    assert win.runner.busy
    assert win.cancelar.isVisibleTo(win)
    gravador.resposta = "keep"
    win.close()
    assert gravador.perguntas and win.isVisible() and win.runner.busy
    gravador.resposta = "stop"
    win.close()
    _espera(lambda: not win.runner.busy)
    _espera(lambda: not win.isVisible(), timeout=5)
    liberar.set()
