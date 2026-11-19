"""Assistente "Cópia criptografada" (visual Cofre, Estilo 5) — ui/copy_window.py.

Regras destes testes: SOMENTE pastas temporárias (tmp_path) com dados sintéticos, política
de teste (TESTING_POLICY/TESTING_PARAMS) e nenhuma pasta protegida; nenhum diálogo modal é
aberto (``ask``/``inform`` e o Explorer são trocados por gravadores; os campos de pasta são
preenchidos direto, sem o seletor do Windows). A criação, a retomada, a conferência e a
restauração rodam de verdade (QThread) numa origem sintética.
"""

from __future__ import annotations

import datetime as _dt
import gc
import itertools
import os
import threading
import time
import types
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QObject, QPoint, QRect, Qt
from PySide6.QtGui import QColor, QScreen
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QAbstractButton,
    QApplication,
    QFrame,
    QGraphicsDropShadowEffect,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QStyleFactory,
    QWidget,
)

from owl_vault.application import restore as restore_mod
from owl_vault.application.create import CreateResult, create_vault, inspect_vault_dir
from owl_vault.application.preflight import CreatePlan, preflight_create
from owl_vault.application.progress import CancelToken, NullProgress
from owl_vault.application.protection import ProtectedPaths
from owl_vault.application.verify import verify_vault
from owl_vault.crypto.kdf import TESTING_PARAMS, TESTING_POLICY
from owl_vault.domain.errors import CancelledError, OwlVaultError
from owl_vault.ui import componentes, copy_window
from owl_vault.ui import strings as S
from owl_vault.ui.copy_window import (
    ABRIR,
    CONFERIR,
    CRIAR,
    OP_ABRIR,
    OP_CONFERENCIA,
    OP_CONFERIR,
    OP_CRIAR,
    TITULOS_CONFERENCIA,
    Checagem,
    CopyWindow,
    conferencia,
    mensagem_de_erro,
)
from owl_vault.ui.theme import apply_theme, current_tokens

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
        #: roda "enquanto a pergunta está aberta" (o laço modal entrega sinais nesse meio-tempo)
        self.durante: Callable[[], None] | None = None

    def ask(self, _parent: object, title: str, text: str, _buttons: object, **_kw: Any) -> str:
        self.perguntas.append((title, text))
        if self.durante is not None:
            self.durante()
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


def test_conferencia_sem_bloqueios_mostra_as_quatro_linhas() -> None:
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
    assert [c.estado for c in linhas[:3]] == ["ok", "ok", "ok"]
    assert "70,0 MB" in linhas[0].detalhe and "2,0 GB" in linhas[0].detalhe
    assert linhas[2].detalhe.startswith("3 arquivo(s) · 1 pasta(s)")
    assert "NTFS" in linhas[3].detalhe


def test_destino_gravavel_nunca_tem_ok_sem_testar_gravacao() -> None:
    """copia-3: a conferência não grava nada (COPIA_P3_TEXTO), então "Destino gravável" não
    pode ter ✓ — fica neutro e diz que a gravação será testada ao criar."""
    plan = _plano(vault_res=object(), test_res=object(), vault_fs="NTFS")
    destino = conferencia(plan, ["Pré-verificação: listando a origem"], None)[3]
    assert destino.titulo == "Destino gravável"
    assert destino.estado == ""  # neutro (•), nunca "ok" (✓)
    assert "ainda não foi testada" in destino.detalhe
    assert "será testada no início da criação" in destino.detalhe
    assert "testada de novo" not in destino.detalhe  # não insinua um teste que não houve


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
    assert win.erro_senha.text() == "A senha deve ter pelo menos 8 caracteres."
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
    # "Destino gravável" fica neutro: a gravação só é testada ao criar (copia-3)
    assert estados[:4] == ["ok", "ok", "ok", ""]
    assert "aviso" in estados  # "Não são preservados: ..." é sempre informado
    assert not win.aceite_fat.isVisibleTo(win)  # NTFS
    # primário só com os aceites; o rodapé diz o que falta de verdade (visual-14)
    assert win.rodape.primario.text() == "Criar cofre agora"
    assert not win.rodape.primario.isEnabled()
    assert win.rodape.texto.text() == S.COPIA_MARQUE_AVISOS
    win.aceite_limites.setChecked(True)
    win.aceite_backup.setChecked(True)
    assert not win.rodape.primario.isEnabled()
    assert win.rodape.texto.text() == S.COPIA_MARQUE_AVISOS
    win.aceite_senha.setChecked(True)
    assert win.rodape.primario.isEnabled()
    assert win.rodape.texto.text() == S.COPIA_PRONTO_CRIAR
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
    # nada foi criado: o texto não manda usar "Retomar" (copia-3/copia-8)
    assert win.erro_criar.text() == S.COPIA_CANCELADA_SEM_RETOMADA
    assert "Retomar" not in win.erro_criar.text()
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


# --------------------------------------------------------------------------------------
# regressões da revisão (qa_confirmados): bloqueio, fechar, aceites, textos e telas baixas


def _textos_na_janela(w: QWidget) -> list[str]:
    """Tudo que os widgets da janela mostram ou guardam como texto (inclusive dicas)."""
    out: list[str] = []
    for x in w.findChildren(QWidget):
        out.append(x.toolTip())
        if isinstance(x, QLabel | QAbstractButton):
            out.append(x.text())
        elif isinstance(x, QLineEdit):
            out += [x.text(), x.displayText()]
        elif isinstance(x, QPlainTextEdit):
            out.append(x.toPlainText())
    return [t for t in out if t]


class _Fechamentos(QObject):
    """Conta os pedidos de fechar (QCloseEvent) que chegam à janela."""

    def __init__(self) -> None:
        super().__init__()
        self.pedidos = 0

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if event.type() == QEvent.Type.Close:
            self.pedidos += 1
        return False


def _cofre_interrompido(pastas: dict[str, Path], nome: str) -> Path:
    cofre = pastas["cofres"] / nome
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
    return cofre


def test_bloquear_sem_trabalho_fecha_ja_sem_senha_nem_caminho(
    win: CopyWindow, pastas: dict[str, Path], gravador: Gravador
) -> None:
    """copia-1 / perfil-1 / fluxos-8 (contrato C1): o bloqueio do app fecha a Cópia e não
    deixa senha (nem "Mostrar" ligado), caminho ou nome de pasta em nenhum widget."""
    _ate_conferencia(win, pastas)
    assert win.c_senha.text() == SENHA
    win.c_senha.mostrar.click()
    assert win.c_senha.echoMode() == QLineEdit.EchoMode.Normal
    win.r_copia.definir(str(pastas["cofres"]))
    win.r_local.definir(str(pastas["saida"]))
    win.r_senha.setText(SENHA_ERRADA)
    win.v_copia.definir(str(pastas["cofres"]))
    win.v_senha.setText(SENHA_ERRADA)
    win.painel_criar.escrever(f"linha do registro com {pastas['origem']}")
    win.session_sources.append(str(pastas["origem"]))  # como depois de criar uma cópia
    QCoreApplication.processEvents()
    raiz = str(pastas["origem"].parent)
    assert any(raiz in t for t in _textos_na_janela(win))  # antes: caminhos na tela

    win.bloquear()

    assert not win.isVisible()
    assert not gravador.perguntas  # fecha sem perguntar nada
    for campo in (win.c_senha, win.r_senha, win.v_senha):
        assert campo.text() == ""
        assert campo.echoMode() == QLineEdit.EchoMode.Password
        assert campo.mostrar.text() == "Mostrar"
    assert win.c_conf.text() == ""
    textos = _textos_na_janela(win)  # ainda sem rodar o laço (nada de "deleteLater depois")
    assert not [t for t in textos if raiz in t or "origem sintética" in t or "Cofre-teste" in t]
    assert not [t for t in textos if SENHA in t or SENHA_ERRADA in t]
    assert win.modo == CRIAR and win.passo == 0 and win.criacao == ""
    assert not any(c.isChecked() for c in win.aceites_todos)
    assert win.session_sources == []
    # aberta de novo depois do desbloqueio: volta a funcionar, do começo
    win.show()
    QCoreApplication.processEvents()
    assert win.resumo.findChildren(QLabel, "secaoLateral")[0].text()  # título da lateral fica
    win.rodape.primario.click()
    assert win.erro_pastas.text() == "Escolha a pasta de origem."


def test_bloquear_com_trabalho_pede_parada_some_e_fecha_sozinha(
    win: CopyWindow, gravador: Gravador
) -> None:
    """C1 com trabalho rodando: some na hora, pede o cancelamento sem perguntar, nada do
    trabalho volta à tela e a janela fecha sozinha quando ele para."""
    liberar = threading.Event()
    parou = threading.Event()
    chamados: list[object] = []

    def job(_p: Any, cancel: CancelToken) -> str:
        try:
            while not liberar.wait(0.01):
                cancel.check()
        finally:
            parou.set()
        return "terminou"

    fechamentos = _Fechamentos()
    win.installEventFilter(fechamentos)
    win._rodar(
        job, chamados.append, chamados.append, win.painel_criar, "Criando…", copy_window.OP_CRIAR
    )
    assert win.runner.busy
    win.c_senha.setText(SENHA)
    win.bloquear()
    assert not win.isVisible()
    assert not gravador.perguntas
    assert win.c_senha.text() == ""
    token = win.runner.cancel_token
    assert token is not None and token.cancelled
    win.runner.bridge.info.emit("arquivo secreto.docx")  # chega depois do bloqueio
    win.runner.bridge.stage.emit("Criptografando segredo.docx", 10, 1)
    _espera(lambda: not win.runner.busy)
    _espera(lambda: fechamentos.pedidos > 0, timeout=5)  # fechou sozinha (sem perguntar)
    assert not gravador.perguntas
    assert parou.is_set()
    assert chamados == []  # o resultado/erro (com caminhos) não volta à tela
    assert "segredo" not in "\n".join(_textos_na_janela(win))
    assert not win.isVisible()
    assert win.rodape.texto.text() == S.COPIA_BLOQUEIO_PAROU
    win.removeEventFilter(fechamentos)
    liberar.set()


def test_seletor_de_pastas_que_volta_depois_do_bloqueio_nao_deixa_caminho(
    win: CopyWindow, pastas: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """C1: o seletor de pastas do Windows não fecha com o bloqueio; o caminho que ele devolve
    depois (origem, que também sugere o teste) não entra na janela bloqueada."""
    escolhida = str(pastas["origem"])

    def seletor(*_a: object) -> str:
        win.bloquear()  # o app bloqueia com o seletor aberto (5 min sem uso, Win+L…)
        return escolhida

    monkeypatch.setattr(componentes, "choose_folder", seletor)
    win.c_origem.botao.click()
    QCoreApplication.processEvents()
    assert win._bloqueada
    assert [c.texto() for c in win._campos_caminho()] == [""] * 6
    textos = "\n".join(_textos_na_janela(win))
    assert escolhida not in textos and str(pastas["origem"].parent) not in textos


SENHA_UNICA = "senha so deste teste pelicano 6631"


def _closures_com_a_senha() -> list[str]:
    """Funções da Cópia ainda vivas cuja closure guarda a senha (direto ou numa caixa
    ``_Senha`` que não foi esvaziada)."""
    gc.collect()
    achados: list[str] = []
    for o in gc.get_objects():
        if not isinstance(o, types.FunctionType) or "CopyWindow." not in o.__qualname__:
            continue
        for cell in o.__closure__ or ():
            try:
                v = cell.cell_contents
            except ValueError:
                continue
            if isinstance(v, str) and SENHA_UNICA in v:
                achados.append(o.__qualname__)
            elif isinstance(v, copy_window._Senha) and v._valor:
                achados.append(f"{o.__qualname__} (caixa cheia)")
    return achados


def test_senha_nao_fica_no_trabalho_depois_que_ele_termina(
    win: CopyWindow, pastas: dict[str, Path]
) -> None:
    """JAN-8 (parte da Cópia): o JobRunner mantém vivo o trabalho de cada operação, e a função
    dele guardava a senha da cópia — alcançável depois do fim e do bloqueio (C1)."""
    # criar (passo 4)
    _preenche_pastas(win, pastas, "Cofre-segredo")
    win.rodape.primario.click()
    win.c_senha.setText(SENHA_UNICA)
    win.c_conf.setText(SENHA_UNICA)
    win.rodape.primario.click()
    _espera(lambda: not win.runner.busy)
    _marca_aceites(win)
    win.rodape.primario.click()
    _espera(lambda: not win.runner.busy)
    assert win.criacao == "ok", win.erro_criar.text()
    cofre = pastas["cofres"] / "Cofre-segredo"
    # conferir uma cópia
    win.bt_conferir.click()
    win.v_copia.definir(str(cofre))
    win.v_senha.setText(SENHA_UNICA)
    win.rodape.primario.click()
    _espera(lambda: not win.runner.busy)
    assert "Cofre íntegro" in win.resultado_conferir.texto()
    # abrir uma cópia numa pasta nova
    win.bt_abrir.click()
    win.r_copia.definir(str(cofre))
    win.r_senha.setText(SENHA_UNICA)
    win.r_local.definir(str(pastas["saida"]))
    win.r_nome.setText("Restaurado-segredo")
    win.rodape.primario.click()
    _espera(lambda: not win.runner.busy)
    assert (pastas["saida"] / "Restaurado-segredo" / "a.txt").is_file()
    win.bloquear()
    _descarta()
    assert _closures_com_a_senha() == []


def test_fechar_a_janela_apaga_as_senhas_e_pede_a_senha_de_novo(
    win: CopyWindow, pastas: dict[str, Path]
) -> None:
    """copia-1: a janela é reaproveitada; fechada, ela não guarda senha nenhuma."""
    _ate_conferencia(win, pastas)
    win.r_senha.setText(SENHA)
    win.v_senha.setText(SENHA)
    win.c_senha.mostrar.click()
    assert win.close()
    for campo in (win.c_senha, win.r_senha, win.v_senha, win.c_conf):
        assert campo.text() == ""
    assert win.c_senha.echoMode() == QLineEdit.EchoMode.Password
    win.show()
    QCoreApplication.processEvents()
    # sem a senha, a conferência pronta não pode virar criação: volta ao passo Senha
    assert win.passo == 1
    assert win.rodape.primario.text() != S.COPIA_PRIMARIO[2]


def test_mostrar_senha_desliga_ao_trocar_de_passo_ou_de_tela(
    win: CopyWindow, pastas: dict[str, Path]
) -> None:
    _preenche_pastas(win, pastas)
    win.rodape.primario.click()
    win.c_senha.setText(SENHA)
    win.c_senha.mostrar.click()
    assert win.c_senha.echoMode() == QLineEdit.EchoMode.Normal
    win.rodape.voltar.click()
    assert win.c_senha.echoMode() == QLineEdit.EchoMode.Password
    assert win.c_senha.text() == SENHA  # voltar não perde o que foi digitado
    win.bt_abrir.click()
    win.r_senha.setText(SENHA)
    win.r_senha.mostrar.click()
    win.bt_conferir.click()
    assert win.r_senha.echoMode() == QLineEdit.EchoMode.Password


def test_iniciar_criacao_sem_senha_volta_ao_passo_senha(
    win: CopyWindow, pastas: dict[str, Path]
) -> None:
    _ate_conferencia(win, pastas)
    _marca_aceites(win)
    win.c_senha.limpar()  # como depois de um bloqueio que aconteceu no meio
    win._iniciar_criacao()
    assert not win.runner.busy and win.criacao == ""
    assert win.passo == 1
    assert win.erro_senha.text() == S.COPIA_DIGITE_DE_NOVO


def test_aceites_sao_pedidos_de_novo_a_cada_conferencia(
    win: CopyWindow, pastas: dict[str, Path], tmp_path: Path
) -> None:
    """copia-2: aceites dados para uma origem/destino/mídia não valem para outra."""
    _ate_conferencia(win, pastas)
    _marca_aceites(win)
    assert win.rodape.primario.isEnabled()
    outra = tmp_path / "outra origem"
    outra.mkdir()
    (outra / "x.txt").write_bytes(b"x")
    win.rodape.voltar.click()
    win.rodape.voltar.click()
    assert win.passo == 0
    win.c_origem.definir(str(outra))
    win.rodape.primario.click()
    assert win.passo == 1
    win.rodape.primario.click()  # a senha continua digitada
    assert win.passo == 2
    _espera(lambda: not win.runner.busy)
    assert win._plan is not None and win._plan.ok
    assert not any(c.isChecked() for c in win.aceites_todos)
    assert not win.rodape.primario.isEnabled()
    # o aceite de FAT/exFAT vale para uma conferência só (a mídia pode ter sido trocada)
    _marca_aceites(win)
    win.aceite_fat.setChecked(True)
    win.bt_de_novo.click()
    _espera(lambda: not win.runner.busy)
    assert not win.aceite_fat.isChecked()


def test_duplo_clique_na_retomada_nao_comeca_sem_mostrar_a_conferencia(
    win: CopyWindow, pastas: dict[str, Path]
) -> None:
    """copia-6: o 2º clique de um duplo clique em "Continuar para a conferência" cai no
    mesmo lugar do rodapé; com os aceites desmarcados, ele não dispara a retomada."""
    _cofre_interrompido(pastas, "Cofre-interrompido")
    _preenche_pastas(win, pastas, "Cofre-interrompido")
    _marca_aceites(win)  # aceites de uma tentativa anterior
    win.c_retomar.click()
    assert win.passo == 1 and win.retomando
    win.c_senha.setText(SENHA)
    win.rodape.primario.click()
    win.rodape.primario.click()
    assert win.passo == 2
    assert not win.runner.busy and win.criacao == ""
    assert not win.rodape.primario.isEnabled()
    assert win.rodape.texto.text() == S.COPIA_MARQUE_AVISOS
    _marca_aceites(win)
    assert win.rodape.texto.text() == S.COPIA_PRONTO_RETOMAR


def test_parar_e_fechar_fecha_mesmo_se_o_trabalho_acaba_durante_a_pergunta(
    win: CopyWindow, gravador: Gravador
) -> None:
    """copia-7."""
    liberar = threading.Event()

    def job(_p: Any, cancel: CancelToken) -> None:
        while not liberar.wait(0.01):
            cancel.check()

    win._rodar(job, lambda _r: None, lambda _e: None, None, "Trabalhando…")

    def termina() -> None:
        liberar.set()
        _espera(lambda: not win.runner.busy)

    gravador.durante = termina
    gravador.resposta = "stop"
    assert win.close()
    assert not win.isVisible()
    assert gravador.perguntas


def test_mensagem_de_erro_por_operacao() -> None:
    """copia-3/copia-8: "Retomar criação interrompida" só quando há o que retomar."""
    parado = CancelledError("x")
    assert mensagem_de_erro(parado, OP_CONFERENCIA) == S.COPIA_CONFERENCIA_CANCELADA
    assert mensagem_de_erro(parado, OP_CONFERIR) == S.COPIA_VERIFICACAO_CANCELADA
    assert mensagem_de_erro(parado, OP_CRIAR, ha_incompleto=True) == S.COPIA_CANCELADA
    assert mensagem_de_erro(parado, OP_CRIAR) == S.COPIA_CANCELADA_SEM_RETOMADA
    assert mensagem_de_erro(parado, OP_ABRIR) == S.COPIA_RESTAURACAO_PARADA_ANTES
    meio = mensagem_de_erro(parado, OP_ABRIR, ha_incompleto=True, destino="C:\\saida\\Volta")
    assert meio.startswith(S.COPIA_RESTAURACAO_PARADA) and "'Volta' ficou incompleta" in meio
    for op in (OP_CONFERENCIA, OP_CONFERIR, OP_ABRIR):
        assert "Retomar" not in mensagem_de_erro(parado, op)
    gravar = OwlVaultError(
        "Criação interrompida (use 'Retomar'): acesso negado. Se o Windows Defender 'Acesso "
        "controlado a pastas' estiver ativo, permita o OwlVault.exe ou escolha outra pasta."
    )
    assert mensagem_de_erro(gravar, OP_CRIAR, ha_incompleto=True) == str(gravar)
    sem = mensagem_de_erro(gravar, OP_CRIAR)
    assert sem.startswith("Não foi possível criar o cofre: acesso negado.")
    assert "Retomar" not in sem
    assert "Retomar" not in mensagem_de_erro(RuntimeError("x"), OP_CRIAR)
    assert "Retomar" in mensagem_de_erro(RuntimeError("x"), OP_CRIAR, ha_incompleto=True)
    erro_abrir = mensagem_de_erro(OwlVaultError("disco cheio."), OP_ABRIR, destino="C:\\s\\V")
    assert erro_abrir.startswith("disco cheio.") and "'V' pode ter ficado incompleta" in erro_abrir


def test_falha_de_gravacao_sem_cofre_incompleto_nao_manda_retomar(
    win: CopyWindow, pastas: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """copia-3: acesso negado no início da criação (nada criado) não sugere "Retomar"."""

    def nega(*_a: Any, **_kw: Any) -> Any:
        raise OwlVaultError(
            "Criação interrompida (use 'Retomar'): acesso negado. Se o Windows Defender "
            "'Acesso controlado a pastas' estiver ativo, permita o OwlVault.exe ou escolha "
            "outra pasta."
        )

    _ate_conferencia(win, pastas)
    monkeypatch.setattr(copy_window, "create_vault", nega)
    _marca_aceites(win)
    win.rodape.primario.click()
    _espera(lambda: not win.runner.busy)
    assert win.criacao == "falhou"
    assert win.erro_criar.text().startswith("Não foi possível criar o cofre: acesso negado.")
    assert "Retomar" not in win.erro_criar.text()
    assert "Retomar" not in win.painel_criar.log.toPlainText()
    assert win.rodape.primario.text() == "Voltar às pastas"


def test_cancelar_a_conferencia_diz_que_nada_foi_gravado(
    win: CopyWindow, pastas: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """copia-8: cancelar a conferência do passo 3 não manda usar "Retomar"."""
    comecou = threading.Event()

    def lenta(*_a: Any, cancel: CancelToken, **_kw: Any) -> Any:
        comecou.set()
        while True:
            cancel.check()
            time.sleep(0.01)

    monkeypatch.setattr(copy_window, "preflight_create", lenta)
    _preenche_pastas(win, pastas)
    win.rodape.primario.click()
    win.c_senha.setText(SENHA)
    win.c_conf.setText(SENHA)
    win.rodape.primario.click()
    assert win.runner.busy
    assert comecou.wait(10)
    win.cancelar.click()
    _espera(lambda: not win.runner.busy)
    parou = win.linhas[-1]
    assert parou.titulo.text() == "A conferência parou"
    assert parou.detalhe.text() == S.COPIA_CONFERENCIA_CANCELADA
    assert "Retomar" not in win.rodape.texto.text()


def _abrir_com(win: CopyWindow, pastas: dict[str, Path], nome: str) -> None:
    win.bt_abrir.click()
    win.r_copia.definir(str(pastas["cofres"]))
    win.r_senha.setText(SENHA)
    win.r_local.definir(str(pastas["saida"]))
    win.r_nome.setText(nome)
    win.rodape.primario.click()


def test_restauracao_parada_diz_o_que_ficou_na_pasta_nova(
    win: CopyWindow, pastas: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """copia-8: a restauração parada fala da pasta nova (e de como continuar), não de
    "Retomar criação"."""

    def parcial(_vault: str, _password: str, dest: str, **_kw: Any) -> Any:
        os.mkdir(dest)
        (Path(dest) / restore_mod.MARKER_NAME).write_text("{}", encoding="utf-8")
        (Path(dest) / "a.txt").write_bytes(b"x")
        raise CancelledError("parada")

    monkeypatch.setattr(copy_window, "restore_vault", parcial)
    _abrir_com(win, pastas, "Volta")
    _espera(lambda: not win.runner.busy)
    msg = win.erro_abrir.text()
    assert msg.startswith(S.COPIA_RESTAURACAO_PARADA)
    assert "'Volta' ficou incompleta" in msg and "mesmo nome" in msg
    assert "Retomar" not in msg

    def antes(*_a: Any, **_kw: Any) -> Any:
        raise CancelledError("parada")

    monkeypatch.setattr(copy_window, "restore_vault", antes)
    _abrir_com(win, pastas, "Outra")
    _espera(lambda: not win.runner.busy)
    assert win.erro_abrir.text() == S.COPIA_RESTAURACAO_PARADA_ANTES


@pytest.mark.parametrize("nome", ["Fotos?", "x*", "a:b", "a|b", "a<b", "CON", "nome."])
def test_abrir_com_nome_invalido_avisa_em_vez_de_nao_fazer_nada(
    win: CopyWindow, pastas: dict[str, Path], nome: str
) -> None:
    """copia-4: o OSError (WinError 123) não escapa do clique; a pessoa vê o motivo."""
    _abrir_com(win, pastas, nome)
    assert not win.runner.busy
    assert win.erro_abrir.isVisibleTo(win)
    assert win.erro_abrir.text().startswith("Escolha outro nome para a pasta nova:")
    assert "caminho absoluto" not in win.erro_abrir.text()
    assert win.r_senha.text() == SENHA  # nada começou


def test_abrir_quando_o_destino_nao_pode_ser_lido(
    win: CopyWindow, pastas: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    def falha(_dest: str) -> str:
        raise OSError(5, "Acesso negado")

    monkeypatch.setattr(copy_window, "inspect_destination", falha)
    _abrir_com(win, pastas, "Restaurado-ok")
    assert not win.runner.busy
    assert win.erro_abrir.text().startswith("Não foi possível olhar a pasta de destino:")


def test_nome_do_cofre_invalido_e_recusado_no_passo_pastas(
    win: CopyWindow, pastas: dict[str, Path]
) -> None:
    _preenche_pastas(win, pastas, "Cofre?")
    win.rodape.primario.click()
    assert win.passo == 0
    assert win.erro_pastas.text().startswith("Escolha outro nome para o cofre:")


def test_texto_final_da_retomada_que_so_limpou_um_cofre_concluido(win: CopyWindow) -> None:
    """copia-9: o motor devolve a conclusão em ISO UTC; a tela mostra data e hora locais."""
    resultado = CreateResult(
        vault="C:\\x\\Cofre",
        status="success",
        files=1,
        dirs=0,
        total_bytes=10,
        snapshot_label="2026-11-17T15:03:22Z",
    )
    win.passo = 3
    win._depois_criar(resultado)
    local = _dt.datetime(2026, 11, 17, 15, 3, 22, tzinfo=_dt.UTC).astimezone()
    texto = win.resultado_criar.texto()
    assert f"(concluída em {local:%d/%m/%Y %H:%M})" in texto
    assert "T15:03" not in texto and " )" not in texto
    assert "T15:03" not in win.painel_criar.log.toPlainText()
    # a criação normal continua com o texto do design (data e hora locais da cópia)
    assert CopyWindow._texto_fim("17/11/2026 14:13") == S.FIM_TEXTO.format(
        data="17/11/2026", hora="14:13"
    )
    assert CopyWindow._texto_fim("???") == S.COPIA_FIM_SEM_DATA


def test_depois_de_abrir_o_nome_sugerido_e_novo_e_o_erro_nao_fica_junto_do_ok(
    win: CopyWindow, cofre_pronto: Path, pastas: dict[str, Path]
) -> None:
    """visual-15."""
    win.bt_abrir.click()
    win.r_copia.definir(str(cofre_pronto))
    win.r_senha.setText(SENHA)
    win.r_local.definir(str(pastas["saida"]))
    usado = win.r_nome.text()
    win.rodape.primario.click()
    _espera(lambda: not win.runner.busy)
    assert (pastas["saida"] / usado).is_dir()
    sugerido = win.r_nome.text()
    assert sugerido != usado and not (pastas["saida"] / sugerido).exists()
    # 2ª tentativa com o nome já usado: o erro aparece sozinho (o ✓ anterior sai da tela)
    win.r_senha.setText(SENHA)
    win.r_nome.setText(usado)
    win.rodape.primario.click()
    assert "não está vazia" in win.erro_abrir.text()
    assert not win.resultado_abrir.isVisibleTo(win)
    assert not win.painel_abrir.isVisibleTo(win)
    assert win.rodape.texto.text() == "Pronto."


@pytest.mark.parametrize(("largura", "altura"), [(1093, 566), (911, 464)], ids=["125", "150"])
def test_janela_cabe_na_area_util_de_1366x768(
    qapp: QApplication,
    gravador: Gravador,
    pastas: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    largura: int,
    altura: int,
) -> None:
    """copia-5 e visual-4: 1366x768 a 125%/150% — a janela nunca passa da área útil, o
    rodapé fica à vista no menor tamanho e a lateral rola em vez de espremer os itens."""
    monkeypatch.setattr(QScreen, "availableGeometry", lambda _s: QRect(0, 0, largura, altura))
    w = CopyWindow(
        kdf_policy=TESTING_POLICY, kdf_params=TESTING_PARAMS, protected=ProtectedPaths.none()
    )
    try:
        w.show()
        QCoreApplication.processEvents()
        moldura = copy_window._MOLDURA_ALTURA
        assert w.height() + moldura <= altura  # o 1040x860 inicial encolheu
        assert w.width() <= largura
        assert w.minimumHeight() + moldura <= altura
        w.resize(w.minimumSize())
        _preenche_pastas(w, pastas)
        w.rodape.primario.click()
        assert w.passo == 1
        for _ in range(3):  # os itens novos da lateral entram no layout nos próximos giros
            _descarta()
        for b in (w.rodape.voltar, w.rodape.primario):
            topo = b.mapTo(w, QPoint(0, 0)).y()
            assert topo >= 0 and topo + b.height() <= w.height(), b.text()
        assert w.lateral.parentWidget() is not None
        assert isinstance(w.lateral.parentWidget().parentWidget(), QScrollArea)
        for b in w.resumo.findChildren(QPushButton):
            if b.isVisibleTo(w):
                assert b.height() >= b.sizeHint().height(), b.text()
        for lbl in w.resumo.findChildren(QLabel):
            if lbl.isVisibleTo(w) and lbl.text():
                assert lbl.height() >= lbl.minimumSizeHint().height(), lbl.text()
    finally:
        w.close()
        w.deleteLater()
        _descarta()


def test_trocar_o_tema_repinta_registro_e_sombras(win: CopyWindow, qapp: QApplication) -> None:
    """visual-10 (C6): a sombra dos cartões e as linhas coloridas do registro acompanham o
    tema novo (a linha verde não fica #7ee2b0 sobre o fundo claro)."""
    folha, paleta, estilo = qapp.styleSheet(), qapp.palette(), qapp.style().name()
    anterior = qapp.property("owlTheme")
    try:
        apply_theme(qapp, "dark")
        QCoreApplication.processEvents()
        win.painel_criar.escrever("Cópia criptografada criada e verificada", "ok")
        win.painel_criar.escrever("linha comum")
        apply_theme(qapp, "light")
        QCoreApplication.processEvents()
        tokens = current_tokens()
        ultimo = win.painel_criar.log.document().lastBlock()
        verde = ultimo.previous().begin().fragment().charFormat().foreground().color()
        assert verde == QColor(tokens["ok"])
        comum = ultimo.begin().fragment().charFormat().foreground()
        assert comum.style() == Qt.BrushStyle.NoBrush
        sombras = [
            f.graphicsEffect()
            for f in win.findChildren(QFrame)
            if f.objectName() in ("cartao", "cartaoLateral")
        ]
        assert sombras
        for efeito in sombras:
            assert isinstance(efeito, QGraphicsDropShadowEffect)
            assert efeito.color() == QColor(tokens["sombra"])
    finally:
        qapp.setStyleSheet(folha)
        qapp.setStyle(QStyleFactory.create(estilo) or QStyleFactory.create("Fusion"))
        qapp.setPalette(paleta)
        qapp.setProperty("owlTheme", anterior)
        _descarta()


def test_texto_do_resultado_nunca_vira_html(win: CopyWindow) -> None:
    """copia-10 (última parte, pendência do agente do tema): o texto do resultado cita nomes de
    pastas e de arquivos; um nome como '<i>Cofre</i>' aparece como está, nunca como HTML."""
    nome = "<i>Cofre</i> <b>Fotos</b>"
    win.resultado_criar.mostrar("Cópia criada", "ok", "", f"O cofre '{nome}' foi criado.")
    corpo = win.resultado_criar.corpo
    assert corpo is not None
    assert corpo.textFormat() == Qt.TextFormat.PlainText
    assert corpo.text() == f"O cofre '{nome}' foi criado."
