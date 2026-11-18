"""Diálogos no visual "Cofre" (folder_dialogs.py e ProgressDialog de common.py).

Regras: plataforma offscreen, nenhum ``exec()`` bloqueante (os diálogos são construídos e os
botões acionados por ``click()``/teclas; onde a função pública chama ``exec()``, ele é trocado
por um gravador), dados sintéticos e nenhum acesso a pastas ou ao perfil real.
"""

from __future__ import annotations

import itertools
import os
from collections.abc import Callable, Iterator

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QPoint, QRect, Qt
from PySide6.QtGui import QColor, QKeyEvent, QScreen, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QGraphicsDropShadowEffect,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QStyleFactory,
    QVBoxLayout,
    QWidget,
)

from owl_vault.application.preflight import CreatePlan
from owl_vault.domain.limits import MIN_PASSWORD_LENGTH
from owl_vault.ui import common, dialogs
from owl_vault.ui import folder_dialogs as fd
from owl_vault.ui.componentes import Aviso, CampoSenha, LinhaChecagem, transparente
from owl_vault.ui.theme import apply_theme, current_tokens
from owl_vault.ui.workers import JobRunner

pytestmark = pytest.mark.gui

PIN = "947361"
PIN_OUTRO = "583920"
SENHA_MESTRA = "cavalo correto bateria grampo"
NOME = "Projeto Sigiloso Ômega"


# =========================================================================== utilidades Qt


@pytest.fixture(scope="module")
def qapp() -> Iterator[QApplication]:
    """Uma QApplication por módulo, sem janela real (plataforma offscreen)."""
    anterior = os.environ.get("QT_QPA_PLATFORM")
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance() or QApplication(["owl-vault-testes-dialogos"])
    assert isinstance(app, QApplication)
    yield app
    _descarta()
    if anterior is None:
        os.environ.pop("QT_QPA_PLATFORM", None)
    else:
        os.environ["QT_QPA_PLATFORM"] = anterior


@pytest.fixture
def guarda(qapp: QApplication) -> Iterator[Callable[[QWidget], QWidget]]:
    """Registra janelas criadas no teste; no fim, fecha e descarta todas."""
    criadas: list[QWidget] = []

    def guardar(w: QWidget) -> QWidget:
        criadas.append(w)
        return w

    yield guardar
    for w in criadas:
        w.hide()
        w.deleteLater()
    _descarta()


@pytest.fixture(params=["dark", "light"])
def tema(request: pytest.FixtureRequest, qapp: QApplication) -> Iterator[str]:
    """Aplica o tema (QSS + paleta + estilo) e devolve o aplicativo como estava."""
    folha, paleta, estilo = qapp.styleSheet(), qapp.palette(), qapp.style().name()
    anterior = qapp.property("owlTheme")
    apply_theme(qapp, request.param)
    yield str(request.param)
    qapp.setStyleSheet(folha)
    qapp.setStyle(QStyleFactory.create(estilo) or QStyleFactory.create("Fusion"))
    qapp.setPalette(paleta)
    qapp.setProperty("owlTheme", anterior)
    _descarta()


def _descarta() -> None:
    QCoreApplication.processEvents()
    QCoreApplication.sendPostedEvents(None, int(QEvent.Type.DeferredDelete.value))
    QCoreApplication.processEvents()


def _tecla(w: QWidget, tecla: Qt.Key) -> None:
    QApplication.sendEvent(
        w, QKeyEvent(QEvent.Type.KeyPress, tecla, Qt.KeyboardModifier.NoModifier)
    )


def _ordem_tab(janela: QWidget, esperado: list[QWidget]) -> list[QWidget]:
    """Os widgets de ``esperado`` na ordem em que o Tab passa por eles."""
    cadeia: list[QWidget] = []
    w = janela.nextInFocusChain()
    for _ in range(1000):
        if w is janela:
            break
        cadeia.append(w)
        w = w.nextInFocusChain()
    return [w for w in cadeia if any(w is e for e in esperado)]


def _assert_ordem(janela: QWidget, esperado: list[QWidget]) -> None:
    """O Tab dá a volta: compara o ciclo a partir de ``esperado[0]`` (onde o foco começa)."""
    obtido = _ordem_tab(janela, esperado)
    assert len(obtido) == len(esperado)
    inicio = next(i for i, w in enumerate(obtido) if w is esperado[0])
    obtido = obtido[inicio:] + obtido[:inicio]
    for a, b in zip(obtido, esperado, strict=True):
        assert a is b, (a.objectName(), a.accessibleName(), b.objectName(), b.accessibleName())


def _botao(janela: QWidget, texto: str) -> QPushButton:
    achados = [b for b in janela.findChildren(QPushButton) if b.text() == texto]
    assert len(achados) == 1, texto
    return achados[0]


def _textos(janela: QWidget) -> list[str]:
    return [lbl.text() for lbl in janela.findChildren(QLabel)]


def _assert_cofre(dlg: QDialog, largura: int = 520) -> None:
    """Estrutura comum: fundo do diálogo + QFrame#cartao com margens 24 e espaçamento 12."""
    assert dlg.windowTitle() == "Owl Vault"
    assert dlg.minimumWidth() >= largura
    externo = dlg.layout()
    assert externo is not None
    m = externo.contentsMargins()
    assert (m.left(), m.top(), m.right(), m.bottom()) == (24, 24, 24, 24)
    cartoes = [f for f in dlg.findChildren(QWidget) if f.objectName() == "cartao"]
    assert len(cartoes) == 1
    lay = cartoes[0].layout()
    assert lay is not None
    m = lay.contentsMargins()
    assert (m.left(), m.top(), m.right(), m.bottom()) == (24, 24, 24, 24)
    assert lay.spacing() == 12
    titulos = [lbl for lbl in dlg.findChildren(QLabel) if lbl.objectName() == "titulo"]
    assert len(titulos) == 1
    assert titulos[0].textFormat() == Qt.TextFormat.PlainText  # nome de pasta nunca vira HTML


# =========================================================================== ChoiceDialog / ask / inform


def test_choice_primeiro_botao_e_o_primario_e_clique_escolhe(
    guarda: Callable[..., QWidget],
) -> None:
    dlg = guarda(
        fd.ChoiceDialog(
            None,
            "Não é possível proteger esta pasta",
            "Feche estes arquivos e clique em Tentar de novo.",
            [("Tentar de novo", "retry"), ("Fechar", "close")],
        )
    )
    assert isinstance(dlg, fd.ChoiceDialog)
    _assert_cofre(dlg)
    assert dlg.title_label.text() == "Não é possível proteger esta pasta"
    assert dlg.text_label.objectName() == "subtitulo"
    retry, close = dlg.buttons["retry"], dlg.buttons["close"]
    assert retry.objectName() == "primario"
    assert retry.isDefault()
    assert close.objectName() == ""  # secundário: contornado (estilo base do QPushButton)
    assert not close.isDefault()
    assert not close.autoDefault()
    assert dlg.notice.isHidden()  # sem aviso, a caixa não aparece
    assert dlg.details_box is None
    assert isinstance(dlg.button_box, QHBoxLayout)
    close.click()
    assert dlg.choice == "close"
    assert dlg.result() == QDialog.DialogCode.Accepted


def test_choice_perigo_e_primario_explicitos(guarda: Callable[..., QWidget]) -> None:
    dlg = guarda(
        fd.ChoiceDialog(
            None,
            "Apagar a versão anterior?",
            "Estes arquivos serão apagados para sempre:",
            [("Apagar", "delete"), ("Cancelar", "cancel")],
            details=["a.docx", "b.jpg"],
            details_open=True,
            primary="cancel",
            perigo="delete",
            aviso="Não dá para desfazer.",
        )
    )
    assert isinstance(dlg, fd.ChoiceDialog)
    apagar, cancelar = dlg.buttons["delete"], dlg.buttons["cancel"]
    assert apagar.objectName() == "perigo"
    assert not apagar.isDefault()
    assert cancelar.objectName() == "primario"
    assert cancelar.isDefault()
    assert not dlg.notice.isHidden()
    assert dlg.notice.objectName() == "aviso"
    assert dlg.notice.texto() == "Não dá para desfazer."
    # lista aberta: sem botão "Detalhes"
    assert dlg.details_toggle is None
    assert dlg.details_box is not None
    assert not dlg.details_box.isHidden()
    # Enter aciona o botão padrão (aqui, Cancelar)
    dlg.show()
    _tecla(dlg, Qt.Key.Key_Return)
    assert dlg.choice == "cancel"


def test_choice_esc_cancela_com_escolha_vazia(guarda: Callable[..., QWidget]) -> None:
    dlg = guarda(fd.ChoiceDialog(None, "Esconder?", "x", [("Esconder", "hide"), ("Cancelar", "c")]))
    assert isinstance(dlg, fd.ChoiceDialog)
    dlg.show()
    _tecla(dlg, Qt.Key.Key_Escape)
    assert dlg.choice == ""
    assert dlg.result() == QDialog.DialogCode.Rejected
    assert not dlg.isVisible()


def test_choice_detalhes_recolhidos_abrem_e_fecham(guarda: Callable[..., QWidget]) -> None:
    itens = ["Relatório.docx", "Planilha.xlsx", "Apresentação.pptx", "e mais 2"]
    dlg = guarda(
        fd.ChoiceDialog(
            None, "Recusa", "Feche estes arquivos.", [("Fechar", "close")], details=itens
        )
    )
    assert isinstance(dlg, fd.ChoiceDialog)
    toggle, box = dlg.details_toggle, dlg.details_box
    assert toggle is not None and box is not None
    assert toggle.objectName() == "discreto"
    assert "Detalhes (4)" in toggle.text()
    assert box.isHidden()
    assert box.toPlainText().splitlines() == [f"• {i}" for i in itens]
    dlg.show()
    _descarta()
    altura_fechado = dlg.height()
    toggle.click()
    _descarta()
    assert not box.isHidden()
    assert dlg.height() > altura_fechado  # a janela cresce para mostrar a lista
    assert toggle.accessibleName().startswith("Ocultar")
    toggle.click()
    _descarta()
    assert box.isHidden()
    assert toggle.accessibleName().startswith("Mostrar")
    _assert_ordem(dlg, [toggle, box, dlg.buttons["close"]])


def test_choice_um_detalhe_aparece_sem_botao(guarda: Callable[..., QWidget]) -> None:
    dlg = guarda(fd.ChoiceDialog(None, "T", "x", [("OK", "ok")], details=["único.txt"]))
    assert isinstance(dlg, fd.ChoiceDialog)
    assert dlg.details_toggle is None
    assert dlg.details_box is not None and not dlg.details_box.isHidden()


def test_choice_textos_nunca_viram_html(guarda: Callable[..., QWidget]) -> None:
    dlg = guarda(
        fd.ChoiceDialog(
            None,
            "Proteger '<b>pasta</b>'?",
            "Arquivo <i>x</i>",
            [("OK", "ok")],
            aviso="Nome <b>estranho</b> & cia",
        )
    )
    assert isinstance(dlg, fd.ChoiceDialog)
    assert dlg.title_label.textFormat() == Qt.TextFormat.PlainText
    assert dlg.text_label.textFormat() == Qt.TextFormat.PlainText
    assert dlg.title_label.text() == "Proteger '<b>pasta</b>'?"
    # o aviso aceita texto rico, então o texto do chamador é escapado
    assert dlg.notice.texto() == "Nome &lt;b&gt;estranho&lt;/b&gt; &amp; cia"


def test_choice_muitos_botoes_longos_ficam_empilhados(
    tema: str, guarda: Callable[..., QWidget]
) -> None:
    """Com o tema (botões de 15px e 24px de respiro), 3 rótulos longos não cabem lado a lado."""
    dlg = guarda(
        fd.ChoiceDialog(
            None,
            f"Versão anterior de '{NOME}'",
            "Foi mantida uma versão anterior.",
            [
                ("Recuperar esses arquivos em outra pasta…", "restore"),
                ("Apagar a versão anterior…", "delete"),
                ("Fechar", "close"),
            ],
            primary="restore",
            perigo="delete",
        )
    )
    assert isinstance(dlg, fd.ChoiceDialog)
    assert isinstance(dlg.button_box, QVBoxLayout)
    assert dlg.buttons["restore"].isDefault()
    assert dlg.buttons["delete"].objectName() == "perigo"
    _assert_ordem(dlg, [dlg.buttons["restore"], dlg.buttons["delete"], dlg.buttons["close"]])
    dlg.buttons["restore"].click()
    assert dlg.choice == "restore"


def test_ask_e_inform_repassam_os_parametros(
    guarda: Callable[..., QWidget], monkeypatch: pytest.MonkeyPatch
) -> None:
    vistos: list[fd.ChoiceDialog] = []

    def exec_falso(self: fd.ChoiceDialog) -> int:
        guarda(self)
        vistos.append(self)
        list(self.buttons.values())[-1].click()  # o último botão
        return int(self.result())

    monkeypatch.setattr(fd.ChoiceDialog, "exec", exec_falso)
    escolha = fd.ask(
        None, "T", "x", [("Apagar", "delete"), ("Cancelar", "cancel")], perigo="delete", aviso="!"
    )
    assert escolha == "cancel"
    assert vistos[-1].buttons["delete"].objectName() == "perigo"
    fd.inform(None, "Tudo certo", "Os arquivos estão íntegros.", ["a", "b"], aviso="Atenção.")
    dlg = vistos[-1]
    assert list(dlg.buttons) == ["ok"]
    assert dlg.buttons["ok"].objectName() == "primario"
    assert dlg.details_toggle is None  # inform mostra os detalhes abertos
    assert dlg.details_box is not None and not dlg.details_box.isHidden()
    assert dlg.notice.texto() == "Atenção."
    assert dlg.choice == "ok"


# =========================================================================== ConfirmProtectDialog


def test_confirmar_protecao_primeira_vez_exige_entendi(guarda: Callable[..., QWidget]) -> None:
    pai = guarda(QWidget())
    dlg = guarda(fd.ConfirmProtectDialog(pai, NOME, 1234, 40 * 1024**3, True))
    assert isinstance(dlg, fd.ConfirmProtectDialog)
    _assert_cofre(dlg, 560)
    assert dlg.title_label.text() == f"Proteger '{NOME}'?"
    assert dlg.text_label.text().startswith("1.234 arquivo(s) · 40,0 GB · pode levar cerca de")
    textos = _textos(dlg)
    for item in fd.PROTECT_BULLETS:  # nenhum texto de aviso some
        assert item in textos
    assert dlg.notice.texto() == fd.PROTECT_WARNING
    assert not dlg.notice.isHidden()
    assert dlg.ack is not None
    assert dlg.ok.objectName() == "primario"
    assert dlg.ok.isDefault()
    assert not dlg.ok.isEnabled()
    dlg.ack.setChecked(True)
    assert dlg.ok.isEnabled()
    cancelar = _botao(dlg, "Cancelar")
    _assert_ordem(dlg, [dlg.ack, dlg.ok, cancelar])
    dlg.ok.click()
    assert dlg.result() == QDialog.DialogCode.Accepted


def test_confirmar_protecao_pequena_sem_tempo_e_sem_entendi(guarda: Callable[..., QWidget]) -> None:
    pai = guarda(QWidget())
    dlg = guarda(fd.ConfirmProtectDialog(pai, "Fotos", 3, 2048, False))
    assert isinstance(dlg, fd.ConfirmProtectDialog)
    assert dlg.text_label.text() == "3 arquivo(s) · 2,0 KB"
    assert dlg.ack is None
    assert dlg.ok.isEnabled()
    _botao(dlg, "Cancelar").click()
    assert dlg.result() == QDialog.DialogCode.Rejected


# =========================================================================== SecretDialog


def test_segredo_pin_valida_aceita_e_apaga(guarda: Callable[..., QWidget]) -> None:
    dlg = guarda(fd.SecretDialog(None, f"Abrir '{NOME}'", "", "Abrir"))
    assert isinstance(dlg, fd.SecretDialog)
    _assert_cofre(dlg)
    assert isinstance(dlg.edit, CampoSenha)
    assert dlg.edit.echoMode() == QLineEdit.EchoMode.Password
    assert dlg.edit.maxLength() == 12
    assert dlg.edit.accessibleName() == "PIN"
    assert dlg.label.text() == "PIN"
    assert dlg.label.objectName() == "rotulo"
    assert dlg.text_label.isHidden()  # sem texto, só o título
    assert dlg.switch.objectName() == "discreto"
    assert dlg.switch.text() == "Usar a senha mestra"
    assert dlg.ok.objectName() == "primario"
    assert dlg.ok.isDefault()
    assert dlg.err.isHidden()
    dlg.ok.click()
    assert dlg.err.objectName() == "erro"
    assert dlg.err.text() == "Digite o PIN."
    assert not dlg.err.isHidden()
    assert dlg.result() != QDialog.DialogCode.Accepted
    dlg.edit.setText(PIN)
    dlg.ok.click()
    assert dlg.result() == QDialog.DialogCode.Accepted
    assert dlg.take() == PIN
    assert dlg.edit.text() == ""


def test_segredo_mostrar_e_troca_para_senha_mestra(guarda: Callable[..., QWidget]) -> None:
    dlg = guarda(fd.SecretDialog(None, "Abrir", "", "Abrir", error="PIN incorreto."))
    assert isinstance(dlg, fd.SecretDialog)
    assert dlg.err.text() == "PIN incorreto."
    assert not dlg.err.isHidden()
    dlg.edit.setText(PIN)
    dlg.edit.mostrar.click()
    assert dlg.edit.echoMode() == QLineEdit.EchoMode.Normal
    assert dlg.edit.mostrar.text() == "Ocultar"
    dlg.switch.click()
    assert dlg.master
    assert dlg.edit.text() == ""  # trocar apaga o que foi digitado e volta a ocultar
    assert dlg.edit.echoMode() == QLineEdit.EchoMode.Password
    assert dlg.edit.maxLength() == 1024
    assert dlg.label.text() == "Senha mestra"
    assert dlg.edit.accessibleName() == "Senha mestra"
    assert dlg.switch.text() == "Usar o PIN"
    assert dlg.err.isHidden()
    dlg.ok.click()
    assert dlg.err.text() == "Digite a senha mestra."
    dlg.switch.click()
    assert not dlg.master
    assert dlg.edit.maxLength() == 12


def test_segredo_so_senha_mestra_e_botao_perigo(guarda: Callable[..., QWidget]) -> None:
    dlg = guarda(
        fd.SecretDialog(
            None,
            "Senha mestra",
            "Digite a senha mestra.",
            "Recuperar",
            master=True,
            allow_master=False,
        )
    )
    assert isinstance(dlg, fd.SecretDialog)
    assert dlg.switch.isHidden()
    assert dlg.edit.maxLength() == 1024
    perigo = guarda(fd.SecretDialog(None, "Remover?", "x", "Remover proteção", perigo=True))
    assert isinstance(perigo, fd.SecretDialog)
    assert perigo.ok.objectName() == "perigo"
    assert perigo.ok.isDefault()  # Enter depois de digitar o PIN continua funcionando


def test_segredo_ordem_de_tab_e_esc(guarda: Callable[..., QWidget]) -> None:
    dlg = guarda(fd.SecretDialog(None, "Abrir", "texto", "Abrir"))
    assert isinstance(dlg, fd.SecretDialog)
    cancelar = _botao(dlg, "Cancelar")
    _assert_ordem(dlg, [dlg.edit, dlg.edit.mostrar, dlg.switch, dlg.ok, cancelar])
    dlg.show()
    dlg.edit.setText(PIN)
    _tecla(dlg, Qt.Key.Key_Escape)
    assert dlg.result() == QDialog.DialogCode.Rejected


# =========================================================================== NewSecretDialog


def test_nova_senha_mestra_valida_medidor_aviso_e_anotei(guarda: Callable[..., QWidget]) -> None:
    dlg = guarda(fd.NewSecretDialog(None, master=True, title="Criar nova senha mestra", text="x"))
    assert isinstance(dlg, fd.NewSecretDialog)
    _assert_cofre(dlg)
    assert dlg.strength is not None
    assert dlg.notice is not None and dlg.notice.texto() == fd.MASTER_LOSS_WARNING
    assert dlg.ack is not None
    assert dlg.a.accessibleName() == "Senha mestra"
    dlg.a.setText("curta")
    veredito = [
        lbl for lbl in dlg.strength.findChildren(QLabel) if lbl.objectName() == "forcaTexto"
    ]
    assert len(veredito) == 1 and veredito[0].text() != ""
    dlg.b.setText("curta")
    dlg.ok.click()
    assert f"pelo menos {MIN_PASSWORD_LENGTH}" in dlg.err.text()
    dlg.a.setText(SENHA_MESTRA)
    dlg.b.setText(SENHA_MESTRA)
    dlg.ok.click()
    assert "Anotei" in dlg.err.text()
    dlg.ack.setChecked(True)
    dlg.b.setText(SENHA_MESTRA + "x")
    dlg.ok.click()
    assert dlg.err.text() == "Os dois campos não são iguais."
    dlg.b.setText(SENHA_MESTRA)
    dlg.ok.click()
    assert dlg.result() == QDialog.DialogCode.Accepted
    assert dlg.take() == SENHA_MESTRA
    assert dlg.a.text() == "" and dlg.b.text() == ""
    cancelar = _botao(dlg, "Cancelar")
    _assert_ordem(dlg, [dlg.a, dlg.a.mostrar, dlg.b, dlg.b.mostrar, dlg.ack, dlg.ok, cancelar])


def test_novo_pin_valida(guarda: Callable[..., QWidget]) -> None:
    dlg = guarda(fd.NewSecretDialog(None, master=False, title="Crie um PIN novo", text="x"))
    assert isinstance(dlg, fd.NewSecretDialog)
    assert dlg.strength is None and dlg.ack is None and dlg.notice is None
    assert dlg.a.maxLength() == 12
    assert fd.PIN_RULES in _textos(dlg)
    for ruim, trecho in (
        ("12345", "6 a 12"),
        ("123456", "fácil de adivinhar"),
        ("311299", "datas"),
    ):
        dlg.a.setText(ruim)
        dlg.b.setText(ruim)
        dlg.ok.click()
        assert trecho in dlg.err.text(), ruim
    dlg.a.setText(PIN)
    dlg.b.setText(PIN_OUTRO)
    dlg.ok.click()
    assert dlg.err.text() == "Os dois campos não são iguais."
    dlg.b.setText(PIN)
    dlg.ok.click()
    assert dlg.result() == QDialog.DialogCode.Accepted
    assert dlg.take() == PIN


# =========================================================================== ChangePinDialog


def test_alterar_pin_valida_e_esqueci(guarda: Callable[..., QWidget]) -> None:
    dlg = guarda(fd.ChangePinDialog(None))
    assert isinstance(dlg, fd.ChangePinDialog)
    _assert_cofre(dlg)
    assert dlg.title_label.text() == "Alterar PIN"
    assert dlg.forgot.objectName() == "discreto"
    cancelar = _botao(dlg, "Cancelar")
    _assert_ordem(
        dlg,
        [dlg.current, dlg.forgot, dlg.new1, dlg.new2, dlg.ok, cancelar],
    )
    dlg.ok.click()
    assert dlg.err.text() == "Digite o PIN atual."
    dlg.current.setText(PIN)
    dlg.new1.setText("123456")
    dlg.new2.setText("123456")
    dlg.ok.click()
    assert "fácil de adivinhar" in dlg.err.text()
    dlg.new1.setText(PIN_OUTRO)
    dlg.ok.click()
    assert dlg.err.text() == "Os dois campos do novo PIN não são iguais."
    dlg.forgot.click()
    assert dlg.master
    assert dlg.forgot.isHidden()
    assert dlg.current.text() == ""
    assert dlg.current.maxLength() == 1024
    assert dlg.current_label.text() == "Senha mestra"
    assert dlg.current.accessibleName() == "Senha mestra"
    assert dlg.err.isHidden()
    dlg.ok.click()
    assert dlg.err.text() == "Digite a senha mestra."
    dlg.current.setText(SENHA_MESTRA)
    dlg.new2.setText(PIN_OUTRO)
    dlg.ok.click()
    assert dlg.result() == QDialog.DialogCode.Accepted
    assert dlg.take() == (SENHA_MESTRA, PIN_OUTRO, True)
    assert dlg.current.text() == dlg.new1.text() == dlg.new2.text() == ""


# =========================================================================== PickDialog


def test_escolher_pastas_marcadas(guarda: Callable[..., QWidget]) -> None:
    dlg = guarda(
        fd.PickDialog(None, "Pastas encontradas", "Marque.", ["Fotos", "Particular", NOME])
    )
    assert isinstance(dlg, fd.PickDialog)
    _assert_cofre(dlg)
    assert dlg.checked() == [0, 1, 2]
    assert dlg.ok.isEnabled() and dlg.ok.isDefault()
    dlg.list.item(1).setCheckState(Qt.CheckState.Unchecked)
    assert dlg.checked() == [0, 2]
    for i in (0, 2):
        dlg.list.item(i).setCheckState(Qt.CheckState.Unchecked)
    assert dlg.checked() == []
    assert not dlg.ok.isEnabled()  # nada marcado: não dá para continuar
    dlg.list.item(2).setCheckState(Qt.CheckState.Checked)
    _assert_ordem(dlg, [dlg.list, dlg.ok, _botao(dlg, "Cancelar")])
    dlg.ok.click()
    assert dlg.result() == QDialog.DialogCode.Accepted
    assert dlg.checked() == [2]


# =========================================================================== limites (T15)


def test_limites_lista_todos_os_textos(
    guarda: Callable[..., QWidget], monkeypatch: pytest.MonkeyPatch
) -> None:
    abertos: list[fd.LimitsDialog] = []

    def exec_falso(self: fd.LimitsDialog) -> int:
        guarda(self)
        abertos.append(self)
        self.ok.click()
        return int(self.result())

    monkeypatch.setattr(fd.LimitsDialog, "exec", exec_falso)
    fd.limits_dialog(None)
    assert len(abertos) == 1
    dlg = abertos[0]
    _assert_cofre(dlg, 600)
    assert len(dlg.rows) == len(fd.LIMITS_TEXT) == len(fd.LIMITS_TITLES)
    for row, titulo, texto in zip(dlg.rows, fd.LIMITS_TITLES, fd.LIMITS_TEXT, strict=True):
        assert isinstance(row, LinhaChecagem)
        assert row.titulo.text() == titulo
        assert row.detalhe.text() == texto
        assert row.detalhe.objectName() == "nota"
        assert row.icone.property("estado") == "aviso"
    assert dlg.ok.objectName() == "primario" and dlg.ok.isDefault()
    assert dlg.result() == QDialog.DialogCode.Accepted


# =========================================================================== tamanho e tema


@pytest.mark.parametrize(
    "fabrica",
    [
        lambda: fd.NewSecretDialog(
            None,
            master=True,
            title="Criar nova senha mestra",
            text="As pastas trancadas continuam abrindo normalmente com o PIN. Para que elas "
            "também abram com a senha nova em outro computador, abra e tranque cada uma de novo.",
        ),
        lambda: fd.ChoiceDialog(
            None,
            "Não é possível proteger esta pasta",
            "Feche estes arquivos e clique em Tentar de novo: Relatório.docx, Planilha.xlsx, "
            "Apresentação.pptx, Orçamento.xlsx",
            [("Tentar de novo", "retry"), ("Fechar", "close")],
            aviso="Nada foi apagado.",
        ),
        lambda: fd.LimitsDialog(None),
    ],
    ids=["nova_senha_mestra", "escolha", "limites"],
)
def test_texto_com_quebra_de_linha_nunca_e_cortado(
    tema: str, guarda: Callable[..., QWidget], fabrica: Callable[[], QDialog]
) -> None:
    """A altura do diálogo é medida na largura real (nenhum texto fica cortado)."""
    dlg = guarda(fabrica())
    dlg.show()
    _descarta()
    assert dlg.width() >= 520
    for lbl in dlg.findChildren(QLabel):
        if lbl.wordWrap() and lbl.isVisible() and lbl.text():
            assert lbl.height() >= lbl.heightForWidth(lbl.width()), lbl.text()[:40]


def test_medidas_do_visual_cofre(tema: str, guarda: Callable[..., QWidget]) -> None:
    dlg = guarda(fd.SecretDialog(None, "Abrir 'Fotos'", "Digite o PIN.", "Abrir"))
    assert isinstance(dlg, fd.SecretDialog)
    dlg.show()
    _descarta()
    assert dlg.edit.height() >= 48  # campos e botões com 48px
    assert dlg.ok.height() >= 48
    assert _botao(dlg, "Cancelar").height() >= 48
    assert dlg.title_label.font().pixelSize() == 22
    assert dlg.text_label.font().pixelSize() == 14
    assert dlg.ok.isDefault()
    assert dlg.focusWidget() is dlg.edit  # o campo já começa com o foco


# =========================================================================== ProgressDialog


def test_progresso_cartao_etapas_aviso_e_fim(guarda: Callable[..., QWidget]) -> None:
    pai = guarda(QWidget())
    runner = JobRunner()
    dlg = guarda(
        common.ProgressDialog(pai, f"Trancando '{NOME}'", runner, mode="lock", note="Não use <a>.")
    )
    assert isinstance(dlg, common.ProgressDialog)
    _assert_cofre(dlg)
    assert not (dlg.windowFlags() & Qt.WindowType.WindowCloseButtonHint)
    assert dlg.stage.objectName() == "etapa"
    assert dlg.eta.objectName() == "nota"
    assert dlg.log_box is None
    assert isinstance(dlg.notice, Aviso)
    assert dlg.notice.texto() == "Não use &lt;a&gt;."
    assert not dlg.notice.isHidden()
    assert not dlg.bar.isTextVisible()
    b = runner.bridge
    b.stage.emit("Criptografando", 1000, 10)
    assert dlg.stage.text() == "1/4 Guardando os arquivos (0 de 10)"
    b.advance.emit(500, 5)
    assert dlg.stage.text() == "1/4 Guardando os arquivos (5 de 10)"
    assert dlg.bar.value() == 500
    b.stage.emit("Apagando as cópias legíveis", 0, 3)
    assert dlg.cancel_button.text() == "Parar depois do arquivo atual"
    dlg.show()
    assert not dlg.close()  # o X não fecha enquanto trabalha
    assert dlg.isVisible()
    dlg.finish()
    assert not dlg.isVisible()
    b.stage.emit("Restaurando", 0, 0)  # desconectado depois de finish
    assert dlg.stage.text() == "4/4 Apagando as cópias legíveis"
    runner.deleteLater()


def test_progresso_sem_nota_e_sem_cancelar(guarda: Callable[..., QWidget]) -> None:
    pai = guarda(QWidget())
    runner = JobRunner()
    dlg = guarda(common.ProgressDialog(pai, "Recuperando…", runner, cancellable=False))
    assert isinstance(dlg, common.ProgressDialog)
    assert dlg.notice.isHidden()
    assert dlg.cancel_button.isHidden()
    _tecla(dlg, Qt.Key.Key_Escape)  # sem Cancelar, Esc não faz nada
    assert dlg.cancel_button.isEnabled()
    assert dlg.stage.text() == "Preparando…"
    runner.deleteLater()


def test_progresso_esc_cancela(guarda: Callable[..., QWidget]) -> None:
    pai = guarda(QWidget())
    runner = JobRunner()
    dlg = guarda(common.ProgressDialog(pai, "Abrindo", runner, mode="unlock"))
    assert isinstance(dlg, common.ProgressDialog)
    assert not dlg.cancel_button.autoDefault()  # Enter não cancela sem querer
    _assert_ordem(dlg, [dlg.cancel_button])
    _tecla(dlg, Qt.Key.Key_Escape)
    assert not dlg.cancel_button.isEnabled()
    assert dlg.stage.text() == "Parando num ponto seguro…"
    assert dlg.result() != QDialog.DialogCode.Accepted  # Esc não fecha: espera o ponto seguro
    runner.deleteLater()


def test_progresso_registro_de_etapas_com_cor(guarda: Callable[..., QWidget]) -> None:
    pai = guarda(QWidget())
    runner = JobRunner()
    dlg = guarda(common.ProgressDialog(pai, "Trancando", runner, mode="lock", log=True))
    assert isinstance(dlg, common.ProgressDialog)
    box = dlg.log_box
    assert box is not None
    assert box.objectName() == "log"
    assert box.isReadOnly()
    assert box.maximumBlockCount() == 5000
    b = runner.bridge
    b.stage.emit("Pré-verificação: conferindo caminhos", 0, 0)
    b.stage.emit("Criptografando", 100, 2)
    b.warning.emit("Arquivo em uso: a.docx")
    b.info.emit("Tudo guardado")
    linhas = box.toPlainText().splitlines()
    assert [linha.split("  ", 1)[1] for linha in linhas] == [
        "Conferindo a pasta",
        "1/4 Guardando os arquivos",
        "Arquivo em uso: a.docx",
        "Tudo guardado",
    ]
    doc = box.document()
    aviso = QTextCursor(doc.findBlockByNumber(2))
    aviso.movePosition(QTextCursor.MoveOperation.EndOfBlock)
    assert aviso.charFormat().foreground().color() == QColor(current_tokens()["warn"])
    comum = QTextCursor(doc.findBlockByNumber(3))
    comum.movePosition(QTextCursor.MoveOperation.EndOfBlock)
    assert comum.charFormat().foreground().color() != QColor(current_tokens()["warn"])
    dlg.finish()
    b.info.emit("depois do fim")
    assert len(box.toPlainText().splitlines()) == 4
    runner.deleteLater()


# =========================================================================== common: helpers e tamanhos


@pytest.mark.parametrize(
    ("n", "esperado"),
    [
        (0, "0 bytes"),
        (1023, "1023 bytes"),
        (1024, "1,0 KB"),
        (1024**2 - 1, "1,0 MB"),
        (1024**2 - 51, "1,0 MB"),  # 1023,95 KB arredonda para 1024,0: sobe de unidade
        (1024**2 - 52, "1023,9 KB"),
        (1024**2, "1,0 MB"),
        (1024**3 - 1, "1,0 GB"),
        (1024**4 - 1, "1,0 TB"),
        (2048 * 1024**4, "2048,0 TB"),
    ],
)
def test_fmt_size_fronteiras(n: int, esperado: str) -> None:
    assert common.fmt_size(n) == esperado


def test_fmt_size_nunca_mostra_1024_numa_unidade_menor() -> None:
    for unidade in range(1, 4):
        for delta in (1, 2, 51, 52):
            assert not common.fmt_size(1024 ** (unidade + 1) - delta).startswith("1024,0")


def test_helpers_antigos_usam_os_nomes_do_design(guarda: Callable[..., QWidget]) -> None:
    assert common.title_label("T").objectName() == "titulo"
    assert common.body("b").objectName() == "subtitulo"
    assert common.hint("h").objectName() == "nota"
    link = common.link_button("Esqueci o PIN")
    assert link.objectName() == "discreto"
    assert not link.autoDefault()
    primario = common.primary_button("Salvar")
    assert primario.objectName() == "primario"
    assert primario.isDefault()
    err = common.error_label()
    assert err.objectName() == "erro"
    assert err.isHidden()
    common.show_error(err, "Falhou.")
    assert not err.isHidden()
    topo = guarda(common.brand_header("Pastas protegidas"))
    nomes = {lbl.objectName(): lbl.text() for lbl in topo.findChildren(QLabel) if lbl.text()}
    assert nomes == {"marca": "Owl", "marcaRoxo": "Vault", "nota": "Pastas protegidas"}
    assert topo.objectName() == "transparente"
    caixa = common.list_box(["a", "b"])
    assert caixa.tabChangesFocus()
    for w in (link, primario, err, caixa):
        w.deleteLater()


def test_tab_order_pula_quem_nao_recebe_tab(guarda: Callable[..., QWidget]) -> None:
    janela = guarda(QWidget())
    lay = QVBoxLayout(janela)
    a, b, x, c = QPushButton("a"), QLabel("rótulo"), QPushButton("x"), QPushButton("c")
    for w in (c, x, b, a):  # entram na janela fora da ordem de leitura
        lay.addWidget(w)
    fd.tab_order([a, b, x, c])
    _assert_ordem(janela, [a, x, c])


# =========================================================================== regressões da revisão

ARQUIVOS = [f"Documentos\\Projeto {i:02d}\\relatório revisado {i:02d}.docx" for i in range(40)]
TEXTO_SENHA_NOVA = (
    "As pastas trancadas continuam abrindo normalmente com o PIN. Para que elas também abram "
    "com a senha nova em outro computador, abra e tranque cada uma de novo."
)


def _erro_visivel(dlg: QDialog) -> None:
    err = getattr(dlg, "err", None)
    assert isinstance(err, QLabel)
    common.show_error(err, "Os dois campos não são iguais.")


def _abre_detalhes(dlg: QDialog) -> None:
    assert isinstance(dlg, fd.ChoiceDialog) and dlg.details_toggle is not None
    dlg.details_toggle.setChecked(True)


def _registro_cheio(dlg: QDialog) -> None:
    assert isinstance(dlg, common.ProgressDialog)
    for i in range(30):
        dlg._log(f"etapa {i}")


_DIALOGOS_ALTOS: list[tuple[str, Callable[[QWidget], QDialog], Callable[[QDialog], None] | None]]
_DIALOGOS_ALTOS = [
    (
        "nova_senha_mestra",
        lambda p: fd.NewSecretDialog(
            p, master=True, title="Criar nova senha mestra", text=TEXTO_SENHA_NOVA
        ),
        None,
    ),
    (
        "nova_senha_mestra_com_erro",
        lambda p: fd.NewSecretDialog(
            p, master=True, title="Criar nova senha mestra", text=TEXTO_SENHA_NOVA
        ),
        _erro_visivel,
    ),
    ("alterar_pin_com_erro", lambda p: fd.ChangePinDialog(p), _erro_visivel),
    (
        "versao_anterior_com_detalhes",
        lambda p: fd.ChoiceDialog(
            p,
            "Versão anterior de 'Fotos'",
            "Foi mantida uma versão anterior de 'Fotos' com 40 arquivos que não estão na pasta.",
            [
                ("Recuperar esses arquivos em outra pasta…", "restore"),
                ("Apagar a versão anterior…", "delete"),
                ("Fechar", "close"),
            ],
            details=ARQUIVOS,
            primary="restore",
            perigo="delete",
        ),
        _abre_detalhes,
    ),
    (
        "proteger_primeira_vez",
        lambda p: fd.ConfirmProtectDialog(p, NOME, 40_000, 80 * 1024**3, True),
        None,
    ),
    ("limites", lambda p: fd.LimitsDialog(p), None),
    (
        "progresso_com_registro",
        lambda p: common.ProgressDialog(
            p, "Trancando", JobRunner(p), mode="lock", note="Não desligue o computador.", log=True
        ),
        _registro_cheio,
    ),
]


@pytest.mark.parametrize(("largura", "altura"), [(1093, 566), (911, 464)], ids=["125", "150"])
@pytest.mark.parametrize(
    ("fabrica", "depois"),
    [(f, d) for _n, f, d in _DIALOGOS_ALTOS],
    ids=[n for n, _f, _d in _DIALOGOS_ALTOS],
)
def test_dialogo_cabe_na_area_util_e_os_botoes_ficam_a_vista(
    guarda: Callable[..., QWidget],
    monkeypatch: pytest.MonkeyPatch,
    largura: int,
    altura: int,
    fabrica: Callable[[QWidget], QDialog],
    depois: Callable[[QDialog], None] | None,
) -> None:
    """dialogos-1: 1366x768 a 125%/150% — o diálogo nunca passa da área útil, o conteúdo
    rola e a linha de botões (fora da rolagem) fica inteira à vista."""
    monkeypatch.setattr(QScreen, "availableGeometry", lambda _s: QRect(0, 0, largura, altura))
    pai = guarda(QWidget())
    pai.resize(700, 450)
    dlg = guarda(fabrica(pai))
    dlg.show()
    _descarta()
    if depois is not None:
        depois(dlg)
        for _ in range(3):
            _descarta()
    assert dlg.height() + common.FOLGA_MOLDURA <= altura
    assert dlg.width() <= largura
    rolagem = dlg.findChild(common.Rolagem)
    assert rolagem is not None
    botoes = [
        b
        for b in dlg.findChildren(QPushButton)
        if b.isVisibleTo(dlg) and b.objectName() != "discreto" and b.parentWidget() is not None
    ]
    assert botoes
    for b in botoes:
        topo = b.mapTo(dlg, QPoint(0, 0)).y()
        assert topo >= 0 and topo + b.height() <= dlg.height(), b.text()
        assert not rolagem.isAncestorOf(b), b.text()  # fora da rolagem: nunca some
    # o que não coube rola (nada é cortado sem barra)
    conteudo = rolagem.widget()
    assert conteudo is not None
    if conteudo.height() > rolagem.viewport().height():
        assert rolagem.verticalScrollBar().maximum() > 0


def test_erro_novo_e_trazido_para_a_vista_numa_tela_baixa(
    guarda: Callable[..., QWidget], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Com o corpo rolando (tela baixa), o erro que aparece embaixo não fica escondido."""
    monkeypatch.setattr(QScreen, "availableGeometry", lambda _s: QRect(0, 0, 911, 464))
    dlg = guarda(
        fd.NewSecretDialog(
            None, master=True, title="Criar nova senha mestra", text=TEXTO_SENHA_NOVA
        )
    )
    assert isinstance(dlg, fd.NewSecretDialog)
    dlg.show()
    _descarta()
    assert dlg.rolagem.verticalScrollBar().maximum() > 0  # o corpo rola
    common.show_error(dlg.err, "Os dois campos não são iguais.")
    for _ in range(4):
        _descarta()
    vista = dlg.rolagem.viewport()
    topo = dlg.err.mapTo(vista, QPoint(0, 0)).y()
    assert topo >= 0 and topo + dlg.err.height() <= vista.height()


def test_dialogo_cresce_quando_aparece_um_erro(guarda: Callable[..., QWidget]) -> None:
    """Com espaço na tela, o diálogo acompanha o conteúdo (o corpo numa rolagem não pode
    deixar o erro escondido atrás de uma barra)."""
    dlg = guarda(fd.NewSecretDialog(None, master=False, title="Novo PIN", text="Escolha."))
    assert isinstance(dlg, fd.NewSecretDialog)
    dlg.show()
    _descarta()
    antes = dlg.height()
    common.show_error(dlg.err, "Os dois campos não são iguais.")
    for _ in range(3):
        _descarta()
    assert dlg.height() > antes
    assert dlg.rolagem.verticalScrollBar().maximum() == 0  # cabe inteiro, sem barra


def test_preflight_e_relatorio_antigos_tambem_cabem_na_tela(
    guarda: Callable[..., QWidget], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(QScreen, "availableGeometry", lambda _s: QRect(0, 0, 911, 464))
    plan = CreatePlan("C:\\o", "C:\\c\\Cofre", "C:\\t", 64 * 1024)
    plan.warnings = list(ARQUIVOS)
    for dlg in (
        dialogs.PreflightDialog(plan),
        dialogs.ReportDialog("Relatório", "Resumo", [("Avisos", ARQUIVOS), ("Notas", ARQUIVOS)]),
    ):
        guarda(dlg)
        dlg.show()
        _descarta()
        assert dlg.height() + common.FOLGA_MOLDURA <= 464
        for b in dlg.findChildren(QPushButton):
            if b.isVisibleTo(dlg):
                topo = b.mapTo(dlg, QPoint(0, 0)).y()
                assert topo + b.height() <= dlg.height(), b.text()


def test_trocar_o_tema_repinta_o_registro_e_a_sombra_do_progresso(
    guarda: Callable[..., QWidget], qapp: QApplication
) -> None:
    """visual-10 (C6) na tela de progresso: as linhas coloridas e a sombra do cartão
    passam para o tema novo."""
    folha, paleta, estilo = qapp.styleSheet(), qapp.palette(), qapp.style().name()
    anterior = qapp.property("owlTheme")
    try:
        apply_theme(qapp, "dark")
        pai = guarda(QWidget())
        runner = JobRunner(pai)
        dlg = guarda(common.ProgressDialog(pai, "Trancando", runner, mode="lock", log=True))
        assert isinstance(dlg, common.ProgressDialog)
        dlg.show()
        _descarta()
        runner.bridge.warning.emit("Arquivo em uso: a.docx")
        apply_theme(qapp, "light")
        _descarta()
        tokens = current_tokens()
        assert dlg.log_box is not None
        aviso = QTextCursor(dlg.log_box.document().lastBlock())
        aviso.movePosition(QTextCursor.MoveOperation.EndOfBlock)
        assert aviso.charFormat().foreground().color() == QColor(tokens["warn"])
        efeito = dlg.card.graphicsEffect()
        assert isinstance(efeito, QGraphicsDropShadowEffect)
        assert efeito.color() == QColor(tokens["sombra"])
        dlg.finish()
    finally:
        qapp.setStyleSheet(folha)
        qapp.setStyle(QStyleFactory.create(estilo) or QStyleFactory.create("Fusion"))
        qapp.setPalette(paleta)
        qapp.setProperty("owlTheme", anterior)
        _descarta()


def test_fmt_size_um_byte_no_singular() -> None:
    """fmt-1: "1 arquivo(s) · 1 byte", nunca "1 bytes"."""
    assert common.fmt_size(1) == "1 byte"
    assert common.fmt_size(0) == "0 bytes"
    assert common.fmt_size(2) == "2 bytes"


@pytest.mark.parametrize(
    ("segundos", "esperado"),
    [
        (150, "cerca de 3 minutos"),  # 2,5 min: o round() do Python dava 2
        (5400, "cerca de 2 horas"),  # 1h30
        (8970, "cerca de 2 horas"),  # 2h29m30s
        (9000, "cerca de 3 horas"),  # 2h30: o round() do Python dava 2
        (float("nan"), "tempo incerto"),
        (float("inf"), "tempo incerto"),
        (float("-inf"), "tempo incerto"),
    ],
)
def test_fmt_duration_arredonda_meio_para_cima_e_nunca_quebra(
    segundos: float, esperado: str
) -> None:
    assert common.fmt_duration(segundos) == esperado


def test_fmt_int_com_float() -> None:
    assert common.fmt_int(1234.5) == "1.235"  # nunca "1.234.5"
    assert common.fmt_int(1234567) == "1.234.567"


# =========================================================================== v2-visual-1 / v2-visual-2

TEXTO_RESOLVER = (
    "Seus arquivos já estão guardados. 3 item(ns) ainda não foram apagados da pasta: 2 estavam "
    "abertos ou mudaram, e 1 item novo foi colocado durante o trancamento e NÃO está guardado. "
    "Feche os arquivos, mova o item novo para outro lugar e clique em 'Continuar trancando'."
)
BOTOES_RESOLVER_APAGANDO = [
    ("Continuar trancando", "cont"),
    ("Desfazer (deixar a pasta aberta)", "undo"),
    ("Mostrar no Explorer", "show"),
    ("Tirar da lista", "forget"),
    ("Fechar", "close"),
]
PENDENTES = [
    "Notas\\2024\\março.xlsx (em uso)",
    "Notas\\2024\\abril.xlsx (mudou)",
    "Nova pasta (item novo)",
]


def _tela(monkeypatch: pytest.MonkeyPatch, largura: int, altura: int) -> None:
    monkeypatch.setattr(QScreen, "availableGeometry", lambda _s: QRect(0, 0, largura, altura))


def _resolver_apagando(pai: QWidget | None) -> fd.ChoiceDialog:
    """O Resolver de 'apagando' com pendências (owl_window._resolve_deleting): 5 botões."""
    return fd.ChoiceDialog(
        pai,
        "Trancamento de 'Notas fiscais' interrompido",
        TEXTO_RESOLVER,
        BOTOES_RESOLVER_APAGANDO,
        details=PENDENTES,
        details_open=True,
    )


def _mostra(dlg: QDialog) -> None:
    dlg.show()
    for _ in range(4):
        _descarta()


def _natural(dlg: QDialog) -> int:
    """Altura que o conteúdo pede na largura atual do diálogo (sem teto nenhum)."""
    lay = dlg.layout()
    assert lay is not None
    return lay.totalHeightForWidth(dlg.width())


def _geometrias(dlg: fd.ChoiceDialog) -> list[QRect]:
    return [QRect(b.mapTo(dlg, QPoint(0, 0)), b.size()) for b in dlg.buttons.values()]


def _assert_botoes_inteiros_e_separados(dlg: fd.ChoiceDialog) -> None:
    """Nenhum par se cruza, o vão entre vizinhos é 12 (linhas e colunas) e todos ficam
    inteiros dentro do diálogo, abaixo da rolagem."""
    geos = _geometrias(dlg)
    for i, a in enumerate(geos):
        for b in geos[i + 1 :]:
            assert not a.intersects(b), (a, b)
    linhas = sorted({g.y() for g in geos})
    for cima, baixo in itertools.pairwise(linhas):
        altura = max(g.height() for g in geos if g.y() == cima)
        assert baixo - (cima + altura) == fd.VAO_BOTOES
    for y in linhas:
        lado = sorted((g for g in geos if g.y() == y), key=lambda g: g.x())
        for esq, dir_ in itertools.pairwise(lado):
            assert dir_.x() - (esq.x() + esq.width()) == fd.VAO_BOTOES
    rolagem = QRect(dlg.rolagem.mapTo(dlg, QPoint(0, 0)), dlg.rolagem.size())
    for g in geos:
        assert g.top() >= 0 and g.bottom() < dlg.height()
        assert not g.intersects(rolagem)


@pytest.mark.parametrize(
    ("largura", "altura"),
    [(1093, 566), (1093, 590), (1366, 720), (1280, 672), (911, 464), (1024, 528)],
    ids=["hd125a", "hd125b", "hd100", "fhd150", "hd150", "720p125"],
)
def test_resolver_de_cinco_botoes_nunca_sobrepoe_os_botoes(
    tema: str,
    guarda: Callable[..., QWidget],
    monkeypatch: pytest.MonkeyPatch,
    largura: int,
    altura: int,
) -> None:
    """v2-visual-1: com o diálogo encolhido para caber na tela, o que falta sai só da
    rolagem. Antes, em 1093x566, cada botão entrava 5-6 px no de cima (um clique na borda de
    'Continuar trancando' acionava 'Desfazer'); em 1280x672 o vão era 0."""
    _tela(monkeypatch, largura, altura)
    pai = guarda(QWidget())
    pai.resize(900, 500)
    dlg = guarda(_resolver_apagando(pai))
    assert isinstance(dlg, fd.ChoiceDialog)
    _mostra(dlg)
    _assert_botoes_inteiros_e_separados(dlg)
    assert dlg.height() + common.FOLGA_TITULO <= altura  # cabe na tela, com a barra de título
    assert dlg.width() <= largura
    if dlg.rolagem.maximumHeight() < common.SEM_TETO:
        assert dlg.rolagem.verticalScrollBar().maximum() > 0  # o corpo rola, nada é cortado
    else:
        assert dlg.height() == _natural(dlg)


def test_resolver_de_cinco_botoes_mantem_a_coluna_quando_cabe(
    tema: str, guarda: Callable[..., QWidget], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Em 1366x768 a 100% (720 úteis) os 5 botões continuam um embaixo do outro, com 12 px
    entre eles (antes, 5 px) e o corpo com pelo menos ``CORPO_MINIMO``."""
    _tela(monkeypatch, 1366, 720)
    dlg = guarda(_resolver_apagando(None))
    assert isinstance(dlg, fd.ChoiceDialog)
    _mostra(dlg)
    assert isinstance(dlg.button_box, QVBoxLayout)
    assert dlg.height() + common.FOLGA_MOLDURA <= 720
    assert dlg.rolagem.height() >= common.CORPO_MINIMO
    _assert_botoes_inteiros_e_separados(dlg)


def test_tela_baixa_demais_poe_os_botoes_em_duas_colunas(
    tema: str, guarda: Callable[..., QWidget], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Em 911x464 a coluna de 5 botões (298 px) não cabe junto com o corpo: antes 'Tirar da
    lista' ficava com 21 de 50 px e 'Fechar' fora da tela. Agora vão em duas colunas iguais,
    na ordem de leitura, e o Tab segue a mesma ordem."""
    _tela(monkeypatch, 911, 464)
    dlg = guarda(_resolver_apagando(None))
    assert isinstance(dlg, fd.ChoiceDialog)
    _mostra(dlg)
    assert isinstance(dlg.button_box, QGridLayout)
    geos = _geometrias(dlg)
    assert geos[0].y() == geos[1].y() and geos[0].x() < geos[1].x()  # leitura: linha a linha
    assert geos[0].width() == geos[1].width() == geos[2].width() == geos[3].width()
    assert geos[4].width() > geos[0].width()  # o último, sozinho, ocupa a linha toda
    _assert_botoes_inteiros_e_separados(dlg)
    assert dlg.height() + common.FOLGA_TITULO <= 464
    assert dlg.rolagem.height() >= common.CORPO_APERTADO
    _assert_ordem(dlg, list(dlg.buttons.values()))


def test_teto_da_rolagem_sai_quando_a_tela_cresce(
    tema: str, guarda: Callable[..., QWidget], monkeypatch: pytest.MonkeyPatch
) -> None:
    """O teto vale para a tela atual: numa tela maior o diálogo volta à altura natural (sem
    barra), e o ajuste para de mudar sozinho (nenhum laço de LayoutRequest)."""
    _tela(monkeypatch, 1280, 672)
    dlg = guarda(_resolver_apagando(None))
    assert isinstance(dlg, fd.ChoiceDialog)
    _mostra(dlg)
    assert dlg.rolagem.maximumHeight() < common.SEM_TETO
    antes = (dlg.size(), dlg.rolagem.maximumHeight())
    for _ in range(5):
        _descarta()
    assert (dlg.size(), dlg.rolagem.maximumHeight()) == antes  # estável
    _tela(monkeypatch, 1920, 1032)
    dlg.fit()
    for _ in range(4):
        _descarta()
    assert dlg.rolagem.maximumHeight() == common.SEM_TETO
    assert dlg.height() == _natural(dlg)
    assert dlg.rolagem.verticalScrollBar().maximum() == 0
    _assert_botoes_inteiros_e_separados(dlg)


@pytest.mark.parametrize(
    ("titulo", "texto"),
    [
        ("Nada encontrado", "Não há pasta protegida pelo Owl Vault aqui."),
        ("Aguarde", "Espere a operação atual terminar e use o atalho de novo."),
        ("Não conferiu", "Senha mestra incorreta."),
    ],
)
def test_dialogo_curto_tem_a_altura_natural(
    tema: str, guarda: Callable[..., QWidget], titulo: str, texto: str
) -> None:
    """v2-visual-2: o mínimo fixo de 120 px da rolagem esticava os diálogos curtos (520x227
    viravam 520x286) e o título e o texto repartiam a sobra (54 px cada, ~45 px de vão)."""
    dlg = guarda(fd.ChoiceDialog(None, titulo, texto, [("OK", "ok")], details_open=True))
    assert isinstance(dlg, fd.ChoiceDialog)
    _mostra(dlg)
    t, x = dlg.title_label, dlg.text_label
    assert t.height() == t.heightForWidth(t.width())
    assert x.height() == x.heightForWidth(x.width())
    vao = x.mapTo(dlg, QPoint(0, 0)).y() - (t.mapTo(dlg, QPoint(0, 0)).y() + t.height())
    assert vao == 12
    ok = dlg.buttons["ok"]
    cromo = 2 * fd.MARGEM + 2 * 24 + 12 + fd.ESPACO_ANTES_DOS_BOTOES
    assert dlg.height() == cromo + t.height() + 12 + x.height() + ok.height()
    assert dlg.rolagem.minimumSizeHint().height() < common.CORPO_MINIMO
    assert dlg.rolagem.verticalScrollBar().maximum() == 0


def test_sobra_de_altura_vai_para_baixo_e_nao_estica_os_textos(
    tema: str, guarda: Callable[..., QWidget]
) -> None:
    """Se o diálogo ficar mais alto que o conteúdo, o título e o texto mantêm a altura e o
    vão de 12 px; a sobra fica embaixo deles."""
    dlg = guarda(fd.ChoiceDialog(None, "Nada encontrado", "Não há pasta aqui.", [("OK", "ok")]))
    assert isinstance(dlg, fd.ChoiceDialog)
    _mostra(dlg)
    dlg.setFixedSize(dlg.width(), dlg.height() + 120)
    for _ in range(3):
        _descarta()
    t, x = dlg.title_label, dlg.text_label
    assert t.height() == t.heightForWidth(t.width())
    assert x.height() == x.heightForWidth(x.width())
    assert x.y() - (t.y() + t.height()) == 12


def test_inform_curto_nao_cresce(
    tema: str, guarda: Callable[..., QWidget], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``inform`` (o caminho real dos avisos de uma linha) também fica na altura natural."""
    vistos: list[fd.ChoiceDialog] = []

    def exec_falso(self: fd.ChoiceDialog) -> int:
        guarda(self)
        vistos.append(self)
        _mostra(self)
        return 0

    monkeypatch.setattr(fd.ChoiceDialog, "exec", exec_falso)
    fd.inform(None, "PIN desativado", "Use a senha mestra.")
    dlg = vistos[0]
    assert dlg.height() == _natural(dlg)
    conteudo = dlg.rolagem.widget()
    assert conteudo is not None
    assert dlg.rolagem.height() == conteudo.heightForWidth(dlg.rolagem.width())


def _largura_com_quebra_diferente(rot: QLabel, barra: int) -> int:
    """Uma largura em que o texto fica mais alto quando perde ``barra`` px (vira mais linhas)."""
    for w in range(160, 700):
        if rot.heightForWidth(w) < rot.heightForWidth(w - barra):
            return w
    raise AssertionError("nenhuma largura muda a quebra do texto")


def test_rolagem_some_com_a_barra_quando_o_conteudo_cabe(guarda: Callable[..., QWidget]) -> None:
    """Uma barra que apareceu num passo intermediário do layout nunca sumia: com ela o texto
    quebra numa largura menor, fica mais alto e continua "precisando" dela (o diálogo de
    Limites, numa tela grande, mostrava uma barra com 16 px para rolar)."""
    conteudo, lay = transparente()
    rot = QLabel(" ".join(["palavra"] * 60))
    rot.setWordWrap(True)
    lay.addWidget(rot)
    rolagem = common.Rolagem(conteudo)
    guarda(rolagem)
    barra = rolagem.verticalScrollBar().sizeHint().width()
    w = _largura_com_quebra_diferente(rot, barra)
    rolagem.resize(w, 40)  # baixa: a barra aparece
    rolagem.show()
    _descarta()
    assert rolagem.verticalScrollBar().isVisible()
    rolagem.resize(w, rolagem.heightForWidth(w))  # agora cabe inteiro na largura toda
    _descarta()
    assert not rolagem.verticalScrollBar().isVisible()
    assert rolagem.viewport().width() == w
    assert conteudo.height() <= rolagem.viewport().height()
    rolagem.resize(w, 40)  # e volta quando não cabe
    _descarta()
    assert rolagem.verticalScrollBar().isVisible()
    assert rolagem.verticalScrollBar().maximum() > 0


def test_limites_em_tela_grande_sem_barra(
    tema: str, guarda: Callable[..., QWidget], monkeypatch: pytest.MonkeyPatch
) -> None:
    _tela(monkeypatch, 1920, 1032)
    dlg = guarda(fd.LimitsDialog(None))
    assert isinstance(dlg, fd.LimitsDialog)
    _mostra(dlg)
    assert not dlg.rolagem.verticalScrollBar().isVisible()
    conteudo = dlg.rolagem.widget()
    assert conteudo is not None
    assert conteudo.height() <= dlg.rolagem.viewport().height()


# =========================================================================== v3-visual-1

#: os botões do Resolver de 'versão anterior' (owl_window, ``versao_anterior``)
BOTOES_VERSAO_ANTERIOR = [
    ("Recuperar esses arquivos em outra pasta…", "restore"),
    ("Apagar a versão anterior…", "delete"),
    ("Tirar da lista", "forget"),
    ("Fechar", "close"),
]


def _resolver_versao_anterior(pai: QWidget | None) -> fd.ChoiceDialog:
    """Como o owl_window o monta: 4 botões, o primeiro com um rótulo longo (339 px), e 40
    arquivos nos detalhes (recolhidos)."""
    return fd.ChoiceDialog(
        pai,
        f"Versão anterior de '{NOME}'",
        "Foi mantida uma versão anterior com 40 arquivo(s) que não estão na pasta.",
        BOTOES_VERSAO_ANTERIOR,
        details=[f"Projeto {i:02d}\\relatório {i:02d}.docx" for i in range(40)],
        primary="restore",
        perigo="delete",
    )


def _assert_botoes_dentro_da_area_util(dlg: fd.ChoiceDialog, largura: int, altura: int) -> None:
    """A janela (com a barra de título) cabe na área útil, e cada botão fica inteiro nela,
    sem cortar o rótulo, na ordem de leitura e de Tab dos botões; o Enter continua no
    primário, nunca na ação destrutiva."""
    botoes = list(dlg.buttons.values())
    geos = _geometrias(dlg)
    _assert_botoes_inteiros_e_separados(dlg)
    assert dlg.height() + common.FOLGA_TITULO <= altura
    assert dlg.width() + common.FOLGA_LARGURA <= largura
    area = QRect(0, 0, largura, altura)
    for b, g in zip(botoes, geos, strict=True):
        # no melhor caso, a janela encostada no topo da área útil, embaixo da barra de título
        na_tela = g.translated(common.FOLGA_LARGURA // 2, common.FOLGA_TITULO)
        assert area.contains(na_tela), (b.text(), na_tela, area)
        assert g.width() >= b.sizeHint().width(), b.text()
        assert g.height() >= b.sizeHint().height(), b.text()
    lidos = sorted(range(len(geos)), key=lambda i: (geos[i].y(), geos[i].x()))
    assert lidos == list(range(len(botoes)))  # linha a linha, da esquerda para a direita
    _assert_ordem(dlg, botoes)
    assert dlg.buttons["restore"].isDefault()
    assert not dlg.buttons["delete"].isDefault()
    assert not dlg.buttons["delete"].autoDefault()
    assert dlg.buttons["delete"].objectName() == "perigo"


@pytest.mark.parametrize(("largura", "altura"), [(731, 384), (780, 411)], ids=["p720_175", "hd175"])
def test_resolver_de_versao_anterior_cabe_em_tela_estreita_e_baixa(
    tema: str,
    guarda: Callable[..., QWidget],
    monkeypatch: pytest.MonkeyPatch,
    largura: int,
    altura: int,
) -> None:
    """v3-visual-1: em 1280x720 e 1366x768 a 175% (escala personalizada) nem a coluna de 4
    botões cabia na altura nem duas colunas iguais (2 x 339 px) na largura. A coluna era usada
    e o diálogo (520x416) passava da área útil: em 731x384 'Fechar' ficava com 35 de 50 px à
    vista. Agora os vizinhos dividem a linha, cada coluna da largura do maior botão dela."""
    _tela(monkeypatch, largura, altura)
    pai = guarda(QWidget())
    pai.resize(700, 300)
    dlg = guarda(_resolver_versao_anterior(pai))
    assert isinstance(dlg, fd.ChoiceDialog)
    _mostra(dlg)
    assert isinstance(dlg.button_box, QGridLayout)
    _assert_botoes_dentro_da_area_util(dlg, largura, altura)
    assert dlg.rolagem.height() >= common.CORPO_APERTADO


def test_rotulo_longo_demais_para_dividir_a_linha_fica_sozinho(
    tema: str, guarda: Callable[..., QWidget], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Numa tela ainda mais estreita (640x440), 'Recuperar…' não divide a linha com ninguém:
    fica sozinho, na largura toda, e os outros seguem dois a dois (o último, sozinho, também
    na largura toda). Antes a coluna era usada e passava da área útil (416 + 40 > 440)."""
    _tela(monkeypatch, 640, 440)
    dlg = guarda(_resolver_versao_anterior(None))
    assert isinstance(dlg, fd.ChoiceDialog)
    _mostra(dlg)
    assert isinstance(dlg.button_box, QGridLayout)
    _assert_botoes_dentro_da_area_util(dlg, 640, 440)
    recuperar, apagar, tirar, fechar = _geometrias(dlg)
    assert apagar.y() == tirar.y() > recuperar.y()  # os dois do meio dividem a linha
    assert fechar.y() > apagar.y()
    assert recuperar.width() == fechar.width() == tirar.right() - apagar.left() + 1
    assert dlg.rolagem.height() >= common.CORPO_APERTADO


@pytest.mark.parametrize(
    ("largura", "altura"), [(800, 552), (1093, 566), (1366, 720)], ids=["x800", "hd125", "hd100"]
)
def test_resolver_de_versao_anterior_mantem_a_coluna_quando_cabe(
    tema: str,
    guarda: Callable[..., QWidget],
    monkeypatch: pytest.MonkeyPatch,
    largura: int,
    altura: int,
) -> None:
    """Onde a coluna de 4 botões cabe junto com o corpo, nada muda: um embaixo do outro."""
    _tela(monkeypatch, largura, altura)
    dlg = guarda(_resolver_versao_anterior(None))
    assert isinstance(dlg, fd.ChoiceDialog)
    _mostra(dlg)
    assert isinstance(dlg.button_box, QVBoxLayout)
    assert dlg.width() == fd.LARGURA
    _assert_botoes_dentro_da_area_util(dlg, largura, altura)
