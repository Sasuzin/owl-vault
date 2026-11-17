"""Diálogos no visual "Cofre" (folder_dialogs.py e ProgressDialog de common.py).

Regras: plataforma offscreen, nenhum ``exec()`` bloqueante (os diálogos são construídos e os
botões acionados por ``click()``/teclas; onde a função pública chama ``exec()``, ele é trocado
por um gravador), dados sintéticos e nenhum acesso a pastas ou ao perfil real.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtGui import QColor, QKeyEvent, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QStyleFactory,
    QVBoxLayout,
    QWidget,
)

from owl_vault.domain.limits import MIN_PASSWORD_LENGTH
from owl_vault.ui import common
from owl_vault.ui import folder_dialogs as fd
from owl_vault.ui.componentes import Aviso, CampoSenha, LinhaChecagem
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
