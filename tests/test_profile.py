"""Perfil das pastas protegidas (``profile.py``) e origem da KEK (``keysource.py``).

PASTAS_PROTEGIDAS.md §2. Todos os testes usam SOMENTE pastas temporárias (tmp_path) com dados
sintéticos, ``TESTING_POLICY``/``TESTING_PARAMS`` e um ``LOCALAPPDATA`` falso: o perfil real do
usuário (%LOCALAPPDATA%\\Owl Vault) nunca é lido nem gravado.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from owl_vault.application import keysource as keysource_mod
from owl_vault.application import profile as profile_mod
from owl_vault.application.keysource import KeySource
from owl_vault.application.profile import (
    MAX_PIN_FAILURES,
    NOTE_BACKUP_PENDING,
    NOTE_BACKUP_USED,
    PRACTICE_EVERY_DAYS,
    PRACTICE_FIRST_DAYS,
    DpapiUnavailableError,
    FolderRecord,
    PinError,
    PinUnavailableError,
    ProfileCorruptError,
    ProfileSession,
    ProfileStore,
    VaultRef,
    default_profile_dir,
    validate_master_password,
    validate_pin,
)
from owl_vault.crypto.kdf import SALT_SIZE, TESTING_PARAMS, TESTING_POLICY, derive_kek
from owl_vault.domain.errors import AuthenticationError, FormatError, OwlVaultError
from owl_vault.domain.limits import MIN_PASSWORD_LENGTH
from owl_vault.domain.models import KdfParams
from owl_vault.storage import dpapi

MASTER = "senha mestra de teste 42"
NEW_MASTER = "outra senha mestra bem longa 7"
WRONG_MASTER = "senha mestra errada 99"
PIN = "947361"
WRONG_PIN = "583920"
NEW_PIN = "961473"
#: parâmetros "calibrados" falsos para change_master (rápidos e diferentes dos do perfil)
NEW_PARAMS = KdfParams(memory_kib=9 * 1024, iterations=2, parallelism=1)
HOJE = _dt.date(2026, 11, 17)
UM_DIA = _dt.timedelta(days=1)
SALT_A = bytes(range(SALT_SIZE))
SALT_B = bytes(range(1, SALT_SIZE + 1))


class Queda(BaseException):
    """Simula o processo morto no meio da derivação do Argon2id."""


# --- fixtures e utilidades -------------------------------------------------------------


@pytest.fixture(autouse=True)
def _localappdata_falso(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Nenhum caminho padrão pode apontar para o perfil real do usuário."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata-falso"))


@dataclass
class Relogio:
    hoje: _dt.date


@pytest.fixture
def relogio(monkeypatch: pytest.MonkeyPatch) -> Relogio:
    """Data de "hoje" controlada pelo teste (o módulo usa ``_dt.date.today()``)."""
    r = Relogio(HOJE)

    class _Date(_dt.date):
        @classmethod
        def today(cls) -> _dt.date:
            return r.hoje

    fake = SimpleNamespace(date=_Date, timedelta=_dt.timedelta, datetime=_dt.datetime)
    monkeypatch.setattr(profile_mod, "_dt", fake)
    return r


@pytest.fixture
def store(tmp_path: Path) -> ProfileStore:
    return ProfileStore(tmp_path / "perfil", TESTING_POLICY)


def _create(store: ProfileStore, master: str = MASTER, pin: str = PIN) -> ProfileSession:
    return store.create(master, pin, params=TESTING_PARAMS)


@pytest.fixture
def created(store: ProfileStore) -> ProfileStore:
    """Perfil recém-criado (sessão já fechada)."""
    _create(store).close()
    return store


@pytest.fixture
def both(created: ProfileStore) -> ProfileStore:
    """Perfil com as DUAS cópias (principal e .bak) gravadas e iguais, contador zerado."""
    created.unlock_with_pin(PIN).close()  # o desbloqueio por PIN grava as duas cópias
    assert created.bak.read_bytes() == created.path.read_bytes()
    return created


def add_folder(session: ProfileSession, name: str = "SegredoXYZ") -> FolderRecord:
    base = f"\\\\?\\C:\\Users\\Fulano\\Documentos\\{name}"
    rec = FolderRecord(
        id=secrets.token_hex(16),
        name=name,
        path=base,
        volume="\\\\?\\Volume{0f0e0d0c-0b0a-0908-0706-050403020100}",
        file_id="ab" * 16,
        state="trancada",
        vaults=[VaultRef("cd" * 16, "atual", base + "\\.owlvault")],
        fingerprints={f"Relatório {name}.docx": [1, "ef" * 16, 10, 20, 30]},
        attention=f"Atenção: {name}",
        pending=[f"sub\\Planilha {name}.xlsx"],
    )
    session.index.folders.append(rec)
    return rec


@pytest.fixture
def com_pasta(created: ProfileStore) -> tuple[ProfileStore, str]:
    """Perfil com uma pasta no índice, gravada nas duas cópias."""
    s = created.unlock_with_master(MASTER)
    rec = add_folder(s)
    s.save()
    created.write_both(s.obj)
    s.close()
    return created, rec.id


@pytest.fixture
def calibracao_rapida(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    """change_master calibra o Argon2id da máquina; nos testes devolve NEW_PARAMS."""
    chamadas: list[tuple[Any, ...]] = []

    def fake(*args: Any, **kwargs: Any) -> KdfParams:
        chamadas.append(args)
        return NEW_PARAMS

    monkeypatch.setattr(profile_mod, "calibrate", fake)
    return chamadas


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_bytes().decode("ascii"))


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.write_bytes(json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii"))


def edit_copies(
    store: ProfileStore, fn: Callable[[dict[str, Any]], None], *, bak: bool = True
) -> None:
    """Altera o JSON em claro do principal (e do .bak, se existir e ``bak``)."""
    for p in [store.path, store.bak] if bak else [store.path]:
        if p.exists():
            obj = read_json(p)
            fn(obj)
            write_json(p, obj)


def failures(store: ProfileStore) -> tuple[int, int]:
    """(pin_failures do principal, pin_failures do .bak)."""
    return read_json(store.path)["pin_failures"], read_json(store.bak)["pin_failures"]


def flip_hex(text: str) -> str:
    i = len(text) // 2
    return text[:i] + ("1" if text[i] == "0" else "0") + text[i + 1 :]


def corrupt_box(obj: dict[str, Any], key: str) -> None:
    obj[key]["ct"] = flip_hex(obj[key]["ct"])


def unlock(store: ProfileStore, modo: str) -> ProfileSession:
    return store.unlock_with_master(MASTER) if modo == "master" else store.unlock_with_pin(PIN)


def wrong_pin(store: ProfileStore) -> int:
    with pytest.raises(PinError) as ei:
        store.unlock_with_pin(WRONG_PIN)
    return ei.value.remaining


# --- validate_pin ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "pin",
    [
        "947361",
        "583920",
        "961473",
        "740385",
        "123457",  # quase sequência
        "47392816",
        "3819274650",
        "584930172648",  # 12 dígitos
        "271946",
        "830561",
        "8305617",
        "62940158",
        "702581",
        "15926073",
        # datas INVÁLIDAS não são recusadas
        "320190",  # 32/01/90 e 32-01-90 (dia 90)
        "31021990",  # 31/02/1990
        "29021990",  # 29/02/1990 (1990 não é bissexto)
        "19902231",  # mês 22
        # ano-mês-dia com 2 dígitos de ano não é tratado como data (ninguém escreve assim)
        "401216",  # seria 16/12/2040: o PIN do relato do usuário
        "900325",
        "991231",
        # ano por extenso fora de 1900–2099
        "15081850",  # 15/08/1850
        "21500704",  # 2150-07-04
        # 901/109 não são sequência (0 e 1 não são vizinhos na fileira): sem "dois pedaços"
        "109456",
        "901456",
        "345901",
        "555901",
    ],
)
def test_validate_pin_aceita(pin: str) -> None:
    validate_pin(pin)


@pytest.mark.parametrize(
    "pin",
    [
        "",
        "94736",  # 5 dígitos
        "9473618254736",  # 13 dígitos
        "94736a",
        "947 361",
        " 947361",
        "947361 ",
        "947-361",
        "+947361",
        "947361\n",
        "９４７３６１",  # dígitos de largura total
        "٩٤٧٣٦١",  # dígitos árabe-índicos
    ],
)
def test_validate_pin_recusa_tamanho_ou_nao_digitos(pin: str) -> None:
    with pytest.raises(OwlVaultError, match="6 a 12"):
        validate_pin(pin)


def test_validate_pin_recusa_none() -> None:
    with pytest.raises(OwlVaultError, match="6 a 12"):
        validate_pin(None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "pin",
    [
        # repetidos
        "000000",
        "7777777",
        "111111111111",
        # sequências crescentes
        "123456",
        "456789",
        "23456789",
        "0123456789",
        # sequências decrescentes
        "654321",
        "987654",
        "876543210",
        "9876543210",
    ],
)
def test_validate_pin_recusa_repetidos_e_sequencias(pin: str) -> None:
    with pytest.raises(OwlVaultError, match="fácil de adivinhar"):
        validate_pin(pin)


@pytest.mark.parametrize(
    "pin",
    [
        "250390",  # ddmmaa
        "010100",  # ddmmaa (01/01/2000)
        "311299",  # ddmmaa
        "25031990",  # ddmmaaaa
        "29022024",  # ddmmaaaa (bissexto)
        "19900325",  # aaaammdd
        "20240229",  # aaaammdd (bissexto)
        "20001231",  # aaaammdd
    ],
)
def test_validate_pin_recusa_datas_validas(pin: str) -> None:
    with pytest.raises(OwlVaultError, match="datas"):
        validate_pin(pin)


@pytest.mark.parametrize("pin", ["1234567890", "0987654321"])
def test_validate_pin_recusa_sequencia_do_teclado(pin: str) -> None:
    """Regressão: a fileira numérica do teclado (9→0 quebrava a sequência) era aceita."""
    with pytest.raises(OwlVaultError, match="fácil de adivinhar"):
        validate_pin(pin)


@pytest.mark.parametrize(
    "pin",
    [
        # lista embutida de PINs comuns (levantamentos públicos)
        "123123",
        "112233",
        "147258",
        "159357",
        "102030",
        "696969",
        "789456",
        "246810",
        "11223344",
        "12341234",
        "112358",
        "135790",
        "147896",
        "314159",
        "1029384756",
        # passo constante "no mostrador" (com a volta 9→0)
        "135791",
        "975319",
        "7890123",
        # bloco repetido (abab, abcabc, abcdabcd, inclusive com a última repetição pela metade)
        "147147",
        "987987",
        "1231231",
        "1234512345",
        "583583",
        # cada dígito repetido em seguida (aabbcc)
        "998877",
        "77553311",
        # palíndromos
        "123321",
        "947749",
        "3816183",
        # no máximo 2 dígitos distintos
        "00000001",
        "100000",
        "131313",
        "202020",
        "939399",
        # linhas, colunas e diagonais do teclado numérico emendadas (e a coluna 2580)
        "852456",
        "159753",
        "789789",
        "963852",
        "741852",
        "369258",
        "147369",
        "456123",
        "123654789",
        "258025",
        "1472583",
        "2580258",
        # contagens (números emendados em progressão)
        "121314",
        "10203040",
        "5101520",
        "9101112",
        "100200300",
        "302010",
    ],
)
def test_validate_pin_recusa_padroes_faceis(pin: str) -> None:
    with pytest.raises(OwlVaultError, match="fácil de adivinhar"):
        validate_pin(pin)


@pytest.mark.parametrize("pin", ["121212", "111222", "010203"])
def test_validate_pin_padrao_que_tambem_e_data_continua_recusado(pin: str) -> None:
    """Datas válidas continuam com a mensagem de data, mesmo quando também são padrões."""
    with pytest.raises(OwlVaultError, match="datas"):
        validate_pin(pin)


@pytest.mark.parametrize(
    ("pin", "data"),
    [
        ("250390", "25/03/90"),
        ("010100", "01/01/00"),
        ("25031990", "25/03/1990"),
        ("19991231", "31/12/1999"),
        ("20240229", "29/02/2024"),
    ],
)
def test_validate_pin_de_data_diz_qual_data_parece(pin: str, data: str) -> None:
    """A mensagem mostra a data que o PIN parece: sem isso, quem digitou não entende o porquê."""
    with pytest.raises(OwlVaultError, match="datas") as ei:
        validate_pin(pin)
    assert f"parece a data {data}." in str(ei.value)


@pytest.mark.parametrize(
    ("pin", "datas"),
    [
        ("25031208", "25/03 e 12/08"),  # dois aniversários sem o ano
        ("29020101", "29/02 e 01/01"),
        ("31120101", "31/12 e 01/01"),
    ],
)
def test_validate_pin_recusa_duas_datas_dia_mes(pin: str, datas: str) -> None:
    """Com 8 dígitos, duas datas dia-mês (ddmmddmm). Antes eram recusadas só por acaso (a
    regra lia qualquer ano de 0001 a 9999: 25/03/1208)."""
    with pytest.raises(OwlVaultError, match="datas") as ei:
        validate_pin(pin)
    assert f"parece as datas {datas}." in str(ei.value)


@pytest.mark.parametrize(("pin", "data"), [("12121212", "12/12"), ("25032503", "25/03")])
def test_validate_pin_mesma_data_dia_mes_duas_vezes(pin: str, data: str) -> None:
    """Não diz "as datas 12/12 e 12/12": diz que é a mesma data repetida."""
    with pytest.raises(OwlVaultError, match="datas") as ei:
        validate_pin(pin)
    assert f"parece a data {data} repetida." in str(ei.value)


@pytest.mark.parametrize("pin", ["25321208", "25031318", "00031208"])
def test_validate_pin_aceita_quase_duas_datas(pin: str) -> None:
    validate_pin(pin)


@pytest.mark.parametrize(
    "pin",
    [
        # antes recusados só por parecerem aammdd/aaaa fora do intervalo; continuam recusados
        "000123",
        "890123",
        "10111213",
        # dois pedaços fáceis: dígito repetido + sequência (ou o contrário)
        "123000",
        "222345",
        "987000",
        "000987",
        "00123456",
        "789000",
        "5556789",
        "345666",
        # contagem com zero à esquerda (antes recusada só por acaso, como "data" 01/02/0304)
        "00010203",
        "000102",
        "0102030405",
        "001002003",
        "000102030405",
        # com passo "redondo" (como 204060 e 100200300 sem os zeros) e largura 4
        "00204060",
        "000100200",
        "000100200300",
        "000100020003",
        "001000200030",
    ],
)
def test_validate_pin_recusa_dois_pedacos_faceis(pin: str) -> None:
    with pytest.raises(OwlVaultError, match="fácil de adivinhar"):
        validate_pin(pin)


@pytest.mark.parametrize("pin", ["01020304", "04030201", "02040608", "03060912"])
def test_validate_pin_contagem_com_zero_a_esquerda_em_8_digitos(pin: str) -> None:
    """Recusados (são também duas datas dia-mês, e essa mensagem vem antes); a contagem com
    zero à esquerda os pega mesmo sem a regra de datas."""
    with pytest.raises(OwlVaultError):
        validate_pin(pin)
    assert profile_mod._padded_counting(pin)


@pytest.mark.parametrize("pin", ["947361", "583920", "961473"])
def test_validate_pin_aceita_os_pins_dos_testes(pin: str) -> None:
    """Os PINs sintéticos usados por todos os testes continuam válidos com as regras novas."""
    validate_pin(pin)


# --- validate_master_password ------------------------------------------------------------


@pytest.mark.parametrize(
    "sm",
    [
        "a" * MIN_PASSWORD_LENGTH,
        MASTER,
        "abc def ghi jkl",  # espaços internos são permitidos
        "çãõáéíóú€😀😀😀",
    ],
)
def test_validate_master_password_aceita(sm: str) -> None:
    validate_master_password(sm)


@pytest.mark.parametrize(
    ("sm", "trecho"),
    [
        ("", "pelo menos"),
        ("a" * (MIN_PASSWORD_LENGTH - 1), "pelo menos"),
        ("ção" * 2 + "x", "pelo menos"),  # 7 caracteres
        (" " + MASTER, "espaço"),
        (MASTER + " ", "espaço"),
        ("\t" + MASTER, "espaço"),
        (MASTER + "\n", "espaço"),
    ],
)
def test_validate_master_password_recusa(sm: str, trecho: str) -> None:
    with pytest.raises(OwlVaultError, match=trecho):
        validate_master_password(sm)


@pytest.mark.parametrize("sm", [None, b"senha mestra em bytes", 123456789012345])
def test_validate_master_password_recusa_nao_str(sm: object) -> None:
    with pytest.raises(OwlVaultError):
        validate_master_password(sm)  # type: ignore[arg-type]


# --- caminho padrão ---------------------------------------------------------------------


def test_default_profile_dir_usa_localappdata(tmp_path: Path) -> None:
    falso = tmp_path / "localappdata-falso" / "Owl Vault"
    assert default_profile_dir() == falso
    s = ProfileStore(policy=TESTING_POLICY)
    assert s.path == falso / "perfil.owlp"
    assert s.bak == falso / "perfil.owlp.bak"
    assert not s.exists()


# --- criação ----------------------------------------------------------------------------


def test_create_grava_perfil(store: ProfileStore) -> None:
    session = _create(store)
    try:
        assert store.path.exists()
        assert store.exists()
        obj = read_json(store.path)
        assert obj["kind"] == "owl-profile"
        assert obj["version"] == 1
        assert obj["profile_id"] == session.profile_id
        assert len(bytes.fromhex(session.profile_id)) == 16
        assert obj["pin"] is not None
        assert obj["pin_failures"] == 0
        assert set(obj["index"]) == {"nonce", "ct"}
        assert set(obj["wrap_sm"]) == {"nonce", "ct"}
        kdf = obj["kdf"]
        salt = bytes.fromhex(kdf["salt"])
        assert len(salt) == SALT_SIZE
        assert (kdf["memory_kib"], kdf["iterations"], kdf["parallelism"]) == (
            TESTING_PARAMS.memory_kib,
            TESTING_PARAMS.iterations,
            TESTING_PARAMS.parallelism,
        )
        [k] = session.index.keks
        assert k.salt == salt
        assert k.params == TESTING_PARAMS
        assert k.kek == derive_kek(MASTER, salt, TESTING_PARAMS, TESTING_POLICY)
        assert session.index.folders == []
        assert store.pin_available()
        assert not list(store.dir.glob("*.tmp"))  # sem sobras de gravação
    finally:
        session.close()


def test_create_grava_tambem_o_bak(store: ProfileStore) -> None:
    """Regressão: o perfil recém-criado ficava sem cópia de segurança até a 2ª gravação."""
    _create(store).close()
    assert store.path.exists()
    assert store.bak.exists()
    assert store.bak.read_bytes() == store.path.read_bytes()
    assert sorted(p.name for p in store.dir.iterdir()) == ["perfil.owlp", "perfil.owlp.bak"]
    # só o .bak já basta para abrir, com a SM e com o PIN
    store.path.unlink()
    s = store.unlock_with_master(MASTER)
    assert NOTE_BACKUP_USED in s.notes
    s.close()
    store.path.unlink()
    store.unlock_with_pin(PIN).close()


def test_bak_e_a_versao_anterior_apos_cada_gravacao(store: ProfileStore) -> None:
    session = _create(store)
    try:
        primeira = store.path.read_bytes()
        session.save()
        assert store.bak.read_bytes() == primeira
        assert read_json(store.path)["generation"] == read_json(store.bak)["generation"] + 1
        assert sorted(p.name for p in store.dir.iterdir()) == ["perfil.owlp", "perfil.owlp.bak"]
    finally:
        session.close()


def test_create_duas_vezes_recusa(created: ProfileStore) -> None:
    antes = created.path.read_bytes()
    with pytest.raises(OwlVaultError, match="Já existe"):
        _create(created, NEW_MASTER, NEW_PIN)
    # outra instância apontando para a mesma pasta também recusa
    with pytest.raises(OwlVaultError, match="Já existe"):
        _create(ProfileStore(created.dir, TESTING_POLICY), NEW_MASTER, NEW_PIN)
    assert created.path.read_bytes() == antes
    created.unlock_with_master(MASTER).close()


def test_create_recusa_se_so_existir_o_bak(both: ProfileStore) -> None:
    both.path.unlink()
    assert both.exists()
    with pytest.raises(OwlVaultError, match="Já existe"):
        _create(both, NEW_MASTER, NEW_PIN)
    assert not both.path.exists()


@pytest.mark.parametrize(
    ("master", "pin"),
    [("curta", PIN), (MASTER, "123456"), (MASTER, "12ab56"), (" " + MASTER, PIN)],
)
def test_create_invalido_nao_grava_nada(store: ProfileStore, master: str, pin: str) -> None:
    with pytest.raises(OwlVaultError):
        store.create(master, pin, params=TESTING_PARAMS)
    assert not store.exists()
    assert not store.dir.exists() or not any(store.dir.iterdir())


def test_create_recusa_params_fora_da_politica(store: ProfileStore) -> None:
    with pytest.raises(FormatError):
        store.create(MASTER, PIN, params=KdfParams(memory_kib=1024, iterations=1, parallelism=1))
    assert not store.exists()


# --- desbloqueio --------------------------------------------------------------------------


def test_unlock_sem_perfil(store: ProfileStore) -> None:
    with pytest.raises(FormatError):
        store.unlock_with_master(MASTER)
    with pytest.raises(FormatError):
        store.unlock_with_pin(PIN)


def test_unlock_com_senha_mestra_certa(created: ProfileStore) -> None:
    obj = read_json(created.path)
    s = created.unlock_with_master(MASTER)
    salt = bytes.fromhex(obj["kdf"]["salt"])
    assert s.profile_id == obj["profile_id"]
    assert s.key_source().kek == derive_kek(MASTER, salt, TESTING_PARAMS, TESTING_POLICY)
    assert s.notes == []
    s.close()
    with pytest.raises(OwlVaultError, match="travado"):
        _ = s.index
    with pytest.raises(OwlVaultError, match="travado"):
        s.save()


def test_unlock_com_senha_mestra_errada(both: ProfileStore) -> None:
    antes = (both.path.read_bytes(), both.bak.read_bytes())
    with pytest.raises(AuthenticationError, match="Senha mestra incorreta") as ei:
        both.unlock_with_master(WRONG_MASTER)
    assert not isinstance(ei.value, PinError)
    assert (both.path.read_bytes(), both.bak.read_bytes()) == antes  # nada foi gravado
    # o PIN não é usado como senha mestra
    with pytest.raises(OwlVaultError):
        both.unlock_with_master(PIN)


def test_unlock_com_pin_certo(created: ProfileStore) -> None:
    salt = bytes.fromhex(read_json(created.path)["kdf"]["salt"])
    s = created.unlock_with_pin(PIN)
    assert s.key_source().kek == derive_kek(MASTER, salt, TESTING_PARAMS, TESTING_POLICY)
    assert s.notes == []
    s.close()
    assert failures(created) == (0, 0)


def test_unlock_com_pin_errado(created: ProfileStore) -> None:
    with pytest.raises(PinError) as ei:
        created.unlock_with_pin(WRONG_PIN)
    assert isinstance(ei.value, AuthenticationError)
    assert ei.value.remaining == MAX_PIN_FAILURES - 1
    assert f"Restam {MAX_PIN_FAILURES - 1}" in str(ei.value)
    # a senha mestra não é aceita como PIN
    with pytest.raises(PinError):
        created.unlock_with_pin(MASTER)


# --- contador de PIN ----------------------------------------------------------------------


def test_falha_gravada_nas_duas_copias_antes_da_derivacao(
    created: ProfileStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    vistos: list[tuple[int, int]] = []
    real = profile_mod.derive_kek

    def espiao(*args: Any, **kwargs: Any) -> bytes:
        vistos.append(failures(created))
        return real(*args, **kwargs)

    monkeypatch.setattr(profile_mod, "derive_kek", espiao)
    with pytest.raises(PinError):
        created.unlock_with_pin(WRONG_PIN)
    assert vistos == [(1, 1)]
    assert failures(created) == (1, 1)
    # mesmo com o PIN certo a tentativa é contada antes; o sucesso zera depois
    created.unlock_with_pin(PIN).close()
    assert vistos == [(1, 1), (2, 2)]
    assert failures(created) == (0, 0)


def test_queda_durante_a_derivacao_conta_como_tentativa(
    created: ProfileStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = profile_mod.derive_kek

    def cai(*args: Any, **kwargs: Any) -> bytes:
        raise Queda

    monkeypatch.setattr(profile_mod, "derive_kek", cai)
    with pytest.raises(Queda):
        created.unlock_with_pin(PIN)
    monkeypatch.setattr(profile_mod, "derive_kek", real)
    assert failures(created) == (1, 1)
    assert wrong_pin(created) == MAX_PIN_FAILURES - 2


def test_tentativas_decrescem_e_pin_e_desativado(created: ProfileStore) -> None:
    restantes: list[int] = []
    ultimo: PinError | None = None
    for _ in range(MAX_PIN_FAILURES):
        with pytest.raises(PinError) as ei:
            created.unlock_with_pin(WRONG_PIN)
        restantes.append(ei.value.remaining)
        ultimo = ei.value
    assert restantes == [4, 3, 2, 1, 0]
    assert ultimo is not None
    assert "desativado" in str(ultimo)
    for p in (created.path, created.bak):
        obj = read_json(p)
        assert obj["pin"] is None
        assert obj["pin_failures"] == MAX_PIN_FAILURES
    assert not created.pin_available()
    # nem o PIN certo funciona mais, e o erro não é "PIN incorreto"
    with pytest.raises(PinUnavailableError) as ei2:
        created.unlock_with_pin(PIN)
    assert type(ei2.value) is PinUnavailableError
    # a senha mestra continua abrindo; o PIN continua desativado
    created.unlock_with_master(MASTER).close()
    assert not created.pin_available()
    with pytest.raises(PinUnavailableError):
        created.unlock_with_pin(PIN)


def test_pin_certo_zera_contador(created: ProfileStore) -> None:
    assert [wrong_pin(created) for _ in range(3)] == [4, 3, 2]
    created.unlock_with_pin(PIN).close()
    assert failures(created) == (0, 0)
    assert wrong_pin(created) == MAX_PIN_FAILURES - 1


def test_senha_mestra_zera_contador_no_principal(created: ProfileStore) -> None:
    assert [wrong_pin(created) for _ in range(2)] == [4, 3]
    created.unlock_with_master(MASTER).close()
    assert read_json(created.path)["pin_failures"] == 0
    assert created.pin_available()
    created.unlock_with_pin(PIN).close()


def test_senha_mestra_zera_contador_efetivo(created: ProfileStore) -> None:
    """Regressão: a SM zerava o contador só no principal; o .bak guardava as falhas."""
    assert [wrong_pin(created) for _ in range(2)] == [4, 3]
    created.unlock_with_master(MASTER).close()
    assert failures(created) == (0, 0)
    assert wrong_pin(created) == MAX_PIN_FAILURES - 1


def test_quatro_erros_senha_mestra_e_mais_um_erro_nao_desativa(created: ProfileStore) -> None:
    assert [wrong_pin(created) for _ in range(4)] == [4, 3, 2, 1]
    created.unlock_with_master(MASTER).close()
    assert failures(created) == (0, 0)
    assert wrong_pin(created) == MAX_PIN_FAILURES - 1
    assert created.pin_available()
    created.unlock_with_pin(PIN).close()


@pytest.mark.parametrize("como", ["por_erros", "so_o_pin_apagado"])
def test_senha_mestra_nao_reativa_pin_desativado_so_no_bak(both: ProfileStore, como: str) -> None:
    """Principal com o PIN (cópia antiga posta de volta), .bak com o PIN desativado: a SM
    devolve as tentativas, mas o PIN continua desativado nas DUAS cópias (só set_pin reativa)."""
    antigo = both.path.read_bytes()  # com o PIN e o contador zerado
    if como == "por_erros":
        for _ in range(MAX_PIN_FAILURES):
            wrong_pin(both)
    else:
        edit_copies(both, lambda o: o.__setitem__("pin", None))
    both.path.write_bytes(antigo)
    assert read_json(both.path)["pin"] is not None
    assert read_json(both.bak)["pin"] is None
    s = both.unlock_with_master(MASTER)
    assert s.obj["pin"] is None
    s.close()
    for p in (both.path, both.bak):
        obj = read_json(p)
        assert obj["pin"] is None
        assert obj["pin_failures"] == 0
    assert not both.pin_available()
    with pytest.raises(PinUnavailableError):
        both.unlock_with_pin(PIN)


def test_senha_mestra_e_set_pin_reativam_pin_desativado(created: ProfileStore) -> None:
    for _ in range(MAX_PIN_FAILURES):
        wrong_pin(created)
    s = created.unlock_with_master(MASTER)
    assert s.obj["pin"] is None
    s.set_pin(NEW_PIN)
    s.close()
    assert failures(created) == (0, 0)
    assert created.pin_available()
    created.unlock_with_pin(NEW_PIN).close()
    with pytest.raises(PinError):
        created.unlock_with_pin(PIN)


def test_restaurar_bak_antigo_nao_devolve_tentativas(both: ProfileStore) -> None:
    antigo = both.bak.read_bytes()  # cópia de ANTES das falhas
    assert read_json(both.bak)["pin_failures"] == 0
    assert [wrong_pin(both) for _ in range(2)] == [4, 3]
    both.bak.write_bytes(antigo)
    assert failures(both) == (2, 0)
    # efetivo = máximo das duas cópias
    assert wrong_pin(both) == 2
    assert failures(both) == (3, 3)


def test_restaurar_copia_antiga_nao_desbloqueia_pin(both: ProfileStore) -> None:
    antigo = both.bak.read_bytes()
    for _ in range(MAX_PIN_FAILURES):
        wrong_pin(both)
    bloqueado = both.path.read_bytes()
    # .bak antigo por cima do .bak
    both.bak.write_bytes(antigo)
    with pytest.raises(PinUnavailableError):
        both.unlock_with_pin(PIN)
    # cópia antiga por cima do PRINCIPAL (o .bak continua bloqueado)
    both.path.write_bytes(antigo)
    both.bak.write_bytes(bloqueado)
    assert not both.pin_available()  # coerente com o .bak
    with pytest.raises(PinUnavailableError):
        both.unlock_with_pin(PIN)
    assert failures(both) == (0, MAX_PIN_FAILURES)  # recusado antes de gravar qualquer coisa


@pytest.mark.parametrize(
    ("principal", "bak", "disponivel"),
    [
        ({}, {}, True),
        ({}, {"pin": None}, False),  # só o .bak desativou
        ({"pin": None}, {}, False),
        ({}, {"pin_failures": MAX_PIN_FAILURES}, False),  # contador esgotado só no .bak
        ({"pin_failures": MAX_PIN_FAILURES}, {}, False),
        ({}, {"pin_failures": MAX_PIN_FAILURES - 1}, True),
        ({"pin_failures": "lixo"}, {}, False),  # contador adulterado conta como esgotado
        ({}, {"pin_failures": None}, False),
        ({"pin_failures": -1000}, {"pin_failures": -1000}, True),  # negativo vale 0
    ],
    ids=[
        "ambas_ok",
        "bak_sem_pin",
        "principal_sem_pin",
        "bak_esgotado",
        "principal_esgotado",
        "bak_quase",
        "contador_lixo",
        "contador_nulo",
        "contador_negativo",
    ],
)
def test_pin_available_coerente_com_o_bak(
    both: ProfileStore, principal: dict[str, Any], bak: dict[str, Any], disponivel: bool
) -> None:
    for path, mudanca in ((both.path, principal), (both.bak, bak)):
        write_json(path, {**read_json(path), **mudanca})
    assert both.pin_available() is disponivel
    if disponivel:
        both.unlock_with_pin(PIN).close()
    else:
        with pytest.raises(PinUnavailableError) as ei:
            both.unlock_with_pin(PIN)
        assert type(ei.value) is PinUnavailableError


def test_contador_negativo_nao_da_tentativas_extras(both: ProfileStore) -> None:
    edit_copies(both, lambda o: o.__setitem__("pin_failures", -1000))
    assert wrong_pin(both) == MAX_PIN_FAILURES - 1
    assert failures(both) == (1, 1)


# --- sessão aberta: save() relê o disco ----------------------------------------------------


def test_sessao_antiga_nao_reativa_pin_desativado(both: ProfileStore) -> None:
    """Sessão aberta + PIN errado 5 vezes no pedido de confirmação ⇒ o save() seguinte da
    sessão (estado antigo em memória: PIN ativo, contador 0) não reativa o PIN."""
    s = both.unlock_with_master(MASTER)
    add_folder(s)
    for _ in range(MAX_PIN_FAILURES):
        wrong_pin(both)
    assert not both.pin_available()
    s.save()
    assert s.obj["pin"] is None
    s.save()  # de novo: o .bak (versão anterior) também fica desativado
    s.close()
    for p in (both.path, both.bak):
        obj = read_json(p)
        assert obj["pin"] is None
        assert obj["pin_failures"] == MAX_PIN_FAILURES
    assert not both.pin_available()
    with pytest.raises(PinUnavailableError):
        both.unlock_with_pin(PIN)


def test_sessao_antiga_nao_zera_o_contador(both: ProfileStore) -> None:
    s = both.unlock_with_pin(PIN)
    assert [wrong_pin(both) for _ in range(2)] == [4, 3]
    s.save()
    s.close()
    assert failures(both) == (2, 2)
    assert wrong_pin(both) == 2


def test_save_usa_o_maximo_entre_memoria_e_disco(both: ProfileStore) -> None:
    antigo = both.path.read_bytes()  # contador 0
    s = both.unlock_with_master(MASTER)
    assert [wrong_pin(both) for _ in range(3)] == [4, 3, 2]
    s.save()
    assert s.obj["pin_failures"] == 3
    # alguém põe cópias antigas (contador 0) nas duas: a memória ainda lembra das 3 falhas
    both.path.write_bytes(antigo)
    both.bak.write_bytes(antigo)
    s.save()
    s.close()
    assert read_json(both.path)["pin_failures"] == 3
    assert wrong_pin(both) == 1


def test_save_com_contador_so_no_bak(both: ProfileStore) -> None:
    s = both.unlock_with_master(MASTER)
    edit_copies(both, lambda o: o.__setitem__("pin_failures", 3))
    write_json(both.path, {**read_json(both.path), "pin_failures": 0})
    s.save()
    s.close()
    assert read_json(both.path)["pin_failures"] == 3
    assert wrong_pin(both) == 1


def test_desbloqueio_bem_sucedido_zera_de_proposito(both: ProfileStore) -> None:
    s = both.unlock_with_master(MASTER)
    assert [wrong_pin(both) for _ in range(2)] == [4, 3]
    both.unlock_with_pin(PIN).close()  # outra confirmação, agora certa: zera
    assert failures(both) == (0, 0)
    s.save()
    s.close()
    assert failures(both) == (0, 0)
    assert wrong_pin(both) == MAX_PIN_FAILURES - 1


def test_set_pin_explicito_reativa_mesmo_com_o_disco_desativado(both: ProfileStore) -> None:
    s = both.unlock_with_master(MASTER)
    for _ in range(MAX_PIN_FAILURES):
        wrong_pin(both)
    s.set_pin(NEW_PIN)
    s.save()  # depois do set_pin, o save() não desfaz nada
    s.close()
    assert failures(both) == (0, 0)
    assert both.pin_available()
    both.unlock_with_pin(NEW_PIN).close()


def test_sessao_antiga_nao_desfaz_pin_trocado_por_outra_sessao(both: ProfileStore) -> None:
    s1 = both.unlock_with_master(MASTER)
    s2 = both.unlock_with_master(MASTER)
    s2.set_pin(NEW_PIN)
    s2.close()
    s1.save()
    s1.close()
    with pytest.raises(PinError):
        both.unlock_with_pin(PIN)
    both.unlock_with_pin(NEW_PIN).close()


def test_sessao_antiga_com_pin_desativado_nao_apaga_pin_novo(both: ProfileStore) -> None:
    for _ in range(MAX_PIN_FAILURES):
        wrong_pin(both)
    s1 = both.unlock_with_master(MASTER)
    assert s1.obj["pin"] is None
    s2 = both.unlock_with_master(MASTER)
    s2.set_pin(NEW_PIN)
    s2.close()
    s1.save()
    s1.close()
    assert both.pin_available()
    both.unlock_with_pin(NEW_PIN).close()


def test_save_mantem_a_geracao_crescente(both: ProfileStore) -> None:
    s1 = both.unlock_with_master(MASTER)
    s2 = both.unlock_with_master(MASTER)
    for _ in range(3):
        s2.save()
    g = read_json(both.path)["generation"]
    s2.close()
    s1.save()
    s1.close()
    assert read_json(both.path)["generation"] == g + 1
    assert read_json(both.bak)["generation"] == g


def test_save_preserva_o_indice_da_sessao(both: ProfileStore) -> None:
    """A mescla só mexe no PIN/contador: o índice gravado é o da memória da sessão."""
    s = both.unlock_with_master(MASTER)
    rec = add_folder(s)
    wrong_pin(both)
    s.save()
    s.close()
    s2 = both.unlock_with_master(MASTER)
    assert s2.index.folder(rec.id) is not None
    s2.close()


# --- DPAPI --------------------------------------------------------------------------------


def _reproteger(store: ProfileStore, entropia: bytes | None) -> None:
    """Decifra o blob do PIN e cifra de novo com outra entropia (None = a correta)."""

    def fn(obj: dict[str, Any]) -> None:
        certa = obj["profile_id"].encode()
        inner = dpapi.unprotect(bytes.fromhex(obj["pin"]["blob"]), certa)
        obj["pin"]["blob"] = dpapi.protect(inner, entropia or certa).hex()

    edit_copies(store, fn)


def test_dpapi_reprotegido_com_a_entropia_certa_funciona(both: ProfileStore) -> None:
    _reproteger(both, None)  # controle do utilitário
    both.unlock_with_pin(PIN).close()


def test_dpapi_com_entropia_errada(both: ProfileStore) -> None:
    _reproteger(both, b"outro-perfil-" + secrets.token_hex(16).encode())
    for _ in range(MAX_PIN_FAILURES + 1):
        with pytest.raises(DpapiUnavailableError, match="senha mestra"):
            both.unlock_with_pin(PIN)
    # falha do DPAPI não conta como PIN errado e não desativa o PIN
    assert failures(both) == (0, 0)
    assert both.pin_available()
    s = both.unlock_with_master(MASTER)
    s.set_pin(NEW_PIN)  # recuperação: SM + PIN novo
    s.close()
    both.unlock_with_pin(NEW_PIN).close()


def test_dpapi_profile_id_trocado(both: ProfileStore) -> None:
    def troca(obj: dict[str, Any]) -> None:
        obj["profile_id"] = secrets.token_hex(16)

    edit_copies(both, troca)
    with pytest.raises(DpapiUnavailableError):
        both.unlock_with_pin(PIN)
    assert failures(both) == (0, 0)


def _flip_byte(b: bytes, i: int) -> bytes:
    return b[:i] + bytes([b[i] ^ 0xFF]) + b[i + 1 :]


CORRUPCOES_BLOB: dict[str, Callable[[bytes], bytes]] = {
    "byte_no_meio": lambda b: _flip_byte(b, len(b) // 2),
    "ultimo_byte": lambda b: _flip_byte(b, len(b) - 1),
    "primeiro_byte": lambda b: _flip_byte(b, 0),
    "truncado": lambda b: b[: len(b) // 2],
    "vazio": lambda b: b"",
}


@pytest.mark.parametrize("corromper", list(CORRUPCOES_BLOB.values()), ids=list(CORRUPCOES_BLOB))
def test_dpapi_blob_corrompido_e_tratado(
    both: ProfileStore, corromper: Callable[[bytes], bytes]
) -> None:
    def fn(obj: dict[str, Any]) -> None:
        obj["pin"]["blob"] = corromper(bytes.fromhex(obj["pin"]["blob"])).hex()

    edit_copies(both, fn)
    with pytest.raises(DpapiUnavailableError, match="senha mestra"):
        both.unlock_with_pin(PIN)
    assert failures(both) == (0, 0)
    s = both.unlock_with_master(MASTER)
    s.set_pin(NEW_PIN)
    s.close()
    both.unlock_with_pin(NEW_PIN).close()


def test_dpapi_blob_nao_hex_e_tratado(both: ProfileStore) -> None:
    """Regressão: um blob com caractere não hexadecimal vazava ValueError cru."""

    def fn(obj: dict[str, Any]) -> None:
        obj["pin"]["blob"] = "zz" + obj["pin"]["blob"][2:]

    edit_copies(both, fn)
    with pytest.raises(DpapiUnavailableError, match="senha mestra"):
        both.unlock_with_pin(PIN)
    assert failures(both) == (0, 0)  # não conta como PIN errado
    s = both.unlock_with_master(MASTER)
    s.set_pin(NEW_PIN)  # recuperação: SM + PIN novo
    s.close()
    both.unlock_with_pin(NEW_PIN).close()


DANOS_CAIXA_PIN: dict[str, Callable[[dict[str, Any]], None]] = {
    "blob_ausente": lambda p: p.pop("blob"),
    "blob_numero": lambda p: p.__setitem__("blob", 12345),
    "salt_nao_hex": lambda p: p.__setitem__("salt", "zz" + p["salt"][2:]),
    "salt_curto": lambda p: p.__setitem__("salt", p["salt"][:8]),
    "params_ausentes": lambda p: p.pop("memory_kib"),
    "params_lixo": lambda p: p.__setitem__("iterations", "muitas"),
    "params_fora_da_politica": lambda p: p.__setitem__("memory_kib", 1),
}


@pytest.mark.parametrize("danificar", list(DANOS_CAIXA_PIN.values()), ids=list(DANOS_CAIXA_PIN))
def test_caixa_do_pin_danificada_e_tratada(
    both: ProfileStore, danificar: Callable[[dict[str, Any]], None]
) -> None:
    edit_copies(both, lambda o: danificar(o["pin"]))
    with pytest.raises(DpapiUnavailableError, match="senha mestra"):
        both.unlock_with_pin(PIN)
    assert failures(both) == (0, 0)
    s = both.unlock_with_master(MASTER)
    s.set_pin(NEW_PIN)
    s.close()
    both.unlock_with_pin(NEW_PIN).close()


@pytest.mark.parametrize("valor", ["um texto", 42, ["lista"]], ids=["texto", "numero", "lista"])
def test_campo_pin_que_nao_e_objeto_e_tratado(both: ProfileStore, valor: object) -> None:
    edit_copies(both, lambda o: o.__setitem__("pin", valor))
    with pytest.raises(DpapiUnavailableError):
        both.unlock_with_pin(PIN)
    assert failures(both) == (0, 0)


# --- índice cifrado -------------------------------------------------------------------------


def _formas(texto: str) -> list[bytes]:
    """Como um texto poderia aparecer em claro no arquivo."""
    formas = {
        texto.encode("utf-8"),
        texto.encode("utf-16-le"),
        texto.encode("utf-16-be"),
        json.dumps(texto)[1:-1].encode("ascii"),  # JSON com ensure_ascii
        texto.encode("utf-8").hex().encode("ascii"),
        texto.encode("utf-16-le").hex().encode("ascii"),
    }
    return [f.lower() for f in formas if f]


def test_indice_nao_aparece_em_claro(created: ProfileStore) -> None:
    s = created.unlock_with_master(MASTER)
    rec = add_folder(s)
    add_folder(s, "Diário da Família")
    s.save()
    created.write_both(s.obj)
    k = s.index.keks[0]
    pk = s._pk
    assert pk is not None
    segredos = [
        "SegredoXYZ",
        "Diário da Família",
        "Fulano",
        "Documentos",
        "Relatório",
        "Planilha",
        "Atenção",
        "owlvault",
        "trancada",
        "Volume{0f0e0d0c",
        rec.id,
        MASTER,
        k.kek.hex(),
        pk.hex(),
    ]
    s.close()
    for arquivo in (created.path, created.bak):
        dados = arquivo.read_bytes().lower()
        for segredo in segredos:
            for forma in _formas(segredo):
                assert forma not in dados, (arquivo.name, segredo, forma)
    # e o índice volta inteiro ao destravar
    s2 = created.unlock_with_pin(PIN)
    volta = s2.index.folder(rec.id)
    assert volta is not None
    assert volta.to_obj() == rec.to_obj()
    assert volta.vault("atual") == rec.vaults[0]
    assert [f.name for f in s2.index.folders] == ["SegredoXYZ", "Diário da Família"]
    s2.close()
    assert sorted(p.name for p in created.dir.iterdir()) == ["perfil.owlp", "perfil.owlp.bak"]


# --- corrupção do principal / das duas cópias -----------------------------------------------


@pytest.mark.parametrize("modo", ["master", "pin"])
def test_indice_do_principal_corrompido_usa_o_bak(
    com_pasta: tuple[ProfileStore, str], modo: str
) -> None:
    store, rid = com_pasta
    edit_copies(store, lambda o: corrupt_box(o, "index"), bak=False)
    s = unlock(store, modo)
    assert s.notes
    assert "cópia de segurança" in s.notes[0]
    rec = s.index.folder(rid)
    assert rec is not None
    assert rec.name == "SegredoXYZ"
    s.close()


def test_indice_corrompido_e_regravado_pela_senha_mestra(
    com_pasta: tuple[ProfileStore, str],
) -> None:
    store, rid = com_pasta
    edit_copies(store, lambda o: corrupt_box(o, "index"), bak=False)
    store.unlock_with_master(MASTER).close()  # regrava o principal com o índice bom
    s = store.unlock_with_master(MASTER)
    assert s.notes == []
    assert s.index.folder(rid) is not None
    s.close()


@pytest.mark.parametrize("pin", [PIN, WRONG_PIN], ids=["pin_certo", "pin_errado"])
def test_pin_com_indice_do_principal_corrompido_preserva_o_bak(
    com_pasta: tuple[ProfileStore, str], pin: str
) -> None:
    """Regressão: o PIN gravava o principal inteiro (índice danificado) nas duas cópias."""
    store, rid = com_pasta
    edit_copies(store, lambda o: corrupt_box(o, "index"), bak=False)
    with contextlib.suppress(PinError):
        store.unlock_with_pin(pin).close()
    s = store.unlock_with_master(MASTER)
    assert s.index.folder(rid) is not None
    s.close()


def test_pin_errado_grava_o_contador_sem_trocar_o_indice_de_cada_copia(
    com_pasta: tuple[ProfileStore, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, rid = com_pasta
    edit_copies(store, lambda o: corrupt_box(o, "index"), bak=False)
    indice_principal = read_json(store.path)["index"]
    indice_bak = read_json(store.bak)["index"]
    assert indice_principal != indice_bak
    vistos: list[tuple[Any, Any, tuple[int, int]]] = []
    real = profile_mod.derive_kek

    def espiao(*args: Any, **kwargs: Any) -> bytes:
        vistos.append(
            (read_json(store.path)["index"], read_json(store.bak)["index"], failures(store))
        )
        return real(*args, **kwargs)

    monkeypatch.setattr(profile_mod, "derive_kek", espiao)
    assert wrong_pin(store) == MAX_PIN_FAILURES - 1
    # na hora de derivar, o contador já está nas duas cópias e cada uma tem o próprio índice
    assert vistos == [(indice_principal, indice_bak, (1, 1))]
    assert read_json(store.path)["index"] == indice_principal
    assert read_json(store.bak)["index"] == indice_bak
    monkeypatch.setattr(profile_mod, "derive_kek", real)
    s = store.unlock_with_pin(PIN)
    assert s.index.folder(rid) is not None
    s.close()


def test_pin_certo_com_indice_corrompido_regrava_o_indice_nas_duas_copias(
    com_pasta: tuple[ProfileStore, str],
) -> None:
    """Depois de usar o .bak, o índice bom (em memória) é re-selado nas DUAS cópias na hora,
    sem depender de um save() posterior."""
    store, rid = com_pasta
    edit_copies(store, lambda o: corrupt_box(o, "index"), bak=False)
    s = store.unlock_with_pin(PIN)
    assert NOTE_BACKUP_USED in s.notes
    assert s.used_backup
    s.close()  # nenhum save()
    assert failures(store) == (0, 0)
    assert store.path.read_bytes() == store.bak.read_bytes()
    # 2ª abertura com o PIN: sem aviso, a pasta continua lá
    s2 = store.unlock_with_pin(PIN)
    assert s2.notes == []
    assert s2.index.folder(rid) is not None
    s2.close()
    # o principal sozinho também abre (o índice dele foi consertado)
    store.bak.write_bytes(b"\x00" * 64)
    s3 = store.unlock_with_master(MASTER)
    assert s3.notes == []
    assert s3.index.folder(rid) is not None
    s3.close()


def test_pin_com_principal_ilegivel_conta_no_bak_sem_apagar_o_principal(
    com_pasta: tuple[ProfileStore, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Principal ilegível: a tentativa é contada no .bak (a cópia que vale) antes de derivar,
    e o principal danificado só é substituído por um desbloqueio bem-sucedido."""
    store, rid = com_pasta
    _estragar_principal(store, "zeros")
    danificado = store.path.read_bytes()
    vistos: list[tuple[int, bytes]] = []
    real = profile_mod.derive_kek

    def espiao(*args: Any, **kwargs: Any) -> bytes:
        vistos.append((read_json(store.bak)["pin_failures"], store.path.read_bytes()))
        return real(*args, **kwargs)

    monkeypatch.setattr(profile_mod, "derive_kek", espiao)
    assert wrong_pin(store) == MAX_PIN_FAILURES - 1
    assert vistos == [(1, danificado)]
    assert wrong_pin(store) == MAX_PIN_FAILURES - 2
    assert store.path.read_bytes() == danificado
    monkeypatch.setattr(profile_mod, "derive_kek", real)
    s = store.unlock_with_pin(PIN)
    assert s.index.folder(rid) is not None
    assert NOTE_BACKUP_USED in s.notes
    s.close()
    assert failures(store) == (0, 0)


def test_gravar_nao_troca_um_bak_bom_por_um_principal_ilegivel(
    com_pasta: tuple[ProfileStore, str],
) -> None:
    store, rid = com_pasta
    bom = store.bak.read_bytes()
    store.path.write_bytes(b"\x00" * 4096)
    store.write(read_json(store.bak))
    assert store.bak.read_bytes() == bom  # o lixo do principal não foi para o .bak
    read_json(store.path)
    s = store.unlock_with_master(MASTER)
    assert s.index.folder(rid) is not None
    s.close()


def _estragar_principal(store: ProfileStore, como: str) -> None:
    if como == "ausente":
        store.path.unlink()
    elif como == "vazio":
        store.path.write_bytes(b"")
    elif como == "zeros":
        store.path.write_bytes(b"\x00" * 4096)
    elif como == "binario":
        store.path.write_bytes(bytes(range(256)) * 8)
    elif como == "json_truncado":
        store.path.write_bytes(store.path.read_bytes()[:-25])
    elif como == "outro_kind":
        edit_copies(store, lambda o: o.__setitem__("kind", "outra-coisa"), bak=False)
    elif como == "versao_futura":
        edit_copies(store, lambda o: o.__setitem__("version", 99), bak=False)
    else:  # pragma: no cover
        raise AssertionError(como)


ESTRAGOS = [
    "ausente",
    "vazio",
    "zeros",
    "binario",
    "json_truncado",
    "outro_kind",
    "versao_futura",
]


@pytest.mark.parametrize("modo", ["master", "pin"])
@pytest.mark.parametrize("como", ESTRAGOS)
def test_principal_ilegivel_usa_o_bak(
    com_pasta: tuple[ProfileStore, str], como: str, modo: str
) -> None:
    store, rid = com_pasta
    _estragar_principal(store, como)
    assert store.exists()
    s = unlock(store, modo)
    rec = s.index.folder(rid)
    assert rec is not None
    assert rec.name == "SegredoXYZ"
    s.close()
    # depois disso o principal volta a ser legível
    read_json(store.path)
    store.unlock_with_master(MASTER).close()


@pytest.mark.parametrize("modo", ["master", "pin"])
@pytest.mark.parametrize("como", ESTRAGOS)
def test_principal_ilegivel_avisa_que_usou_o_bak(
    com_pasta: tuple[ProfileStore, str], como: str, modo: str
) -> None:
    """Regressão: com o principal ilegível o .bak era usado sem nenhum aviso (§2)."""
    store, _rid = com_pasta
    _estragar_principal(store, como)
    store.read_raw()
    assert store.last_read_used_backup
    s = unlock(store, modo)
    notes = list(s.notes)
    assert s.used_backup
    s.close()
    assert notes == [NOTE_BACKUP_USED]
    # consertado: a próxima abertura não avisa mais
    store.read_raw()
    assert not store.last_read_used_backup
    s2 = unlock(store, modo)
    assert s2.notes == []
    s2.close()


def test_wrap_sm_do_principal_corrompido_usa_o_bak(com_pasta: tuple[ProfileStore, str]) -> None:
    """Regressão: a SM era recusada sem tentar o wrap_sm do .bak (que estava bom)."""
    store, rid = com_pasta
    edit_copies(store, lambda o: corrupt_box(o, "wrap_sm"), bak=False)
    s = store.unlock_with_master(MASTER)
    assert s.index.folder(rid) is not None
    assert NOTE_BACKUP_USED in s.notes
    s.close()
    # o principal foi consertado: abre sozinho
    store.bak.write_bytes(b"\x00" * 64)
    s2 = store.unlock_with_master(MASTER)
    assert s2.notes == []
    s2.close()


def test_senha_errada_com_wrap_sm_do_principal_corrompido(
    com_pasta: tuple[ProfileStore, str],
) -> None:
    store, _rid = com_pasta
    edit_copies(store, lambda o: corrupt_box(o, "wrap_sm"), bak=False)
    antes = (store.path.read_bytes(), store.bak.read_bytes())
    with pytest.raises(AuthenticationError, match="Senha mestra incorreta"):
        store.unlock_with_master(WRONG_MASTER)
    assert (store.path.read_bytes(), store.bak.read_bytes()) == antes


def test_kdf_do_principal_corrompido_usa_o_bak(com_pasta: tuple[ProfileStore, str]) -> None:
    store, rid = com_pasta

    def estraga(o: dict[str, Any]) -> None:
        o["kdf"]["salt"] = flip_hex(o["kdf"]["salt"])

    edit_copies(store, estraga, bak=False)
    s = store.unlock_with_master(MASTER)
    assert s.index.folder(rid) is not None
    assert NOTE_BACKUP_USED in s.notes
    s.close()
    assert read_json(store.path)["kdf"] == read_json(store.bak)["kdf"]
    store.bak.unlink()
    store.unlock_with_master(MASTER).close()


def test_wrap_sm_do_principal_corrompido_nao_se_espalha_pelo_pin(
    com_pasta: tuple[ProfileStore, str],
) -> None:
    """Regressão: o desbloqueio por PIN copiava o wrap_sm ruim do principal para o .bak e a
    senha mestra deixava de abrir o perfil."""
    store, rid = com_pasta
    edit_copies(store, lambda o: corrupt_box(o, "wrap_sm"), bak=False)
    s0 = store.unlock_with_pin(PIN)
    assert NOTE_BACKUP_USED in s0.notes
    s0.close()
    # cada cópia, sozinha, abre com a senha mestra
    for apagar in (store.path, store.bak):
        guardada = apagar.read_bytes()
        apagar.write_bytes(b"\x00" * 64)
        s = store.unlock_with_master(MASTER)
        assert s.index.folder(rid) is not None
        s.close()
        apagar.write_bytes(guardada)


def test_wrap_sm_corrompido_nas_duas_copias_e_refeito_pelo_pin(
    com_pasta: tuple[ProfileStore, str],
) -> None:
    store, rid = com_pasta
    edit_copies(store, lambda o: corrupt_box(o, "wrap_sm"))
    with pytest.raises(AuthenticationError, match="Senha mestra incorreta"):
        store.unlock_with_master(MASTER)
    s = store.unlock_with_pin(PIN)  # o PIN abre a PK; o índice tem a KEK da SM
    assert s.notes == [profile_mod.NOTE_MASTER_REBUILT]
    s.close()
    s2 = store.unlock_with_master(MASTER)
    assert s2.index.folder(rid) is not None
    s2.close()


@pytest.mark.parametrize("como", ["zeros", "json_truncado", "versao_futura", "ausente"])
def test_duas_copias_ilegiveis_da_erro(com_pasta: tuple[ProfileStore, str], como: str) -> None:
    store, _rid = com_pasta
    _estragar_principal(store, como)
    store.bak.write_bytes(b"\x00" * 64)
    antes = store.bak.read_bytes()
    with pytest.raises(ProfileCorruptError):
        store.unlock_with_master(MASTER)
    with pytest.raises(ProfileCorruptError):
        store.unlock_with_pin(PIN)
    with pytest.raises(ProfileCorruptError):
        store.practice_due()
    with pytest.raises(ProfileCorruptError):
        store.pin_available()
    assert store.bak.read_bytes() == antes


@pytest.mark.parametrize("modo", ["master", "pin"])
def test_indice_corrompido_nas_duas_copias_da_erro(
    com_pasta: tuple[ProfileStore, str], modo: str
) -> None:
    """Índice que não autentica em nenhuma cópia com a PK certa ⇒ perfil danificado, nunca
    "Senha mestra incorreta"; as cópias danificadas não são reescritas (só o contador)."""
    store, _rid = com_pasta
    edit_copies(store, lambda o: corrupt_box(o, "index"))
    indices = (read_json(store.path)["index"], read_json(store.bak)["index"])
    with pytest.raises(ProfileCorruptError, match="danificado") as ei:
        unlock(store, modo)
    assert isinstance(ei.value, FormatError)
    assert not isinstance(ei.value, AuthenticationError)
    assert "incorreta" not in str(ei.value)
    assert (read_json(store.path)["index"], read_json(store.bak)["index"]) == indices
    assert failures(store) == (0, 0)  # o PIN estava certo: a tentativa não conta


def test_cabecalho_ilegivel_nas_duas_copias_e_perfil_danificado(
    com_pasta: tuple[ProfileStore, str],
) -> None:
    store, _rid = com_pasta
    edit_copies(store, lambda o: o.pop("kdf"))
    with pytest.raises(ProfileCorruptError):
        store.unlock_with_master(MASTER)


def test_wrap_sm_corrompido_nas_duas_copias_da_erro(com_pasta: tuple[ProfileStore, str]) -> None:
    store, _rid = com_pasta
    edit_copies(store, lambda o: corrupt_box(o, "wrap_sm"))
    with pytest.raises(AuthenticationError, match="Senha mestra incorreta"):
        store.unlock_with_master(MASTER)


# --- set_pin ------------------------------------------------------------------------------


def test_set_pin_invalida_o_pin_antigo_inclusive_no_bak(both: ProfileStore) -> None:
    blob_antigo = read_json(both.path)["pin"]["blob"]
    s = both.unlock_with_master(MASTER)
    s.set_pin(NEW_PIN)
    s.close()
    principal, bak = read_json(both.path), read_json(both.bak)
    assert principal["pin"] == bak["pin"]  # o PIN novo está nas DUAS cópias
    assert principal["pin"]["blob"] != blob_antigo
    assert principal["pin_failures"] == bak["pin_failures"] == 0
    with pytest.raises(PinError):
        both.unlock_with_pin(PIN)
    both.unlock_with_pin(NEW_PIN).close()
    # só o .bak: o PIN antigo também não funciona nele
    both.path.write_bytes(b"\x00" * 64)
    with pytest.raises(PinError):
        both.unlock_with_pin(PIN)
    both.unlock_with_pin(NEW_PIN).close()


def test_set_pin_zera_o_contador_nas_duas_copias(created: ProfileStore) -> None:
    for _ in range(3):
        wrong_pin(created)
    s = created.unlock_with_master(MASTER)
    s.set_pin(NEW_PIN)
    s.close()
    assert failures(created) == (0, 0)
    assert wrong_pin(created) == MAX_PIN_FAILURES - 1


@pytest.mark.parametrize("fraco", ["123456", "000000", "250390", "12345", "abcdef"])
def test_set_pin_recusa_pin_fraco(both: ProfileStore, fraco: str) -> None:
    s = both.unlock_with_master(MASTER)
    antes = (both.path.read_bytes(), both.bak.read_bytes())
    with pytest.raises(OwlVaultError):
        s.set_pin(fraco)
    s.close()
    assert (both.path.read_bytes(), both.bak.read_bytes()) == antes
    both.unlock_with_pin(PIN).close()


# --- change_master ------------------------------------------------------------------------


def test_change_master(both: ProfileStore, calibracao_rapida: list[tuple[Any, ...]]) -> None:
    s = both.unlock_with_master(MASTER)
    antiga = s.index.keks[0]
    s.change_master(NEW_MASTER)
    assert calibracao_rapida  # calibrou de novo para a senha nova
    nova = s.index.keks[0]
    assert len(s.index.keks) == 2
    # a KEK antiga continua no índice (cofres ainda não re-trancados)
    assert s.index.keks[1].kek == antiga.kek
    assert s.index.keks[1].salt == antiga.salt
    assert s.index.keks[1].params == antiga.params
    assert nova.salt != antiga.salt
    assert nova.params == NEW_PARAMS
    assert nova.kek == derive_kek(NEW_MASTER, nova.salt, NEW_PARAMS, TESTING_POLICY)
    # key_source() usa keks[0]
    ks = s.key_source()
    assert (ks.salt, ks.params, ks.kek) == (nova.salt, nova.params, nova.kek)
    assert ks.password is None
    assert [k.kek for k in s.key_sources()] == [nova.kek, antiga.kek]
    assert s.key_sources()[1].kek_for(antiga.salt, antiga.params, TESTING_POLICY, None) == (
        antiga.kek
    )
    with pytest.raises(AuthenticationError):
        ks.kek_for(antiga.salt, antiga.params, TESTING_POLICY, None)
    s.close()
    for p in (both.path, both.bak):
        kdf = read_json(p)["kdf"]
        assert kdf["salt"] == nova.salt.hex()
        assert kdf["memory_kib"] == NEW_PARAMS.memory_kib
        assert kdf["iterations"] == NEW_PARAMS.iterations
    with pytest.raises(AuthenticationError, match="Senha mestra incorreta"):
        both.unlock_with_master(MASTER)
    s2 = both.unlock_with_master(NEW_MASTER)
    assert [k.kek for k in s2.index.keks] == [nova.kek, antiga.kek]
    assert s2.key_source().kek == nova.kek
    s2.close()


def test_change_master_bak_tambem_nao_abre_com_a_senha_antiga(
    both: ProfileStore, calibracao_rapida: list[tuple[Any, ...]]
) -> None:
    s = both.unlock_with_master(MASTER)
    s.change_master(NEW_MASTER)
    s.close()
    both.path.unlink()  # só o .bak
    with pytest.raises(AuthenticationError, match="Senha mestra incorreta"):
        both.unlock_with_master(MASTER)
    both.unlock_with_master(NEW_MASTER).close()


def test_change_master_pin_continua_valendo(
    both: ProfileStore, calibracao_rapida: list[tuple[Any, ...]]
) -> None:
    s = both.unlock_with_master(MASTER)
    antiga = s.index.keks[0].kek
    s.change_master(NEW_MASTER)
    nova = s.index.keks[0].kek
    s.close()
    s2 = both.unlock_with_pin(PIN)
    assert s2.key_source().kek == nova
    assert [k.kek for k in s2.index.keks] == [nova, antiga]
    s2.close()
    for p in (both.path, both.bak):
        assert NEW_MASTER.encode() not in p.read_bytes()


@pytest.mark.parametrize(
    "fraca", ["curta", " " + NEW_MASTER, ""], ids=["curta", "espaco_inicial", "vazia"]
)
def test_change_master_recusa_senha_fraca(
    both: ProfileStore, calibracao_rapida: list[tuple[Any, ...]], fraca: str
) -> None:
    s = both.unlock_with_master(MASTER)
    antes = (both.path.read_bytes(), both.bak.read_bytes())
    with pytest.raises(OwlVaultError):
        s.change_master(fraca)
    assert len(s.index.keks) == 1
    s.close()
    assert (both.path.read_bytes(), both.bak.read_bytes()) == antes
    assert not calibracao_rapida
    both.unlock_with_master(MASTER).close()


# --- gravação das duas cópias: tudo ou nada para quem chama (perfil-2) --------------------


def _em_uso() -> PermissionError:
    exc = PermissionError(13, "arquivo em uso (falha simulada)")
    exc.winerror = 32  # type: ignore[attr-defined]
    return exc


class FalhasNaGravacao:
    """Falhas de E/S simuladas dentro de ``write_both``.

    * ``principal``: trocar o principal falha (o principal NÃO muda);
    * ``reler``: ler o principal DEPOIS que ele foi trocado falha (antivírus segurando);
    * ``bak``: trocar o .bak DEPOIS que o principal foi trocado falha (tentativas esgotadas).
    """

    def __init__(self, store: ProfileStore, monkeypatch: pytest.MonkeyPatch) -> None:
        self.store = store
        self.armado = False
        self.principal = self.reler = self.bak = False
        self.disparos = 0
        self._dentro = self._trocou = False
        orig_wb = ProfileStore.write_both
        orig_install = ProfileStore._install
        orig_read = Path.read_bytes
        f = self

        def write_both(st: ProfileStore, obj: dict[str, Any]) -> Any:
            f._dentro, f._trocou = st is f.store, False
            try:
                return orig_wb(st, obj)
            finally:
                f._dentro = False

        def install(st: ProfileStore, tmp: Path, dest: Path) -> None:
            if f.armado and f._dentro:
                if dest == st.path and f.principal:
                    f.disparos += 1
                    tmp.unlink()
                    raise _em_uso()
                if dest == st.bak and f.bak and f._trocou:
                    f.disparos += 1
                    tmp.unlink()
                    raise _em_uso()
            orig_install(st, tmp, dest)
            if f._dentro and dest == st.path:
                f._trocou = True

        def read_bytes(p: Path) -> bytes:
            if f.armado and f.reler and f._dentro and f._trocou and p == f.store.path:
                f.disparos += 1
                raise _em_uso()
            return orig_read(p)

        monkeypatch.setattr(ProfileStore, "write_both", write_both)
        monkeypatch.setattr(ProfileStore, "_install", install)
        monkeypatch.setattr(Path, "read_bytes", read_bytes)

    @contextlib.contextmanager
    def ativas(self, *, principal: bool = False, reler: bool = False, bak: bool = False) -> Any:
        self.principal, self.reler, self.bak, self.armado = principal, reler, bak, True
        try:
            yield self
        finally:
            self.armado = False


@pytest.fixture
def falhas(both: ProfileStore, monkeypatch: pytest.MonkeyPatch) -> FalhasNaGravacao:
    return FalhasNaGravacao(both, monkeypatch)


def _sem_principal(store: ProfileStore) -> None:
    """Deixa só o .bak (o principal some)."""
    store.path.unlink()


def test_set_pin_com_releitura_falhando_vale_nas_duas_copias(
    both: ProfileStore, falhas: FalhasNaGravacao
) -> None:
    """Antes: write_both relia o principal recém-trocado; uma falha nessa releitura virava
    "Erro inesperado" com o PIN novo já valendo no principal e o antigo no .bak."""
    s = both.unlock_with_master(MASTER)
    with falhas.ativas(reler=True):
        s.set_pin(NEW_PIN)  # não pode levantar: nada relê o principal depois de trocá-lo
    s.close()
    assert read_json(both.path)["pin"] == read_json(both.bak)["pin"]
    assert not both.backup_pending
    assert NOTE_BACKUP_PENDING not in s.notes
    with pytest.raises(PinError):
        both.unlock_with_pin(PIN)
    _sem_principal(both)
    with pytest.raises(PinError):
        both.unlock_with_pin(PIN)  # nem o .bak aceita o PIN antigo
    both.unlock_with_pin(NEW_PIN).close()


def test_set_pin_com_bak_travado_vale_e_o_bak_e_refeito_na_proxima_gravacao(
    both: ProfileStore, falhas: FalhasNaGravacao
) -> None:
    s = both.unlock_with_master(MASTER)
    with falhas.ativas(bak=True):
        s.set_pin(NEW_PIN)  # antes: PermissionError ("Erro inesperado"), mas o PIN já tinha mudado
    assert falhas.disparos == 1
    assert both.backup_pending
    assert NOTE_BACKUP_PENDING in s.notes
    assert read_json(both.bak)["pin"] != read_json(both.path)["pin"]  # .bak ficou para depois
    s.save()  # qualquer gravação seguinte passa o principal para o .bak
    assert not both.backup_pending
    assert NOTE_BACKUP_PENDING not in s.notes
    assert read_json(both.bak)["pin"] == read_json(both.path)["pin"]
    s.close()
    both.unlock_with_pin(NEW_PIN).close()
    _sem_principal(both)
    with pytest.raises(PinError):
        both.unlock_with_pin(PIN)
    both.unlock_with_pin(NEW_PIN).close()


@pytest.mark.parametrize("falha", ["reler", "bak"])
def test_change_master_com_falha_depois_do_principal_vale(
    both: ProfileStore,
    falhas: FalhasNaGravacao,
    calibracao_rapida: list[tuple[Any, ...]],
    falha: str,
) -> None:
    """Antes: change_master levantava com a senha nova já no principal e na sessão (as próximas
    trancagens usavam a senha que a interface disse não ter sido salva)."""
    s = both.unlock_with_master(MASTER)
    with falhas.ativas(reler=falha == "reler", bak=falha == "bak"):
        s.change_master(NEW_MASTER)
    nova = s.index.keks[0]
    assert len(s.index.keks) == 2
    assert nova.kek == derive_kek(NEW_MASTER, nova.salt, NEW_PARAMS, TESTING_POLICY)
    assert read_json(both.path)["kdf"]["salt"] == nova.salt.hex()
    if falha == "bak":
        assert NOTE_BACKUP_PENDING in s.notes
        s.save()
    assert read_json(both.bak)["kdf"]["salt"] == nova.salt.hex()
    s.close()
    with pytest.raises(AuthenticationError, match="Senha mestra incorreta"):
        both.unlock_with_master(MASTER)
    _sem_principal(both)
    with pytest.raises(AuthenticationError, match="Senha mestra incorreta"):
        both.unlock_with_master(MASTER)
    both.unlock_with_master(NEW_MASTER).close()


def test_set_pin_que_falha_antes_de_gravar_nao_vale_nem_depois(
    both: ProfileStore, falhas: FalhasNaGravacao
) -> None:
    """Exceção = nada mudou, nem na memória: um ``save`` depois não grava o PIN que a
    interface disse que falhou."""
    s = both.unlock_with_master(MASTER)
    antes = read_json(both.path)["pin"]
    with falhas.ativas(principal=True), pytest.raises(PermissionError):
        s.set_pin(NEW_PIN)
    assert read_json(both.path)["pin"] == antes
    assert s.obj["pin"] == antes
    s.save()
    s.close()
    assert read_json(both.path)["pin"] == antes
    both.unlock_with_pin(PIN).close()
    with pytest.raises(PinError):
        both.unlock_with_pin(NEW_PIN)


def test_change_master_que_falha_antes_de_gravar_nao_vale_nem_depois(
    both: ProfileStore, falhas: FalhasNaGravacao, calibracao_rapida: list[tuple[Any, ...]]
) -> None:
    s = both.unlock_with_master(MASTER)
    keks_antes = [(k.kek, k.salt, k.origin) for k in s.index.keks]
    kdf_antes = dict(s.obj["kdf"])
    with falhas.ativas(principal=True), pytest.raises(PermissionError):
        s.change_master(NEW_MASTER)
    # a sessão continua com a senha mestra antiga: as próximas trancagens usam a antiga
    assert [(k.kek, k.salt, k.origin) for k in s.index.keks] == keks_antes
    assert s.key_source().kek == keks_antes[0][0]
    assert s.obj["kdf"] == kdf_antes
    s.save()
    s.close()
    both.unlock_with_master(MASTER).close()
    with pytest.raises(AuthenticationError, match="Senha mestra incorreta"):
        both.unlock_with_master(NEW_MASTER)


def test_desbloqueio_pelo_pin_com_bak_travado_nao_vira_erro(
    both: ProfileStore, falhas: FalhasNaGravacao
) -> None:
    """Antes: o PIN certo dava erro. Agora o desbloqueio vale; o .bak que não pôde ser trocado
    ainda tem a tentativa contada antes de derivar, e o efetivo continua sendo o máximo das
    cópias (nunca baixa por conta da memória) até o próximo desbloqueio refazer as duas."""
    with falhas.ativas(bak=True):
        s = both.unlock_with_pin(PIN)
    assert NOTE_BACKUP_PENDING in s.notes
    assert failures(both) == (0, 1)
    s.close()
    both.unlock_with_pin(PIN).close()
    assert failures(both) == (0, 0)
    assert not both.backup_pending
    assert wrong_pin(both) == MAX_PIN_FAILURES - 1


def test_write_both_grava_no_bak_os_mesmos_bytes_do_principal(both: ProfileStore) -> None:
    s = both.unlock_with_master(MASTER)
    add_folder(s)
    s.save()
    assert both.bak.read_bytes() != both.path.read_bytes()
    assert both.write_both(s.obj) is True
    assert both.bak.read_bytes() == both.path.read_bytes()
    assert not both.backup_pending
    s.close()


# --- prática da senha mestra ---------------------------------------------------------------


def _due(store: ProfileStore) -> str:
    return read_json(store.path)["practice_due"]


def test_practice_due_no_dia_da_criacao_e_falso(store: ProfileStore, relogio: Relogio) -> None:
    assert PRACTICE_FIRST_DAYS == 1
    _create(store).close()
    assert _due(store) == (HOJE + PRACTICE_FIRST_DAYS * UM_DIA).isoformat()
    assert not store.practice_due()
    relogio.hoje = HOJE + PRACTICE_FIRST_DAYS * UM_DIA
    assert store.practice_due()


@pytest.mark.parametrize(
    ("valor", "esperado"),
    [
        ((HOJE - UM_DIA).isoformat(), True),
        ((HOJE - 400 * UM_DIA).isoformat(), True),
        (HOJE.isoformat(), True),
        ((HOJE + UM_DIA).isoformat(), False),
        ("lixo", True),
        ("", True),
        (None, True),
    ],
)
def test_practice_due_manipulando_o_json(
    relogio: Relogio, created: ProfileStore, valor: str | None, esperado: bool
) -> None:
    edit_copies(created, lambda o: o.__setitem__("practice_due", valor))
    assert created.practice_due() is esperado


def test_practice_due_sem_o_campo(relogio: Relogio, created: ProfileStore) -> None:
    edit_copies(created, lambda o: o.pop("practice_due"))
    assert created.practice_due()


def test_unlock_with_master_renova_a_pratica(relogio: Relogio, created: ProfileStore) -> None:
    edit_copies(created, lambda o: o.__setitem__("practice_due", (HOJE - UM_DIA).isoformat()))
    assert created.practice_due()
    created.unlock_with_master(MASTER).close()
    assert not created.practice_due()
    assert _due(created) == (HOJE + PRACTICE_EVERY_DAYS * UM_DIA).isoformat()
    relogio.hoje = HOJE + (PRACTICE_EVERY_DAYS - 1) * UM_DIA
    assert not created.practice_due()
    relogio.hoje = HOJE + PRACTICE_EVERY_DAYS * UM_DIA
    assert created.practice_due()


def test_unlock_with_pin_nao_renova_a_pratica(relogio: Relogio, created: ProfileStore) -> None:
    vencida = (HOJE - UM_DIA).isoformat()
    edit_copies(created, lambda o: o.__setitem__("practice_due", vencida))
    created.unlock_with_pin(PIN).close()
    assert created.practice_due()
    assert _due(created) == vencida


def test_senha_mestra_errada_nao_renova_a_pratica(relogio: Relogio, created: ProfileStore) -> None:
    """``relogio`` ANTES de ``created``: o pytest monta as fixtures na ordem da assinatura, e o
    perfil criado com a data real (não HOJE) fazia este teste falhar a partir de 21/11/2026."""
    assert _due(created) == (HOJE + PRACTICE_FIRST_DAYS * UM_DIA).isoformat()
    relogio.hoje = HOJE + 5 * UM_DIA
    assert created.practice_due()
    with pytest.raises(AuthenticationError):
        created.unlock_with_master(WRONG_MASTER)
    assert created.practice_due()


# --- KeySource ----------------------------------------------------------------------------


def test_kek_for_mesmo_salt_e_params_devolve_a_kek_sem_derivar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kek = bytes([0x5A]) * 32

    def proibido(*args: Any, **kwargs: Any) -> bytes:
        raise AssertionError("não deveria derivar")

    monkeypatch.setattr(keysource_mod, "derive_kek", proibido)
    ks = KeySource(salt=SALT_A, params=TESTING_PARAMS, kek=kek)
    assert ks.has_kek
    assert ks.kek_for(SALT_A, TESTING_PARAMS, TESTING_POLICY, None) == kek
    # iguais por valor (outras instâncias) também servem
    params_iguais = KdfParams(
        TESTING_PARAMS.memory_kib, TESTING_PARAMS.iterations, TESTING_PARAMS.parallelism
    )
    salt_igual = bytes(bytearray(SALT_A))
    assert salt_igual is not SALT_A
    assert ks.kek_for(salt_igual, params_iguais, TESTING_POLICY, None) == kek


@pytest.mark.parametrize(
    ("salt", "params"),
    [(SALT_B, TESTING_PARAMS), (SALT_A, NEW_PARAMS), (SALT_B, NEW_PARAMS)],
    ids=["salt", "params", "ambos"],
)
def test_kek_for_diferente_sem_senha_recusa(salt: bytes, params: KdfParams) -> None:
    ks = KeySource(salt=SALT_A, params=TESTING_PARAMS, kek=bytes(32))
    with pytest.raises(AuthenticationError, match="outra senha mestra"):
        ks.kek_for(salt, params, TESTING_POLICY, None)


def test_kek_for_diferente_com_senha_deriva() -> None:
    guardada = bytes([0x11]) * 32
    ks = KeySource(password=MASTER, salt=SALT_A, params=TESTING_PARAMS, kek=guardada)
    esperado = derive_kek(MASTER, SALT_B, TESTING_PARAMS, TESTING_POLICY)
    assert ks.kek_for(SALT_B, TESTING_PARAMS, TESTING_POLICY, None) == esperado
    assert ks.kek_for(SALT_A, TESTING_PARAMS, TESTING_POLICY, None) == guardada


def test_keysource_so_com_senha() -> None:
    ks = KeySource.of(MASTER)
    assert ks.password == MASTER
    assert not ks.has_kek
    esperado = derive_kek(MASTER, SALT_A, TESTING_PARAMS, TESTING_POLICY)
    assert ks.kek_for(SALT_A, TESTING_PARAMS, TESTING_POLICY, None) == esperado
    assert KeySource.of(ks) is ks


def test_keysource_sem_kek_e_sem_senha_recusa() -> None:
    with pytest.raises(AuthenticationError):
        KeySource().kek_for(SALT_A, TESTING_PARAMS, TESTING_POLICY, None)
    # KEK sem salt/params não é "has_kek" e não é usada
    ks = KeySource(kek=bytes(32))
    assert not ks.has_kek
    with pytest.raises(AuthenticationError):
        ks.kek_for(SALT_A, TESTING_PARAMS, TESTING_POLICY, None)


def test_keysource_repr_nao_mostra_segredos() -> None:
    ks = KeySource(password=MASTER, salt=SALT_A, params=TESTING_PARAMS, kek=bytes([0xAB]) * 32)
    texto = repr(ks)
    assert MASTER not in texto
    assert "\\xab" not in texto
    assert "abab" not in texto


def test_key_source_da_sessao_abre_cofre_do_perfil(created: ProfileStore) -> None:
    obj = read_json(created.path)
    salt = bytes.fromhex(obj["kdf"]["salt"])
    s = created.unlock_with_pin(PIN)
    ks = s.key_source()
    s.close()
    assert ks.kek_for(salt, TESTING_PARAMS, TESTING_POLICY, None) == derive_kek(
        MASTER, salt, TESTING_PARAMS, TESTING_POLICY
    )
