"""Perfil das pastas protegidas: senha mestra, PIN (DPAPI) e índice cifrado.

PASTAS_PROTEGIDAS.md §2. Arquivo ``%LOCALAPPDATA%\\Owl Vault\\perfil.owlp`` (+ ``.bak``):
JSON em claro com partes cifradas (AES-256-GCM):

* ``kdf``: salt/params do Argon2id da senha mestra (SM). KEK_SM = Argon2id(SM, salt, params).
  Todos os cofres das pastas usam esse salt/params ⇒ abrem só com a SM em qualquer PC.
* ``wrap_sm`` = AES-GCM(KEK_SM, PK): caminho da senha mestra.
* ``pin.blob`` = DPAPI_usuário(AES-GCM(Argon2id(PIN), PK)): caminho do PIN. O PIN dá acesso
  à PK (e por ela à KEK_SM guardada no índice), **nunca à senha mestra**.
* ``index`` = AES-GCM(PK, JSON do índice): KEKs e a lista de pastas (caminhos, estados...).

As duas cópias (principal e ``.bak``) existem desde a criação. O contador de erros do PIN é
gravado em CADA cópia sem trocar o resto dela (o índice de uma cópia nunca é copiado por cima
da outra antes de autenticar); o efetivo é o máximo das duas, e um PIN desativado em qualquer
cópia está desativado. Uma sessão aberta relê o disco antes de gravar: nunca reativa um PIN
desativado nem zera o contador (só ``set_pin`` e um desbloqueio bem-sucedido zeram).

Trocar PIN/senha mestra é tudo ou nada para quem chama: exceção = o principal não foi trocado e a
sessão volta ao que era; sem exceção = a mudança vale. Se só o .bak não puder ser trocado depois
do principal, ele fica com a versão anterior até a próxima gravação (``NOTE_BACKUP_PENDING``).
"""

from __future__ import annotations

import contextlib
import copy
import datetime as _dt
import itertools
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from owl_vault.application.keysource import KeySource
from owl_vault.crypto.kdf import (
    PRODUCTION_POLICY,
    SALT_SIZE,
    KdfPolicy,
    calibrate,
    derive_kek,
    validate_params,
)
from owl_vault.domain.errors import AuthenticationError, FormatError, OwlVaultError
from owl_vault.domain.limits import KEY_SIZE, MIN_PASSWORD_LENGTH, NONCE_SIZE
from owl_vault.domain.models import KdfParams
from owl_vault.storage import dpapi, winfs

PROFILE_KIND = "owl-profile"
PROFILE_VERSION = 1
MAX_PIN_FAILURES = 5
PRACTICE_FIRST_DAYS = 1
PRACTICE_EVERY_DAYS = 30
_MAX_PROFILE_BYTES = 256 * 1024 * 1024

#: aviso em ``session.notes`` quando o desbloqueio precisou da cópia de segurança
NOTE_BACKUP_USED = (
    "O arquivo principal do perfil estava danificado; foi usada a cópia de segurança."
)
NOTE_MASTER_REBUILT = (
    "A parte do perfil que abre com a senha mestra estava danificada e foi refeita."
)
#: aviso em ``session.notes`` quando a mudança valeu no arquivo principal, mas a cópia de
#: segurança não pôde ser trocada (ela ainda tem a versão anterior até a próxima gravação)
NOTE_BACKUP_PENDING = (
    "A cópia de segurança do perfil não pôde ser atualizada agora; ela será refeita na "
    "próxima gravação."
)
_WEAK_PIN = "Este PIN é fácil de adivinhar. Escolha outro."
_DPAPI_GONE = (
    "O Windows não consegue mais usar o PIN deste computador (a senha do Windows foi "
    "redefinida ou o Windows foi reinstalado). Digite sua senha mestra."
)
_PIN_DAMAGED = (
    "O PIN deste computador está danificado. Digite sua senha mestra; depois você cria um PIN novo."
)
_INDEX_CORRUPT = (
    "O perfil do Owl Vault está danificado: a lista de pastas não pôde ser lida nem no "
    "arquivo principal nem na cópia de segurança."
)
_HEADER_CORRUPT = (
    "O perfil do Owl Vault está danificado: a parte que abre com a senha mestra não pôde ser "
    "lida nem no arquivo principal nem na cópia de segurança."
)


class ProfileCorruptError(FormatError):
    """O arquivo do perfil (principal e cópia de segurança) está ilegível ou não autentica.

    Diferente de "senha incorreta": a interface oferece recuperar as pastas com a senha mestra
    num perfil novo (o arquivo danificado é guardado ao lado, nunca apagado).
    """


class PinError(AuthenticationError):
    """PIN incorreto (com tentativas restantes)."""

    def __init__(self, remaining: int) -> None:
        super().__init__(
            f"PIN incorreto. Restam {remaining} tentativa(s); depois disso, só a senha mestra."
            if remaining > 0
            else "PIN incorreto. O PIN foi desativado: use a senha mestra."
        )
        self.remaining = remaining


class PinUnavailableError(AuthenticationError):
    """Não há PIN utilizável (desativado após erros ou DPAPI indisponível)."""


class DpapiUnavailableError(PinUnavailableError):
    """O Windows não consegue mais decifrar o PIN (reinstalação/senha redefinida) ou os dados
    do PIN no perfil estão danificados: pede a senha mestra e depois um PIN novo."""


def default_profile_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "Owl Vault"


# --- validações ------------------------------------------------------------------------

#: PINs muito comuns em levantamentos públicos de PINs de 6 a 10 dígitos. Vários também caem
#: nas regras de ``_is_guessable``; a lista é a segunda linha de defesa.
_COMMON_PINS = frozenset(
    {
        "123123",
        "112233",
        "147258",
        "159357",
        "159753",
        "102030",
        "696969",
        "789456",
        "456123",
        "246810",
        "135790",
        "135791",
        "147852",
        "852456",
        "963852",
        "741852",
        "258369",
        "369258",
        "147369",
        "123654",
        "789789",
        "100200",
        "112358",
        "11235813",
        "314159",
        "31415926",
        "271828",
        "520131",
        "5201314",
        "1314520",
        "147896",
        "102938",
        "1029384756",
        "7894561230",
        "1472583690",
        "11223344",
        "12341234",
        "123321",
        "147147",
        "987987",
    }
)

#: linhas, colunas e diagonais do teclado numérico (e a coluna do meio com o 0 do telefone)
_KEYPAD_LINES = ("123", "456", "789", "147", "258", "369", "159", "357", "2580")
_KEYPAD_SEGMENTS = frozenset(s for line in _KEYPAD_LINES for s in (line, line[::-1]))


def validate_pin(pin: str) -> None:
    """6 a 12 dígitos; recusa datas e PINs fáceis de adivinhar.

    Datas (com a mensagem que mostra a data, ``_date_in``): ddmmaa; ddmmaaaa e aaaammdd de
    1900 a 2099; e, com 8 dígitos, duas datas dia-mês (ddmmddmm).

    Fáceis: todos iguais; sequências (também com a volta 9→0 da fileira do teclado e com
    passo constante, como 135791); blocos repetidos (abab, abcabc, 12341234, aabbcc);
    palíndromos; no máximo 2 dígitos distintos; dois pedaços fáceis emendados (000123,
    222345, 567876); linhas/colunas/diagonais do teclado numérico emendadas (147258, 159357,
    789456123); contagens (102030, 246810, e com zero à esquerda: 01020304, 000102); e uma
    lista curta de PINs comuns.
    """
    if not re.fullmatch(r"[0-9]{6,12}", pin or ""):
        raise OwlVaultError("O PIN deve ter de 6 a 12 números.")
    digits = [int(c) for c in pin]
    steps = {b - a for a, b in itertools.pairwise(digits)}
    if len(set(pin)) == 1 or steps in ({1}, {-1}):
        raise OwlVaultError(_WEAK_PIN)
    date = _date_in(pin)
    if date:
        raise OwlVaultError(f"Este PIN parece {date}. Não use datas como PIN: escolha outro.")
    if _is_guessable(pin):
        raise OwlVaultError(_WEAK_PIN)


#: anos que um PIN de 8 dígitos com o ano por extenso (ddmmaaaa, aaaammdd) pode ser
_DATE_YEARS = range(1900, 2100)


def _day_month(text: str) -> str:
    """'2503' → '25/03' se for um dia-mês válido (29/02 vale); senão ''."""
    try:
        return _dt.datetime.strptime(text + "2000", "%d%m%Y").strftime("%d/%m")
    except ValueError:
        return ""


def _date_in(pin: str) -> str:
    """As datas que o PIN parece, como as pessoas as escrevem no Brasil ("a data 25/03/90",
    "as datas 25/03 e 12/08"; "" se nenhuma): dia-mês-ano com 6 dígitos (ddmmaa, qualquer
    ano) ou 8 (ddmmaaaa), ano-mês-dia só com o ano por extenso (aaaammdd), que se reconhece
    pelo ano no começo, e, com 8 dígitos, duas datas dia-mês (o aniversário de duas pessoas).
    Ano-mês-dia com 2 dígitos (aammdd) não conta: quase ninguém escreve datas assim, e
    recusar barrava PINs que ninguém vê como data (401216 seria 16/12/2040)."""
    if len(pin) == 6:
        candidates = [("%d%m%y", "%d/%m/%y")]
    elif len(pin) == 8:
        candidates = [("%d%m%Y", "%d/%m/%Y"), ("%Y%m%d", "%d/%m/%Y")]
    else:
        return ""
    for fmt, shown in candidates:
        try:
            when = _dt.datetime.strptime(pin, fmt)
        except ValueError:
            continue
        if len(pin) == 8 and when.year not in _DATE_YEARS:
            continue
        return f"a data {when.strftime(shown)}"
    if len(pin) == 8:
        first, second = _day_month(pin[:4]), _day_month(pin[4:])
        if first and first == second:
            return f"a data {first} repetida"  # 12121212, 25032503
        if first and second:
            return f"as datas {first} e {second}"
    return ""


def _is_guessable(pin: str) -> bool:
    n = len(pin)
    if pin in _COMMON_PINS or len(set(pin)) <= 2 or pin == pin[::-1]:
        return True
    digits = [int(c) for c in pin]
    # passo constante "no mostrador" (1234567890, 0987654321, 135791, 7890123)
    if len({(b - a) % 10 for a, b in itertools.pairwise(digits)}) == 1:
        return True
    # bloco repetido, mesmo que a última repetição fique pela metade (abab, abcabc, 1231231)
    for k in range(1, n // 2 + 1):
        if all(pin[i] == pin[i - k] for i in range(k, n)):
            return True
    # cada dígito repetido em seguida (aabbcc, 11223344, 998877)
    if min(len(list(g)) for _, g in itertools.groupby(pin)) >= 2:
        return True
    return _two_easy_pieces(pin) or _keypad_path(pin) or _counting(pin) or _padded_counting(pin)


#: sequências que alguém digita em linha: 0 a 9 e a fileira do teclado (1234567890), nos
#: dois sentidos. 890 e 098 contam; 901 e 109 não (0 e 1 não são vizinhos em nenhuma delas)
_RUNS = ("0123456789", "1234567890", "9876543210", "0987654321")


def _easy_piece(piece: str) -> bool:
    """Um dígito repetido (2 ou mais) ou uma sequência de 3 ou mais de ``_RUNS``."""
    if len(piece) >= 2 and len(set(piece)) == 1:
        return True
    return len(piece) >= 3 and any(piece in run for run in _RUNS)


def _two_easy_pieces(pin: str) -> bool:
    """Dois pedaços fáceis emendados: zeros ou um dígito repetido antes ou depois de uma
    sequência (000123, 123000, 222345, 987000, 00123456), ou duas sequências (567876)."""
    return any(_easy_piece(pin[:i]) and _easy_piece(pin[i:]) for i in range(2, len(pin) - 1))


def _keypad_path(pin: str) -> bool:
    """Linhas/colunas/diagonais do teclado numérico emendadas (147258, 789456123, 159357);
    o último pedaço pode ser só o começo de uma delas (1472583)."""

    def fits(i: int) -> bool:
        if i == len(pin):
            return True
        rest = pin[i:]
        if i > 0 and any(s.startswith(rest) for s in _KEYPAD_SEGMENTS):
            return True
        return any(pin.startswith(s, i) and fits(i + len(s)) for s in _KEYPAD_SEGMENTS)

    return fits(0)


def _counting(pin: str) -> bool:
    """Números emendados em progressão aritmética, com 3 termos ou mais: 102030 (10 20 30),
    246810 (2 4 6 8 10), 9101112, 302010, 100200300. Passos grandes e "quebrados" (como
    58 39 20) não contam: não são um padrão que alguém tente."""
    n = len(pin)
    for i in range(1, n - 1):
        first = pin[:i]
        if len(first) > 1 and first[0] == "0":
            break
        for j in range(i + 1, n):
            second = pin[i:j]
            if len(second) > 1 and second[0] == "0":
                break
            a, b = int(first), int(second)
            d = b - a
            if d == 0 or not (abs(d) <= 10 or (d % 10 == 0 and a % d == 0)):
                continue
            out, term, terms = first + second, b, 2
            while len(out) < n:
                term += d
                if term < 0:
                    break
                out += str(term)
                terms += 1
            if terms >= 3 and out == pin:
                return True
    return False


def _padded_counting(pin: str) -> bool:
    """Contagem com números de largura fixa e zero à esquerda, que ``_counting`` não lê:
    01020304 (01 02 03 04), 000102, 04030201, 001002003, 00204060, 000100020003. 3 termos ou
    mais; o passo segue a regra de ``_counting`` (1 a 10, ou "redondo" como 20 e 100)."""
    n = len(pin)
    for w in (2, 3, 4):
        if n % w or n // w < 3 or not any(pin[i] == "0" for i in range(0, n, w)):
            continue
        terms = [int(pin[i : i + w]) for i in range(0, n, w)]
        diffs = {b - a for a, b in itertools.pairwise(terms)}
        if len(diffs) != 1:
            continue
        d = next(iter(diffs))
        if d != 0 and (abs(d) <= 10 or (d % 10 == 0 and terms[0] % d == 0)):
            return True
    return False


def validate_master_password(sm: str) -> None:
    if not isinstance(sm, str) or len(sm) < MIN_PASSWORD_LENGTH:
        raise OwlVaultError(f"A senha mestra deve ter pelo menos {MIN_PASSWORD_LENGTH} caracteres.")
    if sm.strip() != sm:
        raise OwlVaultError("A senha mestra não pode começar nem terminar com espaço.")


# --- índice ----------------------------------------------------------------------------


@dataclass
class VaultRef:
    vault_id: str  # hex
    role: str  # "atual" | "novo" | "anterior"
    location: str  # caminho estendido da pasta do cofre

    def to_obj(self) -> dict[str, Any]:
        return {"vault_id": self.vault_id, "role": self.role, "location": self.location}

    @staticmethod
    def from_obj(o: dict[str, Any]) -> VaultRef:
        return VaultRef(str(o["vault_id"]), str(o["role"]), str(o["location"]))


@dataclass
class FolderRecord:
    id: str  # hex 32
    name: str
    path: str  # caminho estendido (cache; a identidade manda)
    volume: str  # \\?\Volume{GUID} (parte 0 do Resolved)
    file_id: str  # hex do FileId de 128 bits da pasta
    state: str  # aberta | trancando | apagando | trancada | abrindo | abertura_incompleta
    hidden: bool = False
    vaults: list[VaultRef] = field(default_factory=list)
    fingerprints: dict[str, list[Any]] = field(default_factory=dict)  # "a\\b" → [vol,fid,size,m,c]
    accepted_missing: list[str] = field(default_factory=list)
    zone_files: list[str] = field(default_factory=list)
    attention: str = ""  # texto para "Precisa de atenção" (vazio = nada)
    pending: list[str] = field(default_factory=list)  # itens não apagados / não restaurados
    kek_epoch: int = 0

    def vault(self, role: str) -> VaultRef | None:
        for v in self.vaults:
            if v.role == role:
                return v
        return None

    def to_obj(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "path": self.path,
            "volume": self.volume,
            "file_id": self.file_id,
            "state": self.state,
            "hidden": self.hidden,
            "vaults": [v.to_obj() for v in self.vaults],
            "fingerprints": self.fingerprints,
            "accepted_missing": self.accepted_missing,
            "zone_files": self.zone_files,
            "attention": self.attention,
            "pending": self.pending,
            "kek_epoch": self.kek_epoch,
        }

    @staticmethod
    def from_obj(o: dict[str, Any]) -> FolderRecord:
        return FolderRecord(
            id=str(o["id"]),
            name=str(o["name"]),
            path=str(o["path"]),
            volume=str(o["volume"]),
            file_id=str(o["file_id"]),
            state=str(o["state"]),
            hidden=bool(o.get("hidden", False)),
            vaults=[VaultRef.from_obj(v) for v in o.get("vaults", [])],
            fingerprints=dict(o.get("fingerprints", {})),
            accepted_missing=list(o.get("accepted_missing", [])),
            zone_files=list(o.get("zone_files", [])),
            attention=str(o.get("attention", "")),
            pending=list(o.get("pending", [])),
            kek_epoch=int(o.get("kek_epoch", 0)),
        )


#: origem de uma KEK no índice: a senha mestra do perfil; uma senha mestra substituída por
#: "Criar nova senha mestra"; ou a senha de uma pasta trazida por "Recuperar".
KEK_PERFIL = "perfil"
KEK_TROCADA = "trocada"
KEK_RECUPERADA = "recuperada"


@dataclass
class KekEntry:
    salt: bytes
    params: KdfParams
    kek: bytes = field(repr=False)
    origin: str = KEK_PERFIL


@dataclass
class Index:
    keks: list[KekEntry]  # [0] = atual (senha mestra vigente); demais = antigas
    folders: list[FolderRecord] = field(default_factory=list)

    def folder(self, folder_id: str) -> FolderRecord | None:
        for f in self.folders:
            if f.id == folder_id:
                return f
        return None

    def to_obj(self) -> dict[str, Any]:
        return {
            "keks": [
                {
                    "salt": k.salt.hex(),
                    "memory_kib": k.params.memory_kib,
                    "iterations": k.params.iterations,
                    "parallelism": k.params.parallelism,
                    "kek": k.kek.hex(),
                    "origin": k.origin,
                }
                for k in self.keks
            ],
            "folders": [f.to_obj() for f in self.folders],
        }

    @staticmethod
    def from_obj(o: dict[str, Any]) -> Index:
        keks = [
            KekEntry(
                bytes.fromhex(k["salt"]),
                KdfParams(int(k["memory_kib"]), int(k["iterations"]), int(k["parallelism"])),
                bytes.fromhex(k["kek"]),
                str(k.get("origin", KEK_PERFIL if i == 0 else KEK_TROCADA)),
            )
            for i, k in enumerate(o["keks"])
        ]
        return Index(keks=keks, folders=[FolderRecord.from_obj(f) for f in o.get("folders", [])])


# --- arquivo ---------------------------------------------------------------------------


def _aad(profile_id: str, label: str) -> bytes:
    return f"{PROFILE_KIND}|{PROFILE_VERSION}|{profile_id}|{label}".encode("ascii")


def _seal(key: bytes, plaintext: bytes, aad: bytes) -> dict[str, str]:
    nonce = os.urandom(NONCE_SIZE)
    return {"nonce": nonce.hex(), "ct": AESGCM(key).encrypt(nonce, plaintext, aad).hex()}


def _open(key: bytes, box: dict[str, str], aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(bytes.fromhex(box["nonce"]), bytes.fromhex(box["ct"]), aad)
    except (InvalidTag, KeyError, TypeError, ValueError) as exc:
        raise AuthenticationError("perfil: falha de autenticação") from exc


def _params_obj(p: KdfParams) -> dict[str, int]:
    return {"memory_kib": p.memory_kib, "iterations": p.iterations, "parallelism": p.parallelism}


def _params_from(o: dict[str, Any]) -> KdfParams:
    return KdfParams(int(o["memory_kib"]), int(o["iterations"]), int(o["parallelism"]))


def _dump(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _parse(data: bytes) -> dict[str, Any]:
    obj = json.loads(data.decode("utf-8"))
    if not isinstance(obj, dict) or obj.get("kind") != PROFILE_KIND:
        raise FormatError("arquivo de perfil inválido")
    if obj.get("version") != PROFILE_VERSION:
        raise FormatError("versão de perfil não suportada")
    if not isinstance(obj.get("profile_id"), str) or not obj["profile_id"]:
        raise FormatError("arquivo de perfil inválido")
    return obj


#: o que torna uma cópia "ilegível" (cai para a outra); erro de acesso NÃO está aqui
_UNREADABLE = (FileNotFoundError, FormatError, ValueError, UnicodeDecodeError, RecursionError)


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return 0


def _pin_failures(o: dict[str, Any]) -> int:
    """Contador de uma cópia; um valor adulterado/ilegível conta como esgotado."""
    try:
        return max(0, int(o.get("pin_failures", 0)))
    except (TypeError, ValueError, OverflowError):
        return MAX_PIN_FAILURES


def _pin_state(obj: dict[str, Any], other: dict[str, Any] | None) -> tuple[Any, int]:
    """(caixa do PIN utilizável ou None, contador efetivo). Efetivo = máximo das cópias; um PIN
    desativado em QUALQUER cópia (ou com o contador esgotado) está desativado."""
    copies = [obj] if other is None else [obj, other]
    failures = max(_pin_failures(c) for c in copies)
    if failures >= MAX_PIN_FAILURES or any(c.get("pin") is None for c in copies):
        return None, failures
    return obj.get("pin"), failures


class ProfileStore:
    """Leitura/gravação do arquivo de perfil (principal + .bak)."""

    def __init__(
        self, directory: Path | None = None, policy: KdfPolicy = PRODUCTION_POLICY
    ) -> None:
        self.dir = directory or default_profile_dir()
        self.path = self.dir / "perfil.owlp"
        self.bak = self.dir / "perfil.owlp.bak"
        self.policy = policy
        #: a última ``read_raw`` precisou da cópia de segurança (principal ausente/ilegível)
        self.last_read_used_backup = False
        #: a última ``write_both`` trocou o principal, mas não o .bak (que ficou com a versão
        #: anterior); a próxima gravação que passar o principal para o .bak desfaz isso
        self.backup_pending = False

    def exists(self) -> bool:
        return self.path.exists() or self.bak.exists()

    # -- leitura
    def _read_bytes(self, path: Path) -> bytes:
        delay = 0.05
        for attempt in range(8):
            try:
                if path.stat().st_size > _MAX_PROFILE_BYTES:
                    raise FormatError("perfil grande demais")
                data = path.read_bytes()
                break
            except PermissionError:  # antivírus/indexador segurando: tentar de novo
                if attempt == 7:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 1.0)
        return data

    def _read_one(self, path: Path) -> dict[str, Any]:
        return _parse(self._read_bytes(path))

    def _read_or_none(self, path: Path) -> dict[str, Any] | None:
        try:
            return self._read_one(path)
        except _UNREADABLE:
            return None

    def _read_copies(self) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """(principal, .bak), cada um None se ausente/ilegível. Erro de acesso sobe."""
        return self._read_or_none(self.path), self._read_or_none(self.bak)

    def _read_pair(self) -> tuple[dict[str, Any], dict[str, Any] | None, bool]:
        """(cópia em uso, a outra cópia do MESMO perfil se legível, usou o .bak?)."""
        primary, backup = self._read_copies()
        if primary is None:
            if backup is None:
                raise ProfileCorruptError("perfil ausente ou ilegível")
            return backup, None, True
        if backup is not None and backup.get("profile_id") != primary["profile_id"]:
            backup = None
        return primary, backup, False

    def read_raw(self) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """(principal ou .bak, a outra cópia se legível). Nunca cai para o .bak por erro de
        acesso — só por arquivo ausente/corrompido (``last_read_used_backup`` diz se caiu)."""
        obj, other, used_backup = self._read_pair()
        self.last_read_used_backup = used_backup
        return obj, other

    # -- gravação
    def _tmp_write(self, name: str, data: bytes) -> Path:
        tmp = self.dir / f"{name}.{secrets.token_hex(8)}.tmp"
        with open(tmp, "xb") as fh:  # "x": nunca reaproveita (nem apaga) um arquivo que existe
            try:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            except BaseException:
                fh.close()
                with contextlib.suppress(OSError):
                    tmp.unlink()
                raise
        return tmp

    def _install(self, tmp: Path, dest: Path) -> None:
        try:
            winfs.retry_on_sharing(lambda: os.replace(tmp, dest))
        finally:
            if tmp.exists():
                with contextlib.suppress(OSError):
                    tmp.unlink()

    def _write_one(self, path: Path, obj: dict[str, Any]) -> None:
        """Grava UMA cópia (tmp + flush + os.replace), sem mexer na outra."""
        self.dir.mkdir(parents=True, exist_ok=True)
        self._install(self._tmp_write(path.name, _dump(obj)), path)

    def write(self, obj: dict[str, Any]) -> None:
        """tmp + flush + os.replace; a versão anterior vira o .bak (só se for legível: um
        principal danificado nunca toma o lugar de um .bak bom).

        Se levantar exceção, o principal NÃO foi trocado (continua a versão anterior)."""
        self._write_primary(_dump(obj))

    def _write_primary(self, data: bytes) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self._tmp_write(self.path.name, data)
        try:
            old: bytes | None
            try:
                old = self._read_bytes(self.path)
                _parse(old)
            except _UNREADABLE:
                old = None
            if old is not None:
                self._install(self._tmp_write(self.bak.name, old), self.bak)
                # o .bak agora tem o principal de antes desta gravação: se ele estava atrasado
                # (``backup_pending``), deixou de estar
                self.backup_pending = False
            self._install(tmp, self.path)
        finally:
            if tmp.exists():
                tmp.unlink()

    def write_both(self, obj: dict[str, Any]) -> bool:
        """Grava o mesmo conteúdo nas DUAS cópias (contador e desativação do PIN, PIN novo,
        senha mestra nova, desbloqueio).

        O .bak recebe os MESMOS bytes já gravados no principal, sem reler o arquivo. Exceção
        aqui = o principal NÃO foi trocado (nada mudou). Depois que o principal foi trocado, a
        mudança valeu (é o principal que o desbloqueio usa) e nada vira erro para quem chamou:
        se o .bak não puder ser trocado, devolve False e marca ``backup_pending`` — o .bak fica
        com a versão anterior até a próxima gravação, que o refaz."""
        data = _dump(obj)
        self._write_primary(data)
        try:
            self._install(self._tmp_write(self.bak.name, data), self.bak)
        except Exception:  # o principal já vale: falha aqui não pode virar "não mudou"
            self.backup_pending = True
            return False
        self.backup_pending = False
        return True

    def _store_counter(
        self,
        obj: dict[str, Any],
        other: dict[str, Any] | None,
        used_backup: bool,
        failures: int,
        *,
        disable: bool = False,
        reset: bool = False,
    ) -> None:
        """Grava o contador do PIN (e a desativação) em CADA cópia legível, preservando o resto
        de cada uma: o índice/cabeçalho de uma cópia nunca vai por cima da outra antes de
        autenticar. Uma cópia ilegível não conta (o efetivo vem da legível) e fica como está
        até um desbloqueio bem-sucedido regravar as duas."""

        def updated(o: dict[str, Any]) -> dict[str, Any]:
            c = dict(o)
            c["pin_failures"] = 0 if reset else max(_pin_failures(o), failures)
            if disable:
                c["pin"] = None
            return c

        if other is not None:
            self._write_one(self.bak, updated(other))
        self._write_one(self.bak if used_backup else self.path, updated(obj))

    # -- criação
    def create(self, master: str, pin: str, *, params: KdfParams | None = None) -> ProfileSession:
        if self.exists():
            raise OwlVaultError("Já existe um perfil do Owl Vault neste computador.")
        validate_master_password(master)
        validate_pin(pin)
        mem = winfs.memory_status()
        avail = mem.available_commit if mem else None
        params = params or calibrate(avail, mem.total_physical if mem else None)
        validate_params(params, self.policy)
        salt = os.urandom(SALT_SIZE)
        kek = derive_kek(master, salt, params, self.policy, avail)
        pk = os.urandom(KEY_SIZE)
        profile_id = secrets.token_hex(16)
        index = Index(keks=[KekEntry(salt, params, kek)])
        today = _dt.date.today()
        obj: dict[str, Any] = {
            "kind": PROFILE_KIND,
            "version": PROFILE_VERSION,
            "profile_id": profile_id,
            "generation": 0,
            "kdf": {"salt": salt.hex(), **_params_obj(params)},
            "wrap_sm": _seal(kek, pk, _aad(profile_id, "sm")),
            "pin": None,
            "pin_failures": 0,
            "practice_due": (today + _dt.timedelta(days=PRACTICE_FIRST_DAYS)).isoformat(),
            "index": None,
        }
        session = ProfileSession(self, obj, pk, index)
        session.set_pin(pin, save=False)
        session._commit(both=True, merge=False)  # já nasce com a cópia de segurança
        return session

    # -- desbloqueio
    def practice_due(self) -> bool:
        obj, _ = self.read_raw()
        try:
            due = _dt.date.fromisoformat(str(obj.get("practice_due", "")))
        except ValueError:
            return True
        return _dt.date.today() >= due

    def pin_available(self) -> bool:
        """Há PIN utilizável? Não, se QUALQUER cópia o desativou ou se o contador efetivo
        (máximo das duas cópias) chegou ao limite — o mesmo critério de ``unlock_with_pin``."""
        obj, other = self.read_raw()
        box, _ = _pin_state(obj, other)
        return box is not None

    def _open_with_master(
        self, master: str, obj: dict[str, Any], other: dict[str, Any] | None
    ) -> tuple[bytes, bool]:
        """PK pelo ``wrap_sm`` do principal ou, se ele não autenticar, pelo do .bak.
        Devolve (PK, veio do .bak?)."""
        mem = winfs.memory_status()
        avail = mem.available_commit if mem else None
        aad = _aad(str(obj["profile_id"]), "sm")
        derived: dict[tuple[bytes, KdfParams], bytes] = {}
        tried = False
        problem: Exception | None = None
        for header in (obj, other):
            if header is None:
                continue
            try:
                kdf = header["kdf"]
                params = _params_from(kdf)
                validate_params(params, self.policy)
                salt = bytes.fromhex(kdf["salt"])
                if len(salt) != SALT_SIZE:
                    raise FormatError("salt do perfil com tamanho inválido")
                box = header["wrap_sm"]
            except (KeyError, TypeError, ValueError, FormatError) as exc:
                problem = exc
                continue
            kek = derived.get((salt, params))
            if kek is None:
                kek = derive_kek(master, salt, params, self.policy, avail)
                derived[(salt, params)] = kek
            tried = True
            try:
                return _open(kek, box, aad), header is not obj
            except AuthenticationError:
                continue
        if not tried:
            raise ProfileCorruptError(_HEADER_CORRUPT) from problem
        raise AuthenticationError("Senha mestra incorreta.")

    def unlock_with_master(self, master: str) -> ProfileSession:
        obj, other, used_backup = self._read_pair()
        pk, header_from_backup = self._open_with_master(master, obj, other)
        session = ProfileSession(self, obj, pk, None)
        if used_backup or header_from_backup:
            session._note_backup()
        session.load_index(fallback=other)  # ProfileCorruptError se nenhuma cópia autenticar
        session._heal_header(other)
        today = _dt.date.today()
        obj["practice_due"] = (today + _dt.timedelta(days=PRACTICE_EVERY_DAYS)).isoformat()
        # a SM devolve as tentativas do PIN (nas DUAS cópias), mas não reativa um PIN
        # desativado: isso só com set_pin
        if _pin_state(obj, other)[0] is None:
            obj["pin"] = None
        obj["pin_failures"] = 0
        session._commit(both=True, merge=False)
        return session

    def unlock_with_pin(self, pin: str) -> ProfileSession:
        obj, other, used_backup = self._read_pair()
        box, failures = _pin_state(obj, other)
        if box is None:
            raise PinUnavailableError("O PIN está desativado. Use a senha mestra.")
        profile_id = str(obj["profile_id"])
        try:
            blob = bytes.fromhex(box["blob"])
            salt = bytes.fromhex(box["salt"])
            params = _params_from(box)
            validate_params(params, self.policy)
            if len(salt) != SALT_SIZE:
                raise FormatError("salt do PIN com tamanho inválido")
        except (KeyError, TypeError, ValueError, FormatError) as exc:
            raise DpapiUnavailableError(_PIN_DAMAGED) from exc
        try:
            inner = dpapi.unprotect(blob, profile_id.encode())
        except AuthenticationError as exc:
            raise DpapiUnavailableError(_DPAPI_GONE) from exc
        # conta a tentativa ANTES de derivar, em cada cópia e sem trocar o resto dela
        attempt = failures + 1
        self._store_counter(obj, other, used_backup, attempt)
        mem = winfs.memory_status()
        kpin = derive_kek(pin, salt, params, self.policy, mem.available_commit if mem else None)
        try:
            pk = _open(kpin, json.loads(inner.decode("ascii")), _aad(profile_id, "pin"))
        except (AuthenticationError, ValueError) as exc:
            remaining = MAX_PIN_FAILURES - attempt
            if remaining <= 0:
                self._store_counter(obj, other, used_backup, attempt, disable=True)
            raise PinError(max(0, remaining)) from exc
        session = ProfileSession(self, obj, pk, None)
        if used_backup:
            session._note_backup()
        try:
            session.load_index(fallback=other)
        except ProfileCorruptError:
            # o PIN estava certo: a tentativa não conta (só o contador é regravado; as cópias
            # danificadas ficam como estão)
            self._store_counter(obj, other, used_backup, 0, reset=True)
            raise
        session._heal_header(other)
        obj["pin_failures"] = 0
        # re-sela o índice que está em memória (autêntico, mesmo vindo do .bak) nas DUAS cópias
        session._commit(both=True, merge=False)
        return session


class ProfileSession:
    """Perfil destravado (PK em memória). ``close()`` descarta as chaves da interface."""

    def __init__(
        self, store: ProfileStore, obj: dict[str, Any], pk: bytes, index: Index | None
    ) -> None:
        self.store = store
        self.obj = obj
        self._pk: bytes | None = pk
        self._index = index
        self.notes: list[str] = []
        #: o desbloqueio precisou da cópia de segurança (índice, cabeçalho ou arquivo inteiro)
        self.used_backup = False
        self._pin_seen: Any = obj.get("pin")  # o PIN que esta sessão sabe estar no disco

    @property
    def profile_id(self) -> str:
        return str(self.obj["profile_id"])

    @property
    def index(self) -> Index:
        if self._index is None:
            raise OwlVaultError("perfil travado")
        return self._index

    def _require_pk(self) -> bytes:
        if self._pk is None:
            raise OwlVaultError("perfil travado")
        return self._pk

    def _note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)

    def _note_backup(self) -> None:
        self.used_backup = True
        self._note(NOTE_BACKUP_USED)

    def load_index(self, fallback: dict[str, Any] | None) -> None:
        """Abre o índice do principal ou, se não autenticar, o do ``fallback`` (.bak).
        Nenhum autentica com a PK certa ⇒ ``ProfileCorruptError`` (nunca "senha incorreta")."""
        pk = self._require_pk()
        aad = _aad(self.profile_id, "index")
        sources = [self.obj]
        if (
            fallback is not None
            and fallback is not self.obj
            and fallback.get("profile_id") == self.profile_id
        ):
            sources.append(fallback)
        for n, src in enumerate(sources):
            try:
                data = _open(pk, src["index"], aad)
                index = Index.from_obj(json.loads(data.decode("utf-8")))
            except (AuthenticationError, AttributeError, KeyError, TypeError, ValueError):
                continue
            self._index = index
            if n:
                self._note_backup()
            return
        raise ProfileCorruptError(_INDEX_CORRUPT)

    def _heal_header(self, other: dict[str, Any] | None) -> None:
        """Garante que ``kdf``/``wrap_sm`` abrem com a KEK atual do índice (autenticado) antes
        de gravar as duas cópias: usa o cabeçalho do .bak se só ele estiver bom, ou refaz o
        ``wrap_sm`` quando o ``kdf`` confere. Assim um cabeçalho danificado nunca se espalha."""
        pk = self._require_pk()
        if not self.index.keks:
            return
        k = self.index.keks[0]
        aad = _aad(self.profile_id, "sm")

        def kdf_ok(h: dict[str, Any]) -> bool:
            try:
                kdf = h["kdf"]
                return bytes.fromhex(kdf["salt"]) == k.salt and _params_from(kdf) == k.params
            except (KeyError, TypeError, ValueError):
                return False

        def good(h: dict[str, Any]) -> bool:
            if not kdf_ok(h):
                return False
            try:
                return _open(k.kek, h["wrap_sm"], aad) == pk
            except (AuthenticationError, KeyError, TypeError):
                return False

        if good(self.obj):
            return
        if other is not None and other.get("profile_id") == self.profile_id and good(other):
            self.obj["kdf"] = dict(other["kdf"])
            self.obj["wrap_sm"] = dict(other["wrap_sm"])
            self._note_backup()
            return
        if kdf_ok(self.obj):
            self.obj["wrap_sm"] = _seal(k.kek, pk, aad)
            self._note(NOTE_MASTER_REBUILT)

    def key_source(self) -> KeySource:
        k = self.index.keks[0]
        return KeySource(salt=k.salt, params=k.params, kek=k.kek)

    def key_sources(self) -> list[KeySource]:
        return [KeySource(salt=k.salt, params=k.params, kek=k.kek) for k in self.index.keks]

    def _merge_pin_state(self, disk: list[dict[str, Any]]) -> None:
        """Uma sessão antiga nunca reativa um PIN desativado, nem zera o contador, nem desfaz um
        PIN trocado por outra sessão: nesses campos o disco manda (contador = máximo)."""
        if not disk:
            return
        failures = max([_pin_failures(self.obj)] + [_pin_failures(c) for c in disk])
        if any(c.get("pin") is None for c in disk):
            self.obj["pin"] = None
        else:
            current = disk[0].get("pin")
            if current != self._pin_seen and self.obj.get("pin") == self._pin_seen:
                # outra sessão criou um PIN novo: vale o do disco, com o contador dele
                self.obj["pin"] = current
                failures = max(_pin_failures(c) for c in disk if c.get("pin") == current)
        self.obj["pin_failures"] = failures

    def _commit(self, *, both: bool, merge: bool) -> None:
        pk = self._require_pk()
        index = self.index
        primary, backup = self.store._read_copies()
        disk = [
            c for c in (primary, backup) if c is not None and c.get("profile_id") == self.profile_id
        ]
        if merge:
            self._merge_pin_state(disk)
        generations = [_as_int(self.obj.get("generation"))]
        generations += [_as_int(c.get("generation")) for c in disk]
        self.obj["generation"] = max(generations) + 1
        payload = json.dumps(index.to_obj(), ensure_ascii=False).encode("utf-8")
        self.obj["index"] = _seal(pk, payload, _aad(self.profile_id, "index"))
        if both:
            self.store.write_both(self.obj)
        else:
            self.store.write(self.obj)
        self._pin_seen = self.obj.get("pin")
        if self.store.backup_pending:
            self._note(NOTE_BACKUP_PENDING)
        elif NOTE_BACKUP_PENDING in self.notes:
            self.notes.remove(NOTE_BACKUP_PENDING)

    def _snapshot(self) -> tuple[dict[str, Any], list[tuple[KekEntry, str]]]:
        keks = self._index.keks if self._index is not None else []
        return copy.deepcopy(self.obj), [(k, k.origin) for k in keks]

    def _rollback(self, snap: tuple[dict[str, Any], list[tuple[KekEntry, str]]]) -> None:
        """Volta a memória ao estado de antes de uma troca de PIN/senha mestra que NÃO foi
        gravada: a sessão nunca pode gravar depois, por outro caminho (``save``), uma mudança
        que a interface disse que falhou."""
        obj, keks = snap
        self.obj.clear()
        self.obj.update(obj)
        if self._index is not None:
            for k, origin in keks:
                k.origin = origin
            self._index.keks[:] = [k for k, _ in keks]

    def save(self) -> None:
        """Re-sela o índice e grava (a versão anterior vira o .bak). Relê o disco antes: o
        contador do PIN fica no máximo (memória, principal, .bak) e um PIN desativado no
        disco continua desativado."""
        self._commit(both=False, merge=True)

    def set_pin(self, pin: str, *, save: bool = True) -> None:
        validate_pin(pin)
        pk = self._require_pk()
        mem = winfs.memory_status()
        params = self.index.keks[0].params
        salt = os.urandom(SALT_SIZE)
        kpin = derive_kek(
            pin, salt, params, self.store.policy, mem.available_commit if mem else None
        )
        box = _seal(kpin, pk, _aad(self.profile_id, "pin"))
        blob = dpapi.protect(json.dumps(box).encode("ascii"), self.profile_id.encode())
        snap = self._snapshot()
        self.obj["pin"] = {"salt": salt.hex(), **_params_obj(params), "blob": blob.hex()}
        self.obj["pin_failures"] = 0
        if save:
            # PIN novo e contador zerado DE PROPÓSITO, nas duas cópias (o PIN antigo não pode
            # continuar valendo no .bak). Exceção = nada foi gravado: a memória volta ao PIN
            # antigo. Sem exceção = o PIN novo vale (mesmo que o .bak tenha ficado para depois:
            # ``NOTE_BACKUP_PENDING``).
            try:
                self._commit(both=True, merge=False)
            except BaseException:
                self._rollback(snap)
                raise

    def change_master(self, new_master: str) -> None:
        """Cria uma senha mestra nova (a antiga continua guardada no índice para abrir os
        cofres ainda não re-trancados).

        Exceção = nada foi gravado e a sessão continua com a senha mestra antiga (as próximas
        trancagens não usam a nova). Sem exceção = a senha nova vale."""
        validate_master_password(new_master)
        pk = self._require_pk()
        mem = winfs.memory_status()
        avail = mem.available_commit if mem else None
        params = calibrate(avail, mem.total_physical if mem else None)
        salt = os.urandom(SALT_SIZE)
        kek = derive_kek(new_master, salt, params, self.store.policy, avail)
        snap = self._snapshot()
        try:
            for old in self.index.keks:
                if old.origin == KEK_PERFIL:
                    old.origin = KEK_TROCADA
            self.index.keks.insert(0, KekEntry(salt, params, kek, KEK_PERFIL))
            self.obj["kdf"] = {"salt": salt.hex(), **_params_obj(params)}
            self.obj["wrap_sm"] = _seal(kek, pk, _aad(self.profile_id, "sm"))
            self._commit(both=True, merge=True)
        except BaseException:
            self._rollback(snap)
            raise

    def close(self) -> None:
        self._pk = None
        self._index = None
