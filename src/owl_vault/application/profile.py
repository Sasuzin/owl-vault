"""Perfil das pastas protegidas: senha mestra, PIN (DPAPI) e índice cifrado.

PASTAS_PROTEGIDAS.md §2. Arquivo ``%LOCALAPPDATA%\\Owl Vault\\perfil.owlp`` (+ ``.bak``):
JSON em claro com partes cifradas (AES-256-GCM):

* ``kdf``: salt/params do Argon2id da senha mestra (SM). KEK_SM = Argon2id(SM, salt, params).
  Todos os cofres das pastas usam esse salt/params ⇒ abrem só com a SM em qualquer PC.
* ``wrap_sm`` = AES-GCM(KEK_SM, PK): caminho da senha mestra.
* ``pin.blob`` = DPAPI_usuário(AES-GCM(Argon2id(PIN), PK)): caminho do PIN. O PIN dá acesso
  à PK (e por ela à KEK_SM guardada no índice), **nunca à senha mestra**.
* ``index`` = AES-GCM(PK, JSON do índice): KEKs e a lista de pastas (caminhos, estados...).
"""

from __future__ import annotations

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
    """O Windows não consegue mais decifrar o PIN (reinstalação/senha redefinida)."""


def default_profile_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "Owl Vault"


# --- validações ------------------------------------------------------------------------


def validate_pin(pin: str) -> None:
    """6 a 12 dígitos; recusa repetidos, sequências e datas óbvias."""
    if not re.fullmatch(r"[0-9]{6,12}", pin or ""):
        raise OwlVaultError("O PIN deve ter de 6 a 12 números.")
    if len(set(pin)) == 1:
        raise OwlVaultError("Este PIN é fácil de adivinhar. Escolha outro.")
    digits = [int(c) for c in pin]
    steps = {b - a for a, b in itertools.pairwise(digits)}
    if steps in ({1}, {-1}):
        raise OwlVaultError("Este PIN é fácil de adivinhar. Escolha outro.")
    if _looks_like_date(pin):
        raise OwlVaultError("Não use datas como PIN. Escolha outro.")


def _looks_like_date(pin: str) -> bool:
    candidates = []
    if len(pin) == 6:
        candidates = [("%d%m%y", pin), ("%y%m%d", pin)]
    elif len(pin) == 8:
        candidates = [("%d%m%Y", pin), ("%Y%m%d", pin)]
    for fmt, text in candidates:
        try:
            _dt.datetime.strptime(text, fmt)
            return True
        except ValueError:
            continue
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


@dataclass
class KekEntry:
    salt: bytes
    params: KdfParams
    kek: bytes = field(repr=False)


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
            )
            for k in o["keks"]
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
    except (InvalidTag, KeyError, ValueError) as exc:
        raise AuthenticationError("perfil: falha de autenticação") from exc


def _params_obj(p: KdfParams) -> dict[str, int]:
    return {"memory_kib": p.memory_kib, "iterations": p.iterations, "parallelism": p.parallelism}


def _params_from(o: dict[str, Any]) -> KdfParams:
    return KdfParams(int(o["memory_kib"]), int(o["iterations"]), int(o["parallelism"]))


class ProfileStore:
    """Leitura/gravação do arquivo de perfil (principal + .bak)."""

    def __init__(
        self, directory: Path | None = None, policy: KdfPolicy = PRODUCTION_POLICY
    ) -> None:
        self.dir = directory or default_profile_dir()
        self.path = self.dir / "perfil.owlp"
        self.bak = self.dir / "perfil.owlp.bak"
        self.policy = policy

    def exists(self) -> bool:
        return self.path.exists() or self.bak.exists()

    # -- leitura
    def _read_one(self, path: Path) -> dict[str, Any]:
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
        obj = json.loads(data.decode("utf-8"))
        if not isinstance(obj, dict) or obj.get("kind") != PROFILE_KIND:
            raise FormatError("arquivo de perfil inválido")
        if obj.get("version") != PROFILE_VERSION:
            raise FormatError("versão de perfil não suportada")
        return obj

    def read_raw(self) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """(principal ou .bak, a outra cópia se legível). Nunca cai para o .bak por erro de
        acesso — só por arquivo ausente/corrompido."""
        primary: dict[str, Any] | None = None
        backup: dict[str, Any] | None = None
        try:
            primary = self._read_one(self.path)
        except FileNotFoundError:
            primary = None
        except (FormatError, ValueError, UnicodeDecodeError):
            primary = None
        try:
            backup = self._read_one(self.bak)
        except (FileNotFoundError, FormatError, ValueError, UnicodeDecodeError):
            backup = None
        if primary is None and backup is None:
            raise FormatError("perfil ausente ou ilegível")
        if primary is None:
            assert backup is not None
            return backup, None
        return primary, backup

    # -- gravação
    def write(self, obj: dict[str, Any]) -> None:
        """tmp + flush + os.replace; a versão anterior vira o .bak."""
        self.dir.mkdir(parents=True, exist_ok=True)
        data = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        tmp = self.dir / f"perfil.owlp.{secrets.token_hex(8)}.tmp"
        with open(tmp, "xb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            if self.path.exists():
                old = self.path.read_bytes()
                btmp = self.dir / f"perfil.owlp.bak.{secrets.token_hex(8)}.tmp"
                with open(btmp, "xb") as fh:
                    fh.write(old)
                    fh.flush()
                    os.fsync(fh.fileno())
                winfs.retry_on_sharing(lambda: os.replace(btmp, self.bak))
            winfs.retry_on_sharing(lambda: os.replace(tmp, self.path))
        finally:
            if tmp.exists():
                tmp.unlink()

    def write_both(self, obj: dict[str, Any]) -> None:
        """Grava o mesmo conteúdo nas DUAS cópias (contador de PIN, desativação do PIN)."""
        self.write(obj)
        data = self.path.read_bytes()
        btmp = self.dir / f"perfil.owlp.bak.{secrets.token_hex(8)}.tmp"
        with open(btmp, "xb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        winfs.retry_on_sharing(lambda: os.replace(btmp, self.bak))

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
        session.save()
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
        obj, _ = self.read_raw()
        return obj.get("pin") is not None

    def unlock_with_master(self, master: str) -> ProfileSession:
        obj, other = self.read_raw()
        mem = winfs.memory_status()
        avail = mem.available_commit if mem else None
        kdf = obj["kdf"]
        params = _params_from(kdf)
        validate_params(params, self.policy)
        salt = bytes.fromhex(kdf["salt"])
        kek = derive_kek(master, salt, params, self.policy, avail)
        try:
            pk = _open(kek, obj["wrap_sm"], _aad(obj["profile_id"], "sm"))
        except AuthenticationError as exc:
            raise AuthenticationError("Senha mestra incorreta.") from exc
        session = ProfileSession(self, obj, pk, None)
        session.load_index(fallback=other)
        today = _dt.date.today()
        obj["practice_due"] = (today + _dt.timedelta(days=PRACTICE_EVERY_DAYS)).isoformat()
        obj["pin_failures"] = 0
        session.save()
        return session

    def unlock_with_pin(self, pin: str) -> ProfileSession:
        obj, other = self.read_raw()
        failures = max(int(obj.get("pin_failures", 0)), int((other or {}).get("pin_failures", 0)))
        pin_box = obj.get("pin")
        if pin_box is None or failures >= MAX_PIN_FAILURES:
            raise PinUnavailableError("O PIN está desativado. Use a senha mestra.")
        try:
            inner = dpapi.unprotect(bytes.fromhex(pin_box["blob"]), obj["profile_id"].encode())
        except AuthenticationError as exc:
            raise DpapiUnavailableError(
                "O Windows não consegue mais usar o PIN deste computador (a senha do Windows foi "
                "redefinida ou o Windows foi reinstalado). Digite sua senha mestra."
            ) from exc
        # conta a tentativa ANTES de derivar (nas duas cópias)
        obj["pin_failures"] = failures + 1
        self.write_both(obj)
        mem = winfs.memory_status()
        params = _params_from(pin_box)
        validate_params(params, self.policy)
        kpin = derive_kek(
            pin,
            bytes.fromhex(pin_box["salt"]),
            params,
            self.policy,
            mem.available_commit if mem else None,
        )
        try:
            box = json.loads(inner.decode("ascii"))
            pk = _open(kpin, box, _aad(obj["profile_id"], "pin"))
        except (AuthenticationError, ValueError) as exc:
            remaining = MAX_PIN_FAILURES - (failures + 1)
            if remaining <= 0:
                obj["pin"] = None
                self.write_both(obj)
            raise PinError(max(0, remaining)) from exc
        obj["pin_failures"] = 0
        session = ProfileSession(self, obj, pk, None)
        session.load_index(fallback=other)
        self.write_both(obj)
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

    def load_index(self, fallback: dict[str, Any] | None) -> None:
        pk = self._require_pk()
        try:
            data = _open(pk, self.obj["index"], _aad(self.profile_id, "index"))
        except (AuthenticationError, TypeError) as exc:
            if fallback is None or fallback.get("profile_id") != self.profile_id:
                raise AuthenticationError("o índice do perfil está corrompido") from exc
            data = _open(pk, fallback["index"], _aad(self.profile_id, "index"))
            self.notes.append(
                "O arquivo principal do perfil estava danificado; foi usada a cópia de segurança."
            )
        self._index = Index.from_obj(json.loads(data.decode("utf-8")))

    def key_source(self) -> KeySource:
        k = self.index.keks[0]
        return KeySource(salt=k.salt, params=k.params, kek=k.kek)

    def key_sources(self) -> list[KeySource]:
        return [KeySource(salt=k.salt, params=k.params, kek=k.kek) for k in self.index.keks]

    def save(self) -> None:
        pk = self._require_pk()
        self.obj["generation"] = int(self.obj.get("generation", 0)) + 1
        payload = json.dumps(self.index.to_obj(), ensure_ascii=False).encode("utf-8")
        self.obj["index"] = _seal(pk, payload, _aad(self.profile_id, "index"))
        self.store.write(self.obj)

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
        self.obj["pin"] = {"salt": salt.hex(), **_params_obj(params), "blob": blob.hex()}
        self.obj["pin_failures"] = 0
        if save:
            self.save()
            # o PIN antigo não pode continuar valendo no .bak
            self.store.write_both(self.obj)

    def change_master(self, new_master: str) -> None:
        """Cria uma senha mestra nova (a antiga continua guardada no índice para abrir os
        cofres ainda não re-trancados)."""
        validate_master_password(new_master)
        pk = self._require_pk()
        mem = winfs.memory_status()
        avail = mem.available_commit if mem else None
        params = calibrate(avail, mem.total_physical if mem else None)
        salt = os.urandom(SALT_SIZE)
        kek = derive_kek(new_master, salt, params, self.store.policy, avail)
        self.index.keks.insert(0, KekEntry(salt, params, kek))
        self.obj["kdf"] = {"salt": salt.hex(), **_params_obj(params)}
        self.obj["wrap_sm"] = _seal(kek, pk, _aad(self.profile_id, "sm"))
        self.save()
        self.store.write_both(self.obj)

    def close(self) -> None:
        self._pk = None
        self._index = None
