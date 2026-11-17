"""Utilidades compartilhadas pelos casos de uso."""

from __future__ import annotations

import datetime as _dt
import os
import unicodedata
from dataclasses import dataclass

from owl_vault.domain.errors import OwlVaultError
from owl_vault.domain.limits import MIN_PASSWORD_LENGTH
from owl_vault.storage import winfs


def now_utc_iso() -> str:
    return _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def local_snapshot_label() -> str:
    return _dt.datetime.now().strftime("%d/%m/%Y %H:%M")


def default_vault_name() -> str:
    """Nome genérico (não usa o nome da pasta de origem)."""
    return _dt.datetime.now().strftime("Cofre-%Y%m%d-%H%M")


def validate_new_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise OwlVaultError(f"A senha deve ter pelo menos {MIN_PASSWORD_LENGTH} caracteres.")
    if password.strip() != password:
        raise OwlVaultError("A senha não pode começar nem terminar com espaço.")
    # caracteres invisíveis/de controle (BOM, U+FFFD de decodificação errada...) quase sempre
    # indicam que a senha foi alterada no caminho (ex.: entrada redirecionada no terminal)
    for ch in password:
        if ch == "�" or unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co"):
            raise OwlVaultError(
                "A senha contém caracteres invisíveis ou inválidos (possível problema de "
                "codificação do terminal). Digite-a novamente."
            )


@dataclass(frozen=True, slots=True)
class Strength:
    score: int  # 0..4
    label: str


def password_strength(password: str) -> Strength:
    """Estimativa simples (sem dicionário). Só orienta; não é garantia."""
    if not password:
        return Strength(0, "vazia")
    classes = sum(
        [
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ]
    )
    length = len(password)
    unique = len(set(password))
    score = 0
    if length >= MIN_PASSWORD_LENGTH:
        score = 1
    if length >= 14 and classes >= 2:
        score = 2
    if length >= 16 and classes >= 3:
        score = 3
    if length >= 20 and classes >= 3 and unique >= 10:
        score = 4
    if unique <= 3:
        score = 0
    labels = ["muito fraca", "fraca", "razoável", "boa", "forte"]
    return Strength(score, labels[score])


def read_zone_id(path: str) -> int | None:
    """Lê o ZoneId do Mark-of-the-Web (fluxo ``Zone.Identifier``), se existir."""
    try:
        with open(path + ":Zone.Identifier", "rb") as fh:
            data = fh.read(4096)
    except OSError:
        return None
    for line in data.decode("latin-1", "replace").splitlines():
        key, _, value = line.partition("=")
        if key.strip().lower() == "zoneid":
            try:
                return int(value.strip())
            except ValueError:
                return None
    return None


FILE_NAMED_STREAMS = 0x00040000

MOTW_PAYLOAD = b"[ZoneTransfer]\r\nZoneId=3\r\n"


def write_motw(path: str) -> None:
    """Grava o fluxo ``Zone.Identifier`` enquanto o handle do ``.part`` (com DELETE) está
    aberto: por isso o compartilhamento precisa incluir FILE_SHARE_DELETE."""
    with winfs.Win32File.open(
        path + ":Zone.Identifier",
        winfs.GENERIC_WRITE,
        winfs.FILE_SHARE_READ | winfs.FILE_SHARE_WRITE | winfs.FILE_SHARE_DELETE,
        winfs.CREATE_ALWAYS,
        winfs.FILE_ATTRIBUTE_NORMAL,
    ) as f:
        f.write(MOTW_PAYLOAD)
        f.flush()


def max_zone_id(paths: list[str]) -> int | None:
    zones = [z for z in (read_zone_id(p) for p in paths) if z is not None]
    return max(zones) if zones else None


def round_up(value: int, unit: int) -> int:
    if unit <= 0:
        return value
    return -(-value // unit) * unit


def display(path: str) -> str:
    return winfs.strip_extended(path)


def env_path(name: str) -> str | None:
    v = os.environ.get(name)
    return v if v else None
