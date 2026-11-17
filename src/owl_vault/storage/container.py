"""Contêineres cifrados (manifesto, diário, conclusão) e JSON estrito (FORMAT §5)."""

from __future__ import annotations

import json
import os
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from owl_vault.crypto.keys import KeyPurpose, derive_subkey
from owl_vault.domain.errors import AuthenticationError, FormatError, LimitError
from owl_vault.domain.limits import (
    CONTAINER_HEADER_SIZE,
    FORMAT_VERSION,
    ID_SIZE,
    MAX_COMPLETION_PLAINTEXT,
    MAX_JOURNAL_SEGMENT_PLAINTEXT,
    MAX_MANIFEST_PLAINTEXT,
    NONCE_SIZE,
    TAG_SIZE,
)
from owl_vault.storage import winfs
from owl_vault.storage.atomic import write_new_no_replace

_HDR = struct.Struct(">8sHHI16s16s12sI")
assert _HDR.size == CONTAINER_HEADER_SIZE
_HEX_RE = re.compile(r"[0-9a-f]+")


class ContainerKind(Enum):
    MANIFEST = (b"OWLVMANI", KeyPurpose.MANIFEST, "manifest", MAX_MANIFEST_PLAINTEXT)
    JOURNAL = (b"OWLVJRNL", KeyPurpose.JOURNAL, "journal", MAX_JOURNAL_SEGMENT_PLAINTEXT)
    COMPLETE = (b"OWLVDONE", KeyPurpose.COMPLETE, "completion", MAX_COMPLETION_PLAINTEXT)

    @property
    def magic(self) -> bytes:
        return self.value[0]

    @property
    def purpose(self) -> KeyPurpose:
        return self.value[1]

    @property
    def json_kind(self) -> str:
        return self.value[2]

    @property
    def max_plaintext(self) -> int:
        return self.value[3]

    @property
    def max_file_size(self) -> int:
        return CONTAINER_HEADER_SIZE + self.max_plaintext + TAG_SIZE


# --- JSON canônico e estrito ------------------------------------------------------------


def canonical_json(obj: Any) -> bytes:
    """Único serializador do formato (o estimador de tamanho usa o mesmo)."""
    return json.dumps(
        obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False, sort_keys=True
    ).encode("utf-8")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise FormatError("JSON com chave duplicada")
        out[k] = v
    return out


def _reject_constant(name: str) -> Any:
    raise FormatError(f"JSON com constante não permitida ({name})")


def strict_json_loads(data: bytes) -> Any:
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise FormatError("JSON não é UTF-8 válido") from exc
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise FormatError("JSON malformado") from exc


# --- helpers de esquema -----------------------------------------------------------------


def require_object(
    obj: Any, required: set[str], optional: frozenset[str] = frozenset()
) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise FormatError("esperado um objeto JSON")
    keys = set(obj)
    missing = required - keys
    if missing:
        raise FormatError(f"campos ausentes: {', '.join(sorted(missing))}")
    extra = keys - required - set(optional)
    if extra:
        raise FormatError(f"campos desconhecidos: {', '.join(sorted(extra))}")
    return obj


def get_int(obj: dict[str, Any], key: str, lo: int, hi: int) -> int:
    v = obj[key]
    if isinstance(v, bool) or not isinstance(v, int):
        raise FormatError(f"campo '{key}' deve ser inteiro")
    if not lo <= v <= hi:
        raise LimitError(f"campo '{key}' fora dos limites")
    return v


def get_str(obj: dict[str, Any], key: str, max_len: int = 4096) -> str:
    v = obj[key]
    if not isinstance(v, str):
        raise FormatError(f"campo '{key}' deve ser texto")
    if len(v) > max_len:
        raise LimitError(f"campo '{key}' longo demais")
    return v


def get_hex(obj: dict[str, Any], key: str, nbytes: int) -> bytes:
    v = obj[key]
    if not isinstance(v, str) or len(v) != nbytes * 2:
        raise FormatError(f"campo '{key}' deve ser hex de {nbytes} bytes")
    if _HEX_RE.fullmatch(v) is None:  # bytes.fromhex ignoraria espaços: checagem estrita
        raise FormatError(f"campo '{key}' deve ser hex minúsculo (0-9a-f)")
    out = bytes.fromhex(v)
    if len(out) != nbytes:  # defesa em profundidade
        raise FormatError(f"campo '{key}' com tamanho inválido")
    return out


def get_list(obj: dict[str, Any], key: str, max_len: int) -> list[Any]:
    v = obj[key]
    if not isinstance(v, list):
        raise FormatError(f"campo '{key}' deve ser lista")
    if len(v) > max_len:
        raise LimitError(f"campo '{key}' com itens demais")
    return v


# --- contêiner --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ContainerRead:
    obj: Any
    raw: bytes  # bytes exatos do arquivo


def seal(kind: ContainerKind, master_key: bytes, vault_id: bytes, obj: Any) -> bytes:
    plaintext = canonical_json(obj)
    if len(plaintext) > kind.max_plaintext:
        raise LimitError(f"{kind.json_kind}: conteúdo excede o limite do formato")
    key_id = os.urandom(ID_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = _HDR.pack(
        kind.magic, FORMAT_VERSION, CONTAINER_HEADER_SIZE, 0, vault_id, key_id, nonce, 0
    )
    key = derive_subkey(master_key, vault_id, kind.purpose, key_id)
    return header + AESGCM(key).encrypt(nonce, plaintext, header)


def parse_container_header(data: bytes, kind: ContainerKind) -> tuple[bytes, bytes, bytes]:
    """Retorna (vault_id, key_id, nonce) após validação estrita do cabeçalho em claro."""
    if len(data) < CONTAINER_HEADER_SIZE + TAG_SIZE:
        raise FormatError(f"{kind.json_kind}: arquivo curto demais")
    if len(data) > kind.max_file_size:
        raise LimitError(f"{kind.json_kind}: arquivo grande demais")
    magic, version, hsize, flags, vault_id, key_id, nonce, reserved = _HDR.unpack_from(data, 0)
    if magic != kind.magic:
        raise FormatError(f"{kind.json_kind}: assinatura inválida")
    if version != FORMAT_VERSION:
        raise FormatError(f"{kind.json_kind}: versão não suportada")
    if hsize != CONTAINER_HEADER_SIZE or flags != 0 or reserved != 0:
        raise FormatError(f"{kind.json_kind}: campos reservados inválidos")
    return vault_id, key_id, nonce


def open_sealed(kind: ContainerKind, master_key: bytes, vault_id: bytes, data: bytes) -> Any:
    found_vault, key_id, nonce = parse_container_header(data, kind)
    if found_vault != vault_id:
        raise FormatError(f"{kind.json_kind}: pertence a outro cofre")
    key = derive_subkey(master_key, vault_id, kind.purpose, key_id)
    header = data[:CONTAINER_HEADER_SIZE]
    try:
        plaintext = AESGCM(key).decrypt(nonce, data[CONTAINER_HEADER_SIZE:], header)
    except InvalidTag as exc:
        raise AuthenticationError(f"{kind.json_kind}: falha de autenticação (corrompido)") from exc
    obj = strict_json_loads(plaintext)
    if not isinstance(obj, dict) or obj.get("kind") != kind.json_kind:
        raise FormatError(f"{kind.json_kind}: tipo de conteúdo inesperado")
    return obj


def read_file_bounded(
    path: str, max_size: int, reader: Callable[[str], bytes] | None = None
) -> bytes:
    """Lê um arquivo pequeno do cofre, recusando-o se exceder ``max_size`` (antes de ler)."""
    st = os.lstat(path)
    if not winfs.is_plain_file(st):
        raise FormatError("arquivo do cofre não é um arquivo regular")
    if st.st_size > max_size:
        raise LimitError("arquivo do cofre maior que o permitido")
    if reader is not None:
        return reader(path)
    with open(path, "rb") as fh:
        data = fh.read(max_size + 1)
    if len(data) > max_size:
        raise LimitError("arquivo do cofre maior que o permitido")
    return data


def write_container(
    path: str, kind: ContainerKind, master_key: bytes, vault_id: bytes, obj: Any, op: str
) -> bytes:
    raw = seal(kind, master_key, vault_id, obj)
    write_new_no_replace(path, raw, op=op)
    return raw


def read_container(
    path: str,
    kind: ContainerKind,
    master_key: bytes,
    vault_id: bytes,
    reader: Callable[[str], bytes] | None = None,
) -> ContainerRead:
    raw = read_file_bounded(path, kind.max_file_size, reader)
    return ContainerRead(open_sealed(kind, master_key, vault_id, raw), raw)
