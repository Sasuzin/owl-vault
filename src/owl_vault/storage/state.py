"""``state.json`` — dica NÃO sensível para a UI (FORMAT §6). Sem papel de segurança."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from owl_vault import APP_NAME
from owl_vault.domain.limits import FORMAT_VERSION
from owl_vault.storage import winfs
from owl_vault.storage.atomic import replace_small_file


@dataclass(frozen=True, slots=True)
class StateHint:
    vault_id_hex: str
    phase: str
    files_total: int
    files_done: int
    test_dir_name: str


def write_state(path: str, hint: StateHint) -> None:
    obj = {
        "app": APP_NAME,
        "format_version": FORMAT_VERSION,
        "vault_id": hint.vault_id_hex,
        "phase": hint.phase,
        "files_total": hint.files_total,
        "files_done": hint.files_done,
        "test_dir_name": hint.test_dir_name,
    }
    try:
        replace_small_file(path, json.dumps(obj, ensure_ascii=True, indent=1).encode("ascii"))
    except OSError:
        pass  # melhor esforço


def read_state(path: str) -> dict[str, Any] | None:
    if not winfs.is_plain_file_at(path):  # nunca seguir links
        return None
    try:
        with open(path, "rb") as fh:
            data = fh.read(64 * 1024)
        obj = json.loads(data.decode("ascii"))
    except (OSError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None
