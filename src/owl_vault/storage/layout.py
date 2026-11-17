"""Layout de diretório do cofre (FORMAT §1)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from owl_vault.storage import winfs

HEADER_NAME = "vault.owl"
HEADER_BAK_NAME = "vault.owl.bak"
MANIFEST_NAME = "manifest.owl"
MANIFEST_BAK_NAME = "manifest.owl.bak"
COMPLETE_NAME = "complete.owl"
JOURNAL_DIR = "journal"
DATA_DIR = "data"
STATE_NAME = "state.json"
README_NAME = "LEIA-ME.txt"
LOCK_NAME = ".owlvault.lock"

BLOB_RE = re.compile(r"[0-9a-f]{32}\.owlb")
BLOB_TMP_RE = re.compile(r"[0-9a-f]{32}\.tmp")
DATA_FILE_RE = re.compile(r"[0-9a-f]{32}\.(?:tmp|owlb)")
HH_RE = re.compile(r"[0-9a-f]{2}")
SEGMENT_RE = re.compile(r"[0-9a-f]{16}\.owlj")
ROOT_TMP_RE = re.compile(
    r"(?:vault\.owl|vault\.owl\.bak|manifest\.owl|manifest\.owl\.bak|complete\.owl|"
    r"state\.json|LEIA-ME\.txt)\.[0-9a-f]{32}\.tmp"
)
SEGMENT_TMP_RE = re.compile(r"[0-9a-f]{16}\.owlj\.[0-9a-f]{32}\.tmp")
PROBE_RE = re.compile(r"\.owlvault-probe-[0-9a-f]{32}\.tmp")
CHK_RE = re.compile(r"[0-9a-f]{32}\.chk")
TEST_PART_RE = re.compile(r"\.owl-test-[0-9a-f]{32}\.part")
TEST_DIR_RE = re.compile(r"OwlVault-teste-[0-9a-f]{32}")

KNOWN_ROOT_NAMES = frozenset(
    [
        HEADER_NAME,
        HEADER_BAK_NAME,
        MANIFEST_NAME,
        MANIFEST_BAK_NAME,
        COMPLETE_NAME,
        JOURNAL_DIR,
        DATA_DIR,
        STATE_NAME,
        README_NAME,
        LOCK_NAME,
    ]
)


@dataclass(frozen=True, slots=True)
class VaultLayout:
    root: str  # caminho estendido (\\?\...)

    @property
    def header(self) -> str:
        return winfs.join(self.root, HEADER_NAME)

    @property
    def header_bak(self) -> str:
        return winfs.join(self.root, HEADER_BAK_NAME)

    @property
    def manifest(self) -> str:
        return winfs.join(self.root, MANIFEST_NAME)

    @property
    def manifest_bak(self) -> str:
        return winfs.join(self.root, MANIFEST_BAK_NAME)

    @property
    def complete(self) -> str:
        return winfs.join(self.root, COMPLETE_NAME)

    @property
    def journal_dir(self) -> str:
        return winfs.join(self.root, JOURNAL_DIR)

    @property
    def data_dir(self) -> str:
        return winfs.join(self.root, DATA_DIR)

    @property
    def state(self) -> str:
        return winfs.join(self.root, STATE_NAME)

    @property
    def readme(self) -> str:
        return winfs.join(self.root, README_NAME)

    @property
    def lock(self) -> str:
        return winfs.join(self.root, LOCK_NAME)

    def segment(self, seq: int) -> str:
        return winfs.join(self.journal_dir, f"{seq:016x}.owlj")

    def blob_dir(self, file_id: bytes) -> str:
        return winfs.join(self.data_dir, file_id.hex()[:2])

    def blob(self, file_id: bytes) -> str:
        return winfs.join(self.blob_dir(file_id), f"{file_id.hex()}.owlb")

    def blob_tmp(self, file_id: bytes) -> str:
        return winfs.join(self.blob_dir(file_id), f"{file_id.hex()}.tmp")


README_TEXT = """Owl Vault — cofre criptografado
================================

Esta pasta é um cofre do Owl Vault: uma cópia criptografada (AES-256-GCM, chave derivada
da senha com Argon2id) de uma pasta. Sem a senha não é possível ler o conteúdo nem os
nomes dos arquivos.

* Não altere, renomeie nem apague arquivos desta pasta.
* Para conferir a integridade: Owl Vault > Verificar cofre.
* Para recuperar os arquivos: Owl Vault > Restaurar (para uma pasta nova e vazia).
* Se a senha for perdida, NÃO há como recuperar os dados.
* Guarde mais de uma cópia deste cofre (ex.: outro disco) e mantenha backups.
"""
