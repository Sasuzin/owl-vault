"""Carimba a versão do build (rodado por packaging\\build.ps1 antes do PyInstaller).

Fonte única da versão: ``__version__`` em ``src/owl_vault/__init__.py`` (sobe a cada ajuste,
com uma entrada no CHANGELOG.md). Este script acrescenta o número do build — a quantidade de
commits do repositório, que cresce sozinho a cada ajuste — e o commit, e gera:

* ``src/owl_vault/_build.py`` — lido pela interface ("Sobre", rodapé, título);
* ``packaging/version_info.txt`` — propriedades do ``OwlVault.exe`` no Explorer
  (Versão do arquivo = 0.3.0.<build>).

Os dois arquivos são gerados (não versionados).
"""

from __future__ import annotations

import datetime as _dt
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INIT = ROOT / "src" / "owl_vault" / "__init__.py"
BUILD_PY = ROOT / "src" / "owl_vault" / "_build.py"
VERSION_INFO = ROOT / "packaging" / "version_info.txt"


def read_version() -> str:
    m = re.search(r'^__version__ = "(\d+)\.(\d+)\.(\d+)"$', INIT.read_text(encoding="utf-8"), re.M)
    if not m:
        raise SystemExit("__version__ não encontrado (formato X.Y.Z) em src/owl_vault/__init__.py")
    return ".".join(m.groups())


def _git(*args: str) -> str:
    try:
        out = subprocess.run(  # noqa: S603 - comando fixo, sem shell
            ["git", *args],  # noqa: S607 - git do PATH do desenvolvedor
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip()


def build_info() -> tuple[int, str, bool]:
    count = _git("rev-list", "--count", "HEAD")
    commit = _git("rev-parse", "--short", "HEAD")
    dirty = bool(_git("status", "--porcelain", "--untracked-files=no"))
    return (int(count) if count.isdigit() else 0), commit, dirty


def version_info_text(version: str, build: int, label: str) -> str:
    major, minor, patch = (int(x) for x in version.split("."))
    vers = f"({major}, {minor}, {patch}, {build})"
    return f"""# UTF-8 — GERADO por packaging/stamp_version.py (não editar à mão)
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={vers},
    prodvers={vers},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'041604B0',
        [StringStruct(u'CompanyName', u'Owl Vault'),
        StringStruct(u'FileDescription', u'Owl Vault - pastas protegidas por criptografia'),
        StringStruct(u'FileVersion', u'{version}.{build}'),
        StringStruct(u'InternalName', u'OwlVault'),
        StringStruct(u'LegalCopyright', u''),
        StringStruct(u'OriginalFilename', u'OwlVault.exe'),
        StringStruct(u'ProductName', u'Owl Vault'),
        StringStruct(u'ProductVersion', u'{label}')])
      ]),
    VarFileInfo([VarStruct(u'Translation', [1046, 1200])])
  ]
)
"""


def main() -> int:
    version = read_version()
    build, commit, dirty = build_info()
    date = _dt.date.today().isoformat()
    label = f"{version} (build {build}{' · ' + commit if commit else ''}{' +alterações' if dirty else ''})"
    BUILD_PY.write_text(
        '"""GERADO por packaging/stamp_version.py — não editar nem versionar."""\n\n'
        f"BUILD = {build}\n"
        f"COMMIT = {commit!r}\n"
        f"DIRTY = {dirty!r}\n"
        f"DATE = {date!r}\n",
        encoding="utf-8",
    )
    VERSION_INFO.write_text(version_info_text(version, build, label), encoding="utf-8")
    print(label)
    return 0


if __name__ == "__main__":
    sys.exit(main())
