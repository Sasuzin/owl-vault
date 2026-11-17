"""Pastas protegidas e regras de localização (ARCHITECTURE §4.1 passo 1).

Todas as comparações usam caminhos resolvidos (``winfs.resolve``), nunca strings digitadas.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from owl_vault.application.common import env_path
from owl_vault.domain.errors import OwlVaultError
from owl_vault.storage import winfs

_SYSTEM_TOP = frozenset(["SYSTEM VOLUME INFORMATION", "$RECYCLE.BIN"])


@dataclass
class ProtectedPaths:
    #: origem não pode ser igual, interna ou ancestral (Windows, Program Files, ProgramData, AppData)
    critical: list[winfs.Resolved] = field(default_factory=list)
    #: origem não pode ser igual nem ancestral (perfil do usuário, C:\Users)
    no_ancestor: list[winfs.Resolved] = field(default_factory=list)
    #: destinos (cofre, restauração, teste) não podem ficar dentro
    dest_forbidden: list[winfs.Resolved] = field(default_factory=list)

    @classmethod
    def from_environment(cls) -> ProtectedPaths:
        def res(paths: list[str | None]) -> list[winfs.Resolved]:
            out: list[winfs.Resolved] = []
            for p in paths:
                if not p:
                    continue
                try:
                    r = winfs.resolve(p)
                except (OwlVaultError, OSError):
                    continue
                if r.exists:
                    out.append(r)
            return out

        system = [
            env_path("SystemRoot") or env_path("windir"),
            env_path("ProgramFiles"),
            env_path("ProgramFiles(x86)"),
            env_path("ProgramW6432"),
            env_path("ProgramData"),
        ]
        appdata = [env_path("APPDATA"), env_path("LOCALAPPDATA")]
        profile = env_path("USERPROFILE")
        users_root = os.path.dirname(profile) if profile else None
        return cls(
            critical=res([*system, *appdata]),
            no_ancestor=res([profile, users_root]),
            dest_forbidden=res(system),
        )

    @classmethod
    def none(cls) -> ProtectedPaths:
        """Sem pastas protegidas — usado SOMENTE pelos testes automatizados."""
        return cls()


def _system_area(r: winfs.Resolved) -> bool:
    return len(r.parts) >= 2 and r.parts[1] in _SYSTEM_TOP


def source_location_problems(src: winfs.Resolved, prot: ProtectedPaths) -> list[str]:
    problems: list[str] = []
    if len(src.parts) <= 1:
        problems.append("a origem não pode ser a raiz de uma unidade")
    if _system_area(src):
        problems.append("a origem está numa área de sistema (Lixeira/System Volume Information)")
    for p in prot.critical:
        if src.overlaps(p):
            problems.append(
                f"a origem envolve uma pasta protegida do sistema ({winfs.strip_extended(p.dos_path)})"
            )
    for p in prot.no_ancestor:
        if p.is_within(src):
            problems.append(
                "a origem não pode ser a pasta do perfil do usuário (nem uma pasta acima dela); "
                "escolha uma subpasta, como Documentos\\Projeto"
            )
    return problems


def destination_location_problems(
    dst: winfs.Resolved, prot: ProtectedPaths, what: str
) -> list[str]:
    problems: list[str] = []
    if _system_area(dst):
        problems.append(
            f"{what} não pode ficar numa área de sistema (Lixeira/System Volume Information)"
        )
    for p in prot.dest_forbidden:
        if dst.is_within(p):
            problems.append(
                f"{what} não pode ficar dentro de uma pasta do sistema ({winfs.strip_extended(p.dos_path)})"
            )
    return problems
