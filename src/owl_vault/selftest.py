"""Autoteste do executável (``OwlVault.exe --selftest``).

Exercita as bibliotecas nativas empacotadas (OpenSSL via cryptography, Argon2, Qt offscreen)
e o motor completo (criar → verificar → restaurar) num cofre DESCARTÁVEL com dados sintéticos
numa pasta temporária própria, que é removida ao final. Não toca em pastas do usuário.
Retorna 0 em caso de sucesso.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path


def run() -> int:
    from owl_vault.application.create import create_vault
    from owl_vault.application.protection import ProtectedPaths
    from owl_vault.application.restore import restore_vault
    from owl_vault.application.verify import verify_vault
    from owl_vault.crypto.kdf import TESTING_PARAMS, TESTING_POLICY

    base = Path(tempfile.mkdtemp(prefix="owlvault-selftest-"))
    try:
        src = base / "origem"
        (src / "sub").mkdir(parents=True)
        files = {
            src / "a.txt": b"owl vault selftest",
            src / "sub" / "b.bin": os.urandom(300_000),
            src / "vazio.txt": b"",
        }
        for p, data in files.items():
            p.write_bytes(data)
        (base / "teste").mkdir()
        password = "selftest-" + os.urandom(8).hex()
        result = create_vault(
            str(src),
            str(base / "cofre"),
            password,
            test_parent=str(base / "teste"),
            kdf_params=TESTING_PARAMS,
            kdf_policy=TESTING_POLICY,
            protected=ProtectedPaths.none(),
        )
        if result.status != "success" or result.files != 3:
            return 2
        report = verify_vault(str(base / "cofre"), password, policy=TESTING_POLICY)
        if not report.fully_ok:
            return 3
        rest = restore_vault(
            str(base / "cofre"),
            password,
            str(base / "restaurado"),
            policy=TESTING_POLICY,
            protected=ProtectedPaths.none(),
        )
        if not rest.ok:
            return 4
        for p, data in files.items():
            restored = base / "restaurado" / p.relative_to(src)
            if hashlib.sha256(restored.read_bytes()).digest() != hashlib.sha256(data).digest():
                return 5
        code = _protected_folder_roundtrip(base)
        if code:
            return code
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication

        from owl_vault.ui.icon import asset_available, ico_bytes, owl_image
        from owl_vault.ui.owl_window import OwlWindow

        app = QApplication.instance() or QApplication(sys.argv[:1])
        if not asset_available() or owl_image(64).isNull() or len(ico_bytes()) < 1000:
            return 6  # logo não empacotada no executável
        window = OwlWindow(
            ("OwlVault.exe", ""), policy=TESTING_POLICY, profile_dir=base / "perfil-ui"
        )
        window.close()
        del window, app
        return 0
    except Exception:
        return 1
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _protected_folder_roundtrip(base: Path) -> int:
    """Pasta protegida: perfil (DPAPI) → trancar no lugar (atalho COM) → PIN → abrir → remover."""
    from owl_vault.application.lockers import LockerManager
    from owl_vault.application.profile import ProfileStore
    from owl_vault.application.protection import ProtectedPaths
    from owl_vault.crypto.kdf import TESTING_PARAMS, TESTING_POLICY
    from owl_vault.storage import shell

    folder = base / "Particular"
    (folder / "sub").mkdir(parents=True)
    data = {folder / "x.txt": b"segredo", folder / "sub" / "y.bin": os.urandom(70_000)}
    for path, content in data.items():
        path.write_bytes(content)
    store = ProfileStore(base / "perfil", TESTING_POLICY)
    session = store.create("selftest senha mestra", "947361", params=TESTING_PARAMS)
    mgr = LockerManager(
        session,
        icon_bytes=b"\x00\x00\x01\x00",
        launcher=shell.current_executable(),
        policy=TESTING_POLICY,
        protected=ProtectedPaths.none(),
        known_folders={},
    )
    out = mgr.protect(mgr.check_protect(str(folder)))
    if not out.complete or any(p.exists() for p in data) or not (folder / ".owlvault").is_dir():
        return 7
    if not (folder / "Abrir com Owl Vault.lnk").exists():
        return 8
    session.close()
    session = store.unlock_with_pin("947361")
    mgr.session = session
    opened = mgr.unlock(out.record.id)
    if not opened.complete or any(p.read_bytes() != c for p, c in data.items()):
        return 9
    mgr.remove_protection(out.record.id)
    if session.index.folders or any(p.read_bytes() != c for p, c in data.items()):
        return 10
    return 0
