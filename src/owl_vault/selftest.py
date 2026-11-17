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
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication

        from owl_vault.ui.main_window import MainWindow

        app = QApplication.instance() or QApplication(sys.argv[:1])
        window = MainWindow()
        window.close()
        del window, app
        return 0
    except Exception:
        return 1
    finally:
        shutil.rmtree(base, ignore_errors=True)
