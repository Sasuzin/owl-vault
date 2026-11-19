"""Owl Vault — pastas protegidas por criptografia no Windows.

Versão: ``__version__`` é a fonte única (sobe a cada ajuste, com entrada no CHANGELOG.md).
O executável também carrega o número do build e o commit (``_build.py``, gerado por
``packaging/stamp_version.py``); rodando do código-fonte, o build aparece como "dev".
"""

__all__ = ["APP_NAME", "__version__", "build_label", "version_label"]

APP_NAME = "Owl Vault"
__version__ = "0.3.1"


def _build_info() -> tuple[int | None, str, bool, str]:
    import importlib  # noqa: PLC0415

    try:
        b = importlib.import_module("owl_vault._build")
    except ImportError:
        return None, "", False, ""
    return int(b.BUILD), str(b.COMMIT), bool(b.DIRTY), str(b.DATE)


def build_label() -> str:
    """``build 15 · f731162`` (ou ``build dev`` rodando do código-fonte)."""
    build, commit, dirty, _date = _build_info()
    if build is None:
        return "build dev"
    text = f"build {build}"
    if commit:
        text += f" · {commit}"
    if dirty:
        text += " +alterações"
    return text


def version_label() -> str:
    """``v0.3.0 · build 15 · f731162`` — mostrado no rodapé, no título e em "Sobre"."""
    return f"v{__version__} · {build_label()}"
