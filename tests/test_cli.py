"""CLI de laboratório (ARCHITECTURE §8): ``python -m owl_vault.cli.main``.

A CLI usa PRODUCTION_POLICY (Argon2id calibrado) e ``ProtectedPaths.from_environment()``,
que recusa origens dentro de AppData — e o ``%TEMP%`` do pytest fica em AppData\\Local.
Por isso os testes de criação pela CLI usam uma pasta sintética FORA de AppData, dentro da
raiz do repositório (``.cli-test-tmp\\<aleatório>``), sempre removida no ``finally``.
"""

from __future__ import annotations

import _winapi
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from owl_vault.cli.main import build_parser
from owl_vault.storage import faults
from tests.conftest import (
    PASSWORD,
    Area,
    do_restore,
    make_vault,
    tree_digest,
    write_tree,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI_TMP_ROOT = REPO_ROOT / ".cli-test-tmp"
_TIMEOUT = 600

_SECRET_NAMES = ["planilha-salarios.xlsx", "Cartas Pessoais", "carta à mãe.txt", "日記.md"]


class _Crash(BaseException):
    """Queda simulada (atravessa o tratamento normal de erros)."""


# --------------------------------------------------------------------------------------
# infraestrutura
# --------------------------------------------------------------------------------------


def _remove_junctions(root: Path) -> None:
    """Remove junctions (só o link, nunca o alvo) antes de apagar a árvore de teste."""
    for dirpath, dirnames, _ in os.walk(root):
        for d in list(dirnames):
            p = os.path.join(dirpath, d)
            if os.path.isjunction(p) or os.path.islink(p):
                os.rmdir(p)
                dirnames.remove(d)


@pytest.fixture
def cli_area() -> Iterator[Area]:
    """Pastas sintéticas fora de AppData (a CLI usa as pastas protegidas reais)."""
    base = CLI_TMP_ROOT / secrets.token_hex(8)
    base.mkdir(parents=True)
    try:
        a = Area(
            root=base,
            src=base / "origem",
            vaults=base / "cofres",
            testarea=base / "teste",
            out=base / "saida",
        )
        for p in (a.src, a.vaults, a.testarea, a.out):
            p.mkdir()
        yield a
    finally:
        _remove_junctions(base)
        shutil.rmtree(base)
        try:
            CLI_TMP_ROOT.rmdir()  # só se vazia (outros testes podem estar usando)
        except OSError:
            pass


def _run_cli(*args: str, password: str | None = None) -> tuple[int, str, str]:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    src_dir = str(REPO_ROOT / "src")
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")
    stdin = (password + "\n").encode("utf-8") if password is not None else b""
    proc = subprocess.run(  # noqa: S603 - comando fixo: o próprio interpretador de teste
        [sys.executable, "-m", "owl_vault.cli.main", *args],
        input=stdin,
        capture_output=True,
        timeout=_TIMEOUT,
        env=env,
        cwd=str(REPO_ROOT),
        check=False,
    )
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def _sample(root: Path) -> None:
    write_tree(
        root,
        {
            "planilha-salarios.xlsx": os.urandom(150_000),
            "Cartas Pessoais": {"carta à mãe.txt": "querida mãe".encode() * 50, "vazia": {}},
            "日記.md": b"# diario",
            "vazio.bin": b"",
        },
    )


def _all_bytes(root: Path, skip: Path) -> bytes:
    return b"".join(
        p.read_bytes() for p in root.rglob("*") if p.is_file() and skip not in p.parents
    )


# --------------------------------------------------------------------------------------
# senha: só getpass ou --password-stdin
# --------------------------------------------------------------------------------------


def _subparsers() -> dict[str, object]:
    parser = build_parser()
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            return dict(choices)
    raise AssertionError("parser sem subcomandos")


def test_parser_has_no_password_option_only_password_stdin() -> None:
    subs = _subparsers()
    assert {"preflight", "create", "verify", "restore", "salvage"} <= set(subs)
    root_opts = [o for a in build_parser()._actions for o in a.option_strings]
    assert not any("password" in o for o in root_opts)
    for name, sp in subs.items():
        opts = [o for a in sp._actions for o in a.option_strings]  # type: ignore[attr-defined]
        password_opts = [o for o in opts if "pass" in o.lower() or "senha" in o.lower()]
        if name == "preflight":
            assert password_opts == []
        else:
            assert password_opts == ["--password-stdin"], (name, password_opts)
        # --password-stdin é flag (não recebe a senha como valor)
        for a in sp._actions:  # type: ignore[attr-defined]
            if "--password-stdin" in a.option_strings:
                assert a.nargs == 0


@pytest.mark.parametrize(
    "template",
    [
        ["create", "{src}", "{vault}", "--password", "segredo123456"],
        ["create", "{src}", "{vault}", "--password=segredo123456"],
        ["create", "--password", "segredo123456", "{src}", "{vault}"],
        ["verify", "{vault}", "--password", "segredo123456"],
        ["restore", "{vault}", "{dest}", "--password=segredo123456"],
    ],
)
def test_password_on_command_line_is_rejected(area: Area, template: list[str]) -> None:
    (area.src / "a.txt").write_bytes(b"a")
    paths = {"src": str(area.src), "vault": str(area.vault()), "dest": str(area.dest())}
    argv = [t.format(**paths) for t in template]
    code, out, err = _run_cli(*argv)
    assert code == 2, (out, err)  # erro de uso do argparse, antes de qualquer ação
    assert "usage" in err.lower()
    assert not area.vault().exists()
    assert not area.dest().exists()


@pytest.mark.parametrize("sub", ["create", "verify", "restore", "salvage"])
def test_help_mentions_only_password_stdin(sub: str) -> None:
    code, out, _ = _run_cli(sub, "--help")
    assert code == 0
    assert "--password-stdin" in out
    assert not re.search(r"--password(?!-stdin)", out)


# --------------------------------------------------------------------------------------
# fluxo completo pela CLI (KDF de produção, pastas protegidas reais)
# --------------------------------------------------------------------------------------


def test_cli_preflight_create_verify_restore(cli_area: Area) -> None:
    a = cli_area
    _sample(a.src)
    before = tree_digest(a.src)
    vault = a.vault()

    # preflight: sem bloqueios e sem gravar nada
    code, out, err = _run_cli("preflight", str(a.src), str(vault), "--test-dir", str(a.testarea))
    assert code == 0, (out, err)
    assert "BLOQUEIOS" not in out
    assert "Arquivos: 4 | Pastas: 2" in out
    assert not vault.exists()

    # create
    code, out, err = _run_cli(
        "create",
        str(a.src),
        str(vault),
        "--test-dir",
        str(a.testarea),
        "--password-stdin",
        "--accept-limits",
        password=PASSWORD,
    )
    assert code == 0, (out, err)
    assert "criada e verificada" in out
    assert "A pasta original NÃO foi alterada" in out
    assert "Arquivos: 4 | Pastas: 2" in out
    assert "DIVERGÊNCIAS" not in out
    assert tree_digest(a.src) == before
    assert list(a.testarea.iterdir()) == []  # pasta temporária do teste removida
    assert (vault / "complete.owl").is_file()
    assert not (vault / "journal").exists()

    # cabeçalho com parâmetros de produção calibrados (nunca o piso de teste)
    hdr = (vault / "vault.owl").read_bytes()
    assert len(hdr) == 144
    assert hdr == (vault / "vault.owl.bak").read_bytes()
    m, t, p = struct.unpack(">III", hdr[36:48])
    assert 65_536 <= m <= 1_048_576
    assert 3 <= t <= 16
    assert 1 <= p <= 8
    assert m >= 8 * p

    # verify
    code, out, err = _run_cli("verify", str(vault), "--password-stdin", password=PASSWORD)
    assert code == 0, (out, err)
    assert "Criação concluída e testada" in out
    assert "Arquivos íntegros: 4/4" in out
    assert "Resultado: cofre íntegro." in out

    # verify com senha errada
    code, out, err = _run_cli(
        "verify", str(vault), "--password-stdin", password="senha errada errada"
    )
    assert code == 1, (out, err)
    assert "ERRO" in err
    assert "Senha incorreta" in err
    assert "íntegro" not in out

    # restore
    dest = a.dest()
    code, out, err = _run_cli(
        "restore", str(vault), str(dest), "--password-stdin", password=PASSWORD
    )
    assert code == 0, (out, err)
    assert "Criação concluída e testada" in out
    assert "Restaurados: 4" in out
    assert tree_digest(dest) == before

    # restaurar de novo no mesmo destino (agora não vazio) é recusado sem tocar em nada
    code, out, err = _run_cli(
        "restore", str(vault), str(dest), "--password-stdin", password=PASSWORD
    )
    assert code == 1, (out, err)
    assert "não está vazia" in err
    assert tree_digest(dest) == before

    # a senha nunca é gravada; nomes da origem não aparecem em claro no cofre
    assert PASSWORD.encode() not in _all_bytes(a.root, a.src)
    vault_bytes = _all_bytes(vault, a.src)
    for name in _SECRET_NAMES:
        assert name.encode("utf-8") not in vault_bytes
        assert name.encode("utf-16-le") not in vault_bytes


def test_cli_preflight_lists_junction_blocker(cli_area: Area) -> None:
    a = cli_area
    _sample(a.src)
    target = a.root / "alvo-fora-da-origem"
    target.mkdir()
    (target / "dentro.txt").write_bytes(b"conteudo do alvo")
    link = a.src / "atalho-junction"
    _winapi.CreateJunction(str(target), str(link))
    assert os.path.isjunction(link)
    vault = a.vault()

    code, out, err = _run_cli("preflight", str(a.src), str(vault), "--test-dir", str(a.testarea))
    assert code == 2, (out, err)
    assert "BLOQUEIOS (1):" in out
    lines = [ln for ln in out.splitlines() if "atalho-junction" in ln]
    assert lines, out
    assert "junction" in lines[0]
    assert not vault.exists()
    assert (target / "dentro.txt").read_bytes() == b"conteudo do alvo"

    # create também recusa (código 2) antes de gravar qualquer coisa
    code, out, err = _run_cli(
        "create",
        str(a.src),
        str(vault),
        "--test-dir",
        str(a.testarea),
        "--password-stdin",
        "--accept-limits",
        password=PASSWORD,
    )
    assert code == 2, (out, err)
    assert "atalho-junction" in err
    assert not vault.exists()
    assert list(a.testarea.iterdir()) == []
    assert (target / "dentro.txt").read_bytes() == b"conteudo do alvo"


def test_cli_create_rejects_short_password(cli_area: Area) -> None:
    a = cli_area
    _sample(a.src)
    code, out, err = _run_cli(
        "create",
        str(a.src),
        str(a.vault()),
        "--test-dir",
        str(a.testarea),
        "--password-stdin",
        "--accept-limits",
        password="curta",
    )
    assert code == 1, (out, err)
    assert "12 caracteres" in err
    assert not a.vault().exists()
    assert list(a.testarea.iterdir()) == []


def test_cli_preflight_refuses_source_inside_appdata(area: Area) -> None:
    """Pastas protegidas reais: a origem do pytest (em %TEMP%, dentro de AppData) é bloqueada."""
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        pytest.skip("LOCALAPPDATA não definido")
    try:
        inside = os.path.commonpath([os.path.realpath(area.src), os.path.realpath(local)])
    except ValueError:
        inside = ""
    if os.path.normcase(inside) != os.path.normcase(os.path.realpath(local)):
        pytest.skip("o tmp do pytest não está dentro de AppData nesta máquina")
    (area.src / "a.txt").write_bytes(b"a")
    code, out, err = _run_cli("preflight", str(area.src), str(area.vault()))
    assert code == 2, (out, err)
    assert "BLOQUEIOS" in out
    assert "pasta protegida" in out
    assert not area.vault().exists()


# --------------------------------------------------------------------------------------
# CLI x cofres de teste e restauração interrompida
# --------------------------------------------------------------------------------------


def test_cli_cannot_open_vault_made_with_testing_kdf_floor(area: Area) -> None:
    """O piso de KDF de teste (8 MiB, t=1) é inalcançável pela CLI (FORMAT §3)."""
    (area.src / "a.txt").write_bytes(b"conteudo")
    assert make_vault(area).status == "success"
    code, out, err = _run_cli("verify", str(area.vault()), "--password-stdin", password=PASSWORD)
    assert code == 1, (out, err)
    assert "ERRO" in err
    assert "íntegro" not in out
    dest = area.dest()
    code, out, err = _run_cli(
        "restore", str(area.vault()), str(dest), "--password-stdin", password=PASSWORD
    )
    assert code == 1, (out, err)
    assert not dest.exists()


def test_cli_restore_interrupted_destination_requires_resume_flag(area: Area) -> None:
    (area.src / "a.bin").write_bytes(os.urandom(200_000))
    (area.src / "b.txt").write_bytes(b"b")
    assert make_vault(area).status == "success"
    faults.fail_at("restore.write", 2, _Crash)
    with pytest.raises(_Crash):
        do_restore(area)
    faults.reset()
    dest = area.dest()
    assert (dest / ".owlvault-restore.json").is_file()
    snapshot = sorted(p.name for p in dest.rglob("*"))
    code, out, err = _run_cli("restore", str(area.vault()), str(dest))
    assert code == 5, (out, err)
    assert "--resume" in out
    assert sorted(p.name for p in dest.rglob("*")) == snapshot


def test_cli_error_exit_code_for_missing_vault(area: Area) -> None:
    missing = area.vault("nao-existe")
    code, out, err = _run_cli("verify", str(missing), "--password-stdin", password=PASSWORD)
    assert code == 1, (out, err)
    assert "ERRO" in err
    assert not missing.exists()


def test_cli_create_requires_accepting_limits_non_interactive(cli_area: Area) -> None:
    """Sem --accept-limits, o modo não interativo recusa (código 2) antes de gravar."""
    a = cli_area
    _sample(a.src)
    code, out, err = _run_cli(
        "create",
        str(a.src),
        str(a.vault()),
        "--test-dir",
        str(a.testarea),
        "--password-stdin",
        password=PASSWORD,
    )
    assert code == 2, (out, err)
    assert "--accept-limits" in err
    assert "malware" in err  # os limites foram mostrados
    assert not a.vault().exists()
