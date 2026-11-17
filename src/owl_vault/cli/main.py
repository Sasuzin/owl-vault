"""CLI de laboratório (ARCHITECTURE §8).

A senha é lida SOMENTE por ``getpass`` (sem eco) ou ``--password-stdin``. Não existe opção
``--password`` nem variável de ambiente. Atenção: caminhos digitados na linha de comando
ficam no histórico do PowerShell.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Sequence

from owl_vault import APP_NAME, __version__
from owl_vault.application.create import create_vault, inspect_vault_dir, resume_create
from owl_vault.application.preflight import preflight_create
from owl_vault.application.progress import ProgressSink
from owl_vault.application.restore import inspect_destination, restore_vault
from owl_vault.application.salvage import salvage_vault
from owl_vault.application.verify import verify_vault
from owl_vault.crypto.kdf import PRODUCTION_POLICY
from owl_vault.domain.errors import OwlVaultError, PreflightError
from owl_vault.domain.limits import MIB
from owl_vault.ui import strings as S  # só textos; não importa Qt


class ConsoleProgress:
    def __init__(self) -> None:
        self._stage = ""
        self._total = 0
        self._done = 0
        self._last_pct = -1

    def stage(self, name: str, total_bytes: int = 0, total_items: int = 0) -> None:
        self._stage, self._total, self._done, self._last_pct = name, total_bytes, 0, -1
        print(f"\n== {name}", file=sys.stderr)

    def advance(self, nbytes: int = 0, nitems: int = 0) -> None:
        if not self._total:
            return
        self._done += nbytes
        pct = min(100, int(self._done * 100 / self._total))
        if pct != self._last_pct and pct % 5 == 0:
            self._last_pct = pct
            print(f"   {pct:3d}%", file=sys.stderr)

    def info(self, message: str) -> None:
        print(f"   {message}", file=sys.stderr)

    def warning(self, message: str) -> None:
        print(f"   AVISO: {message}", file=sys.stderr)


def _read_password(args: argparse.Namespace, *, confirm: bool) -> str:
    if args.password_stdin:
        # bytes + UTF-8 estrito: a decodificação de texto do console (cp1252/cp850) ou um BOM
        # alterariam a senha silenciosamente e o cofre não abriria com a senha digitada.
        raw = sys.stdin.buffer.readline().rstrip(b"\r\n")
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise OwlVaultError(
                "--password-stdin: a entrada não é UTF-8 válido. No Windows PowerShell 5.1 use "
                "$OutputEncoding = [Text.UTF8Encoding]::new($false) antes do pipe."
            ) from None
    pw = getpass.getpass("Senha: ")
    if confirm:
        again = getpass.getpass("Confirme a senha: ")
        if again != pw:
            raise OwlVaultError("As senhas não conferem.")
    return pw


def _print_list(title: str, items: Sequence[str], limit: int = 50) -> None:
    if not items:
        return
    print(f"{title} ({len(items)}):")
    for it in items[:limit]:
        print(f"  - {it}")
    if len(items) > limit:
        print(f"  ... e mais {len(items) - limit}")


def cmd_preflight(args: argparse.Namespace, progress: ProgressSink) -> int:
    plan = preflight_create(args.source, args.vault, test_parent=args.test_dir, progress=progress)
    for line in plan.summary_lines():
        print(line)
    _print_list("BLOQUEIOS", plan.blockers)
    _print_list("Avisos", plan.warnings)
    return 0 if plan.ok else 2


def _acknowledge_limits(args: argparse.Namespace) -> bool:
    print(S.BANNER, file=sys.stderr)
    print("\n" + S.LIMITS_TITLE + ":\n" + S.LIMITS_TEXT, file=sys.stderr)
    print("\n" + S.BACKUP_TEXT + "\n" + S.PASSWORD_LOSS_TEXT + "\n", file=sys.stderr)
    if args.accept_limits:
        return True
    if args.password_stdin or not sys.stdin.isatty():
        print(
            "ERRO: confirme os avisos acima com --accept-limits (modo não interativo).",
            file=sys.stderr,
        )
        return False
    answer = input("Digite SIM para confirmar que leu e entendeu os avisos: ")
    return answer.strip().upper() == "SIM"


def cmd_create(args: argparse.Namespace, progress: ProgressSink) -> int:
    if not _acknowledge_limits(args):
        return 2
    status = inspect_vault_dir(args.vault)
    password = _read_password(args, confirm=status.kind != "vault-incomplete")
    if status.kind == "vault-incomplete":
        print("Cofre incompleto encontrado: retomando a criação.", file=sys.stderr)
        result = resume_create(
            args.vault, args.source, password, fat_acknowledged=args.accept_fat, progress=progress
        )
    else:
        result = create_vault(
            args.source,
            args.vault,
            password,
            test_parent=args.test_dir,
            fat_acknowledged=args.accept_fat,
            progress=progress,
        )
    print(result.message)
    print(f"Arquivos: {result.files} | Pastas: {result.dirs} | {result.total_bytes / MIB:.1f} MiB")
    _print_list("DIVERGÊNCIAS", result.divergences)
    _print_list("Avisos", result.warnings)
    _print_list("Notas", result.notes)
    return 0 if result.status == "success" else 3


def cmd_verify(args: argparse.Namespace, progress: ProgressSink) -> int:
    password = _read_password(args, confirm=False)
    report = verify_vault(args.vault, password, policy=PRODUCTION_POLICY, progress=progress)
    print(report.creation_status)
    print(f"Arquivos íntegros: {report.files_ok}/{report.total_files}")
    if report.lock_note:
        print(report.lock_note)
    _print_list("PROBLEMAS", report.bad)
    _print_list("CÓPIAS REDUNDANTES DANIFICADAS (veja docs/RECOVERY.md §2)", report.redundancy)
    _print_list("Anomalias", report.anomalies)
    _print_list("Notas", report.notes)
    if report.fully_ok:
        print("Resultado: cofre íntegro.")
        return 0
    return 4


def cmd_restore(args: argparse.Namespace, progress: ProgressSink) -> int:
    state = inspect_destination(args.dest)
    allow_resume = False
    if state == "resumable":
        if not args.resume:
            print("O destino tem uma restauração interrompida; use --resume para continuar.")
            return 5
        allow_resume = True
    password = _read_password(args, confirm=False)
    report = restore_vault(
        args.vault,
        password,
        args.dest,
        policy=PRODUCTION_POLICY,
        allow_resume=allow_resume,
        progress=progress,
    )
    print(report.creation_status)
    print(
        f"Restaurados: {report.restored} | já existentes conferidos: {report.skipped_existing} | "
        f"pastas: {report.dirs_created}"
    )
    _print_list("FALHAS", report.failed)
    _print_list("CONFLITOS", report.conflicts)
    _print_list("Avisos", report.warnings)
    _print_list("Notas", report.notes)
    return 0 if report.ok else 6


def cmd_salvage(args: argparse.Namespace, progress: ProgressSink) -> int:
    password = _read_password(args, confirm=False)
    report = salvage_vault(
        args.vault, password, args.dest, policy=PRODUCTION_POLICY, progress=progress
    )
    print(f"Recuperados (sem nomes): {report.recovered}")
    _print_list("Falhas", report.failed)
    return 0 if not report.failed else 7


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="owl-vault",
        description=f"{APP_NAME} {__version__} — CLI de laboratório. A senha é pedida sem eco "
        "(ou lida de --password-stdin). Caminhos digitados ficam no histórico do terminal.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    def add_pw(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "--password-stdin",
            action="store_true",
            help="lê a senha da primeira linha da entrada padrão (para automação/testes)",
        )

    sp = sub.add_parser("preflight", help="somente pré-verificação, sem gravar nada")
    sp.add_argument("source")
    sp.add_argument("vault", help="caminho da pasta do cofre a criar")
    sp.add_argument("--test-dir", help="pasta onde criar a pasta temporária do teste")
    sp.set_defaults(func=cmd_preflight)

    sp = sub.add_parser("create", help="criar (ou retomar) um cofre")
    sp.add_argument("source")
    sp.add_argument("vault")
    sp.add_argument("--test-dir")
    sp.add_argument("--accept-fat", action="store_true", help="aceita o aviso de mídia FAT/exFAT")
    sp.add_argument(
        "--accept-limits",
        action="store_true",
        help="confirma que leu os avisos de limites, backup e perda de senha (obrigatório "
        "em modo não interativo)",
    )
    add_pw(sp)
    sp.set_defaults(func=cmd_create)

    sp = sub.add_parser("verify", help="verificar um cofre (somente leitura)")
    sp.add_argument("vault")
    add_pw(sp)
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("restore", help="restaurar para uma pasta nova/vazia")
    sp.add_argument("vault")
    sp.add_argument("dest")
    sp.add_argument("--resume", action="store_true", help="continuar restauração interrompida")
    add_pw(sp)
    sp.set_defaults(func=cmd_restore)

    sp = sub.add_parser("salvage", help="emergência: recupera conteúdos sem nomes")
    sp.add_argument("vault")
    sp.add_argument("dest")
    add_pw(sp)
    sp.set_defaults(func=cmd_salvage)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    progress = ConsoleProgress()
    try:
        return int(args.func(args, progress))
    except PreflightError as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        for b in exc.blockers[:50]:
            print(f"  - {b}", file=sys.stderr)
        return 2
    except OwlVaultError as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrompido.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
