"""Hierarquia de erros do Owl Vault.

As mensagens são destinadas ao usuário (pt-BR). Nunca incluem senhas. Nomes de arquivos
só aparecem em mensagens exibidas na tela (nunca gravadas em disco).
"""

from __future__ import annotations


class OwlVaultError(Exception):
    """Erro base. ``str(e)`` é uma mensagem apresentável ao usuário."""

    retryable: bool = False


class FormatError(OwlVaultError):
    """Estrutura do cofre inválida, versão desconhecida ou fora dos limites."""


class LimitError(FormatError):
    """Valor fora dos limites permitidos pelo formato."""


class AuthenticationError(OwlVaultError):
    """Senha incorreta ou cabeçalho/contêiner adulterado (indistinguíveis por design)."""


class IntegrityError(OwlVaultError):
    """Falha de autenticação/integridade em blob, chunk ou hash."""


class InconsistentVaultError(OwlVaultError):
    """Cópias redundantes autênticas, mas divergentes entre si."""


class UnsafePathError(OwlVaultError):
    """Caminho recusado por regra de segurança (traversal, reservado, rede, protegido...)."""


class PreflightError(OwlVaultError):
    """A pré-verificação encontrou bloqueios."""

    def __init__(self, message: str, blockers: list[str] | None = None) -> None:
        super().__init__(message)
        self.blockers = list(blockers or [])


class CancelledError(OwlVaultError):
    """Operação cancelada pelo usuário em uma fronteira consistente."""

    retryable = True


class InsufficientSpaceError(OwlVaultError):
    """Espaço livre insuficiente no volume de destino."""

    retryable = True


class FileTooLargeForFsError(OwlVaultError):
    """O sistema de arquivos de destino não suporta o tamanho do arquivo (ex.: FAT32)."""


class SourceChangedError(OwlVaultError):
    """Um arquivo da origem mudou durante a leitura ou desde a varredura."""

    retryable = True


class FileInUseError(OwlVaultError):
    """Arquivo aberto/bloqueado por outro programa."""

    retryable = True


class AntivirusBlockedError(OwlVaultError):
    """Operação bloqueada por antivírus ou Acesso controlado a pastas."""


class VaultLockedError(OwlVaultError):
    """Outra janela/processo do Owl Vault está usando o cofre ou o destino."""

    retryable = True


class ResourceError(OwlVaultError):
    """Recurso do sistema insuficiente (ex.: memória para o Argon2id)."""


class StateError(OwlVaultError):
    """Estado da operação incompatível com o pedido (ex.: cofre já concluído)."""
