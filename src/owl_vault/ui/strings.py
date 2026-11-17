"""Textos da interface (pt-BR), centralizados para revisão e teste.

Regra (ARCHITECTURE §7): textos que descrevem a PASTA DE ORIGEM nunca podem sugerir que ela
está protegida. ``ORIGIN_STATUS_TEXTS`` é verificado por ``tests/test_ui_strings.py``.
"""

from __future__ import annotations

APP_TITLE = "Owl Vault"

# --- textos que descrevem a pasta de origem (testados) ---------------------------------
ORIGIN_STILL_READABLE = "A pasta original continua legível até você removê-la manualmente."
ORIGIN_TRACES = (
    "Mesmo depois de removida, podem restar cópias dela (Lixeira, Versões anteriores, "
    "OneDrive, backups, índice do Windows, SSD)."
)
ORIGIN_NOT_CHANGED = "A pasta original não foi alterada."
ORIGIN_STATUS_TEXTS = (ORIGIN_STILL_READABLE, ORIGIN_TRACES, ORIGIN_NOT_CHANGED)

# --- faixa fixa -------------------------------------------------------------------------
BANNER = (
    "O Owl Vault cria uma CÓPIA criptografada da pasta escolhida. "
    + ORIGIN_STILL_READABLE
    + " "
    + ORIGIN_TRACES
)

# --- avisos que exigem aceite antes de criar -------------------------------------------
LIMITS_TITLE = "Limites da proteção"
LIMITS_TEXT = (
    "• O cofre protege os arquivos do cofre contra quem NÃO tem a senha.\n"
    "• Não protege contra malware, nem contra quem administra ou observa este computador "
    "enquanto o Owl Vault está em uso.\n"
    "• O Python não garante apagar a senha e as chaves da memória do computador.\n"
    "• O Owl Vault não faz exclusão segura e não apaga nada da pasta original.\n"
    "• Tamanhos exatos dos arquivos ficam visíveis no cofre (nomes e conteúdo, não)."
)
BACKUP_TEXT = (
    "Mantenha a pasta original e um backup externo até verificar o cofre — de preferência "
    "em outro computador — e até confirmar que a restauração funciona."
)
PASSWORD_LOSS_TEXT = (
    "Entendo que, se eu esquecer a senha, NÃO existe forma de recuperar os dados do cofre."  # noqa: S105
)
FAT_ACK_TEXT = (
    "Entendo que esta mídia (FAT/exFAT) não tem journaling: não vou removê-la durante a "
    "operação e vou rodar 'Verificar cofre' depois de reconectá-la."
)

CREATE_HINT = (
    "Escolha a pasta de origem e onde criar o cofre. O nome sugerido é genérico de propósito: "
    "o nome da pasta do cofre fica visível para qualquer pessoa."
)
TEST_DIR_HINT = (
    "Pasta temporária do teste de restauração (no mesmo disco da origem). Cada arquivo é "
    "restaurado ali com nome aleatório, comparado com a origem e apagado em seguida."
)
VERIFY_HINT = "Confere todos os blocos criptografados e o registro de conclusão. Não altera nada."
RESTORE_HINT = (
    "Restaura para uma pasta NOVA e vazia. O Owl Vault nunca grava por cima de arquivos "
    "existentes nem na pasta de origem."
)
NOT_CANCELLABLE = "Derivando a chave da senha (não cancelável, alguns segundos)..."
