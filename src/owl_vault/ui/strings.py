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

# --- assistente "Cópia criptografada" (visual Cofre, Estilo 5) ---------------------------
# Os cinco textos abaixo são EXATAMENTE os da seção "Textos" de visual/ESTILO5-COFRE.md
# (tests/test_ui_strings.py confere).
AVISO_COPIA = (
    "O cofre é uma cópia criptografada. A pasta original continua legível até você removê-la "
    "— e, mesmo removida, podem restar cópias dela na Lixeira, em Versões anteriores, no "
    "OneDrive, em backups e no índice do Windows."
)
SENHA_TEXTO = (
    "É ela que abre o cofre depois. Sem ela não há recuperação: nem você, nem o Owl Vault "
    "conseguem ler os arquivos de volta."
)
NOME_DICA = (
    "O nome da pasta do cofre fica visível para qualquer pessoa que abrir o computador. "
    "Guarde o assunto na senha, não no nome."
)
TESTE_NOTA = (
    "Pasta temporária no mesmo disco da origem. Cada arquivo é restaurado ali com nome "
    "aleatório, comparado com a origem e apagado em seguida."
)
FIM_TEXTO = (
    "Cópia criptografada criada e verificada (cópia da pasta como estava em {data} {hora}). "
    "Mantenha a origem e um backup externo até verificar o cofre, de preferência em outro "
    "computador."
)

COPIA_TITULO_JANELA = "Owl Vault — Cópia criptografada"
COPIA_PASSOS = ("Pastas", "Senha", "Conferência", "Criar")
COPIA_PRIMARIO = (
    "Continuar para a senha",
    "Continuar para a conferência",
    "Criar cofre agora",
)
COPIA_PRIMARIO_FIM = "Abrir a pasta do cofre"
COPIA_CRIAR_OUTRO = "Criar outro cofre"
COPIA_RETOMAR = "Retomar criação interrompida"
COPIA_RETOMAR_AGORA = "Retomar a criação agora"
COPIA_SECAO_LATERAL = "Escolhas do passo 1"

COPIA_P1_TITULO = "Escolha as pastas"
COPIA_P1_TEXTO = (
    "O Owl Vault lê a pasta de origem e grava uma cópia criptografada no local do cofre. "
    "A origem não é alterada."
)
COPIA_P2_TITULO = "Escolha a senha do cofre"
COPIA_P2_RETOMAR_TITULO = "Digite a senha do cofre"
COPIA_P2_RETOMAR_TEXTO = "Use a mesma senha de quando a criação começou."
COPIA_P3_TITULO = "Conferência antes de criar"
COPIA_P3_TEXTO = "Nada é gravado nesta etapa. Confira os itens e marque os avisos para continuar."
COPIA_P3_RETOMAR_TITULO = "Conferência antes de retomar"
COPIA_P4_TITULO = "Criando o cofre"
COPIA_P4_TITULO_OK = "Cofre criado"
COPIA_P4_TITULO_DIVERGENCIAS = "Cofre criado com divergências"
COPIA_P4_TITULO_PAROU = "A criação parou"
COPIA_P4_TEXTO = "Acompanhe o andamento abaixo. A origem é só lida."
COPIA_P4_TEXTO_FIM = "Confira o resultado abaixo. A origem não foi alterada."
COPIA_DICA_FIM = (
    "E agora?",
    "Confira o cofre em outro computador ('Conferir uma cópia') antes de decidir o que fazer "
    "com a origem. Guarde também um backup externo.",
)
COPIA_ACEITE_LIMITES = "Li e entendi os limites da proteção."

#: (título, texto) da dica de cada passo do assistente
COPIA_DICAS = (
    ("Por que o nome é genérico?", NOME_DICA),
    (
        "Como escolher a senha?",
        "Uma frase com quatro ou mais palavras é fácil de lembrar e difícil de adivinhar. "
        "Anote a senha num lugar seguro, longe do computador.",
    ),
    (
        "O que é conferido?",
        "O Owl Vault lista a origem, abre cada arquivo e calcula o espaço do cofre. "
        "Nada é gravado nesta etapa.",
    ),
    (
        "Pode demorar",
        "Cada arquivo é criptografado, conferido e restaurado num teste. Se precisar parar, "
        "use 'Retomar criação interrompida' depois.",
    ),
)
COPIA_DICA_ABRIR = (
    "Sempre numa pasta nova",
    "Os arquivos voltam numa pasta nova e vazia. Nada é gravado por cima de arquivos que já "
    "existem, nem na pasta de origem.",
)
COPIA_DICA_CONFERIR = (
    "Quando conferir?",
    "Depois de criar, de preferência em outro computador, e sempre que reconectar a mídia "
    "do cofre.",
)
COPIA_MIDIA_REMOVIVEL = (
    "Use 'Remover hardware com segurança'; depois reconecte a mídia e confira o cofre "
    "('Conferir uma cópia') antes de remover qualquer original."
)
#: passo 3: a conferência não grava nada, então a gravação não tem ✓ (é testada ao criar)
COPIA_DESTINO_NAO_TESTADO = (
    "O local do cofre existe ({fs}). A gravação ainda não foi testada: será testada no início "
    "da criação."
)
COPIA_MARQUE_AVISOS = "Conferência concluída. Marque os avisos para continuar."
COPIA_PRONTO_CRIAR = "Pronto para criar o cofre."
COPIA_PRONTO_RETOMAR = "Pronto para retomar a criação."
COPIA_NOME_INVALIDO = "Escolha outro nome para o cofre: {problema}."
COPIA_NOME_NOVO_INVALIDO = "Escolha outro nome para a pasta nova: {problema}."
COPIA_DESTINO_ILEGIVEL = "Não foi possível olhar a pasta de destino: {motivo}"
COPIA_DIGITE_DE_NOVO = "A senha foi apagada da tela por segurança. Digite-a de novo."
#: texto final quando o motor só limpou um cofre já concluído (a data é a da conclusão)
COPIA_FIM_CONCLUIDO = (
    "Cópia criptografada criada e verificada (concluída em {data} {hora}). Mantenha a origem e "
    "um backup externo até verificar o cofre, de preferência em outro computador."
)
COPIA_FIM_SEM_DATA = (
    "Cópia criptografada criada e verificada. Mantenha a origem e um backup externo até "
    "verificar o cofre, de preferência em outro computador."
)

# --- falhas e cancelamentos: um texto por operação, sempre verdadeiro --------------------
#: criação parada quando existe um cofre incompleto para retomar
COPIA_CANCELADA = (
    "Criação parada num ponto seguro. Use 'Retomar criação interrompida' para continuar depois."
)
#: criação parada antes de existir um cofre incompleto (não há o que retomar)
COPIA_CANCELADA_SEM_RETOMADA = (
    "Criação parada num ponto seguro, antes de haver algo para retomar. A pasta original não "
    "foi alterada."
)
#: troca o "Criação interrompida (use 'Retomar')" do motor quando não há o que retomar
COPIA_NAO_CRIOU = "Não foi possível criar o cofre"
COPIA_CONFERENCIA_CANCELADA = "Conferência cancelada. Nada foi gravado."
COPIA_VERIFICACAO_CANCELADA = "Conferência da cópia cancelada. A cópia não foi alterada."
COPIA_RESTAURACAO_PARADA = "Restauração parada num ponto seguro."
COPIA_RESTAURACAO_PARADA_ANTES = (
    "Restauração parada num ponto seguro, antes de gravar arquivos na pasta nova."
)
COPIA_RESTAURACAO_INCOMPLETA = (
    "A pasta nova '{nome}' ficou incompleta: para continuar, abra a cópia de novo com esse "
    "mesmo nome."
)
COPIA_RESTAURACAO_TALVEZ = (
    "A pasta nova '{nome}' pode ter ficado incompleta: confira os arquivos antes de usá-los."
)
#: o app foi bloqueado com um trabalho rodando: a tela foi limpa (sem nomes) e ele parou
COPIA_BLOQUEIO_TERMINOU = "A operação terminou durante o bloqueio; a tela foi limpa."
COPIA_BLOQUEIO_PAROU = "A operação parou durante o bloqueio; a tela foi limpa."

#: "Há uma operação em andamento": o que acontece ao parar, por operação
COPIA_FECHAR_TEXTO = (
    "Parar num ponto seguro e fechar? Se já houver um cofre incompleto, use 'Retomar criação "
    "interrompida' para continuar depois."
)
COPIA_FECHAR_CONFERENCIA = "Parar a conferência e fechar? Nada foi gravado."
COPIA_FECHAR_CONFERIR = "Parar a conferência da cópia e fechar? A cópia não é alterada."
COPIA_FECHAR_ABRIR = (
    "Parar a restauração num ponto seguro e fechar? A pasta nova pode ficar incompleta: para "
    "continuar, abra a cópia de novo com o mesmo nome de pasta."
)
COPIA_FECHAR_TEXTOS: dict[str, str] = {
    "criar": COPIA_FECHAR_TEXTO,
    "conferencia": COPIA_FECHAR_CONFERENCIA,
    "conferir": COPIA_FECHAR_CONFERIR,
    "abrir": COPIA_FECHAR_ABRIR,
}
