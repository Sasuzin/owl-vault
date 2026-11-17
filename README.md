# Owl Vault

**Owl Vault** cria **cópias criptografadas e verificáveis** de pastas no Windows 10/11.

> ⚠️ O Owl Vault **não protege a pasta original**: ele cria uma *cópia* criptografada. A pasta
> original continua legível até você removê-la manualmente — e, mesmo depois, podem restar
> cópias dela (Lixeira, Versões anteriores, OneDrive, backups, índice do Windows, SSD).
> **Sem a senha não há como recuperar os dados.** Não houve auditoria independente.

## O que faz

| Operação | O que acontece |
|----------|----------------|
| **Criar cofre** | Pré-verifica a origem; cifra cada arquivo (AES-256-GCM, chave derivada da senha com Argon2id) numa pasta de cofre nova; verifica todos os blocos com leitura sem cache; faz um **teste de restauração** de cada arquivo comparando SHA-256 com uma releitura da origem; varre a origem de novo; só então declara sucesso. A origem **nunca** é alterada. |
| **Verificar cofre** | Somente leitura: autentica cabeçalho, manifesto, registro de conclusão e todos os blocos; aponta anomalias. |
| **Restaurar** | Para uma pasta **nova e vazia**, validando tudo antes de gravar; nunca sobrescreve; retomável. |
| **Salvamento de emergência** (CLI) | Se o manifesto for perdido, recupera o conteúdo dos arquivos sem os nomes. |

Detalhes: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · formato: [docs/FORMAT.md](docs/FORMAT.md) ·
ameaças e limites: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) · segurança: [SECURITY.md](SECURITY.md) ·
recuperação: [docs/RECOVERY.md](docs/RECOVERY.md) · Windows: [docs/WINDOWS.md](docs/WINDOWS.md) ·
testes: [docs/TEST_PLAN.md](docs/TEST_PLAN.md).

## Usar o executável

1. Rode `OwlVault.exe` (o Windows SmartScreen pode avisar porque o executável não é assinado —
   confira o SHA-256 em `OwlVault.exe.sha256`).
2. **Criar cofre**: escolha a origem, o local do cofre (ex.: HD externo) e uma senha longa
   (mínimo 12 caracteres; prefira uma frase). Leia o relatório de pré-verificação e os avisos.
3. Depois de criado: **Verificar cofre** (de preferência em outro computador) e faça uma
   **restauração de teste** antes de cogitar remover a origem. Mantenha backups.

Limitações importantes da v1: pastas do OneDrive (Arquivos sob Demanda), links simbólicos,
junctions e outros pontos de reparse são **recusados**; caminhos de rede não são suportados;
permissões, atributos, data de criação e fluxos alternativos NTFS não são preservados.

## Desenvolvimento

Requisitos: Windows 10/11, Python 3.12+ (testado com 3.13).

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip install -e . --no-deps
```

Testes, lint e tipos:

```powershell
.\.venv\Scripts\python.exe -m pytest -q                 # suíte padrão
.\.venv\Scripts\python.exe -m pytest -q -m slow         # arquivos grandes sintéticos
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\mypy.exe
```

Os testes usam apenas pastas temporárias com dados sintéticos e uma política de Argon2id
rápida que só existe para testes (a UI/CLI não conseguem usá-la).

Interface gráfica a partir do código: `.\.venv\Scripts\python.exe -m owl_vault`

### CLI de laboratório

```powershell
.\.venv\Scripts\python.exe -m owl_vault.cli.main preflight C:\Dados\Projeto E:\Cofre-1
.\.venv\Scripts\python.exe -m owl_vault.cli.main create    C:\Dados\Projeto E:\Cofre-1
.\.venv\Scripts\python.exe -m owl_vault.cli.main verify    E:\Cofre-1
.\.venv\Scripts\python.exe -m owl_vault.cli.main restore   E:\Cofre-1 C:\Restaurado-1
.\.venv\Scripts\python.exe -m owl_vault.cli.main salvage   E:\Cofre-1 C:\Emergencia-1
```

A senha é pedida sem eco (ou lida de `--password-stdin`, como UTF-8); não existe opção
`--password`. O `create` mostra os avisos de limites/backup/perda de senha e pede `SIM` (ou
`--accept-limits` em modo não interativo).
**Atenção:** os caminhos digitados ficam no histórico do PowerShell (e eles contêm nomes de
pastas); passar a senha por pipe (`"senha" | ...`) também a grava no histórico do PSReadLine.
No Windows PowerShell 5.1, antes de um pipe use `$OutputEncoding = [Text.UTF8Encoding]::new($false)`
(senão acentos viram `?`). Para não deixar rastros, prefira a interface gráfica.

### Gerar o executável

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build.ps1
```

Gera `dist\OwlVault.exe` (onefile, sem console, `asInvoker`, sem UPX) e
`dist\OwlVault.exe.sha256`. O script roda os testes antes e aborta se algum falhar.

## Estrutura

```
src/owl_vault/
  domain/       modelos, erros, limites, nomes do Windows
  crypto/       Argon2id, HKDF, AES-GCM em chunks
  storage/      formatos, layout, diário, E/S Win32 (winfs), varredura
  application/  preflight, criar/retomar, verificar, restaurar, salvar
  cli/          CLI de laboratório
  ui/           PySide6
tests/          pytest
packaging/      PyInstaller
docs/           arquitetura, formato, ameaças, testes, recuperação, Windows
```
