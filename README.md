# Owl Vault

**Owl Vault** tranca pastas do seu computador com criptografia, no Windows 10/11. A pasta
trancada continua no mesmo lugar, com o ícone da coruja, mas os arquivos dentro dela ficam
criptografados: só abrem pelo Owl Vault, com o seu **PIN** (ou a **senha mestra**).

> ⚠️ Enquanto a pasta está **aberta**, qualquer pessoa que use o computador pode ler os
> arquivos. O Windows deixa rastros (Recentes, índice de pesquisa, miniaturas, SSD, backups,
> Lixeira, OneDrive) que o Owl Vault não apaga. **Se você esquecer a senha mestra, ninguém
> recupera os arquivos.** Não houve auditoria independente.

## Como usar

1. Rode `OwlVault-Setup.exe` (instalador: aparece em "Aplicativos instalados", com
   Desinstalar) ou simplesmente `OwlVault.exe`, que na primeira vez se instala sozinho. Os dois
   instalam só para o seu usuário (`%LOCALAPPDATA%\Programs\Owl Vault`, com atalhos no Menu
   Iniciar e na Área de Trabalho; não pedem administrador) e já trazem tudo o que o programa
   precisa — não há nada mais para instalar.
2. **Crie a senha mestra** (mínimo 8 caracteres; mais longa é mais segura — anote num lugar seguro) e o **PIN** (6 a 12
   números, só para este computador).
3. **+ Proteger uma pasta…** → escolha a pasta → confira o resumo → **Proteger**. O Owl Vault
   guarda os arquivos criptografados dentro da própria pasta (`.owlvault`, oculta), confere
   tudo, testa a recuperação de cada arquivo e só então apaga as cópias legíveis.
4. Para abrir: abra o Owl Vault pelo Menu Iniciar, digite o PIN e clique em **Abrir** na pasta
   (o atalho **Abrir com Owl Vault** dentro da pasta faz o mesmo). A pasta abre no Explorer.
   Quando terminar, **Trancar**.
5. **Esconder do Explorer** (menu ⋯) faz a pasta trancada sumir do Explorer; ela volta pelo
   Owl Vault.

| Na lista | Botão | O que significa |
|----------|-------|-----------------|
| Trancada / Escondida | **Abrir** | arquivos criptografados dentro da pasta |
| Aberta — visível neste computador | **Trancar** | arquivos legíveis; tranque ao terminar |
| Precisa de atenção | **Resolver…** | algo foi interrompido ou mudou; o programa explica o problema e oferece as saídas (sempre há **Tirar da lista**, que não apaga nada) |

O programa trava sozinho depois de 5 minutos sem uso, ao bloquear o Windows (Win+L) e ao
suspender. Ao sair com pastas abertas, ele oferece **Trancar e sair**.

**Backup**: copie a pasta trancada inteira (com os itens ocultos). Em outro computador,
instale o Owl Vault e use ☰ → **Recuperar uma pasta protegida** com a sua senha mestra.

Regras que o Owl Vault segue para não perder dados: nada é apagado antes de estar guardado,
conferido e testado; cada original é conferido (identidade, tamanho e datas) no momento de
apagar e, se mudou, fica na pasta; uma versão anterior com arquivos que não estão na pasta
nunca é apagada sem você confirmar a lista. Pastas do OneDrive, unidades FAT/exFAT, pastas do
Windows (Documentos, Área de Trabalho…), pastas com links e arquivos com vínculos são
recusadas. Detalhes: [docs/PASTAS_PROTEGIDAS.md](docs/PASTAS_PROTEGIDAS.md) e
[docs/UI_SPEC_V2.md](docs/UI_SPEC_V2.md).

### Cópia criptografada (uso raro)

☰ → **Cópia criptografada de uma pasta…** mantém o modo da v1: cria uma *cópia* criptografada
noutro lugar (ex.: pendrive) sem alterar a pasta original, e abre uma cópia numa pasta nova.

Detalhes técnicos: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · formato: [docs/FORMAT.md](docs/FORMAT.md) ·
ameaças e limites: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) · segurança: [SECURITY.md](SECURITY.md) ·
recuperação: [docs/RECOVERY.md](docs/RECOVERY.md) · Windows: [docs/WINDOWS.md](docs/WINDOWS.md) ·
testes: [docs/TEST_PLAN.md](docs/TEST_PLAN.md).

O Windows SmartScreen pode avisar porque o executável e o instalador não são assinados —
confira o SHA-256 em `OwlVault-Setup.exe.sha256` / `OwlVault.exe.sha256`.

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

### CLI de laboratório (cópias criptografadas da v1)

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
  storage/      formatos, layout, diário, E/S Win32 (winfs), varredura, DPAPI, Explorer (shell)
  application/  preflight, criar/retomar, verificar, restaurar, salvar;
                profile (senha mestra + PIN), lockers (pastas protegidas), install
  cli/          CLI de laboratório
  ui/           PySide6
tests/          pytest
packaging/      PyInstaller
  brand/        logo original + extract_logo.py (gera src/owl_vault/ui/assets/owl-shield.png)
docs/           arquitetura, formato, ameaças, testes, recuperação, Windows
```

### Identidade visual

O ícone do executável, o cabeçalho e a janela "Sobre" usam o escudo da coruja extraído da
logo oficial (`packaging/brand/owl-vault-logo-original.webp`). A imagem original não tem
transparência (o xadrez está pintado nos pixels); para regenerar o recorte depois de trocar a
logo:

```powershell
.\.venv\Scripts\python.exe packaging\brand\extract_logo.py
```

A interface usa um tema roxo derivado das cores da logo (escuro por padrão; o claro fica em
☰ → Tema).
