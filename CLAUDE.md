# Owl Vault — instruções para o Claude Code

App Windows (Python 3.13, PySide6, cryptography, argon2-cffi, PyInstaller) que tranca pastas
no próprio lugar e faz cópias criptografadas verificáveis. Especificação original:
`OWL_VAULT_CLAUDE_CODE.md`. Visual "Cofre": modelos em `visual/`, tema em
`src/owl_vault/ui/tema/`. Documentos em `docs/` (PASTAS_PROTEGIDAS, THREAT_MODEL, TEST_PLAN,
FORMAT, ARCHITECTURE, UI_SPEC_V2, WINDOWS, RECOVERY).

## Como trabalhar neste projeto

* **Idioma:** responda em português do Brasil; textos de interface, docs, CHANGELOG e
  mensagens de commit em pt-BR. Identificadores de código em inglês (como já estão).
* **Versionar cada ajuste:** todo ajuste sobe `__version__` em `src/owl_vault/__init__.py`
  (0.X.0 = funcionalidade nova ou mudança visível; 0.X.Y = correção ou ajuste pequeno) e ganha
  entrada datada no `CHANGELOG.md`, no mesmo commit. O build (número de commits) e o commit são
  carimbados no exe por `packaging/stamp_version.py`: faça o commit ANTES do build, para o
  rótulo não sair "+alterações".
* **Commit e push sem perguntar** ao terminar uma tarefa, desde que a suíte, o ruff e o mypy
  passem. Nunca envie trabalho pela metade ou com teste falhando. Push só com a conta pessoal
  dona do repositório (Sasuzin/owl-vault), nunca com conta de empresa. Nunca versione `.venv`,
  `build/`, `dist/` (o exe) nem segredos.
* **Releases:** quando o usuário pedir, publique no GitHub como *pré-lançamento* (os testes
  manuais ainda não foram feitos), com `dist/OwlVault.exe` e `dist/OwlVault.exe.sha256`, tag
  `vX.Y.Z-buildN` no commit do build (use o SHA completo em `--target`) e notas em pt-BR.

## Regras de segurança (do usuário, valem sempre)

* Não execute comandos destrutivos nem toque em dados pessoais sem autorização explícita.
* Teste só em pastas temporárias com dados sintéticos e perfil sintético; nunca contra pastas
  pessoais reais nem contra o perfil real do Owl Vault em `%APPDATA%`/`%LOCALAPPDATA%`.
* Nunca grave nomes originais de arquivos em logs, SQLite ou arquivos auxiliares; senhas
  nunca são registradas.
* Decisões já tomadas pelo usuário: pastas do OneDrive "Arquivos sob Demanda" continuam
  recusadas (pontos de reparse); pastas protegidas trancam no lugar seguindo a regra de ouro de
  `docs/PASTAS_PROTEGIDAS.md` (nada legível é apagado sem um cofre conferido). Mudanças no
  formato do cofre ou no tratamento de reparse points: pergunte antes.
* Senha mestra e senha da Cópia criptografada: mínimo de 8 caracteres (pedido do usuário na
  0.3.2; era 12). PIN: 6 a 12 dígitos, regras em `docs/PASTAS_PROTEGIDAS.md` §2.

## Ambiente e comandos

```powershell
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt

# testes (a suíte completa leva ~15 min; -m slow marca os mais lentos)
$env:QT_QPA_PLATFORM='offscreen'; $env:QT_QPA_FONTDIR='C:\Windows\Fonts'
.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
.venv\Scripts\python.exe -m ruff check src tests
.venv\Scripts\python.exe -m ruff format --check src tests
.venv\Scripts\python.exe -m mypy src/owl_vault

# exe (roda a suíte antes; gera dist\OwlVault.exe, .sha256 e VERSAO.txt)
powershell -ExecutionPolicy Bypass -File packaging\build.ps1
dist\OwlVault.exe --selftest   # deve devolver 0
```

* **Instalar para testar:** feche o Owl Vault (a instância única faz o exe novo só "mostrar"
  o aberto) e abra uma CÓPIA do `dist\OwlVault.exe` (não o próprio arquivo: aberto, ele trava
  o `dist\` e o próximo build falha com "Acesso negado"). O exe se instala em
  `%LOCALAPPDATA%\Programs\Owl Vault` e atualiza o atalho do Menu Iniciar.
* Capturas de tela sem janela: `QT_QPA_PLATFORM=offscreen` com `QT_QPA_FONTDIR`.

## Pendências conhecidas

* Testes manuais do `docs/TEST_PLAN.md` ainda não feitos (pendrive retirado no meio, queda de
  energia, máquina limpa, telas reais a 125/150/175%, OneDrive real).
* Resíduos de baixa gravidade: PIN com três pedaços fáceis (000123000) e 901234000 são aceitos;
  diálogos "Resolver" passam um pouco da altura em telas com menos de ~700 px lógicos (200%).
