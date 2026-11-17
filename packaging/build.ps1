# Gera dist\OwlVault.exe e dist\OwlVault.exe.sha256
# Uso (na raiz do projeto):  powershell -ExecutionPolicy Bypass -File packaging\build.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "Ambiente virtual não encontrado: crie com 'py -3.13 -m venv .venv' e instale requirements-dev.txt" }

Write-Host "== Testes"
& $py -m pytest -q -p no:cacheprovider -m "not slow"
if ($LASTEXITCODE -ne 0) { throw "Testes falharam; build abortado." }

Write-Host "== Ícone"
& $py packaging\make_icon.py
if ($LASTEXITCODE -ne 0) { throw "Falha ao gerar o ícone." }

Write-Host "== PyInstaller"
& $py -m PyInstaller --noconfirm --clean --distpath dist --workpath build packaging\owl_vault.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller falhou." }

$exe = Join-Path $root "dist\OwlVault.exe"
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
"$hash  OwlVault.exe" | Out-File -Encoding ascii (Join-Path $root "dist\OwlVault.exe.sha256")
Write-Host "== Pronto: $exe"
Write-Host "   SHA-256: $hash"
