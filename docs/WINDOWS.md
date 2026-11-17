# Owl Vault — Notas para Windows 10/11

## Instalação

Na primeira execução, o `OwlVault.exe` se copia para `%LOCALAPPDATA%\Programs\Owl Vault\`
e cria o atalho **Owl Vault** no Menu Iniciar — só para o seu usuário, sem administrador. Os
atalhos "Abrir com Owl Vault" das pastas trancadas apontam para essa cópia; não a apague.
Ao rodar uma versão nova do `OwlVault.exe`, a cópia instalada é atualizada (se estiver aberta,
a atualização acontece na próxima vez).

O Windows SmartScreen pode mostrar "O Windows protegeu o computador" porque o executável não
é assinado. Confira o SHA-256 (`Get-FileHash .\OwlVault.exe -Algorithm SHA256`) antes de clicar
em "Executar assim mesmo". Não rode como administrador — não é necessário.

O executável é *onefile*: a cada abertura ele se descompacta numa pasta temporária, o que leva
alguns segundos. Alguns antivírus podem desconfiar de executáveis PyInstaller (falso positivo).

## Pastas protegidas (v2)

* Só em unidades **NTFS** (ou ReFS). Pendrives FAT/exFAT: use ☰ → Cópia criptografada.
* Não dá para proteger pastas do Windows inteiras (Área de Trabalho, Documentos, Downloads,
  Imagens, Músicas, Vídeos, a pasta do usuário) nem pastas que as contenham: crie uma pasta
  dentro delas (ex.: `Documentos\Particular`) e proteja essa.
* Pastas do OneDrive são recusadas (a nuvem guarda cópias que o Owl Vault não apaga).
* Ao lado da pasta (na pasta-mãe) o Owl Vault cria, durante as operações, uma pasta oculta
  `.owlvault-<código>` com os dados cifrados temporários e a versão anterior; ela some
  quando não é mais necessária. Não a apague.
* A pasta trancada recebe o ícone da coruja por um `desktop.ini` oculto. Se o Explorer
  demorar a mostrar o ícone, aperte F5.
* "Esconder do Explorer" usa os atributos *oculto* + *sistema*: some do Explorer mesmo com
  "Mostrar itens ocultos" ligado, mas aparece para quem ativar "Mostrar arquivos protegidos do
  sistema operacional".
* Copie a pasta trancada **inteira** (inclusive os itens ocultos) para ter backup; em outro
  computador use ☰ → Recuperar uma pasta protegida.

## Onde guardar uma cópia criptografada (modo v1)

* **HD externo NTFS**: recomendado (journaling, renomeação atômica, sem limite de 4 GiB).
* **Pendrive FAT32**: arquivos de até 4 GiB − 1; sem journaling; o app bloqueia arquivos grandes
  e pede confirmação. Use "Remover hardware com segurança" e rode **Verificar** depois.
  FAT32 também limita ~65 mil itens por pasta (o cofre distribui os blobs em 256 subpastas).
* **exFAT**: sem limite de 4 GiB, mas também sem journaling (mesmos cuidados do FAT32).
* **Unidade de rede / mapeada**: não suportado na v1.
* **Dentro do OneDrive/Dropbox**: funciona como destino, mas o serviço enviará o cofre à nuvem
  (cifrado). Como origem, pastas do OneDrive com Arquivos sob Demanda são recusadas.

## Pastas recusadas como origem (cópia criptografada)

Raiz de unidade; Windows; Program Files; ProgramData; AppData; a pasta do perfil inteira (ou
`C:\Users`) — escolha uma subpasta, como `Documentos\Projeto`; Lixeira e System Volume
Information; pastas com links, junctions, pontos de montagem ou itens do OneDrive (Arquivos sob
Demanda — mesmo marcados como "Sempre manter neste dispositivo"; copie a pasta para fora do
OneDrive e use a cópia). A recusa do OneDrive é uma decisão de produto da v1 (17/11/2026).

## Arquivos em uso

Durante a leitura, o Owl Vault impede que outros programas gravem no arquivo. Se um programa já
estiver com o arquivo aberto para escrita (Outlook, bancos de dados, alguns editores), a
pré-verificação acusa "arquivo em uso": feche o programa e tente de novo.

## Acesso controlado a pastas (Windows Defender)

Se estiver ativo, o Defender pode bloquear a gravação do cofre ou da restauração em pastas
protegidas (Documentos, Imagens...). O Owl Vault mostra "acesso negado" e sugere permitir o
`OwlVault.exe` em Segurança do Windows → Proteção contra ransomware → Permitir um aplicativo.

## Caminhos longos

O Owl Vault usa caminhos estendidos (`\\?\`) e funciona com caminhos de mais de 260
caracteres sem mudar configurações do Windows. Alguns programas antigos, porém, podem não abrir
arquivos restaurados em caminhos muito longos (o app avisa).

## Rastros do Windows fora do controle do Owl Vault

O seletor de pastas do Windows lembra pastas recentes (registro ComDlg32); o índice do Windows
Search, o cache de miniaturas, a Lixeira e as Versões anteriores podem guardar nomes e conteúdo
da pasta original. Para proteção do disco inteiro use também o BitLocker/Criptografia de
dispositivo.

## Executar a partir do código

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip install -e . --no-deps
.\.venv\Scripts\python.exe -m owl_vault
```
