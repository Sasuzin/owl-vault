# Owl Vault — Pastas protegidas ("trancar no lugar") — design v2.1

Status: **normativo para a v2** (revisado após revisão adversarial de design: 4 revisores,
34 apontamentos, 16 decisões aplicadas). Decisão do responsável pelo produto: proteger a pasta
**no próprio lugar**, com ícone do Owl Vault, PIN no dia a dia e opção de esconder a pasta.
Interface simplificada: o usuário só digita PIN ou senha mestra; todo o resto é escolher pasta
ou clicar em botão.

Este documento substitui, **para esta funcionalidade**, duas regras da v1: "nunca apagar
originais" e "sem integração com o Explorer". O formato do cofre (FORMAT.md) não muda.

## 1. Onde ficam os dados

* **Pasta trancada P** contém só: `desktop.ini`, `.owlvault.ico` (ocultos+sistema),
  `Abrir com Owl Vault.lnk`, `Como abrir esta pasta.txt` e **`P\.owlvault\`** (oculta+sistema)
  — o cofre v1 com os arquivos criptografados. Copiar/fazer backup da pasta leva os dados; a
  pasta abre com a senha mestra em qualquer computador. **Apagar a pasta apaga os arquivos.**
* **Área temporária** `<pai de P>\.owlvault-<id>\` (oculta+sistema, mesmo volume, fora de P):
  `novo\` (cofre em criação), `anterior\` (cofre enquanto a pasta está aberta) e a pasta do
  teste de restauração. Se não der para escrever na pasta-mãe de P ⇒ recusa antes de cifrar.
* Só **NTFS/ReFS** (FAT/exFAT recusados: sem journaling; use a Cópia criptografada).

## 2. Perfil, senha mestra (SM) e PIN

`%LOCALAPPDATA%\Owl Vault\perfil.owlp` (+ `.bak`), JSON com partes cifradas:

* Na criação: calibra **salt_perfil + params** (Argon2id) e deriva **KEK_SM = Argon2id(SM)**.
  Todos os cofres das pastas são criados com esse salt/params e a master_key envolvida por
  KEK_SM — o formato v1 não muda: cada cofre abre só com a SM, em qualquer PC.
* **PK** (32 bytes aleatórios) cifra o **índice** (AES-256-GCM). O índice guarda KEK_SM, as
  pastas (identidade, caminho em cache, estado, cofres, impressões digitais para a exclusão).
* `wrap_sm = AES-GCM(KEK_SM, PK)` (recuperação) e `wrap_pin = DPAPI_usuário(AES-GCM(Argon2id(PIN),
  PK))` (dia a dia). **O PIN nunca dá acesso à SM** (só à PK ⇒ KEK_SM). Cópia criptografada
  (Ferramentas) pede a SM digitada e usa salt novo.
* Nonce aleatório a cada gravação; AAD = cabeçalho (magic, versão, profile_id, generation) +
  rótulo ("index" | "sm" | "pin"). Gravação: tmp + flush + `os.replace`, cópia anterior em
  `.bak`. Erros 32/33 ⇒ tenta de novo (nunca cai para o `.bak` por isso); `.bak` só se o
  principal não autenticar, com aviso.
* PIN: 6–12 dígitos; recusados todos iguais, sequências e datas. Contador de erros gravado
  nas DUAS cópias antes de derivar; efetivo = máximo; 5 erros ⇒ `wrap_pin` apagado (só a SM).
* Falha do DPAPI (Windows reinstalado/senha redefinida) é tratada à parte: não conta como PIN
  errado; pede a SM e depois um PIN novo. Perfil ilegível ou pastas `.owlvault` encontradas ⇒
  NUNCA reabrir o assistente de criação (oferecer SM / "Recuperar uma pasta protegida").
* **Prática da SM**: no 1º desbloqueio após 1 dia e depois a cada 30 dias, pede a SM em vez do
  PIN. Assistente exige "Anotei minha senha mestra em um lugar seguro".
* Travamento automático: 5 min sem uso, Windows bloqueado (Win+L) ou suspensão ⇒ descarta
  chaves da interface e volta ao PIN. **Todo pedido pelo atalho pede o PIN**, mesmo com o app
  destravado. "Remover proteção" e "Alterar PIN" pedem o PIN.
* Limite honesto: quem usa a conta do Windows do usuário (ou o disco de uma conta sem senha)
  pode testar PINs fora do app com tempo; cópias antigas do perfil aceitam o PIN antigo.

## 3. Estados (índice) e regra de ouro

`aberta → trancando → apagando → trancada`; `trancada → abrindo → aberta | abertura_incompleta`;
`escondida` é um atributo de `trancada`. O estado exibido vem do índice **reconciliado com o
disco** (identidade da pasta + conteúdo). Cada pasta guarda a **lista** de cofres
`{vault_id, papel: atual|novo|anterior, local}`.

**Regra de ouro (um único primitivo `apagar_cofre`)**: um cofre só é apagado se seu vault_id é o
registrado e `complete.owl` é autêntico, **e** todo arquivo do seu manifesto (caminho dobrado)
está no manifesto de um cofre MAIS NOVO e concluído da mesma pasta, ou (em "Remover proteção")
existe em P, ou o usuário confirmou a lista exata do que falta. Senão vira "versão anterior"
(Precisa de atenção). O primitivo só remove nomes do layout v1.

## 4. Algoritmos

### 4.1 Trancar (de "aberta")
1. Localiza P pela identidade (GUID do volume + FileId); pré-verificação do modo trancar:
   regras da v1 + NTFS/ReFS + não é pasta conhecida do Windows nem ancestral de uma (inclui
   redirecionadas e Públicas) + sem `desktop.ini` com CLSID + sem hard links (bloqueio) + não
   está dentro/contém outra pasta protegida + sonda de escrita na pasta-mãe + sonda de
   exclusão em cada arquivo/pasta (Acesso controlado a pastas, somente leitura, em uso).
2. Se houver cofre `anterior`: compara caminhos ⇒ arquivos apagados desde a abertura ⇒ pede
   confirmação com a lista (grava a lista aceita).
3. Índice `trancando` (+ cofre `novo`). `create_vault(P → .owlvault-<id>\novo,
   test_parent=.owlvault-<id>)` com a KEK do perfil. Falha/cancelamento/divergência ⇒ apaga o
   `novo` (é nosso), volta a `aberta`. **Nada da pasta é apagado nesta fase.**
4. Índice `apagando` + impressões digitais por arquivo (FileId, tamanho, mtime, ctime) vindas do
   motor. Grava em P o marcador de restauração v1 (para "Desfazer").
5. **Exclusão dos originais**, por handle (`DELETE`, compartilhamento 0, `OPEN_REPARSE_POINT`):
   confere sem reparse, 1 vínculo, FileId/tamanho/LastWriteTime/ChangeTime iguais; então
   `FileDispositionInfoEx(DELETE|POSIX|IGNORE_READONLY)` no mesmo handle (não vai para a
   Lixeira). Divergência/erro ⇒ não apaga, anota e segue; no fim, lista tudo. Pastas do
   manifesto de baixo para cima pelo mesmo primitivo (só vazias).
6. Pendências ⇒ fica em `apagando` ("Precisa de atenção": **Continuar trancando** contra o MESMO
   cofre, ou **Desfazer** = `restore_vault(allow_resume)` com o marcador). **Nunca** roda outro
   `create_vault` com um cofre parcialmente aplicado.
7. Sem pendências: remove o marcador; renomeia (por handle, mesmo volume, sem substituir)
   `novo` → `P\.owlvault`; grava o espaço reservado; índice `trancada`; aplica a regra de ouro
   ao `anterior`; remove a área temporária se vazia.

### 4.2 Abrir
1. Localiza P; P deve ter só o espaço reservado + `.owlvault` com o vault_id esperado
   (qualquer outro item ⇒ Precisa de atenção, nada é sobrescrito).
2. Índice `abrindo`; renomeia `P\.owlvault` → `.owlvault-<id>\anterior`; remove o espaço
   reservado; tira atributos de P; marca P "não indexar conteúdo".
3. `restore_vault(anterior → P)` (motor v1). `aberta` só se `report.ok` e restaurados +
   pulados = arquivos do manifesto; senão `abertura_incompleta` (cofre anterior intocado).
4. Reaplica a marca "baixado da internet" (ZoneId≥3) aos arquivos registrados na trava; abre P
   no Explorer.

### 4.3 Esconder / Mostrar
Só de `trancada`: atributos oculto+sistema em P (nada é movido nem apagado) / retira.

### 4.4 Remover proteção (pede PIN)
Abre (se preciso); só apaga o cofre se a abertura terminou completa e P contém todos os
caminhos do manifesto; senão lista e pede confirmação. Tira do índice.

### 4.5 Recuperação
Ao iniciar (após PIN), reconcilia cada pasta: `trancando` ⇒ descarta `novo` e volta a
`aberta`; `apagando` ⇒ Precisa de atenção (Continuar/Desfazer); `abrindo` ⇒ retoma a
restauração. "Recuperar uma pasta protegida…" registra uma pasta com `.owlvault` usando a SM.

## 5. Explorer
* `desktop.ini` em UTF-16LE com BOM, `IconResource=.owlvault.ico,0` (relativo: funciona em
  qualquer conta/PC), InfoTip "Pasta protegida pelo Owl Vault — os arquivos estão aqui,
  criptografados. Não apague."; `PathMakeSystemFolderW(P)` ao trancar e
  `PathUnmakeSystemFolderW(P)` ao abrir; avisos `SHChangeNotify`.
* Atalho `Abrir com Owl Vault.lnk` criado no processo (IShellLinkW + IPersistFile), apontando
  para o executável instalado em `%LOCALAPPDATA%\Programs\Owl Vault\OwlVault.exe` (o app se
  copia para lá na 1ª execução e cria atalho no Menu Iniciar); refeito a cada início se o alvo
  mudou.
* Instância única: mutex `Local\OwlVault-<SID>` + QLocalServer; o lançador chama
  `AllowSetForegroundWindow`; o principal traz a janela para frente.

## 6. Limites (honestos)
* Pasta aberta = legível por quem usa o computador. O nome da pasta trancada continua visível
  (use Esconder). Esconder tira do Explorer, mas quem mostra arquivos protegidos do sistema vê
  que ela existe (não o conteúdo).
* Apagar os originais não remove rastros físicos (SSD, Lixeira de outros programas, Versões
  anteriores, OneDrive, índice do Windows, miniaturas, Recentes). Recomenda-se BitLocker.
* O PIN é mais fraco que a senha mestra (ver §2). Esquecer a SM = perder todas as pastas.
* Ao abrir voltam nome, conteúdo e data de modificação; data de criação, atributos e
  permissões não voltam. Enquanto aberta, a pasta ocupa o dobro do espaço.

## 7. Telas
Ver a especificação consolidada pela revisão (T1–T15) em [UI_SPEC_V2.md](UI_SPEC_V2.md).
