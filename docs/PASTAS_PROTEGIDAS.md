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
  rótulo ("index" | "sm" | "pin"). Gravação: tmp + flush + `os.replace` (temporários sempre
  limpos). O perfil já nasce com as DUAS cópias; a cópia anterior só passa para o `.bak` se
  for um perfil legível (um principal danificado nunca toma o lugar de um `.bak` bom). Erros
  32/33 ⇒ tenta de novo (nunca cai para o `.bak` por isso); `.bak` só se o principal não
  autenticar ou estiver ilegível, e então a sessão avisa (`NOTE_BACKUP_USED`).
* SM: tenta o cabeçalho (`kdf`/`wrap_sm`) do principal e, se não autenticar, o do `.bak`.
  Depois de um desbloqueio, o índice autêntico é re-selado nas duas cópias e o cabeçalho é
  conferido com a KEK do índice (`wrap_sm` ruim não se espalha; se os dois estiverem
  danificados e o `kdf` conferir, o `wrap_sm` é refeito com aviso `NOTE_MASTER_REBUILT`).
  Índice que não autentica em nenhuma cópia, ou as duas cópias ilegíveis ⇒ "perfil danificado"
  (`ProfileCorruptError`), nunca "senha incorreta": a interface renomeia as cópias para
  `*.danificado-<data>` (nunca apaga) e oferece "Recuperar minhas pastas com a senha mestra".
* PIN: 6–12 dígitos; recusados (mensagem "Este PIN é fácil de adivinhar"): todos iguais, no
  máximo 2 dígitos distintos, passo constante módulo 10 (inclui a fileira do teclado
  1234567890/0987654321 e 135791), bloco repetido (mesmo com a última repetição pela metade),
  `aabbcc`, palíndromos, linhas/colunas/diagonais do teclado numérico emendadas (ex.: 2580),
  contagens (102030, 246810, 9101112) e uma lista de PINs comuns; datas são recusadas antes,
  com a mensagem de data.
* Contador de erros: gravado em CADA cópia legível antes de derivar, mudando só
  `pin_failures`/`pin` (o índice e o cabeçalho de cada cópia são preservados; uma cópia
  ilegível só é regravada depois de um desbloqueio bem-sucedido). Efetivo = máximo; contador
  adulterado (não numérico) conta como esgotado; 5 erros ⇒ `wrap_pin` apagado (só a SM). PIN
  desativado em QUALQUER cópia = desativado (`pin_available` usa o mesmo critério). A SM zera o
  contador nas DUAS cópias, mas não reativa um PIN desativado (só "Alterar PIN"/PIN novo).
  `save()` relê o disco e mescla: contador = máximo(memória, principal, `.bak`), PIN `None` em
  qualquer cópia continua `None`, PIN trocado por outra sessão é adotado, `generation` =
  máximo + 1 — uma sessão antiga nunca reativa o PIN nem zera o contador.
* Falha do DPAPI (Windows reinstalado/senha redefinida) — ou a caixa do PIN malformada (blob
  ou salt não-hex, params ausentes/fora da política) — é tratada à parte: não conta como PIN
  errado; pede a SM e depois um PIN novo. Perfil ilegível ou pastas `.owlvault` encontradas ⇒
  NUNCA reabrir o assistente de criação (oferecer SM / "Recuperar uma pasta protegida").
* **Prática da SM**: no 1º desbloqueio após 1 dia e depois a cada 30 dias, pede a SM em vez do
  PIN. Assistente exige "Anotei minha senha mestra em um lugar seguro".
* Travamento automático: 5 min sem uso, Windows bloqueado (Win+L) ou suspensão ⇒ descarta
  chaves da interface e volta ao PIN. **Todo pedido pelo atalho pede o PIN**, mesmo com o app
  destravado; o pedido que chega por mensagem (app já aberto) ainda confirma com o nome da
  pasta. "Remover proteção" e "Alterar PIN" pedem o PIN.
* Limite honesto: quem usa a conta do Windows do usuário (ou o disco de uma conta sem senha)
  pode testar PINs fora do app com tempo; cópias antigas do perfil aceitam o PIN antigo.

## 3. Estados (índice) e regra de ouro

`aberta → trancando → apagando → trancada`; `trancada → abrindo → aberta | abertura_incompleta`;
`escondida` é um atributo de `trancada`; `abrindo` tem a subfase `restaurando` (a interface a
mostra como "abrindo"). O estado exibido vem do índice **reconciliado com o disco** (identidade
da pasta + conteúdo). Cada pasta guarda a **lista** de cofres
`{vault_id, papel: atual|novo|anterior|mantido|descartando, local}`.

**Regra de ouro (um único primitivo `_apagar_cofre`)**: um cofre só é apagado se seu vault_id é
o registrado, `complete.owl` é autêntico e o manifesto foi lido, **e** todo arquivo do seu
manifesto (caminho dobrado) está no manifesto de um cofre MAIS NOVO e concluído da mesma pasta,
ou (em "Remover proteção") existe em P, ou o usuário confirmou a lista exata do que falta. Senão
vira "versão anterior" (`mantido`, Precisa de atenção). Antes de apagar, o papel `descartando` é
gravado no índice; uma exclusão interrompida é retomada a cada início. O primitivo só remove
nomes do layout v1 (cabeçalho primeiro).

* A versão **mantida** é comparada pelo CONTEÚDO (SHA-256 no cofre mais novo; tamanho e data de
  modificação na pasta aberta), não só pelo caminho: o próximo trancamento não a apaga.
* Cofre ausente ou ilegível **nunca** conta como vazio: `kept_only_files`, `removal_missing`,
  `delete_kept` e `remove_protection` recusam (StateError) sem apagar nem esquecer nada; a lista
  mostra "versão anterior ilegível" (só "Tentar recuperar…"/salvamento de emergência) e, se a
  pasta oculta dela sumiu, "Esquecer a versão que sumiu" (`forget_missing_kept`, nada apagado).

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
   motor, **gravado antes de apagar qualquer original** (se a gravação falhar, a memória volta
   a `trancando` e o `novo` é descartado). Grava em P o marcador de restauração v1 (para
   "Desfazer").
5. **Exclusão dos originais**, por handle (`DELETE`, compartilhamento 0, `OPEN_REPARSE_POINT`):
   confere sem reparse, 1 vínculo, FileId/tamanho/LastWriteTime/ChangeTime iguais; então
   `FileDispositionInfoEx(DELETE|POSIX|IGNORE_READONLY)` no mesmo handle (não vai para a
   Lixeira). Divergência/erro ⇒ não apaga, anota e segue; no fim, lista tudo. Pastas do
   manifesto de baixo para cima pelo mesmo primitivo (só vazias).
6. Pendências ⇒ fica em `apagando` ("Precisa de atenção": **Continuar trancando** contra o MESMO
   cofre, ou **Desfazer** = `restore_vault(allow_resume)` com o marcador). **Nunca** roda outro
   `create_vault` com um cofre parcialmente aplicado. No "Desfazer", um conflito num caminho que
   o Owl Vault apagou (outro item colocado no lugar) faz o `novo` virar versão `mantido`, e a
   interface lista os conflitos.
7. Sem pendências: remove o marcador; renomeia (por handle, mesmo volume, sem substituir)
   `novo` → `P\.owlvault` e, **logo em seguida**, troca o papel para `atual` e grava o índice
   `trancada` — antes de qualquer outro passo. Espaço reservado e regra de ouro sobre o
   `anterior` vêm depois, como melhor esforço (falha ⇒ atenção, refeitos ao iniciar); remove a
   área temporária se vazia (só os nossos nomes; com itens desconhecidos, ela continua oculta).

### 4.2 Abrir
1. Localiza P; P deve ter só o espaço reservado + `.owlvault` com o vault_id esperado
   (qualquer outro item ⇒ Precisa de atenção, nada é sobrescrito; uma trava de restauração
   órfã é aceita e limpa).
2. Confere destino, caminho longo, FAT32 e espaço livre **antes** de gravar `abrindo` (sem
   espaço ⇒ recusa com o cofre ainda em P). Índice `abrindo`; renomeia `P\.owlvault` →
   `.owlvault-<id>\anterior`; remove o espaço reservado; tira atributos de P; marca P "não
   indexar conteúdo".
3. Grava a subfase `restaurando` e roda `restore_vault(anterior → P)` (motor v1); se falhar sem
   marcador, volta a `abrindo`. `aberta` só se `report.ok` e restaurados + pulados = arquivos
   do manifesto; senão `abertura_incompleta` (cofre anterior intocado). "P não vazia sem
   marcador" só conta como restaurada em `restaurando`/`abertura_incompleta`; em `abrindo`
   recusa ("Há item(ns) colocado(s)…").
4. Reaplica a marca "baixado da internet" (ZoneId≥3) aos arquivos registrados na trava; abre P
   no Explorer.

### 4.3 Esconder / Mostrar
Só de `trancada`: atributos oculto+sistema em P (nada é movido nem apagado) / retira.

### 4.4 Remover proteção (pede PIN)
Abre (se preciso); só apaga o cofre se a abertura terminou completa e P contém todos os
caminhos do manifesto; senão lista e pede confirmação. Tira do índice.

### 4.5 Recuperação
Ao iniciar (após PIN), reconcilia cada pasta isoladamente (um problema numa pasta não impede
as outras): retoma exclusões `descartando`; `trancando` ⇒ descarta `novo` e volta a `aberta` —
**exceto** se há marcador em P ou falta algum arquivo do manifesto em P: então vai para
`apagando` com atenção, e "Continuar" confere o conteúdo (SHA-256 do manifesto + impressão
digital estável) antes de apagar; um `novo` concluído nunca é apagado nesse caso. `apagando`
com o cofre já em `P\.owlvault` (mesmo vault_id) ⇒ conclui o trancamento; senão Precisa de
atenção (Continuar/Desfazer). `abrindo`/`restaurando` ⇒ "Continuar abrindo". `trancada` ⇒ aplica
a regra de ouro pendente e confere o espaço reservado (ver §5).
"Procurar a pasta…" (`relocate`) funciona em qualquer estado: reconhece a mesma pasta por volume
+ FileId (ou pelo vault_id do `.owlvault` dentro dela) e recalcula o local de cada cofre (dentro
da pasta ou na área temporária); recusa sem alterar nada se algum cofre não for achado. "Tirar
da lista" avisa quando há arquivos guardados fora da pasta (`forget_warning`): eles não
aparecem em "Recuperar". "Recuperar uma pasta protegida…" registra uma pasta com `.owlvault`
usando a SM; as KEKs trazidas assim ficam marcadas `recuperada` e não disparam o aviso de
"senha antiga" (só uma KEK `trocada` por "Criar nova senha mestra" o dispara).

## 5. Explorer
* `desktop.ini` em UTF-16LE com BOM, `IconResource=.owlvault.ico,0` (relativo: funciona em
  qualquer conta/PC), InfoTip "Pasta protegida pelo Owl Vault — os arquivos estão aqui,
  criptografados. Não apague."; `PathMakeSystemFolderW(P)` ao trancar e
  `PathUnmakeSystemFolderW(P)` ao abrir; avisos `SHChangeNotify`.
* Atalho `Abrir com Owl Vault.lnk` criado no processo (IShellLinkW + IPersistFile), apontando
  para o executável instalado em `%LOCALAPPDATA%\Programs\Owl Vault\OwlVault.exe` (o app se
  copia para lá na 1ª execução e cria atalho no Menu Iniciar). O ícone do atalho é o próprio
  executável e o `.lnk` não leva LinkInfo/rastreio: não guarda o caminho de P nem das
  pastas-mãe. O espaço reservado é idempotente e só mexe nos nossos nomes; o atalho é conferido
  (`shortcut_matches`) a cada início e antes de atender um pedido vindo dele, e refeito com
  aviso se estiver diferente. O texto "Como abrir esta pasta" orienta a abrir pelo Menu
  Iniciar ou pelo próprio Owl Vault.
* DACL restrita (conta atual + SYSTEM + Administradores; melhor esforço) na área temporária
  `.owlvault-<id>`, em `P\.owlvault` e em cada item do espaço reservado.
* "Unidade removível" vem do tipo da unidade (`is_removable_drive`), não do sistema de arquivos.
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
