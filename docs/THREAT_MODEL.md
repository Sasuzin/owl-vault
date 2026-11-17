# Owl Vault — Modelo de ameaças (v1 + pastas protegidas v2)

> Este documento descreve o que o Owl Vault tenta garantir e, principalmente, o que ele
> **não** garante. Revisado após revisão adversarial de design. **Não houve auditoria
> independente.**

## 1. Ativos

| Ativo | Onde existe |
|-------|-------------|
| Conteúdo dos arquivos | origem (texto claro), blobs (cifrado), RAM durante operações, pasta de teste (temporário) |
| Nomes, estrutura de pastas, mtime, hashes | origem, manifesto cifrado, diário cifrado, RAM |
| Tamanho exato de cada arquivo | **visível no cofre** (ver §6) |
| Senha | teclado/UI/RAM durante a operação |
| `master_key`, KEK, chaves derivadas | RAM durante a operação; `master_key` envolvida no cabeçalho |

## 2. Objetivos de segurança

* **C1 — Confidencialidade em repouso:** quem tem apenas os arquivos do cofre (pendrive
  perdido, cópia em outro disco, backup) e não tem a senha não consegue ler conteúdo,
  nomes, estrutura de pastas nem hashes.
* **I1 — Integridade/autenticidade:** qualquer alteração em cabeçalho, manifesto, blob,
  chunk (inclusive truncamento, extensão, reordenação, troca de blobs entre arquivos ou
  entre cofres) é detectada antes de entregar dados ao usuário como "restaurados".
* **S1 — Segurança operacional:** o aplicativo nunca altera, move, sobrescreve ou apaga a
  origem; nunca sobrescreve arquivos na restauração; nunca declara sucesso sem verificação,
  teste de restauração e nova varredura da origem.
* **R1 — Resistência a força bruta offline:** Argon2id com memória alta e salt único torna
  cada tentativa cara. A força real depende da senha escolhida.

## 3. Adversários considerados

| ID | Adversário | Capacidade | Resultado esperado |
|----|-----------|------------|--------------------|
| A1 | Acesso ao cofre em repouso | lê todos os arquivos do cofre | C1 vale (exceto vazamentos de §6) |
| A2 | Adulteração do cofre | modifica/trunca/reordena/troca bytes e arquivos do cofre | I1: detectado; restauração recusa o arquivo afetado |
| A3 | Força bruta offline | GPU/ASIC contra o cabeçalho | Custo Argon2id por tentativa; senha fraca ainda cai |
| A4 | Manifesto malicioso (cofre criado por terceiro) | cofre válido com nomes hostis | Validação estrita: sem path traversal, nomes reservados, colisões, recursos abusivos; Mark-of-the-Web propagado aos arquivos restaurados de cofres baixados |
| A5 | Cabeçalho malicioso | parâmetros KDF/tamanhos absurdos | Limites de leitura iguais aos de criação (≤ 1 GiB, t ≤ 16, p ≤ 8) e checagem de memória disponível antes de derivar; custo máximo limitado (a derivação em si não é cancelável) |
| A6 | Falhas acidentais | queda de energia, disco cheio, cancelamento, antivírus, mídia removida | Estado consistente (NTFS/ReFS), retomada, nada verificado é sobrescrito |

Nota: um cofre de terceiro, aberto com a senha que esse terceiro escolheu, é "autêntico"
criptograficamente; a defesa contra conteúdo hostil é a validação de caminhos e limites.

## 4. Fora do escopo (o Owl Vault NÃO protege contra)

* **Malware** ou qualquer processo com os privilégios do usuário ou de administrador na
  máquina enquanto o Owl Vault é usado (keyloggers, leitura de memória, troca do executável).
* **Quem observa o sistema durante o uso** (administrador, acesso remoto, gravação de tela).
* **A própria pasta original:** enquanto não for removida manualmente, continua legível
  para qualquer pessoa com acesso ao disco/conta. O Owl Vault nunca diz que ela está
  "protegida".
* **Cópias e rastros fora do cofre**, que o Owl Vault não controla nem remove:
  * Lixeira; Versões Anteriores / Cópias de Sombra (VSS); Histórico de Arquivos; pontos de
    restauração; backups (inclusive em nuvem); versões no OneDrive/Google Drive/Dropbox;
  * índice do Windows Search (indexa nomes **e conteúdo**); cache de miniaturas
    (`thumbcache_*.db`); listas de Recentes/Jump Lists; Prefetch; caches de aplicativos;
  * arquivos temporários e de autorrecuperação de outros programas; `pagefile.sys`,
    `hiberfil.sys`, despejos de memória;
  * quarentena/telemetria de antivírus;
  * dados residuais após apagar: em **SSD** (wear leveling, TRIM) e mesmo em HDD não há
    garantia de apagamento; arquivos pequenos podem estar residentes na MFT do NTFS;
  * seletores de pasta do Windows/Qt podem lembrar a última pasta usada no registro (MRU do
    ComDlg32, `QtProject\FileDialog`). O Owl Vault não grava caminhos em suas próprias
    configurações e limpa o histórico do Qt por melhor esforço.
* **Apagamento seguro:** não é oferecido nem prometido.
* **Memória do processo:** Python não permite apagar segredos da memória de forma garantida
  (strings imutáveis, cópias, swap/hibernação). Senha e chaves podem permanecer em
  RAM/pagefile por tempo indeterminado.
* **Rollback do cofre inteiro:** substituir o cofre todo por uma versão antiga e válida dele
  mesmo não é detectado. Cofres v1 são de escrita única.
* **Senha antiga após uma futura troca de senha** (não existe na v1): qualquer cópia antiga do
  cabeçalho continua abrindo o cofre com a senha antiga; após vazamento, crie um cofre novo.
* **Canais laterais**, **coerção**, **negação plausível** (o cofre é obviamente um cofre).
* **Metadados não preservados:** ACLs, dono, atributos (oculto/sistema/somente leitura),
  data de criação, fluxos alternativos NTFS (ADS) — inclusive o Mark-of-the-Web original de
  cada arquivo —, compressão/EFS. Só conteúdo, nome relativo e data de modificação.
* **Permissões da restauração:** arquivos restaurados herdam as permissões da pasta de
  destino. Na raiz de volumes secundários e em `C:\Users\Public` outras contas locais podem
  lê-los; FAT/exFAT não têm permissões. Recomenda-se restaurar dentro do próprio perfil.
* **Corrida local na restauração:** outra conta local com escrita no destino poderia tentar
  trocar pastas por junctions durante a restauração; a v1 confere o caminho final de cada
  handle criado e renomeia pelo handle, mas não cria arquivos relativos a handles de pasta.

## 5. Limitações práticas de "proteger uma pasta existente" no Windows

1. **Criptografar uma cópia não remove o original.** A proteção só existe para quem tiver
   acesso *apenas* ao cofre. Para que a máquina deixe de expor os dados, o usuário teria que
   remover a origem — e mesmo assim os rastros de §4 continuam.
2. **Apagar não é destruir.** Em SSD, blocos antigos podem sobreviver; o Windows guarda
   cópias em VSS/Histórico/Lixeira; OneDrive guarda versões. A v1 não apaga nada e não
   promete apagamento seguro.
3. **O Windows Search e o cache de miniaturas já viram o conteúdo.** Nomes e trechos podem
   continuar no índice depois que a origem some.
4. **Pastas do OneDrive (Arquivos sob Demanda):** todo arquivo e pasta dentro de uma raiz de
   sincronização é ponto de reparse (tag de nuvem), **mesmo com "Sempre manter neste
   dispositivo"**. Seguindo o requisito "recusar reparse points", a v1 recusa essas pastas:
   "Pastas do OneDrive (Arquivos sob Demanda) não são suportadas na v1; copie a pasta para
   fora do OneDrive e use a cópia." Com o Backup de pastas do OneDrive (Área de Trabalho,
   Documentos, Imagens) isso afeta muitos usuários do Windows 11. Aceitar arquivos de nuvem
   já hidratados seria um desvio do requisito e só será feito com aprovação explícita do
   responsável pelo produto. **Decisão do responsável pelo produto (17/11/2026): manter a
   recusa na v1.**
5. **Arquivos em uso** podem estar bloqueados (Outlook PST, bancos de dados) ou mudar durante
   a leitura. A v1 abre cada arquivo negando escrita a outros processos durante a leitura,
   acusa "arquivo em uso" e nunca grava um estado inconsistente como válido.
6. **Pendrives FAT/exFAT** não têm journaling: remover a mídia durante a gravação pode
   corromper o cofre; FAT32 não aceita arquivos ≥ 4 GiB. O app bloqueia/avisa antes.
7. **Recomendação complementar:** BitLocker / Criptografia de Dispositivo para o disco
   inteiro protege contra roubo do computador desligado; o Owl Vault serve para gerar
   cópias criptografadas portáteis (pendrive, HD externo, backup).

## 6. Vazamentos aceitos do formato v1

Sem a senha, um observador do cofre aprende: número de arquivos; o **tamanho exato** de cada
arquivo (em claro no cabeçalho do blob e dedutível do tamanho do blob); datas dos arquivos
do cofre; tamanho aproximado do manifesto; parâmetros do Argon2id; que se trata de um cofre
Owl Vault. Com tamanhos exatos, alguém pode **confirmar a presença de um arquivo ou coleção
conhecidos** (um vídeo específico, um conjunto de fotos já publicado). A ordem de cifragem é
embaralhada a cada execução, então datas/ordem dos blobs não revelam a ordem dos caminhos.
Não aprende nomes, estrutura, conteúdo, hashes nem datas originais.

## 7. Mitigações principais (rastreáveis ao código)

| Ameaça | Mitigação |
|--------|-----------|
| Leitura do cofre (A1) | AES-256-GCM com chave por arquivo; manifesto e diário cifrados; nomes de blob aleatórios; ordem embaralhada |
| Adulteração (A2) | GCM em cada chunk; cabeçalho do blob no AAD; nonce = índice+final; tamanho exato; `file_id`/`vault_id` vinculados; SHA-256 no manifesto |
| Força bruta (A3) | Argon2id calibrado (64–512 MiB, t ≥ 3, ~0,5 s na criação); senha mínima de 12 caracteres; indicador de força |
| Manifesto hostil (A4) | componentes validados; sem `..`, separadores, `:` (ADS), nomes reservados; fold de caixa; limites de tamanho/datas; `CREATE_NEW`/rename sem sobrescrita; caminho final de cada handle conferido; Mark-of-the-Web |
| Cabeçalho hostil (A5) | limites de m/t/p e tamanhos checados antes de qualquer alocação; memória disponível conferida |
| Falhas (A6) | tmp+flush+rename sem substituição no mesmo volume; diário em segmentos write-once; máquina de estados autenticada + `complete.owl`; trava de escritor único; cancelamento em fronteiras; verificação com E/S sem cache + teste de restauração + rescan da origem antes de "sucesso"; cópias duplas de cabeçalho e manifesto com leitura normativa |
| Origem alterada/em uso | origem aberta negando escrita a outros processos; FileId/tamanho/datas do handle antes e depois; rescan final |
| Aliases de caminho | checagens de "dentro de" usam caminho final resolvido (GUID do volume), não strings |
| Reuso de nonce | `file_id` gerado dentro da API de cifragem; `CREATE_NEW`; chave por escrita nos contêineres |
| Vazamento por logs | sem log persistente; sem caminhos em configurações; sem SQLite; teste de restauração sem nomes |

## 8. Riscos residuais e do projeto

* **Perda da senha = perda dos dados.** Não há recuperação, por design.
* **Bug no próprio Owl Vault** pode tornar dados irrecuperáveis. Mitigações: verificação
  pós-criação com teste de restauração, suíte de testes adversariais, e a regra de manter a
  origem e backups externos até o usuário validar o cofre (de preferência em outro computador).
* **Dependências** (`cryptography`/OpenSSL, `argon2-cffi`, PySide6, PyInstaller) podem ter
  vulnerabilidades; versões fixadas e atualizadas conscientemente.
* **Executável não assinado** pode ser trocado por um malicioso; distribuir com SHA-256.
* **Falsos positivos de antivírus** com executáveis PyInstaller.
* **Teste de restauração grava conteúdo em texto claro temporário** (sem nomes originais:
  `<file_id>.chk`), arquivo a arquivo, numa pasta do **volume da origem**, e o apaga em
  seguida sem garantia de apagamento seguro — mesma classe de rastro de §4.
* **Elevação:** rodar como administrador amplia o que um erro poderia afetar; o app avisa.


## 9. Pastas protegidas (v2 — "trancar no lugar")

A v2 muda o objetivo S1: o Owl Vault **apaga** as cópias legíveis da pasta escolhida depois de
guardá-las cifradas dentro dela (`P\.owlvault`, um cofre v1). Detalhes normativos em
[PASTAS_PROTEGIDAS.md](PASTAS_PROTEGIDAS.md).

### Objetivos

* **C2 — Pasta trancada:** quem lê o disco, copia a pasta ou usa outra conta do Windows vê só
  dados cifrados, o ícone, o atalho "Abrir com Owl Vault", "Como abrir esta pasta.txt" e o
  **nome da pasta**. Conteúdo, nomes internos e estrutura ficam no cofre (C1).
* **S2 — Nunca perder dados:** um original só é apagado depois de o cofre novo terminar com
  sucesso (verificação + teste de restauração + nova varredura) e de ser conferido no próprio
  handle (identidade, tamanho, datas); um cofre só é apagado quando tudo o que ele contém está
  num cofre mais novo e concluído da mesma pasta ou o usuário confirmou a lista exata do que
  falta (regra de ouro). Todo estado intermediário é gravado no perfil e pode ser retomado
  ("Continuar trancando", "Desfazer", "Continuar abrindo").
* **A1′ — Perfil:** o índice (nomes e caminhos das pastas, estados, KEKs) só existe cifrado
  com a chave do perfil (PK); a PK é aberta pela senha mestra (Argon2id) ou pelo PIN
  (Argon2id + DPAPI da conta).

### Adversários adicionais

| ID | Adversário | Resultado esperado |
|----|-----------|--------------------|
| B1 | Outra conta / outro computador / disco removido | C2 vale; o PIN não funciona fora da conta (DPAPI); só a senha mestra abre |
| B2 | Alguém com acesso à **sua conta** com o app travado | Não abre pastas trancadas sem PIN/senha mestra. Pode tentar PINs: 5 tentativas por cópia do perfil, cada uma custa um Argon2id; quem copia/restaura o arquivo do perfil consegue mais tentativas — o PIN é fraco por natureza (6–12 dígitos) e isso está escrito na tela de limites |
| B3 | Alguém com acesso à sua conta com o app **destravado** ou pasta **aberta** | Fora do escopo: lê tudo o que estiver aberto. Mitigação: travamento automático (5 min, Win+L, suspensão) e "Trancar e sair" |
| B4 | Malware na sua conta | Fora do escopo (§4) |
| B6 | Outra conta comum do computador com permissão de escrita na pasta (pastas criadas direto na raiz de C: ou de D: herdam "Usuários autenticados: Modificar") | Não consegue trocar o atalho nem ler a área temporária: esses itens recebem permissões só da conta dona (+SYSTEM/Administradores). Pode renomear/mover a pasta trancada: o Owl Vault reconhece a pasta pelo identificador do NTFS e pelo cofre dentro dela |
| B5 | Itens colocados numa pasta trancada | Não são apagados nem cifrados; a pasta vai para "Precisa de atenção" e a abertura espera o usuário movê-los |

### Limites conhecidos

* O atalho "Abrir com Owl Vault" contém o caminho do programa instalado (com o nome da conta
  do Windows) e o código da pasta; não contém nome do computador, série do volume, LinkInfo
  nem o caminho da pasta (o ícone é o do próprio executável).
* A DACL restrita (conta atual + SYSTEM + Administradores, sem herança) na área temporária
  `.owlvault-<código>`, em `P\.owlvault` e no espaço reservado é **melhor esforço**: se o
  Windows recusar a troca, esses itens ficam com as permissões herdadas da pasta-mãe (que podem
  dar escrita a "Usuários autenticados", ver B6) e o Owl Vault segue sem erro.
* O atalho é conferido a cada início e antes de atender um pedido vindo dele; se estiver
  diferente, é refeito e o app avisa. Entre a troca e a conferência, porém, quem clicar no
  atalho trocado executa o que estiver nele — por isso "Como abrir esta pasta.txt" orienta a
  abrir pelo Menu Iniciar.
* O nome da pasta trancada é visível; "Esconder do Explorer" usa atributos oculto+sistema e
  não é criptografia.
* Trancar não apaga rastros do Windows nem sobrescreve setores do SSD (§4, §5).
* Enquanto aberta, a pasta ocupa o dobro do espaço (cópia cifrada guardada na pasta oculta
  `.owlvault-<código>` ao lado) e é legível.
* Na abertura, data de criação, atributos, permissões e fluxos alternativos não voltam
  (como na restauração v1); a marca "baixado da internet" é regravada nos arquivos que a
  tinham.
* Quem apagar a pasta trancada apaga os dados cifrados. Backup = copiar a pasta inteira.
