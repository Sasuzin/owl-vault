# Owl Vault — Arquitetura (v1)

Revisado após revisão adversarial de design (4 revisores independentes + triagem). O formato
binário está em [FORMAT.md](FORMAT.md); ameaças em [THREAT_MODEL.md](THREAT_MODEL.md);
matriz de testes em [TEST_PLAN.md](TEST_PLAN.md).

## 1. O que a v1 faz (e não faz)

1. **Criar cofre** — lê uma pasta de origem (somente leitura) e grava uma *cópia
   criptografada* numa pasta de cofre nova; verifica tudo e faz um **teste de restauração**
   comparando SHA-256 antes de declarar sucesso.
2. **Verificar cofre** — somente leitura: autentica cabeçalhos, manifestos, registro de
   conclusão e todos os chunks; confere hashes e anomalias em `data/`.
3. **Restaurar** — descriptografa para uma pasta nova e vazia, validando o manifesto inteiro
   antes de escrever qualquer coisa.

Não faz: driver, sistema de arquivos virtual, criptografia transparente, integração com o
Explorer, apagamento da origem, "exclusão segura", nuvem, telemetria.

**A pasta de origem nunca é alterada.** Arquivos de origem são abertos apenas para leitura
(`GENERIC_READ`); nenhum caminho de código escreve, renomeia ou remove na origem, e todo
destino é verificado (com caminhos resolvidos) para não estar dentro dela.

## 2. Camadas

```
src/owl_vault/
  domain/        modelos, erros, limites, validação de nomes Windows, fold de caixa (sem E/S)
  crypto/        Argon2id + política de limites (kdf), HKDF (keys), AES-GCM (aead),
                 cifragem/decifragem de blobs em chunks (stream)
  storage/       formatos binários (header, blob, container), layout do cofre, diário,
                 E/S Win32 via ctypes (winfs: CreateFileW, final path, FileId, travas,
                 leitura sem cache, rename por handle), escrita sem substituição, varredura
                 segura, ponto de injeção de falhas (faults)
  application/   casos de uso: preflight, create (+retomada), verify, restore, salvage;
                 contratos de progresso/cancelamento (sem Qt)
  cli/           CLI de laboratório (argparse); senha só por getpass ou --password-stdin
  ui/            PySide6: janela, workers (QThread) e sinais; nenhuma criptografia aqui
tests/           pytest — unidade, integração, adversariais (somente pastas temporárias)
packaging/       spec do PyInstaller, build.ps1, version info, ícone
```

Dependências: `ui → application → (storage, crypto, domain)`; `storage → (crypto, domain)`;
`crypto → domain`. A UI nunca vê chaves nem bytes cifrados.

## 3. Progresso e cancelamento

`application/progress.py`: `CancelToken` (`threading.Event`) e `ProgressSink` (Protocol:
`stage`, `advance`, `info`, `warning`). CLI imprime; UI emite sinais Qt de um `QThread`.
Cancelamento é verificado entre chunks e entre arquivos. A derivação Argon2id não é
cancelável (a UI mostra "derivando chave (não cancelável)").

## 4. Fluxos

### 4.0 Máquina de estados da criação

```
INIT → ENCRYPTING → MANIFEST_WRITTEN → VERIFIED → RESTORE_TESTED → COMPLETE
```

Gravada no diário **autenticado** (campo `phase` de cada segmento) e espelhada no
`state.json` (melhor esforço). `COMPLETE` = existe `complete.owl` autêntico.

### 4.1 Criar cofre

1. **Preflight (sem escrita)** — `application/preflight.py`. Todos os caminhos passam por
   `winfs.resolve()` (abre o caminho ou o ancestral existente mais próximo e usa
   `GetFinalPathNameByHandleW` com nome de volume GUID e DOS, número de série do volume e
   FileId). Comparações de "dentro de"/"igual"/"ancestral" usam listas de componentes
   resolvidas e dobradas — nunca strings digitadas (cobre 8.3, `subst`, junctions, montagens).
   * **Origem**: existe, é pasta, não é ponto de reparse, não é raiz de volume; não é igual,
     interna ou ancestral de Windows, Program Files(x86), ProgramData, AppData (Roaming/Local);
     não é igual nem ancestral do perfil do usuário ou de `C:\Users`; não está em System
     Volume Information/`$Recycle.Bin`; caminho de rede ⇒ recusa (DOS final path `\\?\UNC\`
     ou falha ao obter o nome de volume GUID).
   * **Cofre, destino de restauração e pasta de teste**: locais, fora de Windows/Program
     Files/ProgramData/SVI/Lixeira; cofre não pode ser igual/interno/ancestral da origem (e
     vice-versa); pasta de teste fora da origem e do cofre.
   * **Varredura** com `os.scandir`, classificando por `st_file_attributes`/`st_reparse_tag`
     de `DirEntry.stat(follow_symlinks=False)` **antes de qualquer abertura**: qualquer
     `FILE_ATTRIBUTE_REPARSE_POINT` (symlink, junction, montagem, OneDrive/Arquivos sob
     Demanda — inclusive "Sempre manter neste dispositivo" —, WOF, dedup) ⇒ bloqueio; atributos
     OFFLINE/RECALL_* ⇒ bloqueio; arquivos especiais ⇒ bloqueio; nomes inválidos/não
     representáveis, colisões de caixa (fold), limites de quantidade/profundidade/tamanho ⇒
     bloqueio. **Qualquer erro** ao listar ou ler atributos (acesso negado, violação de
     compartilhamento, `ERROR_CANT_ACCESS_FILE`) ⇒ **bloqueio**, nunca subárvore pulada.
   * Cada arquivo é aberto com `winfs.open_source()` (ver §6): detecta "arquivo em uso"
     (erros 32/33) e registra FileId, tamanho e datas lidos do handle.
   * **Volume de destino**: sistema de arquivos e tamanho de cluster. Em FAT/FAT32 bloqueia
     blobs > 4 GiB − 1 (e restaurações de arquivos > 4 GiB − 1). FAT/exFAT exigem aceite:
     "sem journaling: não remova a mídia durante a operação; rode Verificar após reconectar".
   * **Espaço**: Σ arredonda(tamanho do blob, cluster) + ~1 KiB/entrada + 3 × tamanho exato do
     manifesto serializado (2 cópias + diário) + margem de 64 MiB; pasta de teste: maior
     arquivo + margem.
   * **Manifesto**: tamanho serializado exato calculado; > 256 MiB ⇒ bloqueio.
   * Resultado: relatório com **bloqueios** e **avisos** (ocultos/sistema, hard links,
     ADS/permissões não preservados, sistema FAT).
2. **Inicialização** — trava `.owlvault.lock`; `mkdir` exclusivo do cofre (ou pasta vazia);
   sonda de escrita; calibra Argon2id; gera `vault_id`, `master_key`, salt; grava
   `vault.owl` e `vault.owl.bak` (escrita sem substituição + flush); grava o segmento 0 do
   diário (fase `encrypting`, `init` com identidade da origem e caminho da pasta de teste);
   `state.json`; `LEIA-ME.txt`; cria a pasta de teste (`mkdir` exclusivo, sonda de escrita).
3. **Cifragem** — em ordem **embaralhada** (`secrets.SystemRandom`). Para cada arquivo:
   `open_source` (confere FileId) → `encrypt_file` (gera `file_id` próprio; `data/hh/<id>.tmp`
   com `CREATE_NEW`; SHA-256 do texto claro; flush) → confere tamanho/LastWriteTime/ChangeTime
   do handle antes e depois e a contagem exata de bytes → renomeia para `.owlb` sem
   substituir → acumula no próximo segmento do diário (checkpoint a cada 64 arquivos, 256 MiB
   ou 5 s). Arquivo alterado durante a leitura ou em uso ⇒ interrompe com mensagem clara
   (retomável).
4. **Manifesto** — monta, executa o validador do leitor, grava `manifest.owl` (sem
   substituição + flush), relê e autentica, copia byte a byte para `manifest.owl.bak`;
   segmento `manifest_written`.
5. **Verificação** — reabre o cofre do zero (§3.1 do FORMAT, as duas cópias de cabeçalho e de
   manifesto), lê blobs com **E/S sem cache** (`FILE_FLAG_NO_BUFFERING`, buffers alinhados)
   para que os bytes venham do dispositivo, autentica todos os chunks, confere SHA-256 e que
   `data/` contém exatamente os blobs do manifesto. Falha ⇒ a criação falha (sem retry
   automático na v1). Segmento `verified`.
6. **Teste de restauração** — para cada arquivo, usa a **mesma rotina por arquivo da
   restauração real** (decifra com todas as verificações, `.part` com `CREATE_NEW`, flush,
   rename sem substituição) gravando `<pasta de teste>/<file_id>.chk` — **conteúdo, sem nomes
   originais** —, relê do disco sem cache, compara com o SHA-256 do manifesto **e** com uma
   releitura nova da origem (`open_source`), e apaga o `.chk` em seguida. Depois **reescaneia
   a origem** com as regras do preflight e compara caminhos dobrados, tipo, tamanho, mtime e
   FileId com o manifesto. Classificação:
   * (a) restaurado ≠ manifesto ⇒ falha do cofre/motor ⇒ **a criação FALHA**;
   * (b) restaurado = manifesto, mas origem mudou (impressão digital diferente, entrada
     adicionada/removida/alterada) ⇒ "origem alterada após a cifragem";
   * (c) impressão digital igual mas hash diferente ⇒ "leitura instável da origem" ⇒ FALHA.
   Divergências (b) terminam como "concluído com divergências", nunca "criada e verificada";
   listadas só na tela. Segmento `restore_tested`.
   * **Local da pasta de teste**: `%TEMP%` se estiver no mesmo volume da origem; senão uma
     pasta no volume da origem fora dela (padrão: pai da origem), que o usuário confirma ou
     troca. Nunca no volume do cofre, a menos que seja também o volume da origem (texto claro
     temporário num pendrive-cofre deixaria remanescentes justamente na mídia protegida).
7. **Finalização** — reabre e dá flush nas cópias de cabeçalho/manifesto (commita o log do
   NTFS); grava `complete.owl` (sem substituição + flush); `state.json = complete`; remove os
   segmentos do diário e a pasta de teste vazia; libera a trava. Mensagem: "Cópia
   criptografada criada e verificada (cópia da pasta como estava em DD/MM HH:MM). A pasta
   original NÃO foi alterada e continua legível até você removê-la manualmente." Em mídia
   removível/externa: "Use Remover hardware com segurança; depois reconecte e rode Verificar
   cofre (de preferência em outro computador) antes de remover qualquer original."

### 4.2 Retomada da criação

Com a trava, senha e o diário:
* Fase `encrypting`: exige que a origem escolhida tenha a mesma identidade registrada
  (volume + FileId da raiz). Reexecuta o preflight completo (todos os bloqueios, espaço).
  Entradas do diário formam um mapa por caminho dobrado; para cada uma: se a impressão
  digital da origem não mudou **e** o blob existe, é arquivo regular sem reparse, tem o
  tamanho exato e o cabeçalho com `vault_id`/`file_id` corretos ⇒ mantém. Senão ⇒ grava
  `removed`, apaga o blob (se existir) e cifra de novo com `file_id` novo. Arquivo que sumiu da
  origem ⇒ remove entrada e blob. Arquivos novos (passaram no rescan) ⇒ cifra e informa.
  Arquivos em `data/` não referenciados são apagados **somente** se forem regulares, sem
  reparse, na pasta `hh` correta e com nome `^[0-9a-f]{32}\.(tmp|owlb)$`; o resto é relatado e
  mantido. Invariante em `COMPLETE`: `data/` contém exatamente os blobs do manifesto.
* Fases `manifest_written`/`verified`/`restore_tested`: reexecuta apenas as etapas 5–7; nunca
  recifra nem reescreve o manifesto. Se falharem, a criação falha (o usuário cria outro cofre).
* Sem segmento 0 (queda entre cabeçalho e diário): "inicialização incompleta" — o usuário
  remove a pasta e recomeça (o app não apaga automaticamente).

Resíduos possíveis após queda e regra de limpeza (só na retomada, com a trava): `data/**/*.tmp`
(apaga), `.owlb` sem registro (apaga se casa o padrão), `*.tmp` na raiz (apaga se casa o
padrão), segmentos após a quebra (apaga), manifesto sem `.bak` (refaz a cópia), arquivos
`.chk`/`.part` na pasta de teste registrada (apaga se casam o padrão; depois `rmdir`).

### 4.3 Verificar cofre

Somente leitura (trava se possível). Relatório: cópia de cabeçalho/manifesto usada e
divergências; status da criação (`complete.owl`); arquivos OK/corrompidos/ausentes;
anomalias em `data/` (não referenciado, pasta `hh` errada, `vault_id` estranho, tmp, desconhecido).

### 4.4 Restaurar

1. **Destino** (implementa "nunca restaurar por cima da origem"): pasta nova ou vazia; não
   igual/interna/ancestral do cofre nem de qualquer origem escolhida na sessão (com
   `resolve()`); fora de pastas protegidas; sem reparse. Pasta não vazia só para retomada com
   marcador compatível, com confirmação explícita.
2. Abre o cofre, valida **todo** o manifesto (FORMAT §5.2), confere existência e tamanho
   exato de cada blob e o comprimento total de cada caminho (`\\?\` + raiz + componentes +
   maior nome temporário ≤ 32 000 unidades UTF-16; aviso acima de 259); FAT32 ⇒ bloqueia
   arquivos > 4 GiB − 1; espaço livre suficiente. Tudo antes de escrever.
3. Trava `.owlvault-restore.lock`; grava o marcador `.owlvault-restore.json` antes de tudo.
4. Ordem de criação: por profundidade; dentro de cada pasta, nomes que já são 8.3 legais
   primeiro (evita colisão com nomes curtos gerados).
5. Para cada arquivo: `.owl-<restore_id>-<rand32>.part` com `CREATE_NEW` (handle com
   `DELETE`); confere que o caminho final do handle está sob a raiz resolvida do destino;
   decifra verificando todas as tags, o chunk final, contagem de bytes = `size` e SHA-256 =
   manifesto; flush; Mark-of-the-Web (se aplicável); LastWriteTime pelo handle (melhor
   esforço, limitado à faixa do FS); **renomeia pelo handle** sem substituição. Só então o
   arquivo conta como restaurado. Qualquer falha ⇒ apaga o `.part` pelo handle, relata e
   continua (restauração parcial; nomes só na tela).
6. **Retomada**: marcador com `manifest_sha256` igual; percorre sem seguir links; aceita pastas
   existentes só se não forem reparse; apaga só `.part` com o `restore_id` do marcador;
   arquivo final existente com hash correto ⇒ reaplica mtime e pula; hash diferente ⇒
   conflito relatado, arquivo intocado.
7. Conclusão: remove o marcador; libera a trava.
8. **Mark-of-the-Web**: se `vault.owl` (ou `manifest.owl`) tem `Zone.Identifier` com
   `ZoneId ≥ 3`, grava `[ZoneTransfer]\r\nZoneId=3\r\n` em `<arquivo>.part:Zone.Identifier`
   antes do rename (aviso se o FS do destino não suporta fluxos nomeados).

### 4.5 Salvamento de emergência (CLI)

Se os dois manifestos forem perdidos, `owl-vault salvage` decifra cada blob autenticável
(cabeçalho do blob fornece `file_id`, `chunk_size` e tamanho) para `recuperado-00001.bin`...
numa pasta nova e vazia — conteúdo sem nomes. Ver [RECOVERY.md](RECOVERY.md).

## 5. Consistência, atomicidade e falhas

* `write_new_no_replace()` para cabeçalhos, blobs, manifestos, conclusão, segmentos e saída
  da restauração: temporário com `CREATE_NEW` **no mesmo diretório** do final ⇒ flush ⇒
  renomeação sem substituição (no NTFS/ReFS é atômica dentro do volume). Só `state.json` usa
  `os.replace`.
* As garantias de atomicidade/consistência valem para **NTFS/ReFS**. FAT/exFAT não têm
  journaling (renomear é apagar+criar entradas): exigem aceite e Verificar após reconectar.
* Retry com backoff limitado apenas para erros 32/33 e acesso negado ao renomear temporário
  próprio (antivírus/indexador).
* Erros classificados: 32/33 "arquivo em uso"; 112/ENOSPC "disco cheio" (retomável se ainda
  não há espaço); disco cheio com espaço suficiente ou 223 "arquivo grande demais para o
  sistema de arquivos" ⇒ não retomável; 225/226 ou temporário que desaparece ⇒ "bloqueado pelo
  antivírus"; acesso negado em pastas conhecidas ⇒ sugestão de liberar o OwlVault.exe em
  "Acesso controlado a pastas"; 1920 ⇒ entrada inacessível.
* Ponto de injeção de falhas (`storage/faults.py`): `fail_at(op, n, erro)` em cada
  escrita/flush/rename, usado pelos testes de disco cheio e queda.
* Toda remoção feita pelo app passa por **um** primitivo (`safe_remove_own`): só arquivos
  regulares sem reparse, com padrão de nome do Owl Vault, em pastas criadas pelo app para
  este cofre/restauração/teste, revalidados com `resolve()` para não estarem na origem. Nunca
  `rmtree` em caminho fornecido pelo usuário.

## 6. Windows: caminhos, abertura de origem e Unicode

* `to_extended(path)`: recusa caminhos relativos e `C:foo`; troca `/` por `\`;
  `GetFullPathNameW` só em raízes fornecidas pelo usuário, recusando se o último componente
  mudou (ponto/espaço final removido); prefixo `\\?\`. Componentes do manifesto são unidos com
  `\` exatamente como armazenados.
* `open_source(path, fid_esperado)`: `CreateFileW(GENERIC_READ, FILE_SHARE_READ,
  OPEN_EXISTING, SEQUENTIAL_SCAN | OPEN_REPARSE_POINT | OPEN_NO_RECALL)`; confere no handle:
  sem reparse/RECALL_*/OFFLINE (`FileAttributeTagInfo`), FileId igual ao registrado
  (`FileIdInfo`: série do volume + id de 128 bits); tamanho/LastWriteTime/ChangeTime lidos do
  handle antes e depois. O handle é mantido durante toda a leitura+hash e **nega escrita a
  outros processos** (FILE_SHARE_READ apenas) ⇒ o hash é um instantâneo verdadeiro.
* Nomes preservados exatamente; UTF-16 inválido recusado no preflight.
* Executável com manifesto `asInvoker`; aviso se rodando elevado.

## 7. Interface (PySide6)

Abas **Criar cofre**, **Verificar cofre**, **Restaurar**.

* Faixa fixa: "O Owl Vault cria uma cópia criptografada. A pasta original continua legível até
  você removê-la manualmente. Mesmo depois de removida, podem restar cópias (Lixeira, Versões
  anteriores, OneDrive, backups, índice do Windows, SSD)."
* Antes de criar: relatório de preflight; painel de limites (sem proteção contra malware ou
  administrador durante o uso; Python não apaga segredos da memória de forma garantida; sem
  exclusão segura) e aviso de backup ("mantenha a origem e um backup externo até verificar o
  cofre em outro computador") — ambos exigem aceite; caixa "Entendo que sem a senha não há
  recuperação"; senha ≥ 12 caracteres + confirmação + indicador de força.
* Progresso por etapa, cancelar, relatório final. O conselho de backup se repete na mensagem
  de sucesso. Teste automatizado garante que textos sobre a pasta de origem não usem
  "protegid*", "segur*", "bloquead*", "criptografad*".
* `QThread` + sinais; campos de senha limpos após o uso; tema claro/escuro em `QSettings`.
* O Owl Vault **não grava caminhos em suas próprias configurações**. (Os seletores de pasta do
  Windows/Qt podem lembrar a última pasta usada — ver THREAT_MODEL §4; o app limpa o histórico
  do QFileDialog por melhor esforço e permite digitar o caminho.)

## 8. Logs e privacidade

* Nenhum log persistente na v1; mensagens só em memória (UI) ou stderr (CLI).
* Fora do cofre, o app grava apenas: pasta de teste (conteúdo temporário, sem nomes originais,
  apagado arquivo a arquivo) e marcador/trava de restauração (sem nomes). Sem SQLite.
* CLI: senha só via `getpass` ou `--password-stdin`; sem `--password` nem variável de
  ambiente. Caminhos digitados na linha de comando ficam no histórico do PowerShell (aviso no
  README).

## 9. Empacotamento

PyInstaller (`packaging/owl_vault.spec`): `OwlVault.exe` onefile, windowed, ícone de coruja
provisório (gerado com QPainter), version info, manifesto `asInvoker`, só QtCore/QtGui/
QtWidgets. Dependências fixadas. Executável não assinado (SmartScreen avisa) — publicar SHA-256.

## 10. Plano de MVP por etapas

| Etapa | Entrega | Critério de pronto |
|------:|---------|--------------------|
| 1 | ARCHITECTURE, THREAT_MODEL, FORMAT, TEST_PLAN | revisão adversarial aplicada |
| 2 | Estrutura + `domain`, `crypto`, `storage` | testes unitários do motor passando |
| 3 | `application` + CLI + testes de integração/adversariais | **matriz do TEST_PLAN coberta** (não basta suíte verde); ruff/mypy limpos |
| 4 | UI PySide6 | fluxo completo em dados sintéticos |
| 5 | `OwlVault.exe` | exe cria/verifica/restaura cofre sintético |
| 6 | README, SECURITY, RECOVERY, WINDOWS, checklist; revisão de segurança do código | — |
