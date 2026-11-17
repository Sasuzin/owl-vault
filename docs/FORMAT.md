# Owl Vault — Especificação do formato do cofre (v1)

Status: **normativo para a v1** (revisado após revisão adversarial de design). Este documento
governa `src/owl_vault/storage/` e `src/owl_vault/crypto/`. Qualquer mudança de layout exige
novo `format_version`.

Convenções: inteiros sem sinal em **big-endian**; `u8/u16/u32/u64`; `‖` = concatenação;
`HKDF` = HKDF-SHA256 (RFC 5869); `AEAD` = AES-256-GCM (NIST SP 800-38D), tag de 16 bytes,
nonce de 12 bytes; toda aleatoriedade vem de `os.urandom`/`secrets` (CSPRNG do SO).

## 1. Layout de diretório

Um cofre é uma pasta criada pelo Owl Vault (nunca a pasta de origem):

```
<Cofre>/
  vault.owl              cabeçalho do cofre (KDF + chave mestra envolvida) — 144 bytes
  vault.owl.bak          cópia byte a byte idêntica do cabeçalho
  manifest.owl           manifesto cifrado (escrito UMA vez por cofre)
  manifest.owl.bak       cópia byte a byte de manifest.owl (feita após relê-lo e autenticá-lo)
  complete.owl           registro cifrado de conclusão (só existe após o teste de restauração)
  journal/<seq>.owlj     segmentos de diário cifrados, write-once (só durante a criação)
  state.json             dica NÃO sensível para a UI (fase, contagens) — sem nomes
  LEIA-ME.txt            explicação genérica, sem nomes de arquivos
  .owlvault.lock         trava de escritor único (apagada ao fechar; ver §9)
  data/<hh>/<file_id>.owlb   um blob cifrado por arquivo; <hh> = 2 primeiros hex do file_id
```

Nomes temporários (todos criados com `CREATE_NEW`, nunca sobrescritos):
* em `data/<hh>/`: `<file_id>.tmp` → renomeado sem substituição para `<file_id>.owlb`;
* na raiz do cofre: `<nome-final>.<rand32>.tmp`;
* `<seq>` = 16 dígitos hex minúsculos (`0000000000000000`, `0000000000000001`, ...).

O nome padrão da pasta do cofre é genérico (`Cofre-AAAAMMDD-HHMM`). Nomes de blobs são o
`file_id` aleatório (128 bits) em hex minúsculo.

## 2. Hierarquia de chaves

```
senha (str) --NFC--> UTF-8 --Argon2id(salt, m, t, p)--> KEK (32 bytes)
KEK --AES-256-GCM unwrap--> master_key (32 bytes aleatórios, gerada uma vez por cofre)

file_key(file_id)    = HKDF(ikm=master_key, salt=vault_id, info="owlvault/v1/file-key\0"     ‖ file_id, L=32)
manifest_key(key_id) = HKDF(ikm=master_key, salt=vault_id, info="owlvault/v1/manifest-key\0" ‖ key_id,  L=32)
journal_key(key_id)  = HKDF(ikm=master_key, salt=vault_id, info="owlvault/v1/journal-key\0"  ‖ key_id,  L=32)
complete_key(key_id) = HKDF(ikm=master_key, salt=vault_id, info="owlvault/v1/complete-key\0" ‖ key_id,  L=32)
```

* A senha é normalizada em NFC antes de virar UTF-8.
* Cada arquivo tem chave própria ⇒ nonces determinísticos por contador são seguros.
* Cada escrita de contêiner (manifesto, segmento de diário, conclusão) usa `key_id`
  aleatório novo ⇒ chave nova por escrita; o nonce aleatório nunca se repete sob uma chave.
* Os rótulos são distintos, versionados e terminados em `\0` antes do id de tamanho fixo
  (16 bytes) ⇒ sem ambiguidade entre domínios.
* **Troca de senha (não existe na v1):** re-envolver a `master_key` muda a senha apenas nas
  cópias do cabeçalho reescritas. Qualquer cabeçalho antigo sobrevivente (`.bak`
  dessincronizado, Versões Anteriores/VSS, backup, cópia antiga da mídia) continua abrindo o
  cofre com a senha antiga. Após suspeita de vazamento da senha, o único remédio é criar um
  cofre novo (nova `master_key`).

## 3. `vault.owl` — cabeçalho (exatamente 144 bytes)

| off | tam | campo | regra de validação (build distribuído) |
|----:|----:|-------|--------------------|
| 0   | 8   | magic = `OWLVAULT` | exato |
| 8   | 2   | format_version = 1 | exato |
| 10  | 2   | header_size = 144 | exato; tamanho do arquivo = 144 |
| 12  | 4   | flags = 0 | 0 |
| 16  | 16  | vault_id | aleatório |
| 32  | 1   | kdf_algorithm = 1 (Argon2id) | exato |
| 33  | 1   | kdf_version = 0x13 | exato |
| 34  | 2   | reservado = 0 | 0 |
| 36  | 4   | kdf_memory_kib | 65 536 ≤ m ≤ 1 048 576 (64 MiB..1 GiB) e m ≥ 8·p |
| 40  | 4   | kdf_iterations | 3 ≤ t ≤ 16 |
| 44  | 4   | kdf_parallelism | 1 ≤ p ≤ 8 |
| 48  | 32  | kdf_salt | aleatório |
| 80  | 1   | wrap_algorithm = 1 (AES-256-GCM) | exato |
| 81  | 3   | reservado = 0 | 0 |
| 84  | 12  | wrap_nonce | aleatório |
| 96  | 48  | wrapped_master_key = ct(32) ‖ tag(16) | — |

* `AAD = bytes[0:96]` — todos os parâmetros são autenticados.
* Limites de KDF verificados **antes** do Argon2id. Antes de derivar, exige-se memória
  **comprometível** disponível (RAM + arquivo de paginação, `ullAvailPageFile` de
  `GlobalMemoryStatusEx`) ≥ m + 256 MiB; `MemoryError` é tratado. Decisão deliberada: a
  memória física "livre" do Windows exclui a lista de espera e pode ser pequena em máquinas
  com 8 GB ocupadas, o que recusaria cofres válidos; como m ≤ 1 GiB por política, o custo
  máximo continua limitado. A derivação não
  é cancelável (a UI diz isso). Um piso mais baixo (8 MiB, t = 1) existe **somente** como
  política injetada pelos testes automatizados; UI e CLI não conseguem selecioná-lo.

### 3.1 Algoritmo normativo de leitura do cabeçalho

1. Ler `vault.owl` e `vault.owl.bak`; aplicar validação estrutural e de limites em cada um.
2. Se ambos válidos e **byte a byte idênticos**: um Argon2id + unwrap. `InvalidTag` ⇒
   "senha incorreta (ou as duas cópias do cabeçalho estão corrompidas)".
3. Se diferem (ou só um é válido): ordenar primeiro a cópia válida cujo `vault_id` coincide
   com o `vault_id` em claro do manifesto/diário. Derivar a KEK uma vez por tupla distinta
   (salt, m, t, p), tentar o unwrap em cada cópia. Aceitar a primeira que autentica **e** cujo
   `vault_id` coincide com o do manifesto/diário (quando existirem). Se as duas autenticam com
   `vault_id`/`master_key` diferentes ⇒ recusar ("cabeçalhos inconsistentes"). Nenhuma
   autentica ⇒ "cabeçalhos divergentes — provável corrupção (ou senha incorreta)".
4. Informar qual cópia foi usada. **Nunca** reescrever nenhuma cópia automaticamente.
5. Verificar (e a etapa de verificação da criação) autentica as **duas** cópias e reporta
   qualquer divergência mesmo quando o desbloqueio funcionou.

## 4. Blobs `data/<hh>/<file_id>.owlb`

### 4.1 Cabeçalho do blob (64 bytes)

| off | tam | campo | regra |
|----:|----:|-------|-------|
| 0  | 8  | magic = `OWLVBLOB` | exato |
| 8  | 2  | format_version = 1 | exato |
| 10 | 2  | header_size = 64 | exato |
| 12 | 4  | flags = 0 | 0 |
| 16 | 16 | vault_id | igual ao do cofre |
| 32 | 16 | file_id | igual ao nome do arquivo e ao manifesto |
| 48 | 4  | chunk_size | potência de 2, 65 536 ≤ c ≤ 16 777 216 (padrão 1 MiB) |
| 52 | 8  | plaintext_size | 0 ≤ P ≤ 2^40 e igual ao manifesto |
| 60 | 4  | reservado = 0 | 0 |

### 4.2 Chunks

* `n = max(1, ceil(P / c))` — arquivo vazio tem 1 chunk vazio (só a tag). Para `P` múltiplo
  exato de `c` (P > 0), `n = P / c` e o último chunk tem `c` bytes.
* Chunk `i` (0-based) tem `c` bytes de texto claro, exceto o último: `P − (n−1)·c`.
* `final = 1` somente para `i = n−1`.
* `nonce_i = 0x000000 ‖ u8(final) ‖ u64(i)` (12 bytes) — construção estilo STREAM sob
  `file_key`, exclusiva do arquivo.
* `aad_i = blob_header(64) ‖ u64(i) ‖ u8(final)`.
* Armazenamento: `ct_i ‖ tag_i` concatenados.
* **Tamanho exato** do blob: `64 + P + 16·n`, verificado antes de decifrar.

### 4.3 Regra crítica de nonce (estrutural)

A API de cifragem de fluxo **gera o `file_id` internamente** e o devolve; nenhum chamador pode
passar um `file_id`. O temporário `data/<hh>/<file_id>.tmp` é criado com `CREATE_NEW` e
promovido com renomeação sem substituição; qualquer colisão aborta. Retry, retomada, arquivo
alterado, blob ausente ou com tamanho errado ⇒ sempre um `file_id` novo; um blob existente
nunca é aberto para escrita.

## 5. Contêineres cifrados (`manifest.owl`, `journal/*.owlj`, `complete.owl`)

Cabeçalho de 64 bytes + `ciphertext ‖ tag`:

| off | tam | campo | regra |
|----:|----:|-------|-------|
| 0  | 8  | magic: `OWLVMANI` / `OWLVJRNL` / `OWLVDONE` | exato e coerente com o arquivo |
| 8  | 2  | format_version = 1 | exato |
| 10 | 2  | header_size = 64 | exato |
| 12 | 4  | flags = 0 | 0 |
| 16 | 16 | vault_id | igual ao do cofre |
| 32 | 16 | key_id | aleatório por escrita |
| 48 | 12 | nonce | aleatório |
| 60 | 4  | reservado = 0 | 0 |

* Chave: `manifest_key`/`journal_key`/`complete_key` (`key_id`); `AAD = header(64)`.
* Tamanho máximo do arquivo (checado antes de ler): manifesto 256 MiB + 80; segmento de
  diário 64 MiB + 80; conclusão 1 MiB + 80. O escritor checa o **mesmo** limite antes de cifrar.
* Texto claro: JSON UTF-8 produzido por **um único serializador canônico**
  `json.dumps(obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False, sort_keys=True)`.
  O leitor rejeita chaves duplicadas, campos desconhecidos/ausentes, tipos errados, `bool`
  onde se espera inteiro, e `kind` incorreto.

### 5.1 Manifesto (`kind = "manifest"`)

```json
{"kind":"manifest","format_version":1,"vault_id":"<32 hex>","chunk_size":1048576,
 "entries":[
   {"type":"dir","path":["Fotos","2024"]},
   {"type":"file","path":["Fotos","2024","praia.jpg"],"size":123456,
    "mtime_ns":1700000000000000000,"file_id":"<32 hex>","sha256":"<64 hex>"}]}
```

* `path` é lista de componentes (nunca string com separadores). Todo diretório da árvore
  aparece como entrada `dir` (inclusive vazios); o pai de toda entrada deve existir como `dir`
  (ou ser a raiz).
* Limites: ≤ 1 000 000 entradas; profundidade ≤ 256; `0 ≤ size ≤ 2^40`;
  `−11 644 473 600·10^9 ≤ mtime_ns ≤ 2^63−1`; manifesto serializado ≤ 256 MiB. O preflight
  calcula o tamanho **exato** do manifesto serializado e bloqueia antes de cifrar.
* **Escrito uma única vez**; o `.bak` é cópia byte a byte. Regra de leitura: cópias idênticas
  ⇒ usar; uma ausente/inválida/não autêntica ⇒ usar a outra e avisar; ambas autênticas e
  diferentes ⇒ recusar ("manifestos divergentes").
* O escritor executa o validador completo do leitor (§5.2) antes de gravar.

### 5.2 Validação de caminhos

Cada componente deve:
* ser `str` não vazio, codificável em UTF-16 estrito (sem surrogates órfãos), ≤ 255 unidades;
* não ser `.` nem `..`; não conter `< > : " / \ | ? *` nem 0x00–0x1F;
* não terminar em espaço ou ponto;
* não ser nome reservado: `base = componente.split(".", 1)[0].rstrip(" ").upper()`;
  reservado se `base ∈ {CON, PRN, AUX, NUL, CONIN$, CONOUT$, COM0–COM9, COM¹, COM², COM³,
  LPT0–LPT9, LPT¹, LPT², LPT³}` (pega `CON.tar.gz` e `NUL .txt`).

**Dobra de caixa** `fold(componente)`: para cada unidade UTF-16 `u`: se `u` não é surrogate e
`chr(u).upper()` é um único caractere BMP, usa-o; senão mantém `u` (aproxima a tabela
`$UpCase` do NTFS; `ß`, `ﬁ` e não-BMP ficam como estão). Nunca `str.upper()`/`casefold()` na
string inteira.

Regras de conjunto (sobre listas de componentes dobradas): sem caminhos duplicados; nenhuma
entrada `file` é prefixo de outra entrada; `file_id` únicos; pai de cada entrada presente.
Qualquer violação rejeita o manifesto inteiro antes de qualquer escrita. `CREATE_NEW` e a
renomeação sem substituição continuam sendo a autoridade final na restauração.

### 5.3 Diário: segmentos delta write-once (`kind = "journal"`)

`journal/<seq>.owlj`, cada um um contêiner novo (`CREATE_NEW` + flush), nunca modificado:

```json
{"kind":"journal","vault_id":"<hex>","seq":3,"phase":"encrypting",
 "init":null,
 "added":[ <entrada file|dir do manifesto> + "fp":{"vol":int,"fid":"<32 hex>","size":int,
          "mtime_ns":int,"ctime_ns":int} ],
 "removed":["<file_id hex>", ...]}
```

* O segmento 0 é escrito logo após as duas cópias do cabeçalho, antes de qualquer blob, com
  `init = {"source_root": "<caminho absoluto>", "source_volume": int, "source_root_fid":
  "<hex>", "test_dir": "<caminho absoluto>", "chunk_size": int, "created_utc": "<ISO>"}`.
* Leitura: aplica os segmentos em ordem de `seq` a partir de 0 e para no primeiro ausente ou
  não autêntico (perde só progresso, que a retomada reconfere). Segmentos posteriores à quebra
  são removidos na retomada (sob a trava).
* `phase` ∈ `encrypting, manifest_written, verified, restore_tested`; cada transição grava um
  segmento. Todos os segmentos são removidos após `complete.owl` existir.

### 5.4 Registro de conclusão (`complete.owl`, `kind = "completion"`)

```json
{"kind":"completion","vault_id":"<hex>","manifest_sha256":"<hex dos bytes de manifest.owl>",
 "files":120,"dirs":14,"bytes":123456789,"restore_test":"passed","divergences":0,
 "completed_utc":"<ISO>"}
```

Verificar/Restaurar só dizem "criação concluída e testada" se `complete.owl` autentica e
`manifest_sha256` confere. Caso contrário: "criação NÃO concluída / teste de restauração não
executado", independentemente do `state.json`.

## 6. `state.json` (não sensível, melhor esforço)

```json
{"app":"Owl Vault","format_version":1,"vault_id":"<hex>","phase":"encrypting",
 "files_total":120,"files_done":37,"test_dir_name":"OwlVault-teste-<rand32>"}
```

Único arquivo gravado com substituição (tmp + `os.replace` com retry). Não tem papel de
segurança; se faltar ou estiver ilegível, a fase é derivada de `complete.owl`, diário e
manifesto.

## 7. Marcador de restauração (`<destino>/.owlvault-restore.json`)

`{"app":"Owl Vault","vault_id":"<hex>","manifest_sha256":"<hex>","restore_id":"<32 hex>",
"phase":"restoring"}` — escrito **antes** de qualquer outra coisa no destino; removido ao
concluir. Temporários: `.owl-<restore_id>-<rand32>.part`. Trava: `.owlvault-restore.lock`.

## 8. Vazamentos conhecidos (por design, v1)

Sem a senha, quem tem o cofre aprende: quantidade de arquivos; o **tamanho exato** de cada
arquivo (`plaintext_size` está em claro e também é `tamanho_do_blob − 64 − 16·n`), o que
permite confirmar a presença de um arquivo/coleção conhecidos pelos tamanhos; horários dos
arquivos do cofre (a ordem de cifragem é embaralhada com `secrets.SystemRandom` a cada
execução, então não revela a ordem dos caminhos); tamanho aproximado do manifesto;
parâmetros do Argon2id; que é um cofre Owl Vault. **Não** aprende nomes, estrutura,
conteúdo, hashes, datas originais. Padding de tamanho fica para v2 (exigiria tirar
`plaintext_size` do cabeçalho em claro).

## 9. Travas de escritor único

Criação/retomada/finalização seguram `<cofre>/.owlvault.lock`; restauração segura
`<destino>/.owlvault-restore.lock`: `lstat` (a trava existente precisa ser arquivo comum, sem
reparse e sem hard links extras) → `CreateFileW(GENERIC_READ|GENERIC_WRITE|DELETE, share=0,
OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT)` → conferência no handle → disposição "apagar ao
fechar" (`FileDispositionInfo`). Nunca segue links: um cofre adulterado não consegue fazer o
app apagar outro arquivo. Uma trava inválida é relatada como anomalia (Verificar prossegue sem
ela). Segunda instância falha imediatamente ("em uso por outra janela
do Owl Vault"). Limpezas de temporários só ocorrem com a trava. Verificar tenta a mesma trava;
em mídia somente leitura prossegue sem ela e avisa.

## 10. Parâmetros KDF na criação (calibração)

* `p = min(4, núcleos)`. Candidatos de memória: 512, 256, 128, 64 MiB, usando o maior que
  seja ≤ 1/8 da RAM física total e com memória comprometível disponível ≥ m + 512 MiB (assim
  um cofre criado numa máquina potente ainda abre num notebook de 4–8 GB). Com `t = 3`, se
  levar > 1,5 s, desce a memória;
  senão aumenta `t` até ≥ 0,5 s (máx. 16).
* Os parâmetros ficam gravados e autenticados no cabeçalho.

## 11. Versionamento

`format_version` em todo cabeçalho; versões desconhecidas recusadas; rótulos HKDF com `v1`;
flags/reservados devem ser zero.
