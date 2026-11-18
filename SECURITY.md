# Segurança do Owl Vault

## Resumo honesto

* **Pastas protegidas (v2)**: a pasta trancada fica no mesmo lugar, mas o conteúdo está
  criptografado dentro dela (`.owlvault`). Quem copiar a pasta, tirar o disco ou usar outra
  conta do Windows vê só dados cifrados, o ícone e os itens "Abrir com Owl Vault" e "Como abrir
  esta pasta.txt". O **nome** da pasta trancada continua visível (use "Esconder do Explorer"
  se ele for sensível — esconder não é criptografia).
* Enquanto a pasta está **aberta**, ela é uma pasta comum: qualquer pessoa ou programa com
  acesso à sua conta lê os arquivos. Trancar não apaga rastros do Windows (Recentes, índice
  de pesquisa, miniaturas, Lixeira, Versões anteriores/VSS, OneDrive, backups) nem garante que
  os setores antigos do disco/SSD sejam sobrescritos. Use BitLocker para o disco inteiro.
* **Cópia criptografada (modo v1)**: cifra uma *cópia* de uma pasta e **não** altera a
  original, que continua legível.
* Detecta adulteração dos arquivos cifrados (cabeçalho, manifesto, blocos); a substituição do
  cofre inteiro por outra versão válida dele mesmo **não** é detectada (THREAT_MODEL §4).
* **Não** protege contra malware, administradores ou qualquer pessoa usando sua conta
  enquanto o Owl Vault está destravado. Python não garante apagar senha/chaves da memória.
* **Perda da senha mestra = perda dos dados** quando o PIN deste computador também não
  estiver disponível. Não existe recuperação.
* **Não houve auditoria independente.** O projeto usa apenas primitivas de bibliotecas
  estabelecidas e foi revisado internamente (revisão adversarial de design e de código,
  suíte de testes adversariais), o que não substitui uma auditoria.

## PIN e senha mestra (v2)

| Item | Como é protegido |
|------|------------------|
| Senha mestra → KEK | Argon2id calibrado (mesmos limites da v1); a KEK abre a chave do perfil (PK) e é a KEK dos cofres das pastas |
| Perfil (`%LOCALAPPDATA%\Owl Vault\perfil.owlp` + `.bak`) | PK aleatória de 256 bits; índice (nomes, caminhos, estados, KEKs) cifrado com AES-256-GCM sob a PK; AAD liga cada caixa ao perfil e ao rótulo |
| PIN | Argon2id(PIN) cifra a PK; o resultado ainda é protegido pelo DPAPI da sua conta do Windows (o PIN só funciona neste computador e nesta conta) |
| Tentativas do PIN | contadas nas duas cópias do perfil **antes** de derivar a chave; 5 erros desativam o PIN (só a senha mestra volta a funcionar). Quem consegue copiar e restaurar arquivos da sua conta pode tentar mais vezes: o PIN é mais fraco que a senha mestra |
| Prática | a senha mestra é pedida no primeiro desbloqueio depois de 1 dia e a cada 30 dias |
| Sessão | o perfil destravado só existe em memória; é descartado ao bloquear (☰ → Bloquear agora, 5 min sem uso, Win+L, suspensão) |

## Criptografia (v1)

| Uso | Primitiva |
|-----|-----------|
| Senha → KEK | Argon2id (argon2-cffi), salt aleatório de 32 bytes por cofre, parâmetros calibrados (64–512 MiB, t ≥ 3, p ≤ 4), versionados e autenticados no cabeçalho |
| Chave mestra | 256 bits aleatórios (`os.urandom`), envolvida com AES-256-GCM sob a KEK; AAD = todo o cabeçalho |
| Subchaves | HKDF-SHA256 com rótulos versionados por domínio; chave própria por arquivo e por escrita de contêiner |
| Dados | AES-256-GCM em chunks de 1 MiB; nonce = `final ‖ índice`; AAD = cabeçalho do blob + índice + final; tamanho exato verificado |
| Manifesto/diário/conclusão | AES-256-GCM, chave e nonce novos por escrita, JSON estrito |

Vazamentos aceitos: quantidade de arquivos, **tamanho exato** de cada arquivo, datas dos
arquivos do cofre, tamanho aproximado do manifesto, parâmetros do Argon2id. Detalhes em
[docs/FORMAT.md](docs/FORMAT.md) e [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Proteções da pasta trancada no Windows (0.3)

* **Permissões**: o espaço reservado (atalho, `desktop.ini`, ícone, instruções), a pasta oculta
  `.owlvault` e a área temporária `.owlvault-<código>` recebem permissões só para a sua conta,
  SYSTEM e Administradores (sem herança). Outra conta comum do computador não consegue trocar o
  atalho "Abrir com Owl Vault" nem ler as cópias temporárias do teste de restauração. É uma
  defesa a mais: a proteção dos dados continua sendo a criptografia.
* **Atalho conferido**: ao iniciar e antes de abrir uma pasta, o Owl Vault confere o alvo e os
  argumentos do atalho dentro de cada pasta trancada e o recria se tiver sido alterado.
* **Atalho sem rastros da máquina**: o `.lnk` é gravado sem LinkInfo (série do volume) e sem
  o bloco de rastreio (nome do computador, MAC). Ele ainda contém o caminho do programa
  instalado, que inclui o nome da sua conta do Windows.
* **Instância única**: o canal local só aceita mensagens de processos da mesma conta do
  Windows, e um pedido "abrir" vindo por ele nunca abre uma pasta sem o PIN e sem mostrar o nome
  da pasta.
* **Instalação**: um `OwlVault.exe` de versão mais antiga nunca substitui o instalado. Com o
  mesmo número de versão e conteúdo diferente (executável trocado por fora ou novo build com o
  mesmo número), o instalado é substituído — exceto quando ele confere com `versao.sha256` e é
  um build de data mais nova.

## Garantias operacionais

* Cópia criptografada (v1): a origem é aberta somente para leitura, negando escrita a outros
  processos durante a leitura; nenhum código escreve, renomeia ou remove na origem.
* Pasta protegida (v2): cada original só é apagado depois que o cofre novo terminou com
  sucesso (verificação + teste de restauração + nova varredura), pelo próprio handle, conferindo
  identidade, tamanho e datas; se o arquivo mudou ou está em uso, ele fica na pasta e a pasta vai
  para "Precisa de atenção". Um cofre só é apagado quando tudo o que ele tem está num cofre mais
  novo e concluído (ou o usuário confirmou a lista exata do que falta).
* Links, junctions, pontos de montagem, itens de nuvem e outros pontos de reparse são
  recusados e nunca seguidos; caminhos são comparados pelo caminho final resolvido.
* "Sucesso" só depois de verificação completa (leitura sem cache), teste de restauração
  arquivo a arquivo e nova varredura da origem.
* Restauração só em pasta nova/vazia, com validação completa antes de gravar, criação
  exclusiva e renomeação sem substituição.
* Sem logs persistentes, sem telemetria, sem rede, sem SQLite; nenhum nome original é gravado
  fora do cofre pelo próprio Owl Vault, exceto dentro do índice cifrado do perfil. O nome da
  pasta protegida em si continua no sistema de arquivos (é a pasta do usuário).

## Verificar o executável

Compare o SHA-256 de `OwlVault.exe` com o publicado em `OwlVault.exe.sha256`:

```powershell
Get-FileHash .\OwlVault.exe -Algorithm SHA256
```

O executável não é assinado digitalmente; o SmartScreen pode avisar.

## Relatar um problema de segurança

Descreva o problema, a versão e como reproduzir **com dados sintéticos** (nunca envie cofres
reais, senhas ou arquivos pessoais). Use o canal privado do mantenedor do projeto.

## Checklist de revisão

Ver [docs/SECURITY_CHECKLIST.md](docs/SECURITY_CHECKLIST.md).
