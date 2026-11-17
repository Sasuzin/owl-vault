# Segurança do Owl Vault

## Resumo honesto

* O Owl Vault cifra uma **cópia** de uma pasta. Ele **não** torna a pasta original segura e
  **não** a apaga. Enquanto existir, a origem continua legível; mesmo depois de removida,
  podem restar cópias (Lixeira, Versões anteriores/VSS, OneDrive, backups, índice do Windows,
  cache de miniaturas, SSD).
* Protege os arquivos **do cofre** contra quem tem acesso a eles mas não tem a senha
  (pendrive perdido, cópia em outro disco). Detecta adulteração dos arquivos do cofre
  (cabeçalho, manifesto, blocos); a substituição do cofre inteiro por outra versão válida dele
  mesmo **não** é detectada (THREAT_MODEL §4).
* **Não** protege contra malware, administradores ou qualquer pessoa observando o computador
  enquanto o Owl Vault está em uso. Python não garante apagar senha/chaves da memória.
* **Perda da senha = perda dos dados.** Não existe recuperação.
* **Não houve auditoria independente.** O projeto usa apenas primitivas de bibliotecas
  estabelecidas e foi revisado internamente (revisão adversarial de design e de código,
  suíte de testes adversariais), o que não substitui uma auditoria.

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

## Garantias operacionais

* A origem é aberta somente para leitura, negando escrita a outros processos durante a
  leitura; nenhum código escreve, renomeia ou remove na origem.
* Links, junctions, pontos de montagem, itens de nuvem e outros pontos de reparse são
  recusados e nunca seguidos; caminhos são comparados pelo caminho final resolvido.
* "Sucesso" só depois de verificação completa (leitura sem cache), teste de restauração
  arquivo a arquivo e nova varredura da origem.
* Restauração só em pasta nova/vazia, com validação completa antes de gravar, criação
  exclusiva e renomeação sem substituição.
* Sem logs persistentes, sem telemetria, sem rede, sem SQLite; nenhum nome original é gravado
  fora do cofre pelo próprio Owl Vault.

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
