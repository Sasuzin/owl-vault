# Owl Vault — Checklist de revisão de segurança

Use esta lista a cada mudança no motor (`crypto/`, `storage/`, `application/`) e antes de
cada build distribuído. Marque somente o que foi efetivamente verificado — não é uma
auditoria independente.

## Criptografia
- [ ] Nenhuma primitiva própria: só `cryptography` (AESGCM, HKDF, SHA-256) e `argon2-cffi` (Argon2id).
- [ ] Toda aleatoriedade vem de `os.urandom`/`secrets` (nunca `random`).
- [ ] Todo `file_id` é gerado na hora da cifragem e nunca reaproveitado (retry, retomada, arquivo alterado).
- [ ] Nonce de chunk = `000000 ‖ final ‖ u64(índice)` sob chave exclusiva do arquivo; AAD inclui o cabeçalho do blob + índice + final.
- [ ] Manifesto e diário usam `key_id` novo por escrita; nonce aleatório de 12 bytes.
- [ ] Rótulos HKDF distintos, versionados (`owlvault/v1/...`) e terminados em `\0` antes do id.
- [ ] Cabeçalho do cofre: AAD cobre todos os bytes antes da chave envolvida (parâmetros KDF incluídos).
- [ ] Limites de Argon2id (m, t, p) e de tamanhos validados **antes** de derivar/alocar.
- [ ] Senha normalizada em NFC; nunca registrada, nunca em mensagens de erro, nunca em arquivos.
- [ ] Mensagens de erro de autenticação não diferenciam "senha errada" de "cabeçalho adulterado".

## Formato / parsing
- [ ] Todos os campos reservados/flags exigidos zero; versões desconhecidas recusadas.
- [ ] Tamanho exato do blob verificado antes de decifrar.
- [ ] JSON do manifesto: chaves duplicadas, campos desconhecidos e tipos errados rejeitados.
- [ ] `file_id` do manifesto = nome do blob = `file_id` do cabeçalho do blob.
- [ ] Limites: entradas, profundidade, tamanho do manifesto, tamanho por arquivo, chunk_size.

## Sistema de arquivos
- [ ] Origem aberta somente para leitura; nenhum caminho de código escreve/renomeia/remove na origem.
- [ ] Varredura sem seguir links; qualquer ponto de reparse (symlink, junction, montagem, nuvem) recusado.
- [ ] Caminho de rede e raízes/pastas protegidas recusados.
- [ ] Temporários no mesmo diretório do destino final; `fsync` antes do rename; rename sem sobrescrita.
- [ ] Remoções feitas pelo app limitadas a arquivos criados pelo próprio app (padrão de nome + diretório controlado).
- [ ] Restauração: manifesto inteiro validado antes de escrever; destino vazio; criação exclusiva; sem sobrescrita.
- [ ] Caminhos com `\\?\` para suportar > 260 caracteres.

## Privacidade
- [ ] Nenhum log persistente; nenhum caminho em `QSettings`; `state.json`/`LEIA-ME.txt` sem nomes.
- [ ] Nome padrão do cofre é genérico.
- [ ] Teste de restauração grava em `%TEMP%` (fora do volume do cofre) e remove cada cópia após comparar.

## Interface / honestidade
- [ ] A UI nunca diz que a pasta original está "protegida".
- [ ] Avisos de backup, perda de senha e limites de proteção visíveis antes de criar.
- [ ] "Sucesso" só após verificação completa + teste de restauração com hashes iguais.

## Build / distribuição
- [ ] Dependências com versões fixadas (`requirements*.txt`) e revisadas.
- [ ] Testes (`pytest`), `ruff` e `mypy` executados e resultados registrados.
- [ ] SHA-256 do `OwlVault.exe` publicado junto com o arquivo.
- [ ] `OwlVault.exe --selftest` retorna 0 (exercita OpenSSL, Argon2, Qt e Win32 empacotados).

---

## Registro da revisão interna da v0.1.0 (2026-11-17)

Revisão **interna** (não é auditoria independente), feita com revisores automatizados
independentes e verificação cética de cada achado:

1. **Design** (antes do código): 4 revisores (criptografia, Windows/NTFS, falhas/retomada,
   requisitos) → 45 apontamentos → 27 decisões aplicadas aos documentos
   (11 obrigatórias, 14 recomendadas, 2 só documentação).
2. **Matriz de testes**: 7 agentes escreveram ~1.600 testes e encontraram 16 defeitos no motor,
   todos corrigidos (ex.: manifesto corrompido bloqueando o `.bak`; `get_hex` aceitando
   espaços; cancelamento relatado como corrupção; Mark-of-the-Web não gravado).
3. **Código**: 5 revisores (implementação cripto, sistema de arquivos, consistência,
   privacidade/UX, Win32) + 5 verificadores → 28 achados, 26 confirmados e corrigidos, com
   testes de regressão em `tests/test_security_regressions.py`. Os mais graves:
   * retomada com a origem movida e outra pasta no caminho antigo cifraria a pasta errada
     (agora a identidade da pasta no caminho registrado é conferida);
   * a trava `.owlvault.lock` seguia links e, num cofre adulterado, apagaria o alvo ao fechar
     (agora `lstat` + `OPEN_REPARSE_POINT` + conferência no handle antes de "apagar ao fechar").

Itens verificados nesta revisão: todos os da lista acima, exceto os marcados como manuais em
[TEST_PLAN.md](TEST_PLAN.md) (OneDrive real, remoção de pendrive, queda de energia, `subst`,
ponto de montagem, máquina limpa), que **não** foram executados. Testes com link simbólico
foram pulados por falta de privilégio (junctions cobrem o mesmo caminho de código).
