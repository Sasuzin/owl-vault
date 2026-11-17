# Owl Vault — Plano e matriz de testes

Regras: todos os testes rodam em pastas temporárias com dados sintéticos (`tmp_path`);
nunca contra pastas pessoais reais. Testes que dependem de privilégio (symlink, ponto de
montagem) usam `skipif` e são reportados como **não executados** nos relatórios de etapa.
Arquivos grandes são gerados por geradores em streaming (ou arquivos esparsos).
Os testes usam a política de KDF de teste (8 MiB, t=1), inalcançável pela UI/CLI.

| Caso (prompt / revisão) | Módulo de teste |
|-------------------------|-----------------|
| Arquivos vazios | `test_stream.py`, `test_roundtrip.py` |
| Binários, tamanhos de borda (c−1, c, c+1, múltiplos exatos) | `test_stream.py` |
| Unicode (acentos, CJK, emoji/não-BMP, NFC×NFD) | `test_roundtrip.py`, `test_names.py` |
| Vídeos grandes sintéticos (muitos chunks; >1 GiB marcado `slow`) | `test_large.py` |
| Hierarquia profunda + caminho > 260 caracteres | `test_roundtrip.py` |
| Nomes duplicados (mesmo nome em pastas diferentes; colisão de caixa no manifesto) | `test_roundtrip.py`, `test_manifest_validation.py` |
| Senha errada | `test_header.py`, `test_roundtrip.py` |
| Corrupção de cabeçalho (cada campo) + fallback `.bak` (ambas as direções) | `test_header.py` |
| Cabeçalho de outro cofre com a mesma senha | `test_header.py` |
| Corrupção de chunk / tag / cabeçalho do blob | `test_stream.py`, `test_tamper.py` |
| Corrupção de manifesto + fallback `.bak`; manifestos divergentes | `test_tamper.py` |
| Truncamento / extensão de blob | `test_stream.py`, `test_tamper.py` |
| Reordenação de chunks; troca de blobs entre arquivos e entre cofres | `test_tamper.py` |
| Limites de KDF abusivos (DoS) | `test_header.py` |
| JSON hostil (chaves duplicadas, campos extras, tipos, bool como int) | `test_manifest_validation.py` |
| Path traversal (`..`, absolutos, `C:`, `\`, `/`, ADS `:`, reservados, ponto/espaço final) | `test_names.py`, `test_manifest_validation.py` |
| Falta de espaço simulada (injeção de falha) | `test_faults.py` |
| Interrupção/queda em cada ponto de escrita + retomada | `test_faults.py`, `test_resume.py` |
| Cancelamento + retomada | `test_resume.py` |
| Retomada: arquivo alterado, removido, adicionado; blob ausente/truncado; órfão | `test_resume.py` |
| `file_id` sempre novo em retry/retomada | `test_resume.py` |
| Symlinks (skip sem privilégio) / junctions (`_winapi.CreateJunction`) | `test_preflight.py` |
| Aliases de caminho: 8.3, junction (subst: manual) | `test_preflight.py` |
| Cofre dentro da origem / origem dentro do cofre / pastas protegidas | `test_preflight.py` |
| Arquivo em uso (aberto com escrita por outro handle) | `test_preflight.py` |
| Arquivo alterado durante a cifragem | `test_create.py` |
| Restauração fiel (árvore, conteúdo, mtime, pastas vazias) | `test_roundtrip.py` |
| Restauração: destino não vazio recusado; retomada com marcador; conflito | `test_restore.py` |
| Teste de restauração: divergência de origem; limpeza após queda | `test_create.py`, `test_resume.py` |
| Trava de escritor único | `test_create.py` |
| Bloqueio FAT32 > 4 GiB (lógica com FS simulado) | `test_preflight.py` |
| Verificar: blobs ausentes, extras, pasta `hh` errada, `complete.owl` ausente | `test_verify.py` |
| Salvamento de emergência sem manifesto | `test_salvage.py` |
| Textos da UI não chamam a origem de "protegida" | `test_ui_strings.py` |
| CLI: senha só via getpass/`--password-stdin`, aceite de limites, códigos de saída | `test_cli.py` |
| Regressões da revisão de segurança do código (origem movida, trava com link, redundância, limpeza final, senha com BOM, salvamento, junction na retomada da restauração, ponto final em componente) | `test_security_regressions.py` |

| **v2 — perfil**: PIN (validação, contador nas duas cópias, desativação), DPAPI, índice cifrado sem nomes em claro, `.bak`, troca de PIN/senha mestra, prática | `test_profile.py` |
| **v2 — pastas protegidas**: trancar/abrir/esconder/remover, regra de ouro, versão mantida, quedas simuladas em cada estado, arquivo aberto/alterado no meio, recusas da pré-verificação, pasta movida, recuperar | `test_lockers.py` |
| **v2 — Windows e telas**: `desktop.ini`, atributos, atalho (lido pela API), DPAPI, instalação e versão, menus por estado, bloqueio sem nomes na tela | `test_shell_ui_v2.py` |
| **Visual Cofre**: contraste WCAG dos dois temas, QSS casado com os tokens, nenhuma cor literal fora do tema | `test_tema.py` |
| **Diálogos e cópia criptografada (assistente de 4 passos)** | `test_dialogs_v2.py`, `test_copy_window.py` |

Testes manuais (checklist, não automatizados): pasta real do OneDrive; remover pendrive
durante a gravação; queda de energia; `subst`; ponto de montagem (admin); executável em
máquina limpa.
