# Prompt para Claude Code — Owl Vault

Você é um engenheiro de software sênior especializado em Python, Windows, criptografia aplicada e interfaces desktop. Quero construir o Owl Vault, um aplicativo Windows 10/11 empacotável em .exe, com interface PySide6, para proteger o conteúdo de uma pasta existente com senha.

## Identidade do produto e nomes técnicos
- Nome público e de interface: **Owl Vault** (com espaço, exatamente assim).
- Nome do executável final: `OwlVault.exe`.
- Nome sugerido do repositório: `owl-vault`.
- Pacote Python: `owl_vault`; identificadores internos em `snake_case`.
- Título das janelas: `Owl Vault`; documentação e mensagens devem usar o novo nome.
- Não utilizar `SafeVault` em arquivos novos, código, textos, README ou metadados.
- Visual inicial: interface desktop limpa, acessível, com tema escuro opcional e ícone provisório de coruja; não gastar tempo com identidade visual antes de validar o motor criptográfico.

## Objetivo e modelo de segurança
- A proteção deve ser criptográfica, não apenas ocultação, alteração de atributos ou ACLs.
- Um usuário sem a senha não deve conseguir ler o conteúdo e os nomes originais a partir dos arquivos criptografados. Não prometa proteção contra malware, administradores que observam o sistema enquanto desbloqueado, snapshots, backups, arquivos temporários ou cópias antigas.
- Não implementar inicialmente driver, filesystem virtual, criptografia transparente nem integração com Explorer. A v1 deve oferecer exportação criptografada e restauração controlada, com etapas explícitas e verificáveis.
- O produto deve ser seguro por padrão: NUNCA apagar, sobrescrever ou modificar originais automaticamente. O usuário deve manter cópias verificadas e backups externos. Não implementar exclusão segura como promessa, especialmente em SSDs.

## Stack
Python 3.12+, PySide6, cryptography, argon2-cffi, pytest, ruff, mypy quando viável, PyInstaller. SQLite apenas se realmente necessário para operações não sensíveis. Sem telemetria, nuvem ou dependência de serviços externos.

## Arquitetura proposta
Separar `ui/`, `application/`, `domain/`, `crypto/`, `storage/`, `tests/`. Isolar criptografia da interface. Usar workers para tarefas longas e sinais Qt para progresso/cancelamento. Desenhar estados de operação persistentes e recuperação de falhas.

## Criptografia
- Usar primitivas auditadas de bibliotecas estabelecidas; não inventar algoritmo.
- Argon2id com salt aleatório único por cofre, parâmetros versionados e calibrados; derivar uma KEK para envolver uma chave mestra aleatória de 256 bits.
- AES-256-GCM com nonce único por chave e autenticação de metadados relevantes (AAD). Para arquivos grandes, definir um formato de chunks autenticados com nonce derivado de contador sob chave dedicada por arquivo, domínio e índices autenticados, incluindo comprimento total e marcador final para detectar truncamento/reordenação. Documentar limites e versionamento.
- Manifesto criptografado para caminhos relativos, tamanhos e metadados necessários. Nunca gravar nomes originais em logs, SQLite ou arquivos auxiliares.
- Formato do cofre versionado, com validação estrita de cabeçalhos, limites de tamanhos, nomes de caminho e parâmetros KDF para evitar consumo abusivo de recursos.
- Senhas nunca registradas. Avisar que Python não garante apagamento completo de segredos da memória.

## Operação e integridade
- Começar com protótipo que criptografa uma CÓPIA de pasta de teste para destino separado, preservando integralmente a origem.
- Fazer pré-verificações de espaço, permissões, caminhos, arquivos em uso e conflitos. Recusar reparse points, symlinks, junctions, caminhos externos, arquivos especiais e diretórios protegidos na v1. Não seguir links.
- Criar arquivos temporários no volume de destino quando possível, fazer flush/fsync conforme viável e renomeação atômica apenas dentro do mesmo volume. Não assumir atomicidade de operações entre volumes ou da pasta inteira.
- Registrar estados de progresso e oferecer retomada segura sem sobrescrever dados verificados; cancelamento só em limites consistentes.
- Depois de criptografar, validar a autenticação e efetuar teste de restauração em pasta separada, comparando hashes dos arquivos de origem e restaurados antes de declarar sucesso.
- Descriptografar apenas para pasta de destino escolhida, inicialmente vazia, com proteção contra path traversal, colisões, arquivos existentes e nomes inválidos do Windows. Nunca restaurar por cima da origem sem confirmação e backup.
- A migração para o caminho original só deve ser planejada após testes completos; na primeira versão, manter os originais e pedir ação manual explícita para qualquer limpeza.

## Interface
- Tela principal com selecionar pasta, selecionar destino, criar cofre, verificar cofre, restaurar para nova pasta, progresso, cancelamento e mensagens claras.
- Mostrar explicitamente que a pasta original continua legível enquanto não for removida manualmente; jamais mostrar 'protegida' se originais continuam acessíveis.
- Exibir avisos de backup, risco de perda da senha e limites de proteção.

## Testes
- Unitários e integração: arquivos vazios, binários, Unicode, vídeos grandes gerados artificialmente, hierarquia profunda, nomes duplicados, senha errada, corrupção de header/chunk/manifesto, truncamento, reordenação, falta de espaço simulada, interrupção/cancelamento, symlinks/junctions, path traversal e restauração fiel.
- Testar em diretórios temporários com dados sintéticos; não executar contra pastas pessoais reais.
- Incluir análise de ameaças e checklist de revisão de segurança. Não afirmar auditoria independente.

## Entregas e fluxo
1. Primeiro, apresente plano de arquitetura, modelo de ameaças, formato de armazenamento e riscos. Não escreva código até concluir essa etapa.
2. Em seguida, implemente um MVP por etapas pequenas: estrutura do projeto, motor criptográfico, testes, CLI de laboratório, UI, empacotamento.
3. A cada etapa, apresente arquivos criados, decisões, comandos para executar testes e resultados observados; não alegue testes que não rodou.
4. Inclua README, SECURITY.md, documentação de recuperação, instruções para Windows e configuração de build do PyInstaller.
5. Não execute comandos destrutivos nem toque em dados pessoais sem minha autorização explícita.

Comece pela etapa 1: proponha a arquitetura detalhada, o modelo de ameaças e um plano de MVP seguro, incluindo as limitações práticas de proteger uma pasta existente no Windows.
