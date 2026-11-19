# Owl Vault v2 — Especificação das telas

Consolidada pela revisão de design (juiz independente). Princípio: o usuário só digita PIN ou senha mestra.

VISUAL (0.3): estilo "Cofre" do Claude Design (visual/ESTILO5-COFRE.md): tokens únicos em
src/owl_vault/ui/tema/theme_cofre.py, cartões, trilha de passos, lateral de 272 px com resumo e
dica, rodapé com o botão principal e o estado. O assistente do primeiro uso (T1/T2) e "Proteger
uma pasta" (T5: Pasta → Conferência → Trancar) usam a trilha de passos dentro da janela; a
"Cópia criptografada" (T14) é o assistente de 4 passos do design (Pastas → Senha → Conferência
→ Criar).

PRINCÍPIO: o usuário só digita PIN ou senha mestra. Todo o resto é escolher pasta no seletor do Windows ou clicar em botão. Não existe campo de cofre nem de pasta de teste. Estados de uma pasta: Trancada · Aberta — visível neste computador · Escondida · Precisa de atenção · Indisponível — conecte a unidade · Trancando…/Abrindo… N%.


## T0 INSTALAÇÃO (sem tela): na 1ª execução, o app se copia para %LOCALAPPDATA%\Programs\Owl Vault\OwlVault.exe e cria um atalho no Menu Iniciar e outro na Área de Trabalho (este só uma vez: apagado, não volta).


## T1 ASSISTENTE 1/2 — "Crie sua senha mestra"

## Texto: "A senha mestra abre suas pastas em qualquer computador. Se você esquecê-la, ninguém consegue recuperar os arquivos — nem o Owl Vault."
Campos: [Senha mestra] [Repita a senha mestra] (mínimo de 8 caracteres, com indicador de força).
Caixa obrigatória: "Anotei minha senha mestra em um lugar seguro."
Botão: [Continuar]. Link: "Já usei o Owl Vault — recuperar minhas pastas" (→ T12).


## T2 ASSISTENTE 2/2 — "Crie seu PIN"

## Texto: "Use o PIN no dia a dia, só neste computador. Ele é mais fraco que a senha mestra: não use datas nem sequências como 123456."
Campos: [PIN (6 a 12 números)] [Repita o PIN]. Erro: "Este PIN é fácil de adivinhar. Escolha outro." (sequências, fileira do teclado, blocos repetidos, palíndromos, dois pedaços fáceis emendados, caminhos do teclado numérico, contagens e PINs comuns — lista completa em PASTAS_PROTEGIDAS.md §2). Datas têm mensagem própria, que mostra a data: "Este PIN parece a data 25/03/90. Não use datas como PIN: escolha outro."
Botão: [Concluir] (→ T4).


## T3 DESBLOQUEIO — "Digite seu PIN"
Campo: [PIN]. Botão: [Entrar]. Links: "Usar a senha mestra" · "Esqueci o PIN".
Erro: "PIN incorreto. Restam N tentativas; depois disso, só a senha mestra." Depois de 5 erros, o campo passa a ser [Senha mestra].
Variante de prática (no 1º desbloqueio depois de 1 dia e depois a cada 30 dias): "Digite sua senha mestra — pedimos de vez em quando para você não esquecê-la." Campo: [Senha mestra]. Botão: [Entrar]. Depois de 3 erros: "Esqueceu? Enquanto o PIN funciona, você pode criar uma nova." [Criar nova senha mestra] [Usar o PIN desta vez].
Variante DPAPI: "O Windows não consegue mais usar o PIN deste computador (a senha do Windows foi redefinida ou o Windows foi reinstalado). Digite sua senha mestra." Campo: [Senha mestra]. Depois → T2 para criar um PIN novo.
Variante atalho: título "Abrir '<Nome>'", campo [PIN], botão [Abrir]. Aparece SEMPRE que o atalho é usado, mesmo com o app destravado. Se o pedido chegou por mensagem (o app já estava aberto), depois do PIN ainda pergunta "Abrir '<Nome>'?" [Abrir] [Cancelar]. Antes de abrir, o atalho da pasta é conferido; se estava diferente do esperado, é refeito e o app avisa ("O atalho desta pasta foi refeito"). Atalho de uma pasta que não está na lista, com o app destravado: não pede PIN; explica e oferece [Recuperar uma pasta protegida…].
Variante perfil danificado (as duas cópias do perfil ilegíveis ou o índice não autentica): "O perfil deste computador está danificado" — nunca "Senha mestra incorreta" nem o assistente de criação. Botão [Recuperar minhas pastas com a senha mestra]: renomeia perfil.owlp e .bak para *.danificado-<data> (nada é apagado) e abre o assistente no modo recuperar (→ T1 → T12). Perfil que não pôde ser lido agora (erro de disco): "Não foi possível ler o perfil agora" [Tentar de novo]. Se o app usou a cópia .bak, a lista mostra um aviso.

## Travamento automático: o app volta para T3 depois de 5 min sem uso, ao bloquear o Windows (Win+L) e ao suspender. Também existe ☰ > "Bloquear agora".
Todo bloqueio fecha a janela da Cópia criptografada (T14) sem perguntar: as senhas e os caminhos digitados somem; se ela estiver trabalhando, o trabalho para num ponto seguro e a janela se fecha sozinha quando ele parar. Um trabalho da Cópia conta como uso (os 5 min não a interrompem). Os diálogos já fechados, que guardam nomes de pastas e arquivos, são destruídos. Se o bloqueio acontecer no meio de "Trancar agora", nenhum resumo com nomes aparece na tela travada. Seletor de pastas do Windows que estava aberto: continua aberto, mas o caminho escolhido depois do bloqueio é descartado (em "Proteger uma pasta" e em "Recuperar esses arquivos em outra pasta…"). Bloqueio pedido durante um trabalho (Win+L, suspensão): acontece quando o trabalho termina, ANTES de mostrar o resultado — o aviso com nomes não aparece, o Explorer não abre, a sessão nova de um desbloqueio é descartada (no Alterar PIN, só "PIN alterado / Para entrar, use o PIN novo.") e o erro, que pode citar arquivos, não vai para a tela travada; o estado da pasta aparece na lista depois de desbloquear. Nenhum trabalho terminado guarda a senha, o PIN ou a função que os usou.


## T4 TELA PRINCIPAL — "Pastas protegidas"

## Topo: botão principal [+ Proteger uma pasta…] e o menu ☰.
Faixa (enquanto houver pasta aberta): "1 pasta está aberta e visível neste computador. [Trancar agora]". Contam como "abertas e visíveis" (podem ter cópias legíveis) as pastas em: aberta, abertura incompleta, abrindo, restaurando, apagando e trancando — na faixa, no T11 e na contagem guardada ao bloquear. [Trancar agora] tranca em fila: uma falha não para as outras e, no fim, um resumo diz quais ficaram abertas e por quê ("Não deu para trancar '<Nome>'").
Estado vazio: "Nenhuma pasta protegida ainda. Clique em 'Proteger uma pasta…' e escolha a pasta que você quer trancar."
Cada linha mostra ícone, Nome (negrito), Local (cinza), Estado por extenso e UM botão:
- Trancada → [Abrir]
- Escondida → [Abrir]
- Aberta — visível neste computador → [Trancar]
- Precisa de atenção → [Resolver…]
- Indisponível — conecte a unidade X → sem botão
- Trancando…/Abrindo… N% → barra de progresso; clicar abre T6
Menu "⋯" da linha:
- Trancada: "Esconder do Explorer" · "Verificar arquivos" · "Remover proteção…"
- Escondida: "Mostrar no Explorer" · "Verificar arquivos" · "Remover proteção…"
- Aberta: "Abrir a pasta no Explorer" · "Trancar e esconder" · "Remover proteção…"
- Trancando, apagando, abrindo, restaurando, abertura incompleta (ou um estado novo): "Abrir a pasta no Explorer" (quando há conteúdo) · "Procurar a pasta…"
- Não encontrada / Indisponível: "Procurar a pasta…" (a linha de uma pasta indisponível diz: "Se a unidade voltou com outra letra, use ⋯ > Procurar a pasta…")
- Problema desconhecido: a ação base (Abrir/Trancar) quando ela vale, mais "Procurar a pasta…".
- Todo menu termina com "Tirar da lista". Toda linha tem saída.
O nome longo é cortado com "…" (inteiro na dica do mouse); o estado e o detalhe quebram linha, e o botão e o ⋯ nunca somem.
Menu ☰: "Recuperar uma pasta protegida…" · "Cópia criptografada de uma pasta…" · "Alterar PIN…" · "Bloquear agora" · "Limites da proteção" · "Tema" (Escuro/Claro, com a marca no tema em uso).
Tamanho: a janela abre dentro da área útil da tela (descontada a moldura) e maximiza se nem o tamanho mínimo couber; as colunas e cartões rolam e o rodapé fica sempre à vista (testado em 1366×768 a 125% e 150%). Diálogos: o conteúdo rola e a linha de botões fica sempre à vista; um erro novo é trazido para a vista. Num diálogo limitado à tela, a altura que falta sai só do texto (os botões nunca se sobrepõem); se a coluna de botões não couber com o corpo mínimo, eles ficam em duas colunas, na ordem de leitura. Avisos curtos têm a altura natural, e a barra de rolagem só aparece quando o texto não cabe.


## T5 PROTEGER UMA PASTA (nenhum campo para preencher)
Na 0.3 é um assistente NA JANELA (trilha Pasta → Conferência → Trancar), sem caixas modais: o passo 1 tem o caminho com [Escolher] (5a); o passo 2 roda a conferência (5b) e mostra uma linha por checagem (Pasta permitida, Em uso, Espaço, Segurança do Windows…) com ✓/!/✗ — uma checagem que não chegou a rodar fica "Não conferido", nunca com ✓ falso —, os 5 pontos de 5d numa caixa de aviso, a caixa "Entendi" (obrigatória na 1ª proteção), [Trancar agora] (só sem falhas), [Conferir de novo] e "Detalhes" recolhido; o passo 3 é o progresso (T6) com um registro só das etapas. No fim: resultado + [Voltar para a lista] e o discreto "Proteger outra pasta".
5a. Seletor de pastas do Windows: "Escolha a pasta que você quer proteger".
5b. "Conferindo a pasta…" com barra e [Cancelar].
5c. Recusa: cada bloqueio aparece na linha da sua checagem, com o motivo principal, uma ação e "Detalhes" recolhido (até 5 nomes + "e mais N"); botões [Conferir de novo] e [Voltar]. Textos:
- Pasta do Windows: "Não dá para proteger a pasta Documentos inteira. Crie uma pasta dentro dela (ex.: Documentos\Particular), coloque lá o que quer esconder e proteja essa."
- Contém pasta do Windows: "Esta pasta contém a pasta Downloads, que o Windows usa. Escolha uma pasta que não contenha pastas do sistema."
- OneDrive: "Esta pasta está no OneDrive, que guarda cópias na nuvem que o Owl Vault não consegue apagar. Mova a pasta para fora do OneDrive (ex.: C:\Particular), apague-a também da Lixeira do OneDrive na internet e tente de novo."
- FAT/exFAT: "Esta unidade usa exFAT. O Owl Vault só tranca pastas em unidades NTFS. Para pendrives, use ☰ > Cópia criptografada de uma pasta."
- Em uso: "Feche estes arquivos e clique em Tentar de novo: Relatório.docx, …"
- Bloqueio do Windows (Acesso controlado a pastas ou permissão): "O Windows não deixou o Owl Vault apagar arquivos aqui. Em Segurança do Windows > Proteção contra ransomware > Permitir um aplicativo, adicione %LOCALAPPDATA%\Programs\Owl Vault\OwlVault.exe."
- Vínculo: "O arquivo 'X' também existe em outro lugar do computador (vínculo do Windows). Trancado aqui, continuaria visível lá. Copie-o para fora, apague o vínculo e tente de novo."
- Atalhos especiais: "A pasta tem atalhos especiais do Windows que o Owl Vault não protege: X. Tire-os da pasta e tente de novo."
- Maiúsculas: "Dois itens têm o mesmo nome, mudando só maiúsculas e minúsculas: A e a. Renomeie um deles."
- Espaço: "Falta espaço no disco D:. Libere cerca de 12 GB."
- Dentro de outra protegida: "Esta pasta fica dentro de 'Particular', que já é protegida."
- Sem escrita ao lado: "O Windows não deixa criar arquivos ao lado desta pasta. Mova-a para dentro de Documentos e tente de novo."
- Sistema, perfil ou raiz: "Escolha uma pasta sua, como Documentos\Particular."
5d. Confirmação "Proteger '<Nome>'?": "1.234 arquivos · 40 GB · pode levar cerca de 1 hora." (o tempo só aparece se passar de 2 min)
"• Os arquivos ficam guardados, criptografados, dentro da própria pasta. As cópias legíveis são apagadas (não vão para a Lixeira)."
"• Para abrir, use o atalho dentro da pasta ou o Owl Vault, com o seu PIN."
"• Cópias que já existem em outros lugares (Lixeira, OneDrive, backups, versões anteriores) não são apagadas. Recomendamos ativar o BitLocker."
"• Ao abrir, os arquivos voltam com nome, conteúdo e data de modificação; data de criação, atributos e permissões não voltam."
"• Enquanto aberta, a pasta ocupa o dobro do espaço."
Na 1ª proteção do perfil, a caixa "Entendi" é obrigatória. Botões: [Trancar agora] [Voltar].
5e. Progresso (→ T6, no passo 3 do assistente).


## T6 PROGRESSO
"Trancando '<Nome>'": "1/4 Guardando os arquivos (523 de 1.234)" · "2/4 Conferindo" · "3/4 Testando a recuperação" · "4/4 Apagando as cópias legíveis". Mostra o tempo restante e "Não use esta pasta até terminar."
Botões: [Cancelar] nas etapas 1 a 3 ("Nada foi apagado."); na etapa 4, [Parar depois do arquivo atual] (a pasta vai para Precisa de atenção).
Fim: "'<Nome>' está trancada." Em unidade removível NTFS, acrescenta: "Use 'Remover hardware com segurança' antes de tirar a unidade."
"Abrindo '<Nome>' (523 de 1.234)" com [Cancelar] (dá para continuar depois). No fim, a pasta abre no Explorer.


## T7 TRANCAR UMA PASTA ABERTA: vai direto para T6, sem confirmação, EXCETO se faltarem arquivos que estavam no cofre anterior:
"Desde que você abriu '<Nome>', 3 arquivos foram apagados ou movidos: a.docx, b.jpg, c.pdf. Se você trancar, eles não ficarão na pasta trancada e a cópia protegida deles será apagada para sempre." [Trancar mesmo assim] (vermelho) [Cancelar] (padrão: Enter nunca escolhe trancar e apagar)


## T8 RESOLVER… (Precisa de atenção): uma explicação e as saídas. A explicação é o texto do gerente (`attention`), específico do problema atual — nunca uma frase fixa que pode ser falsa. Todo Resolver tem [Tirar da lista].
- Trancamento interrompido (etapa 4, "apagando"): o texto separa os casos — arquivo em uso ("Feche-os e clique em Continuar trancando"), arquivo que mudou depois de criptografado (a versão nova NÃO está guardada) e item novo colocado durante o trancamento (NÃO está guardado: "Mova-os para outro lugar"); a lista vai nos detalhes. [Continuar trancando] [Desfazer (deixar a pasta aberta)] [Mostrar no Explorer] (se há pendências) [Tirar da lista] [Fechar]. Depois de Desfazer: se algum arquivo não voltou porque já havia outro item com o mesmo nome num caminho que o Owl Vault apagou, o app lista esses nomes ("'<Nome>' continua aberta") e a versão guardada vira "Versão anterior mantida"; se algo falhou, "Nem todos os arquivos voltaram para '<Nome>'" com a lista.
- Trancamento interrompido sem confirmação (estado "trancando"): o Owl Vault confere a pasta e mostra o resultado na faixa da lista. Se ela continuar presa (a cópia que estava sendo criada não pode ser conferida): o texto do gerente e [Deixar a pasta aberta] (a pasta volta a ficar aberta e essa cópia fica guardada como versão anterior; nada é apagado) [Procurar a pasta…] [Tirar da lista] [Fechar] (padrão).
- Abertura interrompida: o texto do gerente (inclusive um item colocado na pasta durante a abertura) e [Continuar abrindo] [Tirar da lista] [Fechar].
- Abertura incompleta: "N arquivos não puderam ser abertos: … A cópia protegida deles continua guardada." [Tentar de novo] [Continuar sem eles] [Tirar da lista] (o cofre anterior nunca é apagado automaticamente)
- Indisponível (pelo atalho ou pelo menu): "Conecte a unidade. Se ela voltou com outra letra, clique em 'Procurar a pasta…'" [Procurar a pasta…] [Tirar da lista] [Fechar] (padrão).
- Problema que a janela não conhece (ex.: o cofre da área temporária sumiu ou não abre, o cofre na pasta não é o registrado, sem permissão para ler a pasta, erro de disco): o texto do gerente e [Abrir]/[Trancar] (só quando a ação vale) [Procurar a pasta…] [Tirar da lista] [Cancelar] (padrão). "Verificar arquivos" recusa um cofre que não é o registrado ("Nada foi verificado nem alterado.").
- Item colocado na pasta trancada: "Há 1 item que foi colocado em '<Nome>' depois de trancar: Nova planilha.xlsx. Mova-o para outro lugar e clique em Tentar de novo." [Mostrar no Explorer] [Tentar de novo]
- Pasta não encontrada: "A pasta '<Nome>' não está mais em D:\Fotos." [Procurar a pasta…] [Tirar da lista] ("Nada será apagado."). Vale em qualquer estado: numa pasta aberta renomeada, explica que precisa ser a mesma pasta, na mesma unidade; para uma pasta escondida, dá para escolher a pasta onde ela fica.
- Tirar da lista (confirmação, padrão [Cancelar]): "Nada será apagado." + o aviso do gerente para o estado atual — onde ficam os arquivos legíveis (só diz que continuam na pasta quando é verdade), onde fica cada cópia criptografada fora da pasta (".owlvault-<id>" na pasta-mãe, versão mantida) e que ela NÃO aparece em "Recuperar uma pasta protegida" (para abri-la: Cópia criptografada → "Abrir uma cópia"). "Use ☰ > Recuperar uma pasta protegida" só numa pasta trancada com tudo dentro dela.
- Versão anterior mantida: "Foi mantida uma versão anterior de '<Nome>' com N arquivos que não estão na pasta." [Recuperar esses arquivos em outra pasta…] [Apagar a versão anterior…] (botão vermelho; a confirmação lista os N nomes) [Tirar da lista] [Fechar]
- Versão anterior ilegível: "A versão anterior de '<Nome>' que foi mantida não pôde ser lida. … Nada foi apagado." [Tentar recuperar em outra pasta…] (ou o salvamento de emergência, docs/RECOVERY.md); se a pasta oculta dela sumiu: [Esquecer a versão que sumiu] (nada é apagado) [Tirar da lista] [Fechar]. Nunca é contada como "0 arquivos" nem apagada.
- Senha mestra antiga: "Tranque de novo para atualizar a senha mestra." [Abrir] [Tirar da lista] [Fechar] (só aparece depois de 'Criar nova senha mestra')
- Pedaços de um "Desfazer" interrompido (arquivos ".owl-…part" deixados por uma queda): "Continuar trancando" apaga os que são desse Desfazer; um pedaço preso aparece com texto próprio ("não mova esses pedaços: clique em Continuar trancando de novo") e nunca como "item novo".


## T9 ESCONDER DO EXPLORER: "Esconder '<Nome>'? A pasta some do Explorer e só volta pelo Owl Vault. Quem souber mostrar arquivos protegidos do sistema ainda pode ver que ela existe, mas não o conteúdo." [Esconder] [Cancelar]. Só vale para pasta trancada; numa pasta aberta, a opção é "Trancar e esconder". "Mostrar no Explorer" age na hora, sem confirmação.


## T10 REMOVER PROTEÇÃO: "Remover a proteção de '<Nome>'? A pasta volta a ser comum e qualquer pessoa que use este computador poderá ver os arquivos." Campo: [PIN]. Botões: [Remover proteção] [Cancelar]. Se a pasta estiver trancada, ela é aberta antes (T6). Se faltar algo, o app mostra a lista e pede confirmação antes de apagar o cofre.


## T11 SAIR COM PASTAS ABERTAS: "Sair do Owl Vault? Estas pastas estão abertas e visíveis: • Fotos (trancar leva cerca de 35 min)" [Trancar e sair] (padrão) [Sair sem trancar] [Cancelar]. Entram na lista as pastas em aberta, abertura incompleta, abrindo, restaurando, apagando e trancando; as que não dá para trancar automaticamente aparecem como "precisa de atenção" (quando TODAS precisam de atenção, só [Sair sem trancar] [Cancelar]). Com pastas trancáveis e pastas de atenção juntas, [Trancar e sair] tranca as trancáveis e, no fim, mostra o resumo com as de atenção ("Não deu para trancar '<Nome>'… Volte ao Owl Vault e use 'Resolver…' nesta pasta.") [Voltar ao Owl Vault] (padrão) [Sair sem trancar]. Com essa pergunta na tela, os 5 min sem uso bloqueiam o app (que então não sai). A lista é refeita depois da resposta: se surgiu outra pasta aberta (pelo atalho, com a pergunta na tela), a pergunta volta; durante "Trancar e sair", o atalho pede "Aguarde". As pastas são trancadas em fila; uma falha não para as outras e o app só sai sem trancar se o usuário escolher [Sair sem trancar]. [Cancelar] no T7 de uma pasta da fila desiste da saída: o app volta à lista com o aviso "Nem todas as pastas foram trancadas", sem oferecer [Sair sem trancar], mesmo que haja pastas de atenção. Em caso de erro: "Não deu para trancar 'Fotos': feche 'IMG_0042.jpg' e clique em Tentar de novo." [Tentar de novo] [Sair sem trancar]. Se o trancamento parou na etapa 4: "Os arquivos já estão guardados, mas parte das cópias legíveis ainda está na pasta… use Resolver…" [Voltar ao Owl Vault] [Sair sem trancar] (sem "Tentar de novo", que não trancaria).


## T12 RECUPERAR UMA PASTA PROTEGIDA: "Escolha a pasta com o ícone do Owl Vault. Se ela estava escondida, escolha a pasta onde ela ficava." → seletor do Windows → (se houver mais de uma, uma lista para marcar) → campo [Senha mestra] → botão [Recuperar].


## T13 ALTERAR PIN: campos [PIN atual] [Novo PIN] [Repita o novo PIN], botão [Salvar]. Link "Esqueci o PIN" (pede a senha mestra). Se o PIN novo (ou a senha mestra nova) valeu mas a cópia de segurança do perfil não pôde ser trocada junto, o aviso da lista diz isso ("…ela será refeita na próxima gravação"); se nada foi gravado, a mudança não vale.


## T14 CÓPIA CRIPTOGRAFADA DE UMA PASTA (modo v1, uso raro)
Assistente de 4 passos do design (visual/ESTILO5-COFRE.md): Pastas → Senha → Conferência → Criar, com lateral "Escolhas do passo 1" e dica por passo; no topo, discretos "Abrir uma cópia", "Conferir uma cópia" e "Limites da proteção".
Passo 1: [Origem] [Local do cofre] [Teste de restauração] (com [Escolher]) e o nome do cofre (sugeridos automaticamente); discreto "Retomar criação interrompida".
Passo 2: a cópia usa uma SENHA PRÓPRIA (não a senha mestra das pastas): [Senha] (mínimo 12, com medidor) [Confirmação] e o aviso da cópia: "O cofre é uma cópia criptografada. A pasta original continua legível até você removê-la — e, mesmo removida, podem restar cópias dela na Lixeira, em Versões anteriores, no OneDrive, em backups e no índice do Windows."
Passo 3: conferência numa linha por item (espaço, arquivos em uso, tamanho e contagem, destino gravável) e os aceites obrigatórios como caixas (limites, backup, perda da senha; FAT/exFAT só quando o destino é FAT/exFAT). "Destino gravável" fica neutro (•): a gravação só é testada no início da criação, nunca com ✓ antes disso. Os aceites são desmarcados a cada conferência (inclusive na retomada) e o rodapé acompanha: "marque os avisos" até todos estarem marcados. Nome do cofre inválido (ex.: "Fotos?", "CON", "nome.") é recusado no passo 1.
Passo 4: barra, etapa e registro. Uma falha sem cofre incompleto não manda "Retomar"; cada operação (criar, conferir, abrir) tem a sua mensagem de cancelamento e de erro.
A janela da Cópia cabe na área útil da tela (mínimo 860×480; cartão e lateral rolam, rodapé sempre à vista). "Abrir uma cópia" sugere um nome de pasta que ainda não existe e valida o nome antes de olhar o disco. Fechar ou esconder a janela apaga as senhas digitadas. Fim: "Cópia criptografada criada e verificada (cópia da pasta como estava em <data> <hora>). Mantenha a origem e um backup externo até verificar o cofre, de preferência em outro computador." [Abrir a pasta do cofre] e o discreto "Criar outro cofre".


## T15 LIMITES DA PROTEÇÃO (só texto)
- Pasta aberta é legível por quem usa o computador.
- Rastros: Recentes, listas de atalhos, índice do Windows, miniaturas, SSD e backups.
- O nome da pasta trancada continua visível; use Esconder se o nome for sensível.
- O PIN é mais fraco que a senha mestra.
- Apagar a pasta trancada apaga os arquivos criptografados.
- Copiar a pasta trancada inteira é o seu backup.


## NO EXPLORER (pasta trancada): ícone da coruja; InfoTip "Pasta protegida pelo Owl Vault — os arquivos estão aqui, criptografados. Não apague." Itens visíveis: "Abrir com Owl Vault" (atalho; o ícone é o do próprio programa e ele não guarda o caminho da pasta) e "Como abrir esta pasta.txt", com o texto: "Esta pasta está protegida pelo Owl Vault e seus arquivos estão aqui dentro, criptografados. Para abrir: abra o programa Owl Vault pelo Menu Iniciar e digite seu PIN (o atalho 'Abrir com Owl Vault' desta pasta faz o mesmo). Se o programa não estiver mais neste computador, instale-o de novo e use 'Recuperar uma pasta protegida' com a sua senha mestra. Não apague esta pasta: apagar a pasta apaga os arquivos." O atalho é conferido a cada início e refeito (com aviso) se estiver diferente. Os itens ocultos+sistema (desktop.ini, .owlvault.ico, .owlvault\) não aparecem.


## CAMPOS EM TODO O APP: senha mestra ×2 e PIN ×2 (só no assistente); PIN (desbloquear, abrir pelo atalho, remover proteção); PIN atual + novo ×2 (alterar PIN); senha mestra (prática periódica, recuperar, cópia criptografada).
