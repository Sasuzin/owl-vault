# Histórico de versões do Owl Vault

O Owl Vault está em desenvolvimento contínuo. Cada ajuste sobe a versão
(`__version__` em `src/owl_vault/__init__.py`) e ganha uma entrada aqui:

* **0.X.0** — funcionalidade nova ou mudança visível;
* **0.X.Y** — correção ou ajuste pequeno.

O executável também mostra o **build** (número de commits do projeto, sobe sozinho a cada
ajuste) e o commit, em ☰ → Sobre, no rodapé e nas propriedades do `OwlVault.exe`
(Versão do arquivo `<versão>.<build>`, por exemplo `0.3.1.8`).

## 0.6.0 — 2026-11-23

* Assinatura de autoria: "Desenvolvido por Luís Felipe Galvão" e "© 2026 Luís Felipe Galvão.
  Todos os direitos reservados." em ☰ → Sobre o Owl Vault, nas propriedades do `OwlVault.exe`
  (Detalhes → Empresa e Direitos autorais), no instalador (editor que aparece em
  Configurações → Aplicativos instalados) e no README.

## 0.5.0 — 2026-11-23

* **Instalador** `OwlVault-Setup.exe`, ao lado do `OwlVault.exe` de sempre: telas de
  instalação em português, por usuário e sem administrador, com a opção "Criar atalho na Área
  de Trabalho" (marcada) e "Abrir o Owl Vault" no fim. O Owl Vault passa a aparecer em
  Configurações → Aplicativos instalados, com **Desinstalar**.
* A desinstalação **não apaga** o perfil nem as pastas protegidas. Se houver um perfil neste
  computador, ela avisa antes: pastas protegidas só abrem com o Owl Vault, então, se você não
  for instalá-lo de novo, use "Remover proteção…" em cada pasta antes.
* O instalador não substitui uma versão mais nova já instalada, e grava junto as marcas de
  versão do exe: um `OwlVault.exe` mais antigo aberto depois também não o substitui.
* O `OwlVault.exe` sozinho continua funcionando como antes (ele mesmo se instala na primeira
  vez). Os dois instalam no mesmo lugar e podem ser usados um depois do outro.

## 0.4.3 — 2026-11-23

* O `OwlVault.exe` não leva mais uma cópia do OpenSSL tirada da máquina onde foi gerado
  (`libssl-3-x64.dll` e `libcrypto-3-x64.dll`, na 0.4.0 vindas do Git for Windows, de versão
  desconhecida) nem os plugins de TLS do Qt: o Owl Vault não usa rede. O exe ficou 2,7 MB
  menor. A criptografia não muda (o `cryptography` traz o próprio OpenSSL embutido).

## 0.4.2 — 2026-11-23

* O programa é o mesmo da 0.4.1. Um teste da prática da senha mestra dependia da data do
  computador e passou a falhar a partir de 21/11/2026, impedindo o build: agora ele cria o
  perfil sempre na data simulada do teste.

## 0.4.1 — 2026-11-19

* Ícone da coruja na barra de tarefas também na primeira vez, abrindo o arquivo baixado: no
  0.4.0 a cópia instalada já mostrava a coruja (pelos atalhos), mas o `OwlVault.exe` aberto
  direto de outra pasta ainda mostrava o ícone genérico do Windows. O programa agora registra
  a coruja como ícone da janela antes de ela aparecer, que é o ícone que a barra usa quando o
  Owl Vault ainda está ocupado abrindo.

## 0.4.0 — 2026-11-19

* Atalho **Owl Vault** na Área de Trabalho: criado na primeira instalação em cada computador
  (e na primeira vez que esta versão abre num computador que já tinha o Owl Vault). Se você
  apagar o atalho, ele não volta; se ele apontar para outra cópia do `OwlVault.exe` (a
  baixada, por exemplo), é corrigido para a cópia instalada.
* Ícone da coruja sempre na barra de tarefas: às vezes aparecia o ícone genérico do Windows
  (o programa usava um ID de aplicativo próprio, e a barra caía no ícone padrão quando a
  janela demorava a responder ao abrir). Agora a barra usa o ícone embutido no exe.

## 0.3.3 — 2026-11-19

* Título das janelas sem o nome repetido: era "Owl Vault v0.3.2 · build 10 · 843d2dd - Owl
  Vault" na janela principal e "Owl Vault — Cópia criptografada - Owl Vault" na Cópia
  criptografada (o Qt acrescentava " - Owl Vault" no fim).

## 0.3.2 — 2026-11-19

* A senha mestra e a senha da Cópia criptografada passam a ter no mínimo 8 caracteres (eram
  12). Senhas mais longas continuam mais seguras: o indicador de força mostra "fraca" para
  uma senha de 8 caracteres e sobe conforme ela cresce e mistura letras, números e símbolos.
  Perfis e cofres com senha de 8 a 11 caracteres também abrem nas versões anteriores, mas
  elas recusam essa senha na hora de criar um perfil ou uma cópia: em outro computador, use a
  0.3.2 ou mais nova.

## 0.3.1 — 2026-11-19

* PIN: ano-mês-dia com 2 dígitos de ano (como 401216, que seria 16/12/2040) não é mais
  tratado como data. Continuam recusadas as datas no jeito brasileiro (dia-mês-ano, como
  250390 ou 25031990) e ano-mês-dia com o ano inteiro (19900325), só com anos de 1900 a 2099.
* A mensagem de PIN recusado por data agora diz qual data ele parece ("Este PIN parece a data
  25/03/90").
* PINs feitos de dois pedaços fáceis (dígito repetido ou sequência, como 000123, 222345 ou
  567876) e contagens com zero à esquerda (01020304, 000102) são recusados como fáceis de
  adivinhar. Com 8 dígitos, duas datas dia-mês juntas (25031208, "as datas 25/03 e 12/08")
  continuam recusadas.

## 0.3.0 — 2026-11-17

**Visual**

* Visual "Cofre" (Claude Design, Estilo 5) em todo o app, nos temas escuro e claro (☰ → Tema):
  tokens de cor únicos, cartões, trilha de passos, rodapé com estado, botões pílula, campos de
  48 px, medidor de força, foco de teclado visível e Tab na ordem de leitura.
* "Proteger uma pasta" virou um assistente na própria janela (Pasta → Conferência → Trancar),
  com uma linha por checagem e o andamento das etapas.
* Cópia criptografada refeita como assistente de 4 passos (Pastas → Senha → Conferência → Criar).
* Versão e build visíveis no app e no executável; este histórico.

**Segurança e dados**

* Nenhum cofre é apagado se estiver ilegível, sem gravação do estado ou sem outra cópia
  conferida; o estado "trancada" é gravado logo depois de mover o cofre para a pasta.
* Abrir confere o espaço livre antes de tirar o cofre da pasta; "Desfazer" guarda a versão
  quando há conflito; "Procurar a pasta…" funciona em qualquer estado.
* PIN: o contador de tentativas fica nas duas cópias do perfil, a senha mestra não reativa um
  PIN desativado e PINs fáceis (sequências, repetições, teclado, datas) são recusados.
* Perfil danificado é reconhecido e leva à recuperação, sem apagar o arquivo danificado.
* Atalho, ícone e área temporária com permissões só da sua conta; atalho conferido e refeito
  ao iniciar; atalho sem nome do computador.
* Instância única aceita pedidos só da mesma conta do Windows; versão mais antiga não
  substitui a instalada.

**Correções da revisão final**

* "Desfazer" um trancamento interrompido decide pelo próprio arquivo o que nunca foi apagado:
  um arquivo recriado no lugar não faz perder a versão guardada.
* "Continuar trancando" depois de um "Desfazer" confere o conteúdo de cada arquivo antes de
  apagá-lo.
* Uma falha antes de começar a apagar sempre devolve a pasta aberta, e "Tente de novo" funciona.
* A abertura nunca começa a devolver os arquivos sem gravar a etapa no perfil.
* Uma versão anterior mantida não é mais dada como coberta por um cofre mais velho.
* "Procurar a pasta…" recusa uma cópia trancada (backup) no lugar de uma pasta aberta e acha
  uma pasta escondida pela pasta onde ela fica.
* Cofre da área temporária sumido ou danificado, cofre trocado por outro e pasta sem permissão
  viram "Precisa de atenção" com texto próprio e saída; as outras pastas continuam na lista.
* Trancamento interrompido com a cópia nova ilegível ganhou "Deixar a pasta aberta" (nada é
  apagado).
* Pasta escondida que não abre continua escondida.
* As pendências do trancamento dizem se o arquivo está em uso, se mudou ou se é um item novo
  que não está guardado.
* "Tirar da lista" existe em todo estado e diz onde ficam os arquivos e as cópias fora da pasta.
* Toda linha da lista tem saída: problemas novos caem num "Resolver…" com "Procurar a pasta…" e
  "Tirar da lista"; uma unidade com outra letra explica como procurar.
* Sair e "Trancar agora" contam também pastas abrindo, restaurando e trancando, trancam em fila
  e mostram um resumo do que ficou aberto.
* Enter não escolhe mais "Trancar mesmo assim" (que apaga a cópia protegida dos arquivos que
  sumiram).
* Bloquear (agora, por inatividade, Win+L ou suspensão) fecha a Cópia criptografada e apaga as
  senhas e os caminhos dela.
* "Criar nova senha mestra" com o PIN desativado no meio pede a senha mestra; recuperar a versão
  anterior mostra o que falhou.
* Trocar o PIN ou a senha mestra vale nas duas cópias do perfil ou não vale; uma cópia de
  segurança que ficou para depois é avisada.
* O Owl Vault instalado é refeito se o executável for trocado por fora ou por um build novo com
  o mesmo número, nunca por uma versão mais antiga.
* O pedido de um atalho com o Owl Vault ocupado não se perde: espera a confirmação e avisa se
  não chegar.
* Cópia criptografada: aceites pedidos de novo a cada conferência, "Destino gravável" sem ✓
  antes do teste, nome de cofre inválido recusado e mensagens certas para cada operação.
* A janela principal, a Cópia criptografada e os diálogos cabem em telas de notebook (1366×768
  a 125% e 150%), com os botões sempre à vista.
* Visual: menus com fundo, linha da lista destacada, ícone de aviso maior, foco visível nas
  listas, caminho longo mostrando o fim, nomes nunca viram formatação, sombras e cores
  acompanhando a troca de tema e marca no tema em uso.
* "1 byte" no singular e tempos arredondados certo.

**Segunda revisão**

* Uma falha ao gravar o perfil num trancamento que não deu certo devolve a pasta aberta, e
  "Tente de novo" funciona.
* "Continuar trancando" depois de uma queda no meio de um "Desfazer" apaga os pedaços que esse
  "Desfazer" deixou, em vez de chamá-los de "item novo" sem fim.
* "Trancar e sair" tranca as pastas que dá e mostra as que precisam de atenção, com
  [Voltar ao Owl Vault] como padrão; com essa pergunta na tela, a inatividade bloqueia o app.
* Bloqueio pedido durante um trabalho acontece antes do resultado: nenhum aviso com nomes,
  nenhum Explorer aberto e nenhum erro na tela travada; no Alterar PIN, avisa que o PIN mudou.
* Seletor de pastas aberto no bloqueio não começa nada nem guarda o caminho escolhido.
* Os Resolvers de versão anterior e de senha mestra antiga também têm "Tirar da lista".
* Nenhum trabalho terminado guarda a senha, o PIN ou a função que os usou, e nenhum objeto de
  trabalho sobra na memória.
* Diálogos limitados à tela tiram a altura só do texto (os botões não se sobrepõem); numa tela
  baixa, os botões vão para duas colunas; avisos curtos voltaram à altura natural; a barra de
  rolagem some quando o texto cabe.
* "Trancar agora" põe no resumo também as pastas visíveis que não estão em "aberta" (abrindo,
  restaurando, trancamento interrompido), como o "Trancar e sair".
* Se a gravação do fim de um "Desfazer" falha, dá para clicar em "Desfazer" de novo sem
  reiniciar o app.
* "Trancar e sair": Cancelar na pergunta sobre arquivos apagados volta ao Owl Vault mesmo com
  pasta precisando de atenção, em vez de oferecer "Sair sem trancar" e deixar abertas pastas
  que nem foram tentadas.
* Se o computador desligar logo depois de um trancamento que não deu certo porque a pasta
  mudou, ao reabrir a pasta volta aberta, sem o aviso falso de que arquivos começaram a ser
  apagados.
* Em telas pequenas com escala alta (175%), os botões da "Versão anterior" ficam em duas
  colunas e nenhum some atrás da barra de tarefas.
* O Tab que chega a uma lista ou campo do corpo de um diálogo rola até ele, mesmo com a lista
  rolada por dentro; os diálogos continuam abrindo no topo.

## 0.2.0 — 2026-11-17

* **Pastas protegidas**: tranca uma pasta no próprio lugar (arquivos criptografados dentro
  dela, cópias legíveis apagadas só depois de conferidas), com ícone da coruja, atalho
  "Abrir com Owl Vault", esconder do Explorer, recuperar em outro computador e remover proteção.
* Senha mestra + PIN (PIN protegido também pelo Windows/DPAPI, 5 tentativas).
* Travamento automático (5 min, Win+L, suspensão) e "Trancar e sair".
* Instalação por usuário em `%LOCALAPPDATA%\Programs\Owl Vault` + Menu Iniciar.
* Interface simplificada: só PIN ou senha mestra são digitados.
* A "cópia criptografada" da 0.1 passou para ☰ → Cópia criptografada de uma pasta.

## 0.1.1 — 2026-11-17

* Nova identidade visual: logo da coruja com escudo e tema roxo.

## 0.1.0 — 2026-11-17

* Primeira versão: cópias criptografadas e verificáveis de pastas (AES-256-GCM + Argon2id),
  verificação, restauração em pasta nova, retomada e salvamento de emergência.
