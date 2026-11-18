# Owl Vault — Recuperação e solução de problemas

Regra de ouro: **antes de qualquer tentativa de reparo, copie a pasta do cofre inteira** para
outro lugar. Nunca trabalhe na única cópia.

## 0. Pastas protegidas (v2)

| Situação | O que fazer |
|----------|-------------|
| "Trancamento interrompido" | Leia o texto: ele diz se os arquivos listados estão em uso (feche-os), se mudaram depois de criptografados (a versão nova NÃO está guardada) ou se são itens novos colocados durante o trancamento (NÃO estão guardados: mova-os para outro lugar). Depois clique **Continuar trancando**, ou **Desfazer** para devolver tudo e deixar a pasta aberta. |
| "Trancamento interrompido" sem Continuar/Desfazer (a cópia que estava sendo criada não pôde ser conferida) | **Deixar a pasta aberta**: a pasta volta a ficar aberta, essa cópia fica guardada como "Versão anterior" e nada é apagado. |
| "A cópia criptografada … não foi encontrada / não pode ser lida" (pasta oculta `.owlvault-<código>` ao lado da pasta) | Se você moveu ou apagou essa pasta oculta, coloque-a de volta e clique **Resolver…** de novo. Se não for possível, **Tirar da lista** (nada é apagado). |
| "Os dados criptografados que estão na pasta não são os registrados" | Alguém pôs outra cópia (talvez mais antiga) no lugar de `.owlvault`. O Owl Vault não abre nem verifica essa cópia como se fosse a sua. Devolva a cópia certa ou use **Tirar da lista** e depois ☰ → **Recuperar uma pasta protegida**, que abre a cópia que está na pasta. |
| "O Windows não deixa o Owl Vault ler a pasta" | Confira as permissões da pasta (veio de outro computador? tome posse dela). As outras pastas continuam funcionando. |
| "Não abriu por completo" | **Tentar de novo**. Se insistir, **Continuar sem eles**: a versão guardada desses arquivos é mantida e aparece em "Versão anterior". |
| "Versão anterior mantida" | **Recuperar esses arquivos em outra pasta…** cria uma pasta nova com eles. Só use **Apagar a versão anterior…** depois de conferir a lista. |
| "Há itens novos na pasta trancada" | Mova para fora da pasta o que foi colocado nela depois de trancar e clique **Tentar de novo**. Nada é apagado. |
| "A pasta não foi encontrada" | Ela foi movida ou renomeada: **Procurar a pasta…** e escolha-a no novo lugar (o Owl Vault confere que é a mesma). Pasta escondida: escolha a pasta onde ela fica. **Tirar da lista** não apaga nada; antes de confirmar, leia onde ficam os arquivos e as cópias fora da pasta — "Recuperar uma pasta protegida" não acha as cópias da pasta oculta `.owlvault-<código>` (para abri-las: ☰ → Cópia criptografada → Abrir uma cópia, com a senha mestra). |
| Esqueci o PIN | Na tela do PIN, **Esqueci o PIN** → senha mestra; depois ☰ → Alterar PIN. |
| Windows reinstalado / senha do Windows redefinida | O PIN deixa de funcionar (DPAPI). Entre com a senha mestra e crie um PIN novo. |
| Computador novo ou Owl Vault reinstalado | Instale, crie o acesso com a **mesma senha mestra** e use ☰ → **Recuperar uma pasta protegida** escolhendo a pasta com o ícone da coruja (ou a pasta onde ela ficava, se estava escondida). |
| Esqueci a senha mestra | Enquanto o PIN funcionar, abra as pastas normalmente e crie uma senha mestra nova (aparece depois de 3 erros na prática da senha mestra); abra e tranque cada pasta de novo. Sem PIN e sem senha mestra não há recuperação. |

Os dados cifrados de uma pasta trancada ficam em `<pasta>\.owlvault` (oculta) e são um cofre
v1 comum: em último caso, copie essa pasta para outro lugar e use ☰ → Cópia criptografada →
Abrir uma cópia, com a senha mestra.

## 1. A criação foi interrompida (queda de energia, cancelamento, disco cheio)

* Abra o Owl Vault → **Criar cofre** → preencha a **mesma origem** e o **mesmo local/nome do
  cofre** → digite a senha → **Retomar criação interrompida**.
  CLI: `owl-vault create <origem> <cofre>` detecta o cofre incompleto e retoma.
* A retomada confere cada arquivo já cifrado (existência, tamanho exato, cabeçalho) e se a
  origem mudou; o que estiver alterado ou danificado é cifrado de novo com identificador novo.
  Nada já verificado é sobrescrito.
* Se a mensagem for "interrompida antes do primeiro registro de progresso", apague a pasta do
  cofre manualmente e crie de novo (nada havia sido cifrado).
* A pasta temporária do teste de restauração (`OwlVault-teste-<código>`) é limpa pela
  retomada. Se você desistir do cofre, apague-a manualmente: ela pode conter arquivos
  `.chk`/`.part` temporários **sem os nomes originais, mas com o CONTEÚDO dos arquivos em texto
  claro**. Não há garantia de apagamento seguro.
* Se a criação já tinha terminado e só a limpeza final foi interrompida, "Retomar" apenas
  remove os resíduos (diário e pasta de teste) — nada é cifrado de novo.
* A retomada exige a **mesma pasta de origem, no mesmo caminho**. Se a pasta foi movida ou
  renomeada, devolva-a ao caminho original (o Owl Vault confere a identidade da pasta e recusa
  uma pasta diferente que esteja nesse caminho).

## 2. "Senha incorreta"

* Confira Caps Lock e o layout do teclado. A senha diferencia maiúsculas/minúsculas.
* Se a mensagem disser "cabeçalhos divergentes", uma das duas cópias do cabeçalho
  (`vault.owl`, `vault.owl.bak`) está corrompida. O Owl Vault já tenta as duas
  automaticamente. Se ele abrir usando a cópia de segurança, faça o reparo manual:
  1. copie a pasta do cofre inteira para outro lugar (backup);
  2. na pasta do cofre, substitua o arquivo danificado pela cópia boa (por exemplo, copie
     `vault.owl.bak` sobre `vault.owl`);
  3. rode **Verificar cofre**.
  O Owl Vault nunca faz esse reparo sozinho.

## 3. Verificar aponta problemas

| Mensagem | Significado | O que fazer |
|----------|-------------|-------------|
| "dado criptografado ausente" | o blob do arquivo sumiu | restaure de outra cópia do cofre; os demais arquivos continuam restauráveis |
| "falha de autenticação no bloco N" / "truncado" | o blob foi corrompido/adulterado | idem; não confie no conteúdo |
| "usando a cópia de segurança do manifesto/cabeçalho" | uma cópia está danificada | faça o reparo manual (seção 2) após backup |
| "manifestos divergentes" | as duas cópias do manifesto são válidas e diferentes | não use o cofre; use outra cópia |
| "Criação NÃO concluída" | o teste de restauração nunca terminou | retome a criação (seção 1) |
| "blob não referenciado" / "item desconhecido" | sobras ou arquivos estranhos na pasta | o cofre continua válido; investigue a origem dos itens |

Uma restauração com arquivos danificados é **parcial**: o Owl Vault restaura todos os
arquivos íntegros, lista os que falharam e nunca grava um arquivo que não passou na
verificação.

## 4. Restauração interrompida

Escolha a mesma pasta de destino e confirme "continuar de onde parou". Arquivos já
restaurados são conferidos pelo hash; nada é sobrescrito. Arquivos temporários `.part` desta
restauração são removidos. Alternativa: restaure de novo numa pasta nova.

## 5. Manifesto perdido nas duas cópias (salvamento de emergência)

Sem o manifesto não há nomes nem estrutura de pastas, mas o conteúdo de cada arquivo ainda é
recuperável com a senha:

```powershell
.\.venv\Scripts\python.exe -m owl_vault.cli.main salvage E:\Cofre-1 C:\Emergencia-1
```

Gera `recuperado-00001.bin`, `recuperado-00002.bin`, ... (cada um é o conteúdo autenticado de
um arquivo). Identifique o tipo pelo conteúdo (abrir com o programa adequado). O salvamento
ignora os identificadores em claro do manifesto/diário danificados e usa apenas o cabeçalho
autenticado; blobs de outro cofre são recusados.

## 6. O que NÃO tem solução

* Senha esquecida.
* Todas as cópias do cabeçalho perdidas (`vault.owl` e `vault.owl.bak`).
* Blob de um arquivo perdido em todas as cópias do cofre.

Por isso: mantenha **mais de uma cópia do cofre** em mídias diferentes e mantenha a origem
até confirmar, em outro computador, que o cofre verifica e restaura.
