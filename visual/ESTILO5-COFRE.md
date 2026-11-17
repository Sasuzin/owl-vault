# Owl Vault — refazer a interface no estilo "Cofre"

Instruções para reconstruir a janela do Owl Vault seguindo o design escolhido.
Trabalhe em cima do código que já existe: **nada da lógica de criptografia, hash,
cópia, teste de restauração ou retomada muda.** Isto é só a camada de interface.

## Arquivos deste pacote

| Arquivo | Para que serve |
|---|---|
| `ESTILO5-COFRE.md` | este documento |
| `theme_cofre.py` | os tokens (cores, espaçamento, raio) e o carregador do QSS |
| `owlvault.qss` | a folha de estilo, com `{nome-do-token}` no lugar dos valores |
| `referencia-estilo5.html` | o desenho da tela do passo 2 — **abra no navegador e use como referência visual** |

Copie os três primeiros para dentro do projeto (sugestão: `ui/tema/`).
O HTML é só referência, não precisa ir junto.

## Regras

1. **Não cole cor no código.** Toda cor sai de `theme_cofre.TOKENS`, via QSS.
   Se precisar de uma cor nova, acrescente um token com nome e comentário.
2. **Não mexa no núcleo.** Funções de criptografia, varredura de pastas, hash,
   verificação e retomada continuam como estão. Se a interface precisar de um
   sinal novo (progresso por arquivo, por exemplo), exponha um callback — não
   reescreva a função.
3. **Nenhum texto de aviso some.** Os avisos sobre "é uma cópia" e "sem a senha
   não há recuperação" mudam de lugar, nunca de existência.
4. **Validação continua onde está.** O assistente só impede avançar de passo;
   as regras (senha mínima, pasta válida, espaço em disco) são as mesmas.

## Ligando o tema

```python
from PySide6.QtWidgets import QApplication   # ou PyQt5/PyQt6, conforme o projeto
from ui.tema.theme_cofre import aplicar_tema

app = QApplication(sys.argv)
aplicar_tema(app)
```

`theme_cofre.py` também traz `repintar(widget)` — chame sempre que mudar uma
propriedade dinâmica (`estado`, `ativo`, `caminho`), senão o Qt não reavalia o
seletor.

## A estrutura da janela

A tela de abas vira um **assistente de 4 passos** num `QStackedWidget`.

```
QMainWindow
└── QWidget central  (QVBoxLayout, margens 32/20/32/0)
    ├── QWidget  "cabecalhoPassos"      ← trilha 1-2-3-4, sempre visível
    │   └── por passo: QLabel#passoNumero + QLabel#passoTexto, com QFrame#ligacao entre eles
    ├── QWidget  "palco"  (QHBoxLayout, espaçamento 20)
    │   ├── QStackedWidget "passos"            ← cresce
    │   │   ├── página 0: Pastas
    │   │   ├── página 1: Senha
    │   │   ├── página 2: Conferência
    │   │   └── página 3: Criar
    │   └── QWidget "lateral"  (largura fixa 272)
    │       ├── QFrame#cartaoLateral  ← resumo das escolhas já feitas
    │       └── QFrame#dica           ← explicação curta do passo atual
    └── QFrame#rodape
        ├── QPushButton "Voltar"
        ├── QPushButton#primario  ← o texto muda por passo
        ├── (espaço)
        └── QLabel#estadoPonto + QLabel#estadoTexto
```

Cada página do `QStackedWidget` é um `QFrame#cartao` com `QVBoxLayout`,
margens de 24 e espaçamento de 12.

### objectName e propriedades que o QSS espera

| objectName | Widget | Propriedade dinâmica |
|---|---|---|
| `passoNumero` | QLabel (26×26, centralizado) | `estado` = `feito` / `atual` / *(nada)* |
| `passoTexto` | QLabel | `estado` = `atual` / *(nada)* |
| `ligacao` | QFrame (2px de altura) | `estado` = `feito` / *(nada)* |
| `cartao`, `cartaoLateral`, `dica`, `aviso`, `rodape` | QFrame | — |
| `titulo`, `subtitulo`, `rotulo`, `nota` | QLabel | — |
| `secaoLateral`, `resumoChave`, `resumoValor`, `linkAlterar` | QLabel | — |
| `primario` | QPushButton | — |
| `discreto` | QPushButton sem moldura ("Mostrar", "alterar", "Escolher") | — |
| `forca` | QFrame (4 deles, 5px de altura) | `ativo` = `sim` / `nao` |
| `forcaTexto` | QLabel | — |
| `estadoPonto` | QLabel (8×8) | `estado` = `erro` / `trabalhando` / *(nada = ok)* |
| `estadoTexto` | QLabel | — |
| `log` | QPlainTextEdit | — |
| qualquer QLineEdit de caminho | QLineEdit | `caminho` = `sim` (vira monoespaçada) |

## O que vai em cada passo

**Passo 1 — Pastas**
Origem, Local do cofre, Nome do cofre, Teste de restauração. Cada campo de
caminho com um `QPushButton#discreto` "Escolher" à direita. A nota do teste de
restauração fica como `QLabel#nota` embaixo do campo. O botão **"Retomar criação
interrompida"** vive aqui, como `#discreto` no fim do cartão — não é a ação
principal de ninguém.
Botão primário: *Continuar para a senha*.

**Passo 2 — Senha** (é o que o `referencia-estilo5.html` mostra)
Campo de senha com "Mostrar" dentro, medidor de 4 blocos, "Força da senha" à
esquerda e o veredito à direita, campo de confirmação, e o `QFrame#aviso` com o
texto da cópia. A lateral mostra as escolhas do passo 1 com "alterar".
Botão primário: *Continuar para a conferência*.

**Passo 3 — Conferência**
Lista de verificações antes de criar, uma por linha: ícone + título + uma linha
de detalhe em `#nota`. Ícone em `ok` quando passou, `danger` quando falhou,
`ink-muted` quando ainda não rodou. Mínimo: espaço em disco, arquivos em uso,
tamanho e contagem da origem, destino gravável.
Botão primário: *Criar cofre agora*. Só habilita se nada falhou.

**Passo 4 — Criar**
Barra de progresso, etapa atual em texto, e o `QPlainTextEdit#log` ocupando o
resto do cartão. Ao terminar: o cartão mostra o resultado e o botão primário
vira *Abrir a pasta do cofre*, com um `#discreto` "Criar outro cofre".
Aqui o aviso aparece de novo, por extenso — é a última hora de avisar que a
pasta original continua legível.

## Textos

Use exatamente estes (são os que já estão no programa, só reorganizados):

- Aviso da cópia: *"O cofre é uma cópia criptografada. A pasta original continua
  legível até você removê-la — e, mesmo removida, podem restar cópias dela na
  Lixeira, em Versões anteriores, no OneDrive, em backups e no índice do Windows."*
- Senha: *"É ela que abre o cofre depois. Sem ela não há recuperação: nem você,
  nem o Owl Vault conseguem ler os arquivos de volta."*
- Nome do cofre (dica lateral): *"O nome da pasta do cofre fica visível para
  qualquer pessoa que abrir o computador. Guarde o assunto na senha, não no nome."*
- Teste de restauração: *"Pasta temporária no mesmo disco da origem. Cada arquivo
  é restaurado ali com nome aleatório, comparado com a origem e apagado em seguida."*
- Fim: *"Cópia criptografada criada e verificada (cópia da pasta como estava em
  {data} {hora}). Mantenha a origem e um backup externo até verificar o cofre,
  de preferência em outro computador."*

## Medidas

Campo e botão: **48px** de altura. Texto de campo 15px, título 22px, corpo 14px,
nota 12px. Raio: 8px em campo e botão comum, 24px (pílula) nos botões do rodapé,
18px nos cartões, 12px no aviso e na dica. Espaçamento em múltiplos de 4 —
24 dentro do cartão, 20 entre cartões, 16 entre campos, 12 entre rótulo e campo.

## O que o QSS não resolve (faça no Python)

1. **Sombra** — QSS não tem `box-shadow`. Use `QGraphicsDropShadowEffect` nos
   `QFrame#cartao` (blur 24, offset 0,1, cor preta a 45%) ou simplesmente deixe
   sem sombra: o contraste do cartão com o fundo já separa os dois.
2. **Trocar de passo** — `stack.setCurrentIndex(i)` e, logo depois, atualizar
   `estado` nos `#passoNumero` / `#passoTexto` / `#ligacao` e chamar `repintar()`
   em cada um.
3. **Medidor de força** — calcule a força (comprimento + variedade de
   caracteres), ligue N dos 4 `QFrame#forca` com `ativo="sim"` e escreva o
   veredito em `#forcaTexto`. Nunca bloqueie por força, só informe — o mínimo de
   12 caracteres continua sendo a única regra dura.
4. **Cantos arredondados da janela** — a janela mantém a barra de título do
   Windows. Não vale a pena `FramelessWindowHint` aqui.
5. **Log sem travar** — `setMaximumBlockCount(5000)` e `appendPlainText()`.
   Cor por `QTextCharFormat`, nunca montando HTML a cada linha.
6. **Trabalho pesado fora da thread da interface** — se a cópia já roda em
   thread/processo separado, mantenha; se roda na thread da janela, mova para um
   `QThread` agora, senão o assistente congela no passo 4.

## Checklist de aceite

- [ ] A janela abre no passo 1 e dá para ir e voltar sem perder o que foi digitado.
- [ ] O cabeçalho de passos reflete onde a pessoa está (feito / atual / futuro).
- [ ] O foco de teclado é visível em todo campo — Tab percorre os campos na ordem
      de leitura, e o botão primário é o `default` da página.
- [ ] Nenhuma cor literal fora de `theme_cofre.py`.
- [ ] O aviso da cópia aparece no passo 2 e de novo no passo 4.
- [ ] O passo 4 mostra progresso e log sem congelar a janela.
- [ ] Trocar um valor em `TOKENS` muda o app inteiro, sem editar mais nada.
- [ ] A criação, a verificação e a retomada funcionam exatamente como antes da
      mudança visual.

## Ordem sugerida

1. Ligar `aplicar_tema` e os `objectName` na janela atual, sem mexer no layout.
   Já aqui o programa fica com a cara nova.
2. Quebrar as abas em `QStackedWidget` com os 4 passos e o rodapé fixo.
3. Cabeçalho de passos, lateral de resumo e cartão de dica.
4. Medidor de força, conferência do passo 3 e o log do passo 4.

Faça um commit por etapa, para dar para voltar atrás se alguma quebrar.
