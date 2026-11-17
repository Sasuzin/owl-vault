# Histórico de versões do Owl Vault

O Owl Vault está em desenvolvimento contínuo. Cada ajuste sobe a versão
(`__version__` em `src/owl_vault/__init__.py`) e ganha uma entrada aqui:

* **0.X.0** — funcionalidade nova ou mudança visível;
* **0.X.Y** — correção ou ajuste pequeno.

O executável também mostra o **build** (número de commits do projeto, sobe sozinho a cada
ajuste) e o commit, em ☰ → Sobre, no rodapé e nas propriedades do `OwlVault.exe`
(Versão do arquivo `0.3.0.<build>`).

## 0.3.0 — 2026-11-17 (em andamento)

* Visual "Cofre" (Claude Design, Estilo 5) em todo o app: tokens de cor únicos, cartões,
  trilha de passos, rodapé com estado, botões pílula, campos de 48 px, medidor de força.
* Cópia criptografada refeita como assistente de 4 passos (Pastas → Senha → Conferência → Criar).
* Versão e build visíveis no app e no executável; este histórico.

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
