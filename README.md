```text
   README.md
   
   
   
   # Sistema de Login em Python

Sistema de autenticação desenvolvido em Python com foco em segurança, organização em camadas e simulação de fluxos reais de login.

## Visão geral

O projeto implementa um fluxo completo de autenticação em ambiente local, com persistência em JSON e interface via terminal. A estrutura foi organizada para separar responsabilidades entre persistência, regras de negócio e interação com o usuário.

## Funcionalidades

- Cadastro de usuários
- Validação de e-mail e senha
- Hash seguro de senhas com salt
- Login com verificação de credenciais
- Proteção contra múltiplas tentativas falhas
- Bloqueio temporário de conta
- Geração e validação de sessão com token
- Logout
- Registro de auditoria
- Persistência de dados em arquivos JSON

## Estrutura

```text
.
├── sistemalogin.py
├── data/
│   ├── users.json
│   ├── sessions.json
│   └── audit.json
└── data_demo/
    ├── users.json
    ├── sessions.json
    └── audit.json


      Arquitetura

      O sistema foi estruturado em camadas para manter o código mais legível e escalável:

   Repository: responsável pela persistência dos dados
   Service: concentra as regras de negócio e segurança
   Controller: realiza a interação com o usuário no terminal
   Segurança

      O projeto adota mecanismos importantes de autenticação:

   Hash de senha com PBKDF2-HMAC-SHA256
   Salt individual por usuário
   Comparação segura de credenciais
   Controle de tentativas de login
   Bloqueio temporário após falhas consecutivas
   Sessões com expiração
   Auditoria de eventos relevantes

      Requisitos
   Python 3.10 ou superior




                                                                                                **Desenvolvido por João Paulo Meireles Fagundes.**
