# Meu Tesouro

Meu Tesouro é um sistema de gerenciamento financeiro pessoal desenvolvido em Python usando Flask e SQLAlchemy. Ele permite que os usuários controlem suas finanças, registrem transações e visualizem gráficos interativos com seus dados financeiros. O sistema também possui uma interface amigável com comandos assistidos por IA para facilitar o controle dos dados.

## Funcionalidades

- **Gerenciamento de listas de compras**: Criação, visualização, edição e exclusão de listas de compras.
- **Controle de finanças**: Gerencie dívidas, saldos, gastos diários e históricos financeiros.
- **Interface amigável com Bootstrap**: A interface utiliza exclusivamente classes Bootstrap para estilização.
- **Gráficos interativos**: Visualize dados financeiros por meio de gráficos.
- **Autenticação de usuários**: Login seguro utilizando a biblioteca Flask-Login.
- **Comandos assistidos por IA**: Responda a consultas sobre saldo, gastos e muito mais.
- **Assistente de IA**: Simula uma interação com um assistente virtual para executar comandos.
- **Sistema modular**: Estrutura modular com diferentes componentes para facilitar a manutenção.
- **Armazenamento de histórico de conversas**: Usa sessões para salvar o histórico de conversas do assistente de IA.

## Tecnologias Utilizadas

- **Linguagem de Programação**: Python 3.x
- **Framework Web**: Flask
- **ORM**: SQLAlchemy
- **Banco de Dados**: MySQL (em alguns casos, Oracle)
- **Frontend**: Bootstrap
- **Gráficos**: Chart.js ou similar para visualização interativa
- **Gerenciamento de Estado**: Flask-Session
- **Cache e Tarefas em Segundo Plano**: Redis (em container Debian)
- **Autenticação**: Flask-Login

## Requisitos

- Python 3.x
- Flask
- SQLAlchemy
- MySQL ou Oracle (dependendo da configuração)
- Redis
- Chart.js (para gráficos)
- Bootstrap 4.x ou superior
- Docker (para o container Redis)

## Versão do sistema
- Sistema de Gerenciamento Financeiro Meu Tesouro com J.A.R.V.I.S(versão 2409)

## Recursos esperados na atualização 2410

- Tela de Gastos Recorrentes
- Melhor Gerenciamento de Listas de Compras
- Histórico Mensal
- Uso do J.A.R.V.I.S em demais telas do sistema

