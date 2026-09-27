# Controle de Estoque

Sistema de gerenciamento de estoque desenvolvido em Python com Flask, voltado para controle de produtos, usuários e movimentações de estoque.

## Sobre o projeto

Este projeto permite:

- autenticação de usuários;
- cadastro e gerenciamento de usuários com nível administrativo;
- cadastro de produtos com quantidade mínima e descrição;
- entrada e saída de itens em estoque;
- alerta de produtos abaixo do estoque mínimo;
- registro de logs de alterações para auditoria.

A aplicação usa SQLite como banco de dados e Flask como framework web.

## Tecnologias

- Python 3
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-Bcrypt
- Flask-WTF
- Flask-Migrate
- SQLite

## Estrutura do projeto

```text
controle de estoque/
├── app/
│   ├── __init__.py
│   ├── forms.py
│   ├── models.py
│   ├── views.py
│   ├── static/
│   └── templates/
├── migrations/
├── .env
├── .gitignore
├── LICENSE
├── main.py
├── requirements.txt
└── README.md
```

## Pré-requisitos

- Python 3.10 ou superior
- pip
- ambiente virtual (opcional, mas recomendado)

## Instalação

1. Clone o repositório:

```bash
git clone <url-do-repositorio>
cd "controle de estoque"
```

2. Crie um ambiente virtual:

```bash
python -m venv .venv
```

3. Ative o ambiente virtual:

No Windows (PowerShell):

```powershell
.\.venv\Scripts\Activate.ps1
```

No Windows (CMD):

```cmd
.venv\Scripts\activate.bat
```

4. Instale as dependências:

```bash
pip install -r requirements.txt
```

5. Configure as variáveis de ambiente no arquivo `.env`:

```env
DATABASE_URI = 'sqlite:///database.db'
SECRET_KEY = 'sua-chave-secreta-aqui'
```

> O projeto já inclui um exemplo de configuração e a aplicação lê essas variáveis ao iniciar.

## Banco de dados

O projeto usa SQLite e o Flask-Migrate para gerenciar migrações.

Se o banco ainda não estiver criado ou as tabelas não estiverem prontas, execute:

```bash
flask db upgrade
```

Se necessário, em um ambiente novo, também pode ser usado:

```bash
flask db init
flask db migrate -m "Inicialização do banco"
flask db upgrade
```

## Executando a aplicação

Na raiz do projeto, execute:

```bash
python main.py
```

A aplicação ficará disponível em:

```text
http://127.0.0.1:5000/
```

## Funcionalidades principais

### Autenticação

- login de usuário;
- controle de sessão com Flask-Login;
- acesso restrito para páginas internas;
- usuários administradores têm acesso especial.

### Administração de usuários

- cadastro de novos usuários;
- edição de dados cadastrais;
- remoção lógica de usuários;
- controle de permissões de administrador.

### Gestão de produtos

- cadastro de produtos;
- busca por nome;
- edição de informações;
- controle da quantidade em estoque;
- definição da quantidade mínima permitida;
- descrição do produto.

### Movimentação de estoque

- adição de itens ao estoque;
- retirada de itens do estoque;
- validação de quantidade suficiente;
- registro das alterações em histórico.

### Logs e auditoria

- registro de campos alterados;
- valor anterior e novo valor;
- data da alteração;
- identificação do usuário responsável.

## Observações

- A rota inicial é a tela de login.
- Usuários com perfil de administrador podem acessar as áreas de gerenciamento e visualização de logs.
- Produtos com quantidade inferior à quantidade mínima aparecem como alerta no menu.

## Licença

Este projeto está sob a licença do repositório. Consulte o arquivo LICENSE para mais detalhes.

## Contribuição

Sinta-se à vontade para abrir issues ou enviar pull requests para melhorias, correções de bugs e novas funcionalidades.
