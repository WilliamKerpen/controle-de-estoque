from app import app, db, bcrypt
from app.models import User

def criar_usuario():
    with app.app_context():
        nome = input("Nome: ")
        sobrenome = input("Sobrenome: ")
        login_nome = input("Nome de login: ")
        senha = input("Senha: ")
        admin = input("É administrador? (s/n): ").lower() == 's'

        # Verifica se já existe
        if User.query.filter_by(login_nome=login_nome).first():
            print("Já existe um usuário com esse nome de login.")
            return

        senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')
        novo_usuario = User(
            nome=nome,
            sobrenome=sobrenome,
            login_nome=login_nome,
            senha=senha_hash,
            admin=admin,
            ativo=True
        )

        db.session.add(novo_usuario)
        db.session.commit()
        print("Usuário criado com sucesso!")

if __name__ == '__main__':
    criar_usuario()

# dentro do venv, python criar_usuario.py##
