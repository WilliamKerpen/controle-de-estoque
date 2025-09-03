from app import db, login_manager
from datetime import datetime
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


#Iniciar o Banco de dados: flask db init
# adicionar alteracoes: flask db migrat -m "mensagem"
# salvar alteracoes flak db upgrad
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String, nullable=True)
    sobrenome = db.Column(db.String, nullable=True)
    login_nome = db.Column(db.String, nullable=True)
    senha = db.Column(db.String, nullable=True)

    
class Produto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String, nullable=True)
    quantidade = db.Column(db.Integer, nullable=True)
    quantidade_minima = db.Column(db.Integer, nullable=True, default = 0)

