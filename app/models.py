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
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String, nullable=True)
    sobrenome = db.Column(db.String, nullable=True)
    login_nome = db.Column(db.String, nullable=False)
    senha = db.Column(db.String, nullable=True)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    ativo = db.Column(db.Boolean, nullable=False, default=True)

    __table_args__ = (
        db.UniqueConstraint("login_nome", name="uq_user_login_nome"),
    )

    
class Produto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String, nullable=True)
    quantidade = db.Column(db.Integer, nullable=True)
    quantidade_minima = db.Column(db.Integer, nullable=True, default = 0)
    descricao = db.Column(db.Text, nullable=True)
    

class LogAlteracao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    produto_id = db.Column(db.Integer, db.ForeignKey('produto.id'), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    campo_alterado = db.Column(db.String, nullable=False)
    valor_antigo = db.Column(db.Text, nullable=True)
    valor_novo = db.Column(db.Text, nullable=True)
    data_alteracao = db.Column(db.DateTime, default=datetime.utcnow)

    produto = db.relationship('Produto', backref='logs')
    usuario = db.relationship('User', backref='alteracoes')