from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, ValidationError, NumberRange, Length

import os
from werkzeug.utils import secure_filename

from app import db, bcrypt, app
from flask_login import current_user
from app.models import  Produto, User, LogAlteracao

class UserForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired()])
    sobrenome = StringField('Sobrenome', validators=[DataRequired()])
    login_nome = StringField('Nome de Login', validators=[DataRequired()])
    senha = PasswordField('Senha', validators=[DataRequired()])
    confirmacao_senha = PasswordField('Confirme a Senha', validators=[DataRequired(), EqualTo('senha',message='As senhas devem coincidir.')]) 
    admin = BooleanField('Administrador')
    btnSubmit = SubmitField('Salvar')

    def validate_login_nome(self, field):
        if User.query.filter_by(login_nome=field.data).first():
            raise ValidationError('Usuário já cadastrado com esse nome de login!')
        
    def save(self):
        senha = bcrypt.generate_password_hash(self.senha.data).decode('utf-8')
        user = User(
            nome = self.nome.data,
            sobrenome = self.sobrenome.data,
            login_nome = self.login_nome.data,
            senha=senha,
            admin=self.admin.data
        )

        db.session.add(user)
        db.session.commit()
        return user


class LoginForm(FlaskForm):
    login_nome = StringField('Nome de Login', validators=[DataRequired()])
    senha = PasswordField('Senha', validators=[DataRequired()])
    btnSubmit = SubmitField('Login')

    def login(self):
        # Recuperar o usuário do banco
        user = User.query.filter_by(login_nome=self.login_nome.data).first()

        # Debug: imprimir dados
        print("Senha digitada:", self.senha.data)
        if user:
            print("Hash no banco:", user.senha)

            # Verificar se a senha é válida
            if bcrypt.check_password_hash(user.senha, self.senha.data):
                return user
            else:
                raise Exception('Senha Incorreta!!!')
        else:
            raise Exception('Usuário não encontrado!!!')



class ProdutoForm(FlaskForm):
    nome = StringField('Nome do Produto', validators=[
        DataRequired(message="O nome é obrigatório."),
        Length(max=100, message="O nome deve ter no máximo 100 caracteres.")
    ])

    quantidade = IntegerField('Quantidade em Estoque', validators=[
        DataRequired(message="Informe a quantidade."),
        NumberRange(min=0, message="A quantidade não pode ser negativa.")
    ])

    quantidade_minima = IntegerField('Quantidade Mínima Permitida', validators=[
        DataRequired(message="Informe a quantidade mínima."),
        NumberRange(min=0, message="A quantidade mínima não pode ser negativa.")
    ])

    descricao = TextAreaField('Descrição do Produto', validators=[
        Length(max=1000, message="A descrição deve ter no máximo 1000 caracteres.")
    ])

    btnSubmit = SubmitField('Salvar')

    def __init__(self, *args, produto=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.produto = produto  # Produto atual (usado na edição)

    def validate_nome(self, field):
        produto_existente = Produto.query.filter_by(nome=field.data).first()
        if produto_existente and (not self.produto or produto_existente.id != self.produto.id):
            raise ValidationError('Já existe outro produto com esse nome.')

    def save(self):
        produto = Produto(
            nome=self.nome.data,
            quantidade=self.quantidade.data,
            quantidade_minima=self.quantidade_minima.data,
            descricao=self.descricao.data
        )
        db.session.add(produto)
        db.session.commit()
        return produto

    def update(self, produto):
        campos = ['nome', 'quantidade', 'quantidade_minima', 'descricao']
        alterado = False

        for campo in campos:
            valor_antigo = getattr(produto, campo)
            valor_novo = getattr(self, campo).data

            if str(valor_antigo) != str(valor_novo):
                log = LogAlteracao(
                    produto_id=produto.id,
                    usuario_id=current_user.id,
                    campo_alterado=campo,
                    valor_antigo=valor_antigo,
                    valor_novo=valor_novo
                )
                db.session.add(log)
                setattr(produto, campo, valor_novo)
                alterado = True

        if alterado:
            db.session.commit()
        return produto
