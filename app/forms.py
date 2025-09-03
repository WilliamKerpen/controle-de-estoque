from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError

import os
from werkzeug.utils import secure_filename

from app import db, bcrypt, app
from app.models import  Produto, User

class UserForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired()])
    sobrenome = StringField('Sobrenome', validators=[DataRequired()])
    login_nome = StringField('Nome de Login', validators=[DataRequired(), Email()])
    senha = PasswordField('Senha', validators=[DataRequired()])
    confirmacao_senha = PasswordField('Senha', validators=[DataRequired(), EqualTo('senha')])
    btnSubmit = SubmitField('Cadastrar')

    def validade_login_nome(self, login_nome):
        if User.query.filter(login_nome=login_nome.data).first():
            return ValidationError('Usuário Já cadastrado com esse Nome de Login!!!')
        
    def save(self):
        senha = bcrypt.generate_password_hash(self.senha.data.encode('utf-8'))
        user = User(
            nome = self.nome.data,
            sobrenome = self.sobrenome.data,
            login_nome = self.login_nome.data,
            senha=senha
        )

        db.session.add(user)
        db.session.commit()
        return user


class LoginForm(FlaskForm):
    login_nome = StringField('Nome de Login', validators=[DataRequired(), Email()])
    senha = PasswordField('Senha', validators=[DataRequired()])
    btnSubmit = SubmitField('Login')

    def login(self):
        # Recuperar o usuário do e-mail
        user = User.query.filter_by(login_nome=self.login_nome.data).first()

        # Verificar se a senha é valida
        if user:
            if bcrypt.check_password_hash(user.senha, self.senha.data.encode('utf-8')):
                # Retorna o Usuário
                return user
            else:
                raise Exception('Senha Incorreta!!!')
        else:
            raise Exception('Usuário não encontrado!!!')


class ProdutoForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired()])
    quantidade = StringField('Quantidade: ', validators=[DataRequired(), Email()])
    quantidade_minima = StringField('Quantidade minima para estoque:', validators=[DataRequired()])
    btnSubmit = SubmitField('Salva')
    def save(self):
        produto = ProdutoForm(
            nome = self.nome.data,
            quantidade = self.quantidade.data,
            quantidade_minima = self.quantidade_minima.data,
        )

        db.session.add(produto)
        db.session.commit()