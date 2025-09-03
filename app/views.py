from app import app, db
from flask import render_template, url_for, request, redirect
from flask_login import login_user, logout_user, current_user, login_required

from app.models import User, Produto
from app.forms import UserForm, LoginForm, ProdutoForm


@app.route('/', methods=['GET', 'POST'])
def homepage():
    form = LoginForm()

    if form.validate_on_submit():
        user = form.login()
        login_user(user, remember=True)
        
    return render_template('index.html', form=form)

@app.route('/wk/')
def wk():
        return render_template('wk.html')

@app.route('/ajuda/')
def ajuda():
        return render_template('ajuda.html')

@app.route('/produtos/', methods=['GET', 'POST'])
def produtos():
    if request.method == 'POST':
        nome = request.form['nome']
        quantidade = int(request.form['quantidade'])
        quantidade_minima = int(request.form['quantidade_minima'])
        novo = Produto(nome=nome, quantidade=quantidade, quantidade_minima=quantidade_minima)
        db.session.add(novo)
        db.session.commit()
        return redirect(url_for('produtos'))
    
    lista = Produto.query.all()
    return render_template('produtos.html', produtos=lista)

@app.route('/cadastro_produtos/', methods=['GET', 'POST'])
def cadastro_produtos():
    if request.method == 'POST':
        nome = request.form['nome']
        quantidade = int(request.form['quantidade'])
        quantidade_minima = int(request.form['quantidade_minima'])
        novo = Produto(nome=nome, quantidade=quantidade, quantidade_minima=quantidade_minima)
        db.session.add(novo)
        db.session.commit()
        return redirect(url_for('cadastro_produtos'))
    
    lista = Produto.query.all()
    return render_template('cadastro_produtosprodutos.html', produtos=lista)