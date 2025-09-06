from app import app, db, bcrypt
from flask import render_template, url_for, request, redirect, flash, abort
from flask_login import login_user, logout_user, current_user, login_required

from app.models import User, Produto, LogAlteracao
from app.forms import UserForm, LoginForm, ProdutoForm


# LOGIN
@app.route('/', methods=['GET', 'POST'])
def homepage():
    if current_user.is_authenticated:
        return redirect(url_for('menu'))

    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = form.login()
            login_user(user, remember=True)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('menu'))
        except Exception as e:
            flash(str(e), 'danger')

    return render_template('index.html', form=form)


# PÁGINAS GERAIS
@app.route('/menu/')
@login_required
def menu():
    # Buscar produtos com estoque abaixo do mínimo
    produtos_alerta = Produto.query.filter(Produto.quantidade < Produto.quantidade_minima).all()
    return render_template('menu.html', produtos_alerta=produtos_alerta)

@app.route('/wk/')
def wk():
    return render_template('wk.html')

@app.route('/ajuda/')
def ajuda():
    return render_template('ajuda.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da sua conta com sucesso.', 'info')
    return redirect(url_for('homepage'))


# USUÁRIOS
@app.route('/admin/usuarios/', methods=['GET', 'POST'])
@login_required
def gerenciar_usuarios():
    if not current_user.admin:
        abort(403)

    form = UserForm()
    usuarios = User.query.filter_by(ativo=True).order_by(User.nome.asc()).all()

    if form.validate_on_submit():
        try:
            form.save()
            flash('Usuário cadastrado com sucesso!', 'success')
            return redirect(url_for('gerenciar_usuarios'))
        except Exception as e:
            flash(str(e), 'danger')

    return render_template('admin_usuarios.html', form=form, usuarios=usuarios)

@app.route('/admin/usuarios/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_usuario(id):
    if not current_user.admin:
        abort(403)

    usuario = User.query.get_or_404(id)
    form = UserForm(obj=usuario)

    if form.validate_on_submit():
        usuario.nome = form.nome.data
        usuario.sobrenome = form.sobrenome.data
        usuario.login_nome = form.login_nome.data
        usuario.admin = form.admin.data

        if form.senha.data:
            usuario.senha = bcrypt.generate_password_hash(form.senha.data).decode('utf-8')

        db.session.commit()
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('gerenciar_usuarios'))

    return render_template('editar_usuario.html', form=form, usuario=usuario)

@app.route('/admin/usuarios/<int:id>/remover', methods=['GET', 'POST'])
@login_required
def remover_usuario(id):
    if not current_user.admin:
        abort(403)

    usuario = User.query.get_or_404(id)
    usuario.ativo = False
    db.session.commit()
    flash('Usuário removido com sucesso.', 'info')
    return redirect(url_for('gerenciar_usuarios'))

# PRODUTOS
@app.route('/produtos/', methods=['GET', 'POST'])
@login_required
def produtos():
    form = ProdutoForm()
    termo_busca = request.args.get('busca', '')

    if termo_busca:
        produtos = Produto.query.filter(Produto.nome.ilike(f'%{termo_busca}%')).all()
    else:
        produtos = Produto.query.order_by(Produto.nome.asc()).all()

    if form.validate_on_submit():
        form.save()
        flash('Produto cadastrado com sucesso!', 'success')
        return redirect(url_for('produtos'))

    return render_template('produtos.html', form=form, produtos=produtos)

@app.route('/cadastrar_produto/', methods=['GET', 'POST'])
@login_required
def cadastrar_produto():
    form = ProdutoForm()

    if form.validate_on_submit():
        form.save()
        flash('Produto cadastrado com sucesso!', 'success')
        return redirect(url_for('produtos'))

    return render_template('cadastrar_produto.html', form=form)

@app.route('/editar_produto/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_produto(id):
    produto = Produto.query.get_or_404(id)
    form = ProdutoForm(obj=produto, produto=produto)

    if form.validate_on_submit():
        form.update(produto)
        flash(f'Produto "{produto.nome}" atualizado com sucesso!', 'success')
        return redirect(url_for('produtos'))

    return render_template('editar_produto.html', form=form, produto=produto)


@app.route('/adicionar_produto/<int:id>', methods=['GET', 'POST'])
@login_required
def adicionar_produto(id):
    produto = Produto.query.get_or_404(id)

    if request.method == 'POST':
        try:
            quantidade_adicional = int(request.form.get('quantidade_adicional', 0))
            if quantidade_adicional < 0:
                flash('A quantidade deve ser positiva.', 'danger')
            else:
                valor_antigo = produto.quantidade
                produto.quantidade += quantidade_adicional

                log = LogAlteracao(
                    produto_id=produto.id,
                    usuario_id=current_user.id,
                    campo_alterado='quantidade',
                    valor_antigo=valor_antigo,
                    valor_novo=produto.quantidade
                )
                db.session.add(log)
                db.session.commit()

                flash(f'{quantidade_adicional} unidades adicionadas ao produto "{produto.nome}".', 'success')
                return redirect(url_for('produtos'))
        except ValueError:
            flash('Informe uma quantidade válida.', 'danger')

    return render_template('adicionar_produto.html', produto=produto)

@app.route('/retirar_produto/<int:id>', methods=['GET', 'POST'])
@login_required
def retirar_produto(id):
    produto = Produto.query.get_or_404(id)

    if request.method == 'POST':
        try:
            quantidade_retirada = int(request.form.get('quantidade_retirada', 0))
            if quantidade_retirada <= 0:
                flash('A quantidade deve ser maior que zero.', 'danger')
            elif quantidade_retirada > produto.quantidade:
                flash('Quantidade insuficiente em estoque.', 'danger')
            else:
                valor_antigo = produto.quantidade
                produto.quantidade -= quantidade_retirada

                log = LogAlteracao(
                    produto_id=produto.id,
                    usuario_id=current_user.id,
                    campo_alterado='quantidade',
                    valor_antigo=valor_antigo,
                    valor_novo=produto.quantidade
                )
                db.session.add(log)
                db.session.commit()

                flash(f'{quantidade_retirada} unidades retiradas do produto "{produto.nome}".', 'success')
                return redirect(url_for('produtos'))
        except ValueError:
            flash('Informe uma quantidade válida.', 'danger')

    return render_template('retirar_produto.html', produto=produto)


# LOGS
@app.route('/logs/')
@login_required
def ver_logs():
    if not current_user.admin:
        abort(403)

    logs = LogAlteracao.query.order_by(LogAlteracao.data_alteracao.desc()).all()
    return render_template('logs.html', logs=logs)
