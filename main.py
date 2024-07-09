from flask import Flask, render_template, request, redirect, url_for, make_response, send_file, session, flash
from models.models import db, User, ShoppingList, debts, Balance, Diario, Saldo
from sqlalchemy import exc, text, create_engine,desc
from sqlalchemy.pool import QueuePool
from flask_migrate import Migrate
from datetime import datetime, timedelta, timezone
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
import io
import os
import calendar
import time
import plotly.graph_objs as go
import stripe
from functools import wraps
import uuid

def load_env():
    """Carregar variáveis de ambiente do arquivo .env."""
    env_path = '.env'
    with open(env_path) as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

# Carregar variáveis de ambiente
load_env()

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://casaos:casaos@meutesouro.site/casaos'
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 20
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Desativar o rastreamento de modificações para evitar avisos
app.config['SECRET_KEY'] = 'homium-001'  # Defina uma chave secreta única e segura

engine = create_engine(
  app.config['SQLALCHEMY_DATABASE_URI'],
  poolclass=QueuePool,
  pool_size=20,
  max_overflow=0,
  pool_recycle=3600,
  execution_options={'autoflush': False, 'expire_on_commit': False}
)

# Configure a sessão permanente com tempo limite de 10 minutos
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'auth'  # Define a rota para redirecionamento quando o usuário não estiver logado


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Atualizar o tempo limite da sessão sempre que uma solicitação for recebida
@app.before_request
def update_session_timeout():
    session.modified = True
    session.permanent = True


# Verificar se o tempo limite da sessão expirou e fazer logout do usuário, se necessário
@app.before_request
def check_session_timeout():
    if 'last_activity' in session:
        last_activity = session.get('last_activity')
        now = datetime.now().astimezone(last_activity.tzinfo)
        if (now - last_activity).total_seconds() > 600:  # 600 segundos = 10 minutos
            # Fazer logout do usuário
            logout_user()
            # Redirecionar para a página de login ou para onde desejar
            return redirect(url_for('auth'))
    # Atualizar o registro de última atividade
    session['last_activity'] = datetime.now(timezone.utc)
    
def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.subscription_status != 'active':
            flash('You need an active subscription to access this page.', 'warning')
            return redirect(url_for('checkout'))
        return f(*args, **kwargs)
    return decorated_function

# Função para verificar e atualizar automaticamente os itens antigos do balanço com a data atual
def update_old_balance_items():
    data_atual = datetime.now()
    old_balance_items = Balance.query.filter_by(date=None, username=current_user.username).all()
    for item in old_balance_items:
        item.date = data_atual
    db.session.commit()
    
@app.before_request
def before_request():
    db.session()
    
def calcular_saldo(balance_total, debts_total, gastos_total):
    saldo_atualizado = balance_total - debts_total - gastos_total
    return round(saldo_atualizado, 2)


@app.route('/share', methods=['POST'])
@login_required
def share():
    # Consulta para obter os IDs dos itens da lista de compras
    shopping_list = ShoppingList.query.filter_by(status=0).all()
    shopping_list_ids = [item.id for item in shopping_list]


    if not shopping_list_ids:
        return "Sua lista de compras está vazia."

    shopping_list = ShoppingList.query.filter(ShoppingList.id.in_(shopping_list_ids)).all()
    list_id = str(uuid.uuid4())

    try:
        # Atualiza os itens da lista de compras com o novo list_id
        for item in shopping_list:
            item.list_id = list_id
            db.session.add(item)  # Adiciona o item à sessão

        # Realiza o commit após o loop de atualização
        db.session.commit()

        # Verifica se os itens foram atualizados corretamente
        updated_items = ShoppingList.query.filter_by(list_id=list_id).all()
        for item in updated_items:
            print(f"ID: {item.id}, List ID: {item.list_id}, Status: {item.status}")

        shareable_link = url_for('view_list', list_id=list_id, _external=True)
        return render_template('shared.html', link=shareable_link)

    except Exception as e:
        db.session.rollback()
        return f"Ocorreu um erro ao compartilhar a lista de compras: {str(e)}"

@app.route('/list/<list_id>')
def view_list(list_id):
    shopping_list = ShoppingList.query.filter_by(status=0, list_id=list_id).order_by(ShoppingList.name.asc()).all()
    total_price = sum(item.price * item.quantity for item in shopping_list)
    return render_template('index.html', shopping_list=shopping_list, total_price=total_price)

@app.route('/checkout')
@login_required
def checkout():
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price': 'price_1POhzU2MGdLJSgZSMeaSsWH8',  # Use the price ID from your Stripe Dashboard
            'quantity': 1,
        }],
        mode='subscription',
        success_url=url_for('subscription_success', _external=True),
        cancel_url=url_for('subscription_cancel', _external=True),
    )
    return render_template('checkout.html', session_id=session.id, stripe_public_key=os.getenv('STRIPE_PUBLIC_KEY'))

@app.route('/subscription_success')
@login_required
def subscription_success():
    user = current_user
    user.subscription_status = 'active'
    db.session.commit()
    flash('Subscription successful!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/subscription_cancel')
@login_required
def subscription_cancel():
    flash('Subscription cancelled or failed.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, 'your_webhook_secret'
        )
    except ValueError as e:
        # Invalid payload
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return 'Invalid signature', 400

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        handle_checkout_session(session)

    return 'Success', 200

def handle_checkout_session(session):
    customer_email = session['customer_email']
    user = User.query.filter_by(email=customer_email).first()
    if user:
        user.subscription_status = 'active'
        db.session.commit()


@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        action = request.form.get('action')
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        username = request.form['username']
        password = request.form['password']

        if action == 'login':
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                return render_template('auth.html', login_error='Usuário ou senha incorretos.')

        elif action == 'register':
            existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
            if existing_user:
                return render_template('auth.html', register_error='Nome de usuário ou e-mail já cadastrados.')
            new_user = User(full_name=full_name, email=email, username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('auth', login_error='Usuário registrado com sucesso. Faça login.'))

    return render_template('auth.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Logout do usuário
    return redirect(url_for('index'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        new_password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')

        if new_password != confirm_password:
            flash('As senhas não coincidem. Por favor, tente novamente.', 'danger')
        elif not new_password:
            flash('A nova senha não pode estar vazia.', 'danger')
        else:
            # Atualize a senha do usuário
            user = User.query.get(current_user.id)
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Sua senha foi alterada com sucesso.', 'success')
        return redirect(url_for('account'))

    return render_template('account.html', 
                           username=current_user.username, 
                           email=current_user.email, 
                           status=current_user.subscription_status,
                           full_name=current_user.full_name)


@app.route('/daily_history')
@login_required
@subscription_required
def daily_history():
    # Obter a data atual
    current_month = datetime.now().date().replace(day=1)
    # Consultar o banco de dados para obter os registros do histórico diário
    daily_history = Diario.query.filter_by(status=1, username=current_user.username).filter(Diario.date >= current_month).order_by(Diario.date.desc()).all()
    
    # Calcular o valor total dos registros
    total_value = sum(item.value for item in daily_history)
    total_value_formatado = round(total_value, 2)
    
    # Renderizar o template com os dados
    return render_template('historico_diario.html', daily_history=daily_history, total_value=total_value_formatado, username=current_user.full_name)

@app.route('/')
@login_required
def index():
    update_old_balance_items()
    current_month = datetime.now().date().replace(day=1)
    shopping_list = ShoppingList.query.filter_by(status=0, username=current_user.username).filter(ShoppingList.date >= current_month).order_by(ShoppingList.name.asc()).all()
    total_price = sum(item.quantity * item.price for item in shopping_list)
    total_price_formatado = round(total_price, 2)
    db.session.remove()
    return render_template('index.html', shopping_list=shopping_list, total_price=total_price_formatado, username=current_user.full_name)


@app.route('/history')
@subscription_required
@login_required
def history():
    current_month = datetime.now().date().replace(day=1)
    shopping_list = ShoppingList.query.filter_by(status=1, username=current_user.username).filter(ShoppingList.date >= current_month).order_by(ShoppingList.date.desc()).all()
    total_price = sum(item.quantity * item.price for item in shopping_list)
    total_price_formatado = round(total_price, 2)
    db.session.remove()
    return render_template('history.html', shopping_list=shopping_list, total_price=total_price_formatado, username=current_user.full_name)


@app.route('/debts_history')
@login_required
def debts_history():
    current_month = datetime.now().date().replace(day=1)
    debts_history = debts.query.filter_by(status=1, username=current_user.username).filter(debts.maturity >= current_month).order_by(debts.maturity.desc()).all()
    total_value = sum(item.value for item in debts_history)
    total_value_formatado = round(total_value, 2)
    db.session.remove()
    return render_template('debts_history.html', debts_history=debts_history, total_value=total_value_formatado, username=current_user.full_name)

@app.route('/about')
@login_required
def about():
    return render_template('about.html', username=current_user.full_name)

@app.route('/add', methods=['POST'])
@login_required
def add():
    name = request.form['name']
    quantity = request.form['quantity']
    price = request.form['price']
    category = request.form['category']
    current_time = datetime.now().date()

    # Adicione validações e formatação necessárias aqui

    new_item = ShoppingList(name=name, quantity=quantity, price=price, category=category, status=0, date=current_time, username=current_user.username)
    db.session.add(new_item)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/debts', methods=['GET','POST'])
@login_required
def debitos():
    # Obter o número total de dias no mês atual
    ano_atual = time.localtime().tm_year
    mes_atual = time.localtime().tm_mon
    dias_no_mes = calendar.monthrange(ano_atual, mes_atual)[1]

    # Calcular quantos dias faltam até o final do mês
    dias_faltando = dias_no_mes - time.localtime().tm_mday + 1
    
    
    current_month = datetime.now().date().replace(day=1)
    debts_list = debts.query.filter_by(status=0, username=current_user.username).filter(debts.maturity >= current_month).order_by(debts.value.desc()).all()
    balance_list = Balance.query.filter_by(status=0, username=current_user.username).filter(Balance.date >= current_month).all()
    debts_1 = debts.query.filter_by(status=1, username=current_user.username).filter(debts.date >= current_month).all()
    gastos = Diario.query.filter_by(status=1, username=current_user.username).filter(Diario.date >= current_month).order_by(Diario.value.desc()).all()
    gastos_total = sum(item.value for item in gastos)
    gastos_formatado = round(gastos_total, 2)
    balance_total = sum(item.value for item in balance_list)
    debts_total = sum(item.value for item in debts_1)
    balance_total_formatado = round(balance_total, 2)
    debts_1_formatado = round(debts_total, 2)
    total_price = sum(item.value for item in debts_list)
    total_price_formatado = round(total_price, 2)
    saldo_atualizado_formatado = calcular_saldo(balance_total_formatado, debts_1_formatado, gastos_formatado)
    por_dia = saldo_atualizado_formatado / dias_faltando
    por_dia_atualizado = round(por_dia, 2)
        
    return render_template('finance.html', debts_list=debts_list, total_price=total_price_formatado, saldo_atualizado=saldo_atualizado_formatado, por_dia=por_dia_atualizado, username=current_user.full_name)

# Rota para listar todos os gastos
@app.route('/diario')
@login_required
@subscription_required
def listar_gastos():
    current_month = datetime.now().date().replace(day=1)
    # Obter o número total de dias no mês atual
    ano_atual = time.localtime().tm_year
    mes_atual = time.localtime().tm_mon
    dias_no_mes = calendar.monthrange(ano_atual, mes_atual)[1]

    # Calcular quantos dias faltam até o final do mês
    dias_faltando = dias_no_mes - time.localtime().tm_mday + 1
    gastos = Diario.query.filter_by(status=0, username=current_user.username).filter(Diario.date >= current_month).order_by(Diario.value.desc()).all()
    debts_list = debts.query.filter_by(status=0, username=current_user.username).filter(debts.maturity >= current_month).order_by(debts.value.desc()).all()
    balance_list = Balance.query.filter_by(status=0, username=current_user.username).filter(Balance.date >= current_month).all()
    debts_1 = debts.query.filter_by(status=1, username=current_user.username).filter(debts.date >= current_month).all()
    gastos_processado = Diario.query.filter_by(status=1, username=current_user.username).filter(Diario.date >= current_month).order_by(Diario.value.desc()).all()
    gastos_total = sum(item.value for item in gastos_processado)
    gastos_nao_processados = sum(item.value for item in gastos)
    gastos_formatado = round(gastos_total, 2)
    balance_total = sum(item.value for item in balance_list)
    debts_total = sum(item.value for item in debts_1)
    balance_total_formatado = round(balance_total, 2)
    debts_1_formatado = round(debts_total, 2)
    total_price = sum(item.value for item in debts_list)
    total_price_formatado = round(total_price, 2)
    saldo_atualizado_formatado = calcular_saldo(balance_total_formatado, debts_1_formatado, gastos_formatado)
    por_dia = saldo_atualizado_formatado / dias_faltando
    por_dia_atualizado = round(por_dia, 2)
        
    return render_template('diario.html', gastos=gastos, gastos_nao_processados=gastos_nao_processados, username=current_user.full_name, saldo_atualizado=saldo_atualizado_formatado, por_dia=por_dia_atualizado,)

@app.route('/balance', methods=['GET','POST'])
@login_required
def balance():
    current_month = datetime.now().date().replace(day=1)
    balance_list = Balance.query.filter_by(status=0, username=current_user.username).filter(Balance.date >= current_month).order_by(Balance.date.desc()).all()
    total_price = sum(item.value for item in balance_list)
    total_price_formatado = round(total_price, 2)
    db.session.remove()
    return render_template('balance.html', balance_list=balance_list, total_price=total_price_formatado, username=current_user.full_name)

@app.route('/add_balance', methods=['POST'])
@login_required
def add_balance():
    name = request.form['name']
    value = request.form['value']
    data = request.form['data']

    # Adicione validações e formatação necessárias aqui

    new_item = Balance(name=name, value=value, status=0, date=data, username=current_user.username)
    db.session.add(new_item)
    db.session.commit()
    db.session.remove()
    return redirect(url_for('balance'))

# Rota para adicionar um gasto
@app.route('/add_diario', methods=['POST'])
def add_daily():
    descricao = request.form['descricao']
    valor = request.form['valor']
    data_gasto = request.form['data_gasto']
    
    gasto = Diario(
        name=descricao,
        value=valor,
        date=data_gasto,
        status=0, 
        username=current_user.username
    )
    
    db.session.add(gasto)
    db.session.commit()

    return redirect(url_for('listar_gastos'))

# Rota para editar um gasto
@app.route('/editar/<int:id>', methods=['POST'])
def editar_gasto(id):
    gasto = Diario.query.get(id)
    if request.method == 'POST':
        gasto.name = request.form['descricao']
        gasto.value = request.form['valor']
        gasto.date = datetime.strptime(request.form['data_gasto'], '%Y-%m-%d').date()
        db.session.commit()
    return redirect(url_for('listar_gastos'))

# Rota para excluir um gasto
@app.route('/excluir/<int:id>', methods=['POST'])
def excluir_gasto(id):
    gasto = Diario.query.get(id)
    if gasto:
        db.session.delete(gasto)
        db.session.commit()
    return redirect(url_for('listar_gastos'))

# Rota para computar um gasto
@app.route('/computar/<int:id>', methods=['POST'])
def computar_gasto(id):
    gasto = Diario.query.get(id)
    if gasto:
        gasto.status = True
        db.session.commit()
    return redirect(url_for('listar_gastos'))


@app.route('/add_debts', methods=['POST'])
@login_required
def add_debts():
    name = request.form['name']
    maturity = request.form['maturity']
    value = request.form['value']
    current_time = datetime.now().date()

    # Adicione validações e formatação necessárias aqui

    new_item = debts(name=name, maturity=maturity, value=value, date=current_time, status=0, username=current_user.username)
    db.session.add(new_item)
    db.session.commit()
    db.session.remove()
    return redirect(url_for('debitos'))

# Rota para excluir um item
@app.route('/delete/<int:id>', methods=['GET'])
@login_required
def delete(id):
    item_to_delete = ShoppingList.query.get(id)
    if item_to_delete:
        db.session.delete(item_to_delete)
        db.session.commit()
        db.session.remove()
    return redirect(url_for('index'))


@app.route('/delete_debts/<int:id>', methods=['GET'])
@login_required
def delete_debts(id):
    item_to_delete = debts.query.get(id)
    if item_to_delete:
        db.session.delete(item_to_delete)
        db.session.commit()
        db.session.remove()
    return redirect(url_for('debitos'))

# Rota para editar um item
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    item_to_edit = ShoppingList.query.get(id)
    if request.method == 'POST':
        item_to_edit.name = request.form['name']
        item_to_edit.quantity = request.form['quantity']
        item_to_edit.category = request.form['category']
        item_to_edit.price = request.form['price']
        db.session.commit()
        db.session.remove()
        return redirect(url_for('index'))
    return render_template('edit.html', item=item_to_edit)

# Rota para editar um item
@app.route('/edit_debts/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_debts(id):
    item_to_edit = debts.query.get(id)
    if request.method == 'POST':
        item_to_edit.name = request.form['name']
        item_to_edit.maturity = request.form['maturity']
        item_to_edit.value = request.form['value']
        db.session.commit()
        db.session.remove()
        return redirect(url_for('debitos'))
    return render_template('edit.html', item=item_to_edit)

# Rota para comprar um item
@app.route('/buy/<int:id>', methods=['GET'])
@login_required
def buy(id):
    item_to_buy = ShoppingList.query.get(id)
    if item_to_buy:
        item_to_buy.status = 1
        db.session.commit()
        db.session.remove()
    return redirect(url_for('index'))

# Rota para comprar um item
@app.route('/pay/<int:id>', methods=['GET'])
@login_required
def pay(id):
    item_to_buy = debts.query.get(id)
    current_time = datetime.now().date()
    if item_to_buy:
        item_to_buy.status = 1
        item_to_buy.date = current_time
        db.session.commit()
        db.session.remove()
    return redirect(url_for('debitos'))

@app.route('/dashboard')
@login_required
def dashboard():
    current_month = datetime.now().date().replace(day=1)
    
    # Obter o número total de dias no mês atual
    ano_atual = time.localtime().tm_year
    mes_atual = time.localtime().tm_mon
    dias_no_mes = calendar.monthrange(ano_atual, mes_atual)[1]

    # Calcular quantos dias faltam até o final do mês
    dias_faltando = dias_no_mes - time.localtime().tm_mday + 1
    
    debts_list = debts.query.filter_by(status=0, username=current_user.username).filter(debts.date >= current_month).order_by(debts.value.desc()).all()
    balance_list = Balance.query.filter_by(status=0, username=current_user.username).filter(Balance.date >= current_month).all()
    debts_1 = debts.query.filter_by(status=1, username=current_user.username).filter(debts.date >= current_month).all()
    gastos = Diario.query.filter_by(status=1, username=current_user.username).filter(Diario.date >= current_month).order_by(Diario.value.desc()).all()
    gastos_total = sum(item.value for item in gastos)
    gastos_formatado = round(gastos_total, 2)
    balance_total = sum(item.value for item in balance_list)
    debts_total = sum(item.value for item in debts_1)
    balance_total_formatado = round(balance_total, 2)
    debts_1_formatado = round(debts_total, 2)
    total_price = sum(item.value for item in debts_list)
    total_price_formatado = round(total_price, 2)
    saldo_atualizado_formatado = calcular_saldo(balance_total_formatado, debts_1_formatado, gastos_formatado)
    if balance_total_formatado != 0:
        porcentagem = (saldo_atualizado_formatado / balance_total_formatado) * 100
    else:
        porcentagem = 0 
    percent = round(porcentagem, 2)
    por_dia = saldo_atualizado_formatado / dias_faltando
    por_dia_atualizado = round(por_dia, 2)
        
    # Dívidas
    diario_list = Diario.query.filter_by(status=1, username=current_user.username).filter(Diario.date >= current_month).order_by(Diario.date.desc()).all()
    dates_diario = [item.date.strftime('%d/%m/%Y') for item in diario_list]
    values_diario = [item.value for item in diario_list]

    
    pie_chart_debts = go.Pie(
        labels=dates_diario,
        values=values_diario,
        name='Dívidas',
        marker=dict(colors=['rgb(26, 118, 255)', 'rgb(255, 127, 14)', 'rgb(44, 160, 44)', 'rgb(214, 39, 40)', 'rgb(148, 103, 189)']),
        hoverinfo='label+percent+value'
    )
    
    # Compras
    balance_list = ShoppingList.query.filter_by(status=1, username=current_user.username).filter(ShoppingList.date >= current_month).order_by(ShoppingList.date.desc()).all()
    dates_balance = [purchase.date.strftime('%d/%m/%Y') for purchase in balance_list]
    values_balance = [purchase.price for purchase in balance_list]
    
    pie_chart_balance = go.Pie(
        labels=dates_balance,
        values=values_balance,
        name='Compras',
        marker=dict(colors=['rgb(255, 118, 26)', 'rgb(31, 119, 180)', 'rgb(255, 127, 14)', 'rgb(44, 160, 44)', 'rgb(214, 39, 40)']),
        hoverinfo='label+percent+value'
    )
    
    # Layout dos gráficos
    layout_debts = go.Layout(
        title='Gastos por Data',
        hovermode='closest',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='royalblue')  # Letras verdes
    )
    
    layout_balance = go.Layout(
        title='Compras por Data',
        hovermode='closest',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='royalblue')  # Letras verdes
    )
    
    # Criar figuras
    fig_debts = go.Figure(data=[pie_chart_debts], layout=layout_debts)
    fig_balance = go.Figure(data=[pie_chart_balance], layout=layout_balance)
    
    # Converter figuras para HTML
    graph_html_debts = fig_debts.to_html(full_html=False)
    graph_html_balance = fig_balance.to_html(full_html=False)

    return render_template('dashboard.html', username=current_user.full_name, graph_html1=graph_html_debts, graph_html2=graph_html_balance, porcentagem_formatado=percent,  total_price=total_price_formatado, saldo_atualizado=saldo_atualizado_formatado, por_dia=por_dia_atualizado, current_month=current_month, status=current_user.subscription_status)

@app.route('/export_pdf', methods=['GET'])
@login_required
def export_pdf():
    # Obtenha a lista de contas a pagar do banco de dados (ou de onde você a obtém)
    debts_list = debts.query.filter_by(status=0, username=current_user.username).all()

    # Defina a largura da página
    page_width, page_height = letter

    # Defina a largura das colunas da tabela
    col_widths = [page_width * 0.4, page_width * 0.6]

    # Crie um buffer de memória para armazenar o PDF
    buffer = io.BytesIO()

    # Crie um documento PDF usando o ReportLab
    pdf = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []

    # Crie uma lista de dados para a tabela
    data = [["Nome", "Valor"]]

    for debt in debts_list:
        data.append([debt.name, f"R${debt.value}"])
        
    db.session.remove()

    # Crie a tabela
    table = Table(data, colWidths=col_widths)

    # Estilize a tabela
    style = TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.gray),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)])

    table.setStyle(style)

    # Adicione a tabela aos elementos do PDF
    elements.append(table)

    # Construa o PDF
    pdf.build(elements)

    # Reinicie a posição do buffer
    buffer.seek(0)

    # Crie uma resposta Flask para enviar o arquivo PDF como anexo
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=contas_a_pagar.pdf'

    return response

@app.route('/export_pdf_list', methods=['GET'])
@login_required
def export_pdf_list():
    # Obtenha a lista de contas a pagar do banco de dados (ou de onde você a obtém)
    shopping_list = ShoppingList.query.filter_by(status=0, username=current_user.username).all()

    # Defina a largura da página
    page_width, page_height = letter

    # Defina a largura das colunas da tabela
    col_widths = [page_width * 0.4, page_width * 0.6]

    # Crie um buffer de memória para armazenar o PDF
    buffer = io.BytesIO()

    # Crie um documento PDF usando o ReportLab
    pdf = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []

    # Crie uma lista de dados para a tabela
    data = [["Nome", "Quantidade"]]

    for item in shopping_list:
        data.append([item.name, f"{item.quantity}"])
        
    db.session.remove()

    # Crie a tabela
    table = Table(data, colWidths=col_widths)

    # Estilize a tabela
    style = TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.gray),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)])

    table.setStyle(style)

    # Adicione a tabela aos elementos do PDF
    elements.append(table)

    # Construa o PDF
    pdf.build(elements)

    # Reinicie a posição do buffer
    buffer.seek(0)

    # Crie uma resposta Flask para enviar o arquivo PDF como anexo
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=lista_de_compras.pdf'

    return response


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        users = User.query.all()  # Recuperar todos os usuários
    
        for user in users:
            # Verifica se a senha já está criptografada (opcional, depende de como foram armazenadas inicialmente)
            if not user.password.startswith('pbkdf2:sha256'):
                # Criptografa a senha
                hashed_password = generate_password_hash(user.password, method='pbkdf2:sha256')
                user.password = hashed_password
        
        # Confirmar as alterações no banco de dados
        db.session.commit()
    app.run(debug=True, host='0.0.0.0', port=3000)
