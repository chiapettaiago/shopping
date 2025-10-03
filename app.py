from flask import Flask, render_template, request, redirect, url_for, make_response, send_file, session, flash, abort, Response, jsonify
from models.models import db, User, ShoppingList, debts, Balance, Diario, Report, Historico
from controllers.ia_controller import process_user_input
from sqlalchemy import exc, text, desc, or_
from sqlalchemy.pool import QueuePool
from flask_migrate import Migrate
from datetime import datetime, timedelta, timezone
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
import mysql.connector
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from itsdangerous import URLSafeTimedSerializer
import io
import os
import calendar
import time
import plotly.graph_objs as go
import stripe
from functools import wraps
import uuid
import secrets
import json
import hashlib
import smtplib
import ssl
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from authlib.integrations.flask_client import OAuth

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE


def load_env():
    """Carregar variáveis de ambiente do arquivo .env usando python-dotenv."""
    try:
        from dotenv import load_dotenv
        load_dotenv()
        return True
    except ImportError:
        # Fallback para método manual se python-dotenv não estiver disponível
        env_path = '.env'
        if not os.path.exists(env_path):
            return False

        with open(env_path) as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value
        return True

# Carregar variáveis de ambiente
load_env()

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

LEGACY_DB_HOST_TOKENS = ('meutesouro.site', 'meutesouro.site:3306')
STACKHERO_DEFAULT_HOST = os.getenv('STACKHERO_DB_HOST', '59zo8a.stackhero-network.com:4791')
STACKHERO_DEFAULT_DB_URL = (
    'mysql://root:TOS5UWYaAvq4HfCoBGaIVEmN7sBK0ACD@'
    '59zo8a.stackhero-network.com:4791/root?useSSL=true&requireSSL=true'
)


def _is_legacy_db_target(value) -> bool:
    if not value:
        return False
    normalized_value = value.lower()
    return any(token in normalized_value for token in LEGACY_DB_HOST_TOKENS)


app = Flask(__name__)

# Ajusta a chave secreta com prioridade para variáveis de ambiente
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'homium-001')
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

oauth = OAuth(app)

google_login_enabled = bool(app.config['GOOGLE_CLIENT_ID'] and app.config['GOOGLE_CLIENT_SECRET'])

if google_login_enabled:
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )
else:
    app.logger.warning('Google OAuth desativado: credenciais ausentes.')

# Obtém as variáveis de ambiente para construir a URI do banco de dados
db_username = os.getenv('DB_USERNAME')
db_password = os.getenv('DB_PASSWORD')
db_host = os.getenv('DB_HOST')
db_name = os.getenv('DB_NAME')

# Configuração de banco de dados com fallback para SQLite
database_url = os.getenv('DATABASE_URL')

# Se não houver DATABASE_URL, usar SQLite como fallback
if not database_url:
    # Usar SQLite local para desenvolvimento
    sqlite_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'database.db')
    database_url = f'sqlite:///{sqlite_path}'
    app.logger.info(f"Usando SQLite como banco de dados: {sqlite_path}")
else:
    app.logger.info("Usando DATABASE_URL configurada")

# Verificar URLs legadas (manter para compatibilidade)
if database_url and _is_legacy_db_target(database_url):
    app.logger.warning('Ignorando host legado meutesouro.site; usando SQLite.')
    sqlite_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'database.db')
    database_url = f'sqlite:///{sqlite_path}'

engine_connect_args = {}

if database_url:
    # SQLite (desenvolvimento/local)
    if database_url.startswith('sqlite://'):
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        app.logger.info("Configurando SQLite")
        
    # Heroku PostgreSQL support
    elif database_url.startswith(('postgres://', 'postgresql://')):
        # Heroku fornece postgres:// mas SQLAlchemy precisa de postgresql://
        normalized_url = database_url.replace('postgres://', 'postgresql://', 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = normalized_url
        app.logger.info("Configurando PostgreSQL para Heroku")
        
    elif database_url.startswith('mysql://'):
        parsed_db_url = urlparse(database_url)
        query_params = parse_qsl(parsed_db_url.query, keep_blank_values=True)
        retained_query_params = []
        ssl_required = None

        for key, raw_value in query_params:
            normalized_key = key.lower()
            value_lower = raw_value.lower()
            bool_value = value_lower not in ('0', 'false', 'no', '')

            if normalized_key == 'requiressl':
                ssl_required = bool_value
                continue
            if normalized_key == 'usessl':
                if ssl_required is None:
                    ssl_required = bool_value
                continue

            retained_query_params.append((key, raw_value))

        # Configurações SSL para MySQL
        if ssl_required is not None and ssl_required:
            # Para MySQL com SSL (Stackhero)
            import ssl
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            engine_connect_args['ssl'] = ssl_context
            app.logger.info("Configurando MySQL com SSL")
        elif ssl_required is not None and not ssl_required:
            engine_connect_args['ssl_disabled'] = True
            app.logger.info("Configurando MySQL sem SSL")
        
        # Configurações de conexão otimizadas para Heroku
        engine_connect_args.update({
            'connect_timeout': 30,  # Timeout menor para Heroku
            'read_timeout': 30,
            'write_timeout': 30,
            'charset': 'utf8mb4',
            'autocommit': True,
        })

        mysql_url = parsed_db_url._replace(
            scheme='mysql+pymysql',  # PyMySQL é mais estável no Heroku
            query=urlencode(retained_query_params)
        )

        app.config['SQLALCHEMY_DATABASE_URI'] = urlunparse(mysql_url)
        app.logger.info("Configurando MySQL com PyMySQL")
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        app.logger.info(f"Configurando banco de dados: {database_url[:50]}...")
        
elif all([db_username, db_password, db_host, db_name]):
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f'mysql+mysqlconnector://{db_username}:{db_password}@{db_host}/{db_name}'
    )
else:
    raise RuntimeError('Database configuration is missing. Check environment variables.')
# Configurações otimizadas para Heroku
is_heroku = os.environ.get('DYNO')  # Heroku define esta variável
if is_heroku:
    # Configurações mais conservadoras para Heroku
    app.config['SQLALCHEMY_POOL_SIZE'] = 2
    app.config['SQLALCHEMY_MAX_OVERFLOW'] = 3
    app.config['SQLALCHEMY_POOL_TIMEOUT'] = 30
    app.config['SQLALCHEMY_POOL_RECYCLE'] = 1800  # 30 minutos
    app.logger.info("Configurações otimizadas para Heroku aplicadas")
else:
    # Configurações para desenvolvimento local
    app.config['SQLALCHEMY_POOL_SIZE'] = 3
    app.config['SQLALCHEMY_MAX_OVERFLOW'] = 5
    app.config['SQLALCHEMY_POOL_TIMEOUT'] = 60
    app.config['SQLALCHEMY_POOL_RECYCLE'] = 3600  # 1 hora

app.config['SQLALCHEMY_POOL_PRE_PING'] = True  # Verificar conexões antes de usar
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

csrf = CSRFProtect(app)
csrf.init_app(app)

app.config['WTF_CSRF_ENABLED'] = False  # Desabilita a proteção global

engine_options = dict(
    poolclass=QueuePool,
    pool_size=app.config['SQLALCHEMY_POOL_SIZE'],
    max_overflow=app.config['SQLALCHEMY_MAX_OVERFLOW'],
    pool_recycle=app.config['SQLALCHEMY_POOL_RECYCLE'],
    pool_pre_ping=True,
    pool_timeout=app.config['SQLALCHEMY_POOL_TIMEOUT'],
    execution_options={
        'autoflush': False, 
        'expire_on_commit': False
    }
)

# Adicionar isolation_level apenas para bancos que suportam
if not app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite://'):
    engine_options['execution_options']['isolation_level'] = 'READ_COMMITTED'

if engine_connect_args:
    engine_options['connect_args'] = engine_connect_args

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = engine_options

# Configure a sessão permanente com tempo limite de 5 minutos
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config['SESSION_USE_SIGNER'] = True

db.init_app(app)
migrate = Migrate(app, db)

# Função para testar e aguardar conexão com banco
def wait_for_db_connection(max_retries=5, delay=10):
    """Aguarda conexão com banco de dados estar disponível"""
    import time
    from sqlalchemy import text
    
    # Heroku precisa de menos tentativas e delays menores
    is_heroku = os.environ.get('DYNO')
    if is_heroku:
        max_retries = 3
        delay = 5
    
    retries = 0
    while retries < max_retries:
        try:
            with app.app_context():
                # Tenta uma query simples
                result = db.session.execute(text("SELECT 1"))
                result.close()
                app.logger.info("Conexão com banco de dados estabelecida com sucesso")
                return True
        except Exception as e:
            retries += 1
            app.logger.warning(f"Tentativa {retries}/{max_retries} de conexão com banco falhou: {e}")
            if retries < max_retries and not is_heroku:  # No Heroku, não fazer sleep
                app.logger.info(f"Aguardando {delay} segundos antes da próxima tentativa...")
                time.sleep(delay)
            else:
                app.logger.error("Todas as tentativas de conexão falharam")
                return False
    return False

# Tentar conectar ao banco na inicialização
# No Heroku, não bloquear o startup se o banco não estiver disponível imediatamente
is_heroku = os.environ.get('DYNO')
if not is_heroku:
    db_available = wait_for_db_connection()
    if not db_available:
        app.logger.error("Não foi possível conectar ao banco de dados")
        app.logger.error("Verifique se o servidor Stackhero está ativo e as credenciais estão corretas")
        app.logger.error("URL de conexão configurada: " + app.config.get('SQLALCHEMY_DATABASE_URI', 'N/A'))
else:
    app.logger.info("Executando no Heroku - conexão com banco será verificada sob demanda")

login_manager = LoginManager(app)
login_manager.login_view = 'auth'  # Define a rota para redirecionamento quando o usuário não estiver logado

# Configuração para redefinição de senha
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


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

def db_required(f):
    """Decorator para rotas que precisam de conexão com banco"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Tenta uma query simples para verificar conexão
            with app.app_context():
                db.session.execute(text("SELECT 1"))
            return f(*args, **kwargs)
        except Exception as e:
            app.logger.warning(f"Banco indisponível: {e}")
            return render_template('db_unavailable.html'), 503
    return decorated_function

def get_user_data(user_id):
    user_data = db.session.query(User).filter_by(id=user_id).first()

    if user_data:
        return user_data.to_dict()

    return None

def cache_route(timeout=300):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            response = f(*args, **kwargs)

            if isinstance(response, str):
                response = Response(response, mimetype='text/html')
            return response
        return wrapped
    return decorator
    
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

def send_password_reset_email(email, reset_url):
    import smtplib
    import certifi
    from email.mime.text import MIMEText
    import ssl

    msg = MIMEText(f'''Redefinição de Senha - ME finanças\n\n
    Clique no link: {reset_url}\n\nLink válido por 1 hora.''')
    
    msg['Subject'] = 'Redefinição de Senha'
    msg['From'] = os.getenv('EMAIL_USER')
    msg['To'] = email

    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = False  # Apenas para testes com certificados autoassinados
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with smtplib.SMTP_SSL(
            host=os.getenv('SMTP_SERVER'),
            port=int(os.getenv('SMTP_PORT')),
            context=context
        ) as server:
            server.login(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASSWORD'))
            server.send_message(msg)
            app.logger.info(f'E-mail enviado para {email}')
            
    except Exception as e:
        app.logger.error(f'Erro SMTP: {str(e)}')
        raise

@app.route('/reset_password', methods=['POST'])
def reset_password_request():
    try:
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = serializer.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('reset_password_token', token=token, _external=True)
            
            # Envio do e-mail
            send_password_reset_email(user.email, reset_url)
            
            return jsonify({'success': True, 'message': 'Verifique seu e-mail para as instruções'})
        
        return jsonify({'success': False, 'message': 'E-mail não cadastrado'}), 404
    
    except Exception as e:
        app.logger.error(f'Erro no reset_password_request: {str(e)}')
        return jsonify({'success': False, 'message': 'Erro interno no servidor'}), 500

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Usuário não encontrado', 'danger')
            return redirect(url_for('auth'))
        if request.method == 'POST':
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            if not new_password or not confirm_password:
                flash('Todos os campos são obrigatórios.', 'danger')
                return redirect(url_for('reset_password_token', token=token))
            if new_password != confirm_password:
                flash('As senhas não coincidem.', 'danger')
                return redirect(url_for('reset_password_token', token=token))
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Senha alterada com sucesso!', 'success')
            return redirect(url_for('auth'))
        return render_template('reset_password.html', token=token)
    except Exception as e:
        app.logger.error(f'Erro no reset_password_token: {str(e)}')
        flash('Token inválido ou expirado', 'danger')
        return redirect(url_for('auth'))

        
@app.route('/test_smtp_connection')
def test_smtp():
    try:
        port = int(os.getenv('SMTP_PORT'))
        context = ssl.create_default_context()
        
        if port == 465:
            with smtplib.SMTP_SSL(
                os.getenv('SMTP_SERVER'),
                port,
                context=context
            ) as server:
                server.login(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASSWORD'))
                return "Conexão SSL bem-sucedida!", 200
                
        elif port == 587:
            with smtplib.SMTP(
                os.getenv('SMTP_SERVER'),
                port
            ) as server:
                server.starttls(context=context)
                server.login(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASSWORD'))
                return "Conexão STARTTLS bem-sucedida!", 200
                
    except Exception as e:
        return f"Falha na conexão: {str(e)}", 500



@app.route('/delete_history', methods=['POST'])
@login_required
def delete_chat_history():
    if 'chat_history' in session:
        session.pop('chat_history')  # Remove o histórico da sessão
    return redirect(url_for('assistente_ia'))


@app.route('/share', methods=['POST'])
@login_required
def share():
    # Consulta para obter os IDs dos itens da lista de compras do usuário logado
    shopping_list = ShoppingList.query.filter_by(status=0, username=current_user.username).all()
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
        return render_template('shared.html', link=shareable_link, username=current_user.full_name)

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
@db_required
def auth():
    if request.method == 'POST':
        form_action = request.form.get('action', 'login')

        if form_action == 'register':
            full_name = (request.form.get('full_name') or '').strip()
            email = (request.form.get('email') or '').strip().lower()
            username = (request.form.get('username') or '').strip()
            password = request.form.get('password') or ''
            confirm_password = request.form.get('confirm_password') or ''

            if not full_name or not email or not username or not password or not confirm_password:
                flash('Informe todos os dados para concluir seu cadastro.', 'danger')
                return redirect(url_for('auth', tab='register'))

            if len(password) < 8:
                flash('A senha deve ter pelo menos 8 caracteres.', 'danger')
                return redirect(url_for('auth', tab='register'))

            if password != confirm_password:
                flash('As senhas informadas não conferem.', 'danger')
                return redirect(url_for('auth', tab='register'))

            # Verificações de usuário e email existentes com retry
            max_retries = 3
            retry_count = 0
            
            while retry_count < max_retries:
                try:
                    if User.query.filter_by(username=username).first():
                        flash('Este nome de usuário já está em uso.', 'danger')
                        return redirect(url_for('auth', tab='register'))

                    if User.query.filter_by(email=email).first():
                        flash('Este e-mail já está cadastrado.', 'danger')
                        return redirect(url_for('auth', tab='register'))
                    
                    break  # Se chegou aqui, as queries funcionaram
                    
                except exc.OperationalError as e:
                    retry_count += 1
                    app.logger.warning(f"Tentativa {retry_count} de verificação falhou: {e}")
                    if retry_count >= max_retries:
                        flash('Serviço temporariamente indisponível. Tente novamente em alguns minutos.', 'danger')
                        return redirect(url_for('auth', tab='register'))
                    time.sleep(2)  # Aguarda 2 segundos antes de tentar novamente
                except Exception as e:
                    app.logger.error(f"Erro inesperado na verificação: {e}")
                    flash('Erro interno. Tente novamente.', 'danger')
                    return redirect(url_for('auth', tab='register'))

            new_user = User(
                username=username,
                password=generate_password_hash(password),
                email=email,
                full_name=full_name,
                subscription_status='inactive'
            )

            db.session.add(new_user)
            retry_count = 0
            
            while retry_count < max_retries:
                try:
                    db.session.commit()
                    flash('Cadastro criado com sucesso! Você já pode acessar com suas credenciais.', 'success')
                    return redirect(url_for('auth', tab='login'))
                    
                except exc.IntegrityError as e:
                    db.session.rollback()
                    app.logger.warning(f"Erro de integridade: {e}")
                    flash('Dados já existem no sistema. Verifique usuário e e-mail.', 'danger')
                    return redirect(url_for('auth', tab='register'))
                    
                except exc.OperationalError as e:
                    db.session.rollback()
                    retry_count += 1
                    app.logger.warning(f"Tentativa {retry_count} de commit falhou: {e}")
                    if retry_count >= max_retries:
                        flash('Serviço temporariamente indisponível. Tente novamente em alguns minutos.', 'danger')
                        return redirect(url_for('auth', tab='register'))
                    time.sleep(2)  # Aguarda 2 segundos antes de tentar novamente
                    
                except exc.SQLAlchemyError as e:
                    db.session.rollback()
                    app.logger.exception('Falha ao cadastrar usuário.')
                    flash('Erro interno do sistema. Tente novamente.', 'danger')
                    return redirect(url_for('auth', tab='register'))
                except Exception as e:
                    db.session.rollback()
                    app.logger.exception(f'Erro inesperado: {e}')
                    flash('Erro inesperado. Tente novamente.', 'danger')
                    return redirect(url_for('auth', tab='register'))

        identifier = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not identifier or not password:
            flash('Informe usuário e senha.', 'danger')
            return redirect(url_for('auth', tab='login'))

        user = User.query.filter(
            or_(User.username == identifier, User.email == identifier)
        ).first()

        if not user or not check_password_hash(user.password, password):
            flash('Credenciais inválidas. Verifique seus dados e tente novamente.', 'danger')
            return redirect(url_for('auth', tab='login'))

        login_user(user)
        flash('Login realizado com sucesso.', 'success')
        return redirect(url_for('start'))

    # Redirecionamento para solicitação de redefinição de senha
    if request.args.get('reset'):
        return redirect(url_for('reset_password_request'))

    error_message = request.args.get('error')
    if error_message:
        flash(error_message, 'danger')

    active_tab = request.args.get('tab', 'login')
    if active_tab not in {'login', 'register'}:
        active_tab = 'login'

    return render_template('auth.html', google_login_enabled=google_login_enabled, active_tab=active_tab)


@app.route('/auth/google')
def google_login():
    if not google_login_enabled:
        app.logger.warning('Tentativa de login com Google sem credenciais configuradas.')
        flash('Login com Google está desativado no momento.', 'warning')
        return redirect(url_for('auth'))

    redirect_uri = url_for('google_authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/auth/google/callback')
def google_authorize():
    if not google_login_enabled:
        app.logger.warning('Callback do Google recebido enquanto o login está desativado.')
        flash('Login com Google está desativado no momento.', 'warning')
        return redirect(url_for('auth'))

    try:
        token = oauth.google.authorize_access_token()
    except Exception as exc:
        app.logger.exception('Google login failed', exc_info=exc)
        flash('Não foi possível autenticar com o Google. Tente novamente.', 'danger')
        return redirect(url_for('auth'))

    try:
        user_info = oauth.google.parse_id_token(token)
    except Exception:
        user_info = None

    if not user_info:
        user_info = oauth.google.get('userinfo').json()

    email = user_info.get('email')
    if not email:
        flash('Não foi possível obter o e-mail da conta Google.', 'danger')
        return redirect(url_for('auth'))

    full_name = user_info.get('name') or email.split('@')[0]

    user = User.query.filter_by(email=email).first()

    if not user:
        username_base = email.split('@')[0]
        username_candidate = username_base
        counter = 1

        while User.query.filter_by(username=username_candidate).first():
            username_candidate = f"{username_base}{counter}"
            counter += 1

        placeholder_password = generate_password_hash(
            secrets.token_urlsafe(32),
            method='pbkdf2:sha256'
        )

        user = User(
            full_name=full_name,
            email=email,
            username=username_candidate,
            password=placeholder_password
        )

        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for('start'))

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Logout do usuário
    return redirect(url_for('index'))

def atualizar_status_mes_passado():
    # Obtém a data de hoje e calcula o primeiro e o último dia do mês passado
    hoje = datetime.now()
    primeiro_dia_mes_passado = (hoje.replace(day=1) - timedelta(days=1)).replace(day=1)
    ultimo_dia_mes_passado = hoje.replace(day=1) - timedelta(days=1)

    # Atualiza o status dos itens do mês passado
    stmt = (
        db.update(ShoppingList).
        where(ShoppingList.date.between(primeiro_dia_mes_passado, ultimo_dia_mes_passado)).
        values(status=1)
    )
    
    # Executa a atualização
    db.session.execute(stmt)
    db.session.commit()

def mover_debitos_para_historico():
    # Data limite para considerar débitos com mais de um mês
    data_limite = datetime.now() - timedelta(days=32)

    # Obter débitos com mais de um mês
    debitos_antigos = debts.query.filter(debts.maturity < data_limite).all()

    # Inserir débitos na tabela historico
    for debito in debitos_antigos:
        historico = Historico(
            username=debito.username,
            value=debito.value,
            date=debito.date,
            maturity=debito.maturity,
            name=debito.name
        )
        db.session.add(historico)

    # Remover débitos da tabela original
    for debito in debitos_antigos:
        db.session.delete(debito)

    # Confirmar as mudanças no banco de dados
    db.session.commit()

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
@subscription_required
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

@app.route('/terms')
def terms_of_use():
    return render_template('terms.html')

@app.route('/privacy')
def privacy_policy():
    return render_template('privacy.html')

@app.route('/manage_admins')
@login_required
def manage_admins():
    if not current_user.is_admin:
        flash('Acesso negado. Você não tem permissão para acessar esta página.', 'danger')
        return redirect(url_for('start'))
    
    # Buscar todos os usuários
    users = User.query.all()
    
    return render_template('manage_admins.html', 
                         username=current_user.full_name,
                         users=users)

@app.route('/toggle_admin', methods=['POST'])
@login_required
def toggle_admin():
    if not current_user.is_admin:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('start'))
    
    user_id = request.form.get('user_id')
    make_admin = request.form.get('make_admin') == '1'
    
    user = User.query.get(user_id)
    if not user:
        flash('Usuário não encontrado.', 'danger')
        return redirect(url_for('manage_admins'))
    
    # Verificar se está tentando remover o último admin
    if not make_admin and user.is_admin:
        admin_count = User.query.filter_by(is_admin=True).count()
        if admin_count <= 1:
            flash('Não é possível remover o último administrador do sistema.', 'warning')
            return redirect(url_for('manage_admins'))
    
    user.is_admin = make_admin
    db.session.commit()
    
    action = 'promovido a administrador' if make_admin else 'removido dos administradores'
    flash(f'Usuário {user.username} foi {action} com sucesso.', 'success')
    return redirect(url_for('manage_admins'))

@app.route('/database/setup', methods=['GET', 'POST'])
@login_required
def database_setup():
    if not current_user.is_admin:
        flash('Acesso negado. Você não tem permissão para acessar esta página.', 'danger')
        return redirect(url_for('start'))
    
    # Carregar configuração atual do banco
    db_url = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    
    # Valores padrão do formulário
    form_data = {
        'engine': 'sqlite',
        'host': '',
        'port': '',
        'username': '',
        'password': '',
        'database': '',
        'file_path': ''
    }
    
    # Parse da URL atual do banco
    if db_url:
        if db_url.startswith('sqlite:///'):
            form_data['engine'] = 'sqlite'
            form_data['file_path'] = db_url.replace('sqlite:///', '')
        elif db_url.startswith('mysql'):
            form_data['engine'] = 'mysql'
            # Parse básico da URL MySQL
            try:
                from urllib.parse import urlparse
                parsed = urlparse(db_url)
                form_data['host'] = parsed.hostname or ''
                form_data['port'] = str(parsed.port) if parsed.port else '3306'
                form_data['username'] = parsed.username or ''
                form_data['database'] = parsed.path.lstrip('/') if parsed.path else ''
            except:
                pass
        elif db_url.startswith('postgres'):
            form_data['engine'] = 'postgresql'
            try:
                from urllib.parse import urlparse
                parsed = urlparse(db_url)
                form_data['host'] = parsed.hostname or ''
                form_data['port'] = str(parsed.port) if parsed.port else '5432'
                form_data['username'] = parsed.username or ''
                form_data['database'] = parsed.path.lstrip('/') if parsed.path else ''
            except:
                pass
    
    if request.method == 'POST':
        # Processar configuração do banco
        engine = request.form.get('engine', 'sqlite')
        host = request.form.get('host', '')
        port = request.form.get('port', '')
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        database = request.form.get('database', '')
        file_path = request.form.get('file_path', '')
        
        # Aqui você pode adicionar a lógica para salvar a configuração
        flash('Configurações do banco de dados atualizadas com sucesso!', 'success')
        return redirect(url_for('database_setup'))
    
    # Converter dict para objeto para uso no template
    class FormData:
        def __init__(self, data):
            for key, value in data.items():
                setattr(self, key, value)
    
    return render_template('database_setup.html', 
                         username=current_user.full_name,
                         form_data=FormData(form_data))

@app.route('/add', methods=['POST'])
@cache_route(timeout=300)
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
@app.route('/daily')
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

@app.route('/delete_history', methods=['POST'])
def delete_history():
    # Aqui você limpa o histórico de chat, pode ser no banco de dados ou em sessão
    session.pop('chat_history', None)
    return redirect(url_for('assistente_ia'))

@app.route('/ia', methods=['GET', 'POST'])
@login_required
@subscription_required
def assistente_ia():
    # Inicialização do histórico do chat na sessão
    if 'chat_history' not in session:
        session['chat_history'] = []

    # Cálculos e consultas ao banco de dados
    current_month = datetime.now().date().replace(day=1)
    ano_atual = time.localtime().tm_year
    mes_atual = time.localtime().tm_mon
    dias_no_mes = calendar.monthrange(ano_atual, mes_atual)[1]
    dias_faltando = dias_no_mes - time.localtime().tm_mday + 1

    gastos = Diario.query.filter_by(status=0, username=current_user.username).filter(Diario.date >= current_month).order_by(Diario.value.desc()).all()
    debts_list = debts.query.filter_by(status=0, username=current_user.username).filter(debts.maturity >= current_month).order_by(debts.value.desc()).all()
    balance_list = Balance.query.filter_by(status=0, username=current_user.username).filter(Balance.date >= current_month).all()
    debts_1 = debts.query.filter_by(status=1, username=current_user.username).filter(debts.date >= current_month).all()
    gastos_processado = Diario.query.filter_by(status=1, username=current_user.username).filter(Diario.date >= current_month).order_by(Diario.value.desc()).all()

    # Cálculos de totais e salario
    gastos_total = sum(item.value for item in gastos_processado)
    dividas = sum(item.value for item in debts_list)
    gastos_nao_processados = sum(item.value for item in gastos)
    gastos_formatado = round(gastos_total, 2)
    balance_total = sum(item.value for item in balance_list)
    debts_total = sum(item.value for item in debts_1)
    balance_total_formatado = round(balance_total, 2)
    debts_1_formatado = round(debts_total, 2)
    total_price = sum(item.value for item in debts_list)
    total_price_formatado = round(total_price, 2)
    saldo_atualizado_formatado = calcular_saldo(balance_total_formatado, debts_1_formatado, gastos_formatado)
    por_dia = saldo_atualizado_formatado / dias_faltando if dias_faltando > 0 else 0
    por_dia_atualizado = round(por_dia, 2)

    if request.method == 'POST':
        user_input = request.json.get('user_input')
        if user_input:
            # Adiciona a mensagem do usuário ao histórico
            session['chat_history'].append({'type': 'user', 'text': user_input})

            # Cria uma lista com o nome dos débitos
            debts_names = [debt.name for debt in debts_list]

            # Cria uma lista com o nome dos débitos
            debts_values = [debt.value for debt in debts_list]

            # Processa a entrada do usuário
            response = process_user_input(user_input, saldo_atualizado_formatado, gastos_formatado, por_dia_atualizado, current_user.full_name, balance_total_formatado, dividas, gastos_nao_processados, debts_names, debts_values)

            # Adiciona a resposta ao histórico
            session['chat_history'].append({'type': 'ai', 'text': response})

            # Marca a sessão como modificada
            session.modified = True

            # Retorna a resposta como JSON
            return jsonify({'response': response})

    return render_template('assistente_ia.html', 
                           chat_history=session['chat_history'],
                           username=current_user.full_name)
    

@app.route('/start')
def start():
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
    por_dia = saldo_atualizado_formatado / dias_faltando if dias_faltando > 0 else 0
    por_dia_atualizado = round(por_dia, 2)
    return render_template('start.html', saldo_atual=saldo_atualizado_formatado, por_dia_atualizado=por_dia_atualizado, username=current_user.username)
    
    

@app.route('/add_balance', methods=['POST'])
@cache_route(timeout=300)
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
    return redirect(url_for('debitos'))

# Rota para adicionar um gasto
@app.route('/add_diario', methods=['POST'])
@cache_route(timeout=300)
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

@app.route('/atualizar')
@login_required
def mover_debitos_view():
    if current_user.username not in ['Iago', 'ma720']:
        abort(403)  # Retorna um erro 403 Forbidden se o usuário não for "Iago" ou "ma720"
    mover_debitos_para_historico()
    atualizar_status_mes_passado()
    return redirect(url_for('debitos'))


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

@app.route('/flash_report')
@login_required
def flash_report():
    return render_template('flash_report.html')

@app.route('/sitemap.xml')
def sitemap():
    # Consultar as URLs das tabelas relevantes
    pages = [
        {'url': 'https://meutesouro.site/', 'lastmod': datetime.utcnow(), 'changefreq': 'daily', 'priority': 1.0},
        {'url': 'https://meutesouro.site/about', 'lastmod': datetime.utcnow(), 'changefreq': 'daily', 'priority': 1.0},
        {'url': 'https://meutesouro.site/balance', 'lastmod': datetime.utcnow(), 'changefreq': 'daily', 'priority': 1.0},
        {'url': 'https://meutesouro.site/debts_history', 'lastmod': datetime.utcnow(), 'changefreq': 'daily', 'priority': 1.0},
        {'url': 'https://meutesouro.site/debts', 'lastmod': datetime.utcnow(), 'changefreq': 'daily', 'priority': 1.0},
        {'url': 'https://meutesouro.site/history', 'lastmod': datetime.utcnow(), 'changefreq': 'daily', 'priority': 1.0},
        {'url': 'https://meutesouro.site/ia', 'lastmod': datetime.utcnow(), 'changefreq': 'daily', 'priority': 1.0},
        {'url': 'https://meutesouro.site/dashboard', 'lastmod': datetime.utcnow(), 'changefreq': 'daily', 'priority': 1.0},
        {'url': 'https://meutesouro.site/account', 'lastmod': datetime.utcnow(), 'changefreq': 'daily', 'priority': 1.0},
        
        # Adicione URLs relevantes das tabelas aqui
    ]

    # Criar o conteúdo do sitemap XML
    sitemap_xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    sitemap_xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'

    for page in pages:
        sitemap_xml += '  <url>\n'
        sitemap_xml += f'    <loc>{page["url"]}</loc>\n'
        sitemap_xml += f'    <lastmod>{page["lastmod"].strftime("%Y-%m-%d")}</lastmod>\n'
        sitemap_xml += f'    <changefreq>{page["changefreq"]}</changefreq>\n'
        sitemap_xml += f'    <priority>{page["priority"]}</priority>\n'
        sitemap_xml += '  </url>\n'

    sitemap_xml += '</urlset>'

    return Response(sitemap_xml, mimetype='application/xml')

# Rota para lidar com o envio do formulário
@app.route('/report', methods=['POST'])
def report():
    if request.method == 'POST':
        email = request.form['reportEmail']
        description = request.form['reportDescription']
        attachment = request.files['reportAttachment']

        # Salvar o arquivo anexo
        attachment_path = None
        if attachment:
            filename = attachment.filename
            attachment_path = os.path.join('uploads', filename)
            attachment.save(attachment_path)

        # Inserir os dados no banco de dados
        new_report = Report(email=email, description=description, attachment=attachment_path)
        db.session.add(new_report)
        db.session.commit()

        flash('Problema reportado com sucesso!', 'success')
        return redirect(url_for('flash_report'))

# Rota para computar um gasto
@app.route('/computar/<int:id>', methods=['POST'])
def computar_gasto(id):
    gasto = Diario.query.get(id)
    if gasto:
        gasto.status = True
        db.session.commit()
        
    return redirect(url_for('listar_gastos'))


@app.route('/add_debts', methods=['POST'])
@cache_route(timeout=300)
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
        
        users = User.query.all()
    
        for user in users:
            if not user.password.startswith('pbkdf2:sha256'):
                hashed_password = generate_password_hash(user.password, method='pbkdf2:sha256')
                user.password = hashed_password
        
        db.session.commit()
    
    # Configurações para otimização de memória
    app.config['JSON_SORT_KEYS'] = False
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000  # 1 ano em segundos
    
    # Configurar o servidor para usar menos recursos
    app.run(
        debug=False,  # Desativar debug em produção
        host='0.0.0.0',
        port=3000,
        threaded=True,
        processes=1  # Usar apenas 1 processo
    )
