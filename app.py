from flask import Flask, render_template, request, redirect, url_for, make_response, send_file, session, flash, abort, Response, jsonify
from models.models import db, User, ShoppingList, debts, Balance, Diario, Report, Historico
from controllers.ia_controller import process_user_input
from sqlalchemy import exc, text, create_engine, desc
from sqlalchemy.engine import URL
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
from pathlib import Path
import calendar
import time
import plotly.graph_objs as go
from functools import wraps
import uuid
import redis
import json
import hashlib
import smtplib
import ssl
from urllib.parse import urlparse

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE


BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / 'config'
DB_CONFIG_PATH = CONFIG_DIR / 'database.json'
FALLBACK_SQLITE_PATH = BASE_DIR / 'tmp' / 'mefinancas.db'
FALLBACK_SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)


def load_db_config_from_file():
    """Carrega um dicionário de configuração de banco salvo localmente."""
    if not DB_CONFIG_PATH.exists():
        return None

    try:
        with open(DB_CONFIG_PATH, 'r', encoding='utf-8') as config_file:
            return json.load(config_file)
    except (json.JSONDecodeError, OSError):
        return None


def _coerce_port(value):
    if value in (None, ''):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def build_database_url_from_dict(config_dict):
    """Monta uma URL de conexão SQLAlchemy com base no dicionário informado."""
    if not config_dict:
        return None

    engine_name = (config_dict.get('engine') or config_dict.get('dialect') or '').lower()

    if engine_name in ('mysql', 'mysql+mysqlconnector'):
        url_obj = URL.create(
            drivername='mysql+mysqlconnector',
            username=config_dict.get('username') or None,
            password=config_dict.get('password') or None,
            host=config_dict.get('host') or None,
            port=_coerce_port(config_dict.get('port')),
            database=config_dict.get('database') or None
        )
        return str(url_obj)

    if engine_name in ('postgres', 'postgresql', 'postgresql+psycopg2'):
        url_obj = URL.create(
            drivername='postgresql+psycopg2',
            username=config_dict.get('username') or None,
            password=config_dict.get('password') or None,
            host=config_dict.get('host') or None,
            port=_coerce_port(config_dict.get('port')),
            database=config_dict.get('database') or None
        )
        return str(url_obj)

    if engine_name in ('sqlite', 'sqlite3'):
        db_path = config_dict.get('database') or config_dict.get('path')
        if not db_path:
            return None

        db_path = Path(db_path)
        if not db_path.is_absolute():
            db_path = BASE_DIR / db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        url_obj = URL.create(drivername='sqlite', database=str(db_path))
        return str(url_obj)

    return None


def persist_db_config(config_payload):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(DB_CONFIG_PATH, 'w', encoding='utf-8') as config_file:
        json.dump(config_payload, config_file, indent=2, ensure_ascii=False)


def load_env():
    """Carregar variáveis de ambiente do arquivo .env."""
    env_path = '.env'
    if not os.path.exists(env_path):
        return

    with open(env_path) as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

# Carregar variáveis de ambiente
load_env()


def determine_database_uri():
    db_username = os.getenv('DB_USERNAME')
    db_password = os.getenv('DB_PASSWORD')
    db_host = os.getenv('DB_HOST')
    db_name = os.getenv('DB_NAME')
    db_port = os.getenv('DB_PORT')
    database_url = (
        os.getenv('DATABASE_URL')
        or os.getenv('CLEARDB_DATABASE_URL')
        or os.getenv('SQLALCHEMY_DATABASE_URI')
    )

    if database_url:
        if database_url.startswith('mysql://'):
            parsed_db_url = urlparse(database_url)
            url_obj = URL.create(
                drivername='mysql+mysqlconnector',
                username=parsed_db_url.username,
                password=parsed_db_url.password or None,
                host=parsed_db_url.hostname,
                port=parsed_db_url.port,
                database=parsed_db_url.path.lstrip('/')
            )
            return str(url_obj), True, None

        if database_url.startswith(('postgres://', 'postgresql://')):
            normalized_url = database_url.replace('postgres://', 'postgresql://', 1)
            return normalized_url, True, None

        return database_url, True, None

    if all([db_username, db_password, db_host, db_name]):
        url_obj = URL.create(
            drivername='mysql+mysqlconnector',
            username=db_username,
            password=db_password,
            host=db_host,
            port=_coerce_port(db_port),
            database=db_name
        )
        return str(url_obj), True, None

    file_config = load_db_config_from_file()
    file_url = build_database_url_from_dict(file_config)
    if file_url:
        return file_url, True, file_config

    fallback_url = URL.create(drivername='sqlite', database=str(FALLBACK_SQLITE_PATH))
    return str(fallback_url), False, None



app = Flask(__name__)

# Ajusta a chave secreta com prioridade para variáveis de ambiente
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'homium-001')

database_uri, db_is_configured, file_config = determine_database_uri()
app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
app.config['DB_CONFIGURED'] = db_is_configured
app.config['DB_FILE_CONFIGURATION'] = file_config
app.config['SQLALCHEMY_POOL_SIZE'] = 5  # Reduzir o tamanho do pool
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 10  # Limitar conexões extras
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 30  # Timeout mais curto
app.config['SQLALCHEMY_POOL_RECYCLE'] = 1800  # Reciclar conexões a cada 30 minutos
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

redis_url = os.getenv('REDIS_URL')
if redis_url:
    redis_cache = redis.StrictRedis.from_url(
        redis_url,
        decode_responses=True,
        socket_timeout=5,
        socket_connect_timeout=5,
        retry_on_timeout=True,
        max_connections=10
    )
else:
    redis_cache = redis.StrictRedis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        password=os.getenv('REDIS_PASSWORD'),
        db=int(os.getenv('REDIS_DB', 0)),
        decode_responses=True,
        socket_timeout=5,
        socket_connect_timeout=5,
        retry_on_timeout=True,
        max_connections=10
    )

csrf = CSRFProtect(app)
csrf.init_app(app)

app.config['WTF_CSRF_ENABLED'] = False  # Desabilita a proteção global

def configure_sqlalchemy_engine(sqlalchemy_uri):
    return create_engine(
        sqlalchemy_uri,
        poolclass=QueuePool,
        pool_size=20,
        max_overflow=0,
        pool_recycle=3600,
        execution_options={'autoflush': False, 'expire_on_commit': False}
    )


engine = configure_sqlalchemy_engine(app.config['SQLALCHEMY_DATABASE_URI'])


def get_db_form_defaults(existing_config=None):
    defaults = {
        'engine': 'mysql',
        'host': '',
        'port': '',
        'username': '',
        'password': '',
        'database': ''
    }

    if existing_config:
        defaults['engine'] = existing_config.get('engine', defaults['engine'])
        defaults['host'] = existing_config.get('host', defaults['host']) or ''
        defaults['username'] = existing_config.get('username', defaults['username']) or ''
        defaults['database'] = existing_config.get('database', defaults['database']) or ''

        port_value = existing_config.get('port')
        defaults['port'] = str(port_value) if port_value not in (None, '') else ''

        if defaults['engine'] in ('sqlite', 'sqlite3'):
            defaults['host'] = ''
            defaults['port'] = ''
            defaults['username'] = ''

    return defaults


def extract_form_payload(form_data, existing_config=None):
    engine_name = (form_data.get('engine') or 'mysql').lower()
    payload = {'engine': engine_name}

    if engine_name in ('sqlite', 'sqlite3'):
        payload['database'] = form_data.get('database', '').strip()
        return payload

    payload['host'] = form_data.get('host', '').strip()
    payload['port'] = form_data.get('port', '').strip()
    payload['username'] = form_data.get('username', '').strip()
    password_value = form_data.get('password', '')

    if not password_value and existing_config and existing_config.get('engine') == engine_name:
        password_value = existing_config.get('password', '')

    payload['password'] = password_value
    payload['database'] = form_data.get('database', '').strip()
    return payload


def validate_db_payload(payload):
    errors = []
    engine_name = payload.get('engine')

    if engine_name in ('sqlite', 'sqlite3'):
        if not payload.get('database'):
            errors.append('Informe o caminho do arquivo SQLite.')
        return errors

    if not payload.get('host'):
        errors.append('O host do banco é obrigatório.')
    if not payload.get('username'):
        errors.append('O usuário do banco é obrigatório.')
    if not payload.get('database'):
        errors.append('O nome do banco é obrigatório.')

    port_value = payload.get('port')
    if port_value:
        try:
            int(port_value)
        except (TypeError, ValueError):
            errors.append('A porta deve ser um número inteiro.')

    return errors


def test_database_connection(sqlalchemy_uri):
    test_engine = None
    try:
        test_engine = create_engine(
            sqlalchemy_uri,
            poolclass=QueuePool,
            pool_size=1,
            max_overflow=0,
            pool_recycle=3600,
            execution_options={'autoflush': False, 'expire_on_commit': False}
        )
        with test_engine.connect() as connection:
            connection.execute(text('SELECT 1'))
        return True, 'Conexão bem-sucedida.'
    except Exception as error:  # noqa: B902 - queremos capturar qualquer erro de conexão
        return False, str(error)
    finally:
        if test_engine:
            test_engine.dispose()


def apply_database_configuration(sqlalchemy_uri, payload):
    global engine

    app.config['SQLALCHEMY_DATABASE_URI'] = sqlalchemy_uri
    app.config['DB_CONFIGURED'] = True
    app.config['DB_FILE_CONFIGURATION'] = payload

    try:
        db.session.remove()
    except Exception:
        pass

    try:
        db.engine.dispose()
    except Exception:
        pass

    try:
        engine.dispose()
    except Exception:
        pass

    engine = configure_sqlalchemy_engine(sqlalchemy_uri)


@app.route('/database/setup', methods=['GET', 'POST'])
def database_setup():
    existing_config = load_db_config_from_file() or app.config.get('DB_FILE_CONFIGURATION') or {}
    form_defaults = get_db_form_defaults(existing_config)
    test_result = None

    if form_defaults.get('engine') not in ('sqlite', 'sqlite3'):
        form_defaults['password'] = ''

    if request.method == 'POST':
        form_payload = extract_form_payload(request.form, existing_config)
        errors = validate_db_payload(form_payload)
        action = request.form.get('action', 'test')
        force_save_requested = request.form.get('force_save') == '1'
        connection_uri = build_database_url_from_dict(form_payload) if not errors else None

        if errors:
            for error in errors:
                flash(error, 'danger')
        elif not connection_uri:
            flash('Não foi possível montar a URL de conexão. Verifique os dados informados.', 'danger')
        else:
            if action == 'save' and force_save_requested:
                success = False
                message = 'A conexão não foi testada. Verifique manualmente assim que possível.'
                test_result = {'success': False, 'message': message}
            else:
                success, message = test_database_connection(connection_uri)
                test_result = {'success': success, 'message': message}

            if action == 'save':
                if success:
                    payload_to_store = dict(form_payload)
                    if payload_to_store.get('port') in ('', None):
                        payload_to_store.pop('port', None)
                    else:
                        payload_to_store['port'] = int(payload_to_store['port'])

                    persist_db_config(payload_to_store)
                    apply_database_configuration(connection_uri, payload_to_store)
                    flash('Configuração salva com sucesso.', 'success')
                    return redirect(url_for('database_setup'))

                if force_save_requested:
                    payload_to_store = dict(form_payload)
                    if payload_to_store.get('port') in ('', None):
                        payload_to_store.pop('port', None)
                    else:
                        payload_to_store['port'] = int(payload_to_store['port'])

                    persist_db_config(payload_to_store)
                    apply_database_configuration(connection_uri, payload_to_store)
                    flash(
                        'Configuração salva, mas a conexão não pôde ser verificada automaticamente. '
                        'Confira o banco assim que o acesso estiver disponível.',
                        'warning'
                    )
                    return redirect(url_for('database_setup'))

                flash(f'Não foi possível salvar: {message}', 'danger')

        form_defaults = get_db_form_defaults(form_payload)
        if form_payload.get('engine') not in ('sqlite', 'sqlite3'):
            form_defaults['password'] = ''

        return render_template(
            'database_setup.html',
            form_data=form_defaults,
            test_result=test_result,
            db_configured=app.config.get('DB_CONFIGURED', False)
        )

    return render_template(
        'database_setup.html',
        form_data=form_defaults,
        test_result=test_result,
        db_configured=app.config.get('DB_CONFIGURED', False)
    )


# Configure a sessão permanente com tempo limite de 5 minutos
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis_cache
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'session:'

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'auth'  # Define a rota para redirecionamento quando o usuário não estiver logado

# Configuração para redefinição de senha
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.before_request
def ensure_database_configuration():
    if app.config.get('DB_CONFIGURED', False):
        return

    endpoint = request.endpoint or ''

    if endpoint in ('database_setup', 'static'):
        return

    if request.path.startswith('/static/') or request.path.startswith('/favicon'):
        return

    return redirect(url_for('database_setup'))

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
        return f(*args, **kwargs)
    return decorated_function

def get_user_data(user_id):
    cache_key = f'user_data:{user_id}'
    cached_data = redis_cache.get(cache_key)

    if cached_data:
        print('Returning data from cache')
        return json.loads(cached_data)

    user_data = db.session.query(User).filter_by(id=user_id).first()

    if user_data:
        # Convert user_data to a dictionary before caching
        user_dict = user_data.to_dict()
        redis_cache.setex(cache_key, 600, json.dumps(user_dict))  # Cache for 10 minutos
        print('Data stored in cache')
        return user_dict

    return None

def cache_route(timeout=300):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Gerar uma chave única de cache baseada no caminho da requisição e nos parâmetros
            cache_key = f"route_cache:{request.path}:{request.query_string.decode('utf-8')}"
            
            # Verificar se existe uma resposta em cache
            cached_response = redis_cache.get(cache_key)
            
            if cached_response:
                return Response(cached_response, mimetype='text/html')
            
            # Caso não haja cache, chamar a função original
            response = f(*args, **kwargs)
            
            # Certificar que a resposta seja um objeto Response
            if isinstance(response, str):
                response = Response(response, mimetype='text/html')
            
            # Armazenar no cache apenas se for uma resposta HTML bem-sucedida e menor que 1MB
            if (response.status_code == 200 and 
                response.mimetype == 'text/html' and 
                len(response.data) < 1024 * 1024):  # 1MB
                redis_cache.setex(cache_key, timeout, response.data)
            
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

    msg = MIMEText(f'''Redefinição de Senha - ME Finanças\n\n
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


@app.route('/auth', methods=['GET', 'POST'])
def auth():
    # Redirecionamento para solicitação de redefinição de senha
    if request.args.get('reset'):
        return redirect(url_for('reset_password_request'))
    
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
                return redirect(url_for('start'))
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


@app.route('/politica-de-privacidade')
def privacy_policy():
    return render_template('privacy.html')


@app.route('/termos-de-uso')
def terms_of_use():
    return render_template('terms.html')

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
