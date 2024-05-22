from flask import Flask, render_template, request, redirect, url_for, make_response, send_file, session
from models.models import db, User, ShoppingList, debts, Balance
from sqlalchemy import exc, text, create_engine,desc
from sqlalchemy.pool import QueuePool
from flask_migrate import Migrate
from datetime import datetime, timedelta
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import google.generativeai as genai
import mysql.connector
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
import io
import calendar
import time
import plotly.graph_objs as go


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://casaos:casaos@shoppinglist.ddns.net/casaos'
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
login_manager.login_view = 'login'  # Define a rota para redirecionamento quando o usuário não estiver logado

        
# Configurar a API uma única vez
genai.configure(api_key="AIzaSyACwhkVuzzzK4tXoSarhqaL9Y4CJ-FUc3M")

# Configuração do modelo
generation_config = {
    "temperature": 0.9,
    "top_p": 1,
    "top_k": 1,
    "max_output_tokens": 2048,
}

safety_settings = [
    {
        "category": "HARM_CATEGORY_HARASSMENT",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
        "category": "HARM_CATEGORY_HATE_SPEECH",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
]

model = genai.GenerativeModel(model_name="gemini-1.0-pro",
                              generation_config=generation_config,
                              safety_settings=safety_settings)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
        now = datetime.utcnow().replace(tzinfo=last_activity.tzinfo)  # Torna a hora atual sensível ao fuso horário
        if (now - last_activity).total_seconds() > 600:  # 600 segundos = 10 minutos
            # Fazer logout do usuário
            logout_user()
            # Redirecionar para a página de login ou para onde desejar
            return redirect(url_for('login'))
    # Atualizar o registro de última atividade
    session['last_activity'] = datetime.utcnow()

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            login_user(user)  # Login do usuário
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Usuário ou senha incorretos.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error='Nome de usuário já existe.')
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/ai', methods=['GET' , 'POST'])
@login_required
def ai():
    if request.method == 'POST':
        entrada = request.form['entrada']

        # Interagir com o modelo
        convo = model.start_chat(history=[
    {
        "role": "user",
        "parts": ["You are a financial assistant and your name is Echo"]
    },
    {
        "role": "model",
        "parts": ["Hello, my name is Echo. I am a financial assistant. I can help you with a variety of financial tasks, such as:\n* Budgeting\n* Saving\n* Investing\n* Debt repayment\n* Financial planning\n\nI can also answer any questions you have about personal finance.\n\nI am here to help you reach your financial goals. Please feel free to ask me any questions you have.\n\n**Here are some of the things I can do:**\n\n* Help you create a budget.\n* Track your income and expenses.\n* Set financial goals.\n* Create a savings plan.\n* Get out of debt.\n* Invest your money.\n* Plan for retirement.\n* Learn more about personal finance.\n\nI am constantly learning and updating my knowledge base. I am also committed to providing you with the best possible service.\n\nI am here to help you succeed. Please don't hesitate to reach out to me if you have any questions or need assistance."]
    },
    {
        "role": "user",
        "parts": ["Answer always in portuguese"]
    },
    {
        "role": "model",
        "parts": ["Olá, meu nome é Echo. Sou uma assistente financeira. Posso ajudá-lo com uma variedade de tarefas financeiras, como:\n\n* Orçamento\n* Poupança\n* Investimento\n* Pagamento de dívidas\n* Planejamento financeiro\n\nTambém posso responder a quaisquer perguntas que você tenha sobre finanças pessoais.\n\nEstou aqui para ajudá-lo a atingir seus objetivos financeiros. Sinta-se à vontade para me fazer qualquer pergunta que você tenha.\n\n**Aqui estão algumas das coisas que posso fazer:**\n\n* Ajudá-lo a criar um orçamento.\n* Acompanhe sua receita e despesas.\n* Estabeleça metas financeiras.\n* Crie um plano de poupança.\n* Saia da dívida.\n* Invista seu dinheiro.\n* Planeje a aposentadoria.\n* Aprenda mais sobre finanças pessoais.\n\nEstou constantemente aprendendo e atualizando minha base de conhecimento. Também estou comprometida em fornecer a você o melhor serviço possível.\n\nEstou aqui para ajudá-lo a ter sucesso. Não hesite em entrar em contato comigo se tiver alguma dúvida ou precisar de ajuda."]
    },
    {
        "role": "user",
        "parts": ["Your gender is male"]
    },
    {
        "role": "model",
        "parts": ["Olá, sou o Echo, seu assistente financeiro pessoal. Estou aqui para ajudá-lo a atingir seus objetivos financeiros.\n\nSou um assistente financeiro masculino e posso ajudá-lo com uma variedade de tarefas financeiras, tais como:\n\n* Orçamento\n* Poupança\n* Investimento\n* Pagamento de dívidas\n* Planejamento financeiro\n\nTambém posso responder a quaisquer perguntas que você tenha sobre finanças pessoais.\n\nEstou aqui para ajudá-lo a ter sucesso. Não hesite em entrar em contato comigo se tiver alguma dúvida ou precisar de ajuda.\n\n**Aqui estão algumas das coisas que posso fazer:**\n\n* Ajudá-lo a criar um orçamento.\n* Acompanhe sua receita e despesas.\n* Estabeleça metas financeiras.\n* Crie um plano de poupança.\n* Saia da dívida.\n* Invista seu dinheiro.\n* Planeje a aposentadoria.\n* Aprenda mais sobre finanças pessoais.\n\nEstou constantemente aprendendo e atualizando minha base de conhecimento. Também estou comprometido em fornecer a você o melhor serviço possível.\n\nEstou aqui para ajudá-lo a atingir seus objetivos financeiros. Por favor, sinta-se à vontade para me fazer qualquer pergunta que você tenha."]
    },
    ])

        convo.send_message(entrada)

        # Obter a resposta do modelo
        response = convo.last.text
        print("Entrada do usuário:", entrada)
        print("Resposta do modelo:", response)
        return render_template('ai.html', response=response, entrada=entrada)
    return render_template('ai.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Logout do usuário
    return redirect(url_for('index'))

    
@app.route('/')
@login_required
def index():
    update_old_balance_items()
    current_month = datetime.now().date().replace(day=1)
    shopping_list = ShoppingList.query.filter_by(status=0, username=current_user.username).filter(ShoppingList.date >= current_month).all()
    total_price = sum(item.quantity * item.price for item in shopping_list)
    total_price_formatado = round(total_price, 2)
    db.session.remove()
    return render_template('index.html', shopping_list=shopping_list, total_price=total_price_formatado, username=current_user.username)

@app.route('/history')
@login_required
def history():
    current_month = datetime.now().date().replace(day=1)
    shopping_list = ShoppingList.query.filter_by(status=1, username=current_user.username).filter(ShoppingList.date >= current_month).order_by(ShoppingList.date.desc()).all()
    total_price = sum(item.quantity * item.price for item in shopping_list)
    total_price_formatado = round(total_price, 2)
    db.session.remove()
    return render_template('history.html', shopping_list=shopping_list, total_price=total_price_formatado, username=current_user.username)


@app.route('/debts_history')
@login_required
def debts_history():
    current_month = datetime.now().date().replace(day=1)
    debts_history = debts.query.filter_by(status=1, username=current_user.username).filter(debts.maturity >= current_month).order_by(debts.maturity.desc()).all()
    total_value = sum(item.value for item in debts_history)
    total_value_formatado = round(total_value, 2)
    db.session.remove()
    return render_template('debts_history.html', debts_history=debts_history, total_value=total_value_formatado, username=current_user.username)

@app.route('/about')
@login_required
def about():
    return render_template('about.html', username=current_user.username)

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
    debts_1 = debts.query.filter_by(status=1, username=current_user.username).filter(debts.maturity >= current_month).all()
    balance_total = sum(item.value for item in balance_list)
    debts_total = sum(item.value for item in debts_1)
    balance_total_formatado = round(balance_total, 2)
    debts_1_formatado = round(debts_total, 2)
    total_price = sum(item.value for item in debts_list)
    total_price_formatado = round(total_price, 2)
    saldo_atualizado = balance_total_formatado - debts_1_formatado
    saldo_atualizado_formatado = round(saldo_atualizado, 2)
    por_dia = saldo_atualizado_formatado / dias_faltando
    por_dia_atualizado = round(por_dia, 2)
    db.session.remove()
    return render_template('finance.html', debts_list=debts_list, total_price=total_price_formatado, saldo_atualizado=saldo_atualizado_formatado, por_dia=por_dia_atualizado, username=current_user.username)

@app.route('/balance', methods=['GET','POST'])
@login_required
def balance():
    current_month = datetime.now().date().replace(day=1)
    balance_list = Balance.query.filter_by(status=0, username=current_user.username).filter(Balance.date >= current_month).order_by(Balance.date.desc()).all()
    total_price = sum(item.value for item in balance_list)
    total_price_formatado = round(total_price, 2)
    db.session.remove()
    return render_template('balance.html', balance_list=balance_list, total_price=total_price_formatado, username=current_user.username)

@app.route('/add_balance', methods=['POST'])
@login_required
def add_balance():
    name = request.form['name']
    value = request.form['value']
    data = datetime.now()

    # Adicione validações e formatação necessárias aqui

    new_item = Balance(name=name, value=value, status=0, date=data, username=current_user.username)
    db.session.add(new_item)
    db.session.commit()
    db.session.remove()
    return redirect(url_for('balance'))


@app.route('/add_debts', methods=['POST'])
@login_required
def add_debts():
    name = request.form['name']
    maturity = request.form['maturity']
    value = request.form['value']

    # Adicione validações e formatação necessárias aqui

    new_item = debts(name=name, maturity=maturity, value=value, status=0, username=current_user.username)
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
    if item_to_buy:
        item_to_buy.status = 1
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
    
    debts_list = debts.query.filter_by(status=0, username=current_user.username).filter(debts.maturity >= current_month).order_by(debts.value.desc()).all()
    balance_list = Balance.query.filter_by(status=0, username=current_user.username).filter(Balance.date >= current_month).all()
    debts_1 = debts.query.filter_by(status=1, username=current_user.username).filter(debts.maturity >= current_month).all()
    balance_total = sum(item.value for item in balance_list)
    debts_total = sum(item.value for item in debts_1)
    balance_total_formatado = round(balance_total, 2)
    debts_1_formatado = round(debts_total, 2)
    total_price = sum(item.value for item in debts_list)
    total_price_formatado = round(total_price, 2)
    saldo_atualizado = balance_total_formatado - debts_1_formatado
    saldo_atualizado_formatado = round(saldo_atualizado, 2)
    porcentagem = saldo_atualizado_formatado / balance_total_formatado * 100
    por_dia = saldo_atualizado_formatado / dias_faltando
    por_dia_atualizado = round(por_dia, 2)
    
    # Dívidas
    debts_list = debts.query.filter_by(status=1, username=current_user.username).filter(debts.maturity >= current_month).order_by(debts.maturity.desc()).all()
    dates_debts = [debt.maturity.strftime('%d/%m/%Y') for debt in debts_list]
    values_debts = [debt.value for debt in debts_list]
    
    pie_chart_debts = go.Pie(
        labels=dates_debts,
        values=values_debts,
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
        title='Distribuição de Gastos por Data',
        hovermode='closest',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='royalblue')  # Letras verdes
    )
    
    layout_balance = go.Layout(
        title='Distribuição de Compras por Data',
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

    return render_template('dashboard.html', username=current_user.username, graph_html1=graph_html_debts, graph_html2=graph_html_balance, porcentagem_formatado=porcentagem,  total_price=total_price_formatado, saldo_atualizado=saldo_atualizado_formatado, por_dia=por_dia_atualizado, current_month=current_month)

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
    app.run(debug=True, host='0.0.0.0', port=3000)
