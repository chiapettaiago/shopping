from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, timedelta
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import google.generativeai as genai


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shopping_list.db'
app.config['SECRET_KEY'] = 'homium-001'  # Defina uma chave secreta única e segura
db = SQLAlchemy(app)
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

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class ShoppingList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    status = db.Column(db.Integer)
    date = db.Column(db.DateTime)
    username = db.Column(db.String(50), db.ForeignKey('user.username'))
    
class debts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    maturity = db.Column(db.Integer, nullable=False)
    value = db.Column(db.Float, nullable=False)
    status = db.Column(db.Integer)
    date = db.Column(db.DateTime)
    username = db.Column(db.String(50), db.ForeignKey('user.username'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            login_user(user)  # Login do usuário
            return redirect(url_for('index'))
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
        convo = model.start_chat(history=[])
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
    shopping_list = ShoppingList.query.filter_by(status=0, username=current_user.username).all()
    total_price = sum(item.quantity * item.price for item in shopping_list)
    return render_template('index.html', shopping_list=shopping_list, total_price=total_price)

@app.route('/history')
@login_required
def history():
    shopping_list = ShoppingList.query.filter_by(status=1,).all()
    total_price = sum(item.quantity * item.price for item in shopping_list)
    return render_template('history.html', shopping_list=shopping_list, total_price=total_price)


@app.route('/debts_history')
@login_required
def debts_history():
    debts_history = debts.query.filter_by(status=1).all()
    total_value = sum(item.value for item in debts_history)
    return render_template('debts_history.html', debts_history=debts_history, total_value=total_value)

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/add', methods=['POST'])
@login_required
def add():
    name = request.form['name']
    quantity = request.form['quantity']
    price = request.form['price']
    category = request.form['category']
    current_time = datetime.now()

    # Adicione validações e formatação necessárias aqui

    new_item = ShoppingList(name=name, quantity=quantity, price=price, category=category, status=0, date=current_time, username=current_user.username)
    db.session.add(new_item)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/debts', methods=['GET','POST'])
@login_required
def debitos():
    debts_list = debts.query.filter_by(status=0, username=current_user.username).all()
    total_price = sum(item.value for item in debts_list)
    return render_template('finance.html', debts_list=debts_list, total_price=total_price)

@app.route('/add_debts', methods=['POST'])
@login_required
def add_debts():
    name = request.form['name']
    maturity = request.form['maturity']
    value = request.form['value']
    current_time = datetime.now()

    # Adicione validações e formatação necessárias aqui

    new_item = debts(name=name, maturity=maturity, value=value, date=current_time, status=0, username=current_user.username)
    db.session.add(new_item)
    db.session.commit()
    return redirect(url_for('debitos'))
# Rota para excluir um item
@app.route('/delete/<int:id>', methods=['GET'])
@login_required
def delete(id):
    item_to_delete = ShoppingList.query.get(id)
    if item_to_delete:
        db.session.delete(item_to_delete)
        db.session.commit()
    return redirect(url_for('index'))


@app.route('/delete_debts/<int:id>', methods=['GET'])
@login_required
def delete_debts(id):
    item_to_delete = debts.query.get(id)
    if item_to_delete:
        db.session.delete(item_to_delete)
        db.session.commit()
    return redirect(url_for('debitos'))

# Rota para editar um item
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    item_to_edit = ShoppingList.query.get(id)
    if request.method == 'POST':
        item_to_edit.name = request.form['name']
        item_to_edit.quantity = request.form['quantity']
        item_to_edit.price = request.form['price']
        db.session.commit()
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
    return redirect(url_for('index'))

# Rota para comprar um item
@app.route('/pay/<int:id>', methods=['GET'])
@login_required
def pay(id):
    item_to_buy = debts.query.get(id)
    if item_to_buy:
        item_to_buy.status = 1
        db.session.commit()
    return redirect(url_for('debitos'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=3000)
