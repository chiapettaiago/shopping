from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shopping_list.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class ShoppingList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    status = db.Column(db.Integer)
    date = db.Column(db.DateTime)
    
@app.route('/')
def index():
    shopping_list = ShoppingList.query.filter_by(status=0).all()
    total_price = sum(item.quantity * item.price for item in shopping_list)
    return render_template('index.html', shopping_list=shopping_list, total_price=total_price)

@app.route('/history')
def history():
    shopping_list = ShoppingList.query.filter_by(status=1).all()
    total_price = sum(item.quantity * item.price for item in shopping_list)
    return render_template('history.html', shopping_list=shopping_list, total_price=total_price)

@app.route('/add', methods=['POST'])
def add():
    name = request.form['name']
    quantity = request.form['quantity']
    price = request.form['price']
    category = request.form['category']
    current_time = datetime.now()

    # Adicione validações e formatação necessárias aqui

    new_item = ShoppingList(name=name, quantity=quantity, price=price, category=category, status=0, date=current_time)
    db.session.add(new_item)
    db.session.commit()
    return redirect(url_for('index'))

# Rota para excluir um item
@app.route('/delete/<int:id>', methods=['GET'])
def delete(id):
    item_to_delete = ShoppingList.query.get(id)
    if item_to_delete:
        db.session.delete(item_to_delete)
        db.session.commit()
    return redirect(url_for('index'))

# Rota para editar um item
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    item_to_edit = ShoppingList.query.get(id)
    if request.method == 'POST':
        item_to_edit.name = request.form['name']
        item_to_edit.quantity = request.form['quantity']
        item_to_edit.price = request.form['price']
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit.html', item=item_to_edit)

# Rota para comprar um item
@app.route('/buy/<int:id>', methods=['GET'])
def buy(id):
    item_to_buy = ShoppingList.query.get(id)
    if item_to_buy:
        item_to_buy.status = 1
        db.session.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=9000)
