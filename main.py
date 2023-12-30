from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

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
    

@app.route('/')
def index():
    shopping_list = ShoppingList.query.all()
    total_price = sum(item.quantity * item.price for item in shopping_list)
    return render_template('index.html', shopping_list=shopping_list, total_price=total_price)

@app.route('/add', methods=['POST'])
def add():
    name = request.form['name']
    quantity = request.form['quantity']
    price = request.form['price']
    category = request.form['category']

    # Adicione validações e formatação necessárias aqui

    new_item = ShoppingList(name=name, quantity=quantity, price=price, category=category)
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0')
