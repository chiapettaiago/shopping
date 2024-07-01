from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin


db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False, unique=True)
    full_name = db.Column(db.String(150), nullable=False)
    subscription_status = db.Column(db.String(50), nullable=True)

class ShoppingList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    status = db.Column(db.Integer)
    date = db.Column(db.DateTime)
    username = db.Column(db.String(50), db.ForeignKey('user.username'))
    list_id = db.Column(db.String(36), nullable=True)
    
class debts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    maturity = db.Column(db.DateTime(50), nullable=False)
    value = db.Column(db.Float, nullable=False)
    status = db.Column(db.Integer)
    date = db.Column(db.DateTime)
    username = db.Column(db.String(50), db.ForeignKey('user.username'))
    
class Balance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    value = db.Column(db.Float, nullable=False)
    status = db.Column(db.Integer)
    date = db.Column(db.DateTime)
    username = db.Column(db.String(50), db.ForeignKey('user.username'))

class Diario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    date = db.Column(db.DateTime(50), nullable=False)
    value = db.Column(db.Float, nullable=False)
    status = db.Column(db.Integer)
    username = db.Column(db.String(50), db.ForeignKey('user.username'))

