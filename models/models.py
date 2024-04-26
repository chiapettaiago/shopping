from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin


db = SQLAlchemy()


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
    maturity = db.Column(db.DateTime(50), nullable=False)
    value = db.Column(db.Float, nullable=False)
    status = db.Column(db.Integer)
    username = db.Column(db.String(50), db.ForeignKey('user.username'))
    
class Balance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    value = db.Column(db.Float, nullable=False)
    status = db.Column(db.Integer)
    date = db.Column(db.DateTime)
    username = db.Column(db.String(50), db.ForeignKey('user.username'))

