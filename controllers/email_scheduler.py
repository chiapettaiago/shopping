# email_scheduler.py
from flask_mail import Mail, Message
from celery import Celery
from datetime import timedelta
from models.models import User  # Altere para o caminho correto do seu modelo
from flask import Flask, current_app as app
import os

# Configuração do Flask Mail
mail = Mail()

# Função para configurar e integrar o Celery
def make_celery(app):
    celery = Celery(app.import_name, broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)
    return celery

# Função para enviar um e-mail personalizado para um único usuário
def send_personalized_email(user):
    with app.app_context():
        msg = Message(
            subject=f"Olá, {user.full_name}",
            sender=app.config['MAIL_USERNAME'],
            recipients=[user.email]
        )
        msg.body = f"Oi {user.full_name}, esta é uma mensagem de boas-vindas personalizada!"
        mail.send(msg)

# Função para enviar e-mails para todos os usuários cadastrados
def send_initial_emails():
    users = User.query.all()
    for user in users:
        send_personalized_email(user)

# Inicializando o Celery e configurando tarefas periódicas e de inicialização
def init_scheduler(app: Flask):
    celery = make_celery(app)
    
    # Configurações para o agendamento de e-mails a cada 48 horas
    celery.conf.beat_schedule = {
        'schedule-emails-every-48-hours': {
            'task': 'email_scheduler.schedule_emails_task',
            'schedule': timedelta(hours=48),
        }
    }

    # Tarefa para enviar e-mails de boas-vindas na inicialização
    @celery.task(name='email_scheduler.send_initial_emails_task')
    def send_initial_emails_task():
        send_initial_emails()

    # Tarefa para enviar e-mails periódicos
    @celery.task(name='email_scheduler.schedule_emails_task')
    def schedule_emails_task():
        send_initial_emails()

    # Disparo inicial de e-mails ao iniciar o aplicativo
    with app.app_context():
        send_initial_emails_task.delay()
    
    return celery
