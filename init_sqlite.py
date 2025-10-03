#!/usr/bin/env python3
"""
Script para inicializar o banco SQLite e testar cadastro
"""

import os
import sys
from dotenv import load_dotenv

# Carregar variáveis de ambiente
load_dotenv()

# Remover DATABASE_URL temporariamente para forçar SQLite
if 'DATABASE_URL' in os.environ:
    del os.environ['DATABASE_URL']

print("🗄️ INICIALIZANDO BANCO SQLITE")
print("=" * 40)

try:
    from app import app, db
    from models.models import User
    from werkzeug.security import generate_password_hash, check_password_hash
    
    with app.app_context():
        print("📁 Removendo banco antigo se existir...")
        db_path = 'shopping.db'
        if os.path.exists(db_path):
            os.remove(db_path)
            print(f"✅ Arquivo {db_path} removido")
        
        print("🔨 Criando tabelas...")
        db.create_all()
        print("✅ Tabelas criadas com sucesso")
        
        # Verificar tabelas criadas
        from sqlalchemy import text
        result = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        tables = [row[0] for row in result.fetchall()]
        print(f"📋 Tabelas criadas: {tables}")
        
        # Testar cadastro de usuário
        print("\n👤 TESTANDO CADASTRO DE USUÁRIO")
        print("=" * 40)
        
        test_user_data = {
            'username': 'admin',
            'email': 'admin@test.com',
            'full_name': 'Administrador',
            'password': 'admin123456',
            'subscription_status': 'active'
        }
        
        # Verificar se usuário já existe
        existing_user = User.query.filter_by(username=test_user_data['username']).first()
        if existing_user:
            print("❌ Usuário admin já existe, removendo...")
            db.session.delete(existing_user)
            db.session.commit()
        
        # Criar usuário de teste
        new_user = User(
            username=test_user_data['username'],
            password=generate_password_hash(test_user_data['password']),
            email=test_user_data['email'],
            full_name=test_user_data['full_name'],
            subscription_status=test_user_data['subscription_status']
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Verificar se foi criado
        created_user = User.query.filter_by(username=test_user_data['username']).first()
        if created_user:
            print(f"✅ Usuário criado com sucesso!")
            print(f"   ID: {created_user.id}")
            print(f"   Username: {created_user.username}")
            print(f"   Email: {created_user.email}")
            print(f"   Nome: {created_user.full_name}")
            print(f"   Status: {created_user.subscription_status}")
            
            # Testar autenticação
            if check_password_hash(created_user.password, test_user_data['password']):
                print("✅ Autenticação funcionando")
            else:
                print("❌ Erro na autenticação")
        else:
            print("❌ Erro: Usuário não foi encontrado após criação")
        
        # Contar total de usuários
        total_users = User.query.count()
        print(f"📊 Total de usuários no banco: {total_users}")
        
except Exception as e:
    print(f"❌ Erro: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n🎉 INICIALIZAÇÃO CONCLUÍDA!")
print("=" * 40)
print("💡 Para testar a aplicação:")
print("1. python app.py")
print("2. Acesse: http://localhost:5000")
print("3. Faça login com:")
print("   - Usuário: admin")
print("   - Senha: admin123456")
print("")
print("📝 Para criar novos usuários, use o formulário de cadastro na web")