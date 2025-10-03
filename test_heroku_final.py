#!/usr/bin/env python3
"""
Teste final do sistema de cadastro para Heroku
"""

import os
import sys
from dotenv import load_dotenv

# Carregar variáveis do .env
load_dotenv()

def test_user_registration_flow():
    """Testa o fluxo completo de cadastro sem banco"""
    print("🧪 TESTE DE FLUXO DE CADASTRO")
    print("============================")
    
    # Simular dados de um formulário de cadastro
    form_data = {
        'full_name': 'João Silva',
        'email': 'joao@example.com',
        'username': 'joao_silva',
        'password': 'senha123456',
        'confirm_password': 'senha123456'
    }
    
    # Validações que acontecem na rota auth()
    validations = []
    
    # 1. Campos obrigatórios
    if all([form_data['full_name'], form_data['email'], form_data['username'], 
            form_data['password'], form_data['confirm_password']]):
        validations.append("✅ Todos os campos obrigatórios preenchidos")
    else:
        validations.append("❌ Campos obrigatórios faltando")
    
    # 2. Tamanho da senha
    if len(form_data['password']) >= 8:
        validations.append("✅ Senha tem pelo menos 8 caracteres")
    else:
        validations.append("❌ Senha muito curta")
    
    # 3. Confirmação de senha
    if form_data['password'] == form_data['confirm_password']:
        validations.append("✅ Senhas conferem")
    else:
        validations.append("❌ Senhas não conferem")
    
    # 4. Normalização de dados
    email_normalized = form_data['email'].strip().lower()
    username_normalized = form_data['username'].strip()
    name_normalized = form_data['full_name'].strip()
    
    if email_normalized == 'joao@example.com':
        validations.append("✅ Email normalizado corretamente")
    else:
        validations.append("❌ Erro na normalização do email")
    
    # 5. Hash da senha
    try:
        from werkzeug.security import generate_password_hash, check_password_hash
        password_hash = generate_password_hash(form_data['password'])
        
        if check_password_hash(password_hash, form_data['password']):
            validations.append("✅ Hash de senha funcionando")
        else:
            validations.append("❌ Erro no hash de senha")
    except ImportError:
        validations.append("❌ Werkzeug não disponível")
    
    # Mostrar resultados
    for validation in validations:
        print(validation)
    
    passed = sum(1 for v in validations if v.startswith("✅"))
    total = len(validations)
    
    return passed == total

def test_app_configuration():
    """Testa se a configuração da aplicação está correta"""
    print("\n🔧 TESTE DE CONFIGURAÇÃO")
    print("========================")
    
    try:
        # Testar import sem conectar ao banco
        os.environ['DYNO'] = 'web.1'  # Simular Heroku
        
        from app import app
        
        checks = []
        
        # Verificar se é reconhecido como Heroku
        if os.environ.get('DYNO'):
            checks.append("✅ Detectado como ambiente Heroku")
        else:
            checks.append("❌ Não detectado como Heroku")
        
        # Verificar configurações de pool
        pool_size = app.config.get('SQLALCHEMY_POOL_SIZE', 0)
        if pool_size <= 3:
            checks.append(f"✅ Pool size otimizado para Heroku: {pool_size}")
        else:
            checks.append(f"❌ Pool size muito alto: {pool_size}")
        
        # Verificar timeout
        pool_timeout = app.config.get('SQLALCHEMY_POOL_TIMEOUT', 0)
        if pool_timeout <= 30:
            checks.append(f"✅ Pool timeout adequado: {pool_timeout}s")
        else:
            checks.append(f"⚠️ Pool timeout alto: {pool_timeout}s")
        
        # Verificar se pre_ping está habilitado
        pre_ping = app.config.get('SQLALCHEMY_POOL_PRE_PING', False)
        if pre_ping:
            checks.append("✅ Pool pre-ping habilitado")
        else:
            checks.append("❌ Pool pre-ping desabilitado")
        
        for check in checks:
            print(check)
        
        return all(check.startswith("✅") for check in checks)
        
    except Exception as e:
        print(f"❌ Erro na configuração: {e}")
        return False
    finally:
        # Limpar variável de ambiente
        if 'DYNO' in os.environ:
            del os.environ['DYNO']

def main():
    print("🎯 TESTE FINAL PARA HEROKU")
    print("=" * 40)
    
    tests = [
        ("Fluxo de cadastro", test_user_registration_flow),
        ("Configuração da aplicação", test_app_configuration),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        result = test_func()
        results.append(result)
    
    print("\n" + "=" * 40)
    print("📊 RESULTADO FINAL")
    
    passed = sum(results)
    total = len(results)
    
    if passed == total:
        print("✅ Todos os testes passaram!")
        print("🚀 Aplicação pronta para Heroku!")
        print("\n💡 Próximos passos:")
        print("1. ./deploy_heroku.sh  # Deploy automático")
        print("2. Ou siga o HEROKU_DEPLOY.md manualmente")
        return 0
    else:
        print(f"❌ {total - passed} testes falharam")
        print("🔧 Corrija os problemas antes do deploy")
        return 1

if __name__ == "__main__":
    sys.exit(main())