import google.generativeai as genai
from datetime import datetime
import os
from functools import lru_cache

def obter_data_atual():
    return datetime.now().strftime("%d/%m/%Y")

# Configuração do Gemini usando variável de ambiente
genai.configure(api_key=os.getenv('AIzaSyAY4OKe9VNjUgNHgchSA7Um5c7vqR2dxSY'))

# Configuração otimizada do modelo
generation_config = {
    "temperature": 0.7,  # Reduzido para respostas mais consistentes
    "top_p": 0.8,
    "top_k": 40,
    "max_output_tokens": 2048,  # Reduzido para melhor performance
    "candidate_count": 1
}

# Cache do modelo para evitar recriação
@lru_cache(maxsize=1)
def get_model():
    return genai.GenerativeModel(
        model_name="gemma-3-27b-it",  # Modelo mais estável
        generation_config=generation_config
    )

def get_gemini_response(user_input, context_info):
    try:
        model = get_model()
        # Inicia uma nova sessão a cada chamada para evitar problemas de contexto
        chat = model.start_chat(history=[])
        
        # Combina o contexto com a entrada do usuário
        full_prompt = f"{context_info}\n\nUsuário: {user_input}"
        
        response = chat.send_message(full_prompt)
        return response.text.strip()
    except Exception as e:
        return f"Desculpe, ocorreu um erro ao processar sua solicitação. Por favor, tente novamente mais tarde."

def process_user_input(user_input, saldo, gastos, por_dia, usuario, balance, dividas, gastos_nao_processados, debts_list, debts_values):
    if not user_input or not isinstance(user_input, str):
        return "Por favor, forneça uma entrada válida."

    user_input = user_input.lower().strip()

    # Formatação dos valores monetários
    saldo_fmt = f"R$ {saldo:.2f}"
    gastos_fmt = f"R$ {gastos:.2f}"
    por_dia_fmt = f"R$ {por_dia:.2f}"
    balance_fmt = f"R$ {balance:.2f}"
    dividas_fmt = f"R$ {dividas:.2f}"
    gastos_nao_processados_fmt = f"R$ {gastos_nao_processados:.2f}"

    # Criação do contexto de forma mais estruturada
    context_info = f"""Você é J.A.R.V.I.S., um assistente financeiro pessoal do sistema Meu Tesouro.

Informações financeiras atuais:
- Saldo disponível: {saldo_fmt}
- Gastos totais do mês: {gastos_fmt}
- Gasto médio por dia restante: {por_dia_fmt}
- Data atual: {obter_data_atual()}
- Total recebido este mês: {balance_fmt}
- Total de dívidas pendentes: {dividas_fmt}
- Gastos não processados hoje: {gastos_nao_processados_fmt}

Contas a pagar:
{chr(10).join(f"- {nome}: {valor}" for nome, valor in zip(debts_list, debts_values))}

Instruções:
1. Responda de forma clara e objetiva
2. Use os valores exatos fornecidos
3. Não adicione valores fictícios
4. Mantenha um tom profissional e amigável
5. Não repita o nome do usuário ({usuario}) em cada resposta
6. Forneça sugestões práticas quando apropriado"""

    return get_gemini_response(user_input, context_info)