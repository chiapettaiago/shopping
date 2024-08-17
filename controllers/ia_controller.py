import google.generativeai as genai

# Configuração do Gemini
genai.configure(api_key='AIzaSyACwhkVuzzzK4tXoSarhqaL9Y4CJ-FUc3M')

generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 64,
    "max_output_tokens": 8192
}

model = genai.GenerativeModel(
    model_name="gemini-1.5-flash",
    generation_config=generation_config,
)

chat_session = model.start_chat(history=[])

def get_gemini_response(user_input):
    try:
        response = chat_session.send_message(user_input)
        return response.text  # Retorna a resposta da IA
    except Exception as e:
        # Captura a mensagem de erro e exibe para depuração
        return f"Desculpe, houve um erro ao processar sua solicitação: {str(e)}"


def process_user_input(user_input, saldo, gastos, por_dia):
    user_input = user_input.lower().strip()

    # Cria um contexto mais estruturado e informativo
    context_info = f"""
    Informações financeiras atuais:
    - Saldo: R$ {saldo:.2f}
    - Gastos totais no mês: R$ {gastos:.2f}
    - Gasto médio por dia restante no mês: R$ {por_dia:.2f}
    """

    # Adiciona o contexto à mensagem do usuário
    full_input = f"{user_input}\n\n{context_info}"

    return get_gemini_response(full_input)