import requests
from datetime import datetime

def obter_data_atual():
    # Obtendo a data atual
    data_atual = datetime.now()

    # Formatando a data no formato brasileiro
    data_formatada = data_atual.strftime("%d/%m/%Y")

    return data_formatada

# Configuração da API do Hugging Face
API_URL = "https://api-inference.huggingface.co/models/google-bert/bert-large-uncased-whole-word-masking-finetuned-squad"
HEADERS = {"Authorization": "Bearer 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"}

def query(payload):
    try:
        response = requests.post(API_URL, headers=HEADERS, json=payload)
        response.raise_for_status()  # Levanta uma exceção se houver erro na requisição
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def get_gemini_response(user_input, context):
    payload = {
        "inputs": {
            "question": user_input,
            "context": context
        },
        "parameters": {
            "max_new_tokens": 512  # Define o número máximo de novos tokens gerados na resposta
        }
    }
    response = query(payload)
    if "error" in response:
        return f"Desculpe, houve um erro ao processar sua solicitação: {response['error']}"
    return response.get("answer", "Não foi possível obter uma resposta.")

def process_user_input(user_input, saldo, gastos, por_dia, usuario, balance, dividas, gastos_nao_processados, debts_list, debts_values, debts_1_formatado):
    user_input = user_input.lower().strip()

    # Cria um contexto mais estruturado e informativo
    context_info = f"""
    Informações financeiras atuais:
    - Saldo: R$ {saldo:.2f}
    - Gastos totais no mês: R$ {gastos:.2f}
    - O gasto diário recomendado ao usuário é: R$ {por_dia:.2f}. O ajude para que ele evite estourar esse valor por dia.
    - Data atual: {obter_data_atual()}
    - Você é um assistente pessoal financeiro amigável e companheiro, que faz parte do sistema de gerenciamento de finanças Meu Tesouro.
    - O nome de quem está utilizando você é: {usuario}.
    - O valor total recebido esse mês é: R${balance}.
    - O total de dívidas ainda não pagas é: R$ {dividas}.
    - O valor total de dívidas pagas é de: R$ {debts_1_formatado}
    - O valor que o usuário já gastou hoje até esse momento é: R$ {gastos_nao_processados}
    - Não repita o nome do usuário a cada interação.
    - Seu nome é J.A.R.V.I.S.
    - Não adicione valores fictícios ou de exemplos nos cálculos que o usuário pedir.
    - Lista de contas a serem pagas: {debts_list}
    - E o valor de cada conta a ser paga respectivamente é: {debts_values}
    - Não use asteriscos antes e depois dos valores para que pareça mais natural.
    - Ao gerar previsões financeiras para o usuário refaça os cálculos duas vezes para garantir que não existirão erros.
    - Dê dicas financeiras durante as conversas quando achar oportuno. Não faça em toda interação.
    - Sempre cumprimente o usuário.
    """

    # Adiciona o contexto à mensagem do usuário
    full_input = f"{user_input}\n\n{context_info}"

    return get_gemini_response(user_input=user_input, context=context_info)