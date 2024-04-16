# Use uma imagem base do Ubuntu
FROM ubuntu:22.04

# Atualize o sistema e instale o Python
RUN apt-get update && apt-get install -y && apt dist-upgrade -y python3 python3-pip

# Defina o diretório de trabalho no Docker
WORKDIR /app

# Copie os arquivos do projeto para o diretório de trabalho
COPY . /app

# Instale as dependências
RUN pip3 install --no-cache-dir -r requirements.txt

# Comando para iniciar o aplicativo
CMD ["python3", "./main.py"]