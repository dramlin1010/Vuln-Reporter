FROM python:3.11-alpine

RUN apk update && apk upgrade
RUN adduser --disabled-password --gecos '' team_iscp

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py /app/main.py
COPY config.cfg /app/config.cfg

USER team_iscp

CMD ["sh", "-c", "while true; do python main.py; echo 'Script finalizado, esperando 5 minutos...'; sleep 300; done"]