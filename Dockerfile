FROM python:3.11-alpine

RUN apk update && apk upgrade && \
    adduser --disabled-password --gecos '' team_iscp

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ./

RUN chown -R team_iscp:team_iscp /app

USER team_iscp

CMD ["python", "main.py"]
