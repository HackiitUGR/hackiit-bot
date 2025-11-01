FROM python:3.14-slim

WORKDIR /app

RUN pip install --no-cache-dir python-telegram-bot==22.5 python-dotenv requests

COPY . .

CMD ["python", "bot.py"]
