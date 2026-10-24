FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copier tout le contenu du backend
COPY . .

# Vérification pendant le build
RUN echo "=== CONTENU /app ===" && \
    find /app -maxdepth 4 -type f -print && \
    echo "=== VERIFICATION ADMIN ===" && \
    test -d /app/app/static/admin

EXPOSE 10000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
