FROM python:3.12-slim

WORKDIR /app


RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev libpq-dev && \
    rm -rf /var/lib/apt/lists/*


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


COPY . .

ENTRYPOINT ["sh", "-c"]
CMD ["alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]