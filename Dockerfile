FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
RUN addgroup --system agentshield && adduser --system --ingroup agentshield agentshield
COPY pyproject.toml README.md ./
COPY agentshield ./agentshield
COPY migrations ./migrations
COPY alembic.ini ./
RUN pip install --no-cache-dir .

USER agentshield
EXPOSE 8000
CMD ["uvicorn", "agentshield.service.api:app", "--host", "0.0.0.0", "--port", "8000"]
