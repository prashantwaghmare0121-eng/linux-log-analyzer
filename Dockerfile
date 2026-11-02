FROM python:3.12-slim
WORKDIR /app
COPY loganalyzer ./loganalyzer
COPY sample_logs ./sample_logs
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
# Load the sample logs, then start the API. Mount your own logs and database as needed.
CMD ["sh", "-c", "python -m loganalyzer ingest --auth sample_logs/auth.log --access sample_logs/access.log --db /tmp/logs.db --year 2026 && python -m loganalyzer serve --db /tmp/logs.db --host 0.0.0.0 --port 8000"]
