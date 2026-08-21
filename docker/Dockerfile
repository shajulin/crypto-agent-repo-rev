FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Self-contained: each device container runs its own REAL crypto/RNG inspection,
# the aggregator runs Modules 2-7. No external dataset is required.
CMD ["python", "run_all.py"]
