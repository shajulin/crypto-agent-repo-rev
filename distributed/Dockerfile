# One image for device / aggregator / monitor roles (role chosen at runtime).
# Build context is the crypto/ project root so the real Module-1 code is available.
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/crypto-requirements.txt
COPY distributed/requirements.txt /app/dist-requirements.txt
RUN pip install --no-cache-dir -r /app/crypto-requirements.txt -r /app/dist-requirements.txt
COPY . /app
ENV PYTHONPATH=/app
CMD ["python", "distributed/device_agent.py"]
