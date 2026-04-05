FROM python:3.9-slim
WORKDIR /app
COPY Requirements.txt .
COPY performance_metrics.py .
RUN pip install -r Requirements.txt
COPY client.py .
COPY attack_client.py .
RUN mkdir -p results
CMD ["python", "client.py"]