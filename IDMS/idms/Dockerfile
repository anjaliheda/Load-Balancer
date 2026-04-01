FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY rule_engine.py .
COPY anomaly_engine.py .
COPY mitigation_controller.py .
COPY idms_proxy.py .

RUN mkdir -p /data

EXPOSE 5001

CMD ["python", "idms_proxy.py"]
