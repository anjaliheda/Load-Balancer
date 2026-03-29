FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot.py .

RUN mkdir -p /data

EXPOSE 5002

CMD ["python", "honeypot.py"]
