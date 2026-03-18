FROM python:3.11-slim

WORKDIR /app

# System deps for adb/tshark and WeasyPrint runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       android-tools-adb \
       tshark \
       libcairo2 \
       libpango-1.0-0 \
       libpangocairo-1.0-0 \
       libgdk-pixbuf-2.0-0 \
       libffi8 \
       shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
