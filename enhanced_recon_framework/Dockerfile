FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    jq \
    postgresql-client \
    dnsutils \
    wget \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://go.dev/dl/go1.22.4.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz && \
    rm go1.22.4.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

RUN go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/tomnomnom/waybackurls@latest

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY database_schema.sql .
COPY continuous_recon.py .
COPY js_analysis.py .
COPY dashboard.py .
COPY config.example.yaml ./config.example.yaml

CMD ["python", "continuous_recon.py"]
