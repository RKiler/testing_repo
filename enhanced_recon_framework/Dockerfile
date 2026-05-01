FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    curl \
    git \
    jq \
    postgresql-client \
    dnsutils \
    unzip \
    wget \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://go.dev/dl/go1.23.1.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.1.linux-amd64.tar.gz && \
    rm go1.23.1.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV CHROME_PATH="/usr/bin/chromium"

RUN go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/tomnomnom/unfurl@latest && \
    go install github.com/tomnomnom/anew@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/sensepost/gowitness@latest

RUN nuclei -update-templates -silent || true

RUN wget -q https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux -O /usr/local/bin/findomain && \
    chmod +x /usr/local/bin/findomain

RUN wget -q https://github.com/owasp-amass/amass/releases/latest/download/amass_Linux_amd64.zip -O /tmp/amass.zip && \
    unzip -q /tmp/amass.zip -d /tmp/amass && \
    install /tmp/amass/amass_Linux_amd64/amass /usr/local/bin/amass && \
    rm -rf /tmp/amass /tmp/amass.zip

RUN git clone --depth 1 https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r && \
    pip install --no-cache-dir -r /opt/Sublist3r/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/Sublist3r/sublist3r.py "$@"\n' > /usr/local/bin/sublist3r && \
    chmod +x /usr/local/bin/sublist3r

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY database_schema.sql .
COPY continuous_recon.py .
COPY js_analysis.py .
COPY dashboard.py .
COPY export_review_queue.py .
COPY config.example.yaml ./config.example.yaml

CMD ["python", "continuous_recon.py"]
