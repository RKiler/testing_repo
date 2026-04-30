#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example. Edit it before continuing."
fi

if [[ ! -f config.yaml ]]; then
  cp config.example.yaml config.yaml
  echo "Created config.yaml from config.example.yaml. Edit it before continuing."
fi

echo "Starting enhanced recon framework..."
docker compose up -d --build

echo
echo "Framework started."
echo "Grafana:    http://localhost:3000"
echo "Dashboard:  http://localhost:5000"
echo "Prometheus: http://localhost:9090"
echo
echo "Add a domain with:"
echo "docker compose exec postgres psql -U recon_user -d recon_framework -c \"INSERT INTO domains (domain, organization, scan_interval_hours) VALUES ('example.com', 'Example', 24) ON CONFLICT (domain) DO NOTHING;\""
