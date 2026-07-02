# Sandwalk v2 dashboard server. Bundles the Kingfisher binary so the
# "Check Active" and "Validate All" endpoints validate with the same engine as
# the endpoint agent. Build for linux/amd64 (ECS Fargate).
FROM python:3.12-slim

WORKDIR /app

ARG KINGFISHER_VERSION=1.105.0

# curl is kept — the ECS container health check uses it.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL "https://github.com/mongodb/kingfisher/releases/download/v${KINGFISHER_VERSION}/kingfisher-linux-x64.tgz" \
       -o /tmp/kf.tgz \
    && tar -xzf /tmp/kf.tgz -C /usr/local/bin kingfisher \
    && chmod +x /usr/local/bin/kingfisher \
    && rm /tmp/kf.tgz \
    && rm -rf /var/lib/apt/lists/*

COPY server/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt httpx pyyaml

COPY server/ server/
COPY VERSION VERSION

# Pre-built dashboard (run `npm run build` in dashboard/ before docker build)
COPY dashboard/dist/ dashboard/dist/

EXPOSE 8000
ENV PYTHONPATH=/app
ENV KINGFISHER_BIN=/usr/local/bin/kingfisher

CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
