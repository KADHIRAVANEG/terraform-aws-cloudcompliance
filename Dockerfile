FROM python:3.11-slim

LABEL maintainer="Kadhiravan E.G."
LABEL description="CloudCompliance — SOC2 Evidence Report Generator"
LABEL org.opencontainers.image.source=https://github.com/KADHIRAVANEG/cloudcompliance

WORKDIR /app

COPY pyproject.toml .
COPY README.md .
COPY LICENSE .
COPY cloudcompliance/ ./cloudcompliance/

RUN pip install --no-cache-dir . && \
    mkdir -p /app/compliance /app/terraform

VOLUME ["/app/terraform", "/app/compliance"]

ENTRYPOINT ["cloudcompliance"]
CMD ["report"]
