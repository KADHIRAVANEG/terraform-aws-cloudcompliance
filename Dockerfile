FROM python:3.11-slim

LABEL maintainer="Kadhiravan E.G."
LABEL description="CloudCompliance — SOC2 Evidence Report Generator"
LABEL org.opencontainers.image.source=https://github.com/KADHIRAVANEG/terraform-aws-cloudcompliance

# Create dedicated non-root system user and group (CIS Docker Benchmark 4.1)
RUN groupadd -g 10001 compliance && \
    useradd -u 10001 -g compliance -m -d /home/compliance -s /bin/bash compliance

WORKDIR /app

COPY pyproject.toml .
COPY README.md .
COPY LICENSE .
COPY cloudcompliance/ ./cloudcompliance/

RUN pip install --no-cache-dir . && \
    mkdir -p /app/compliance /app/terraform && \
    chown -R compliance:compliance /app

VOLUME ["/app/terraform", "/app/compliance"]

USER compliance

ENTRYPOINT ["cloudcompliance"]
CMD ["report"]
