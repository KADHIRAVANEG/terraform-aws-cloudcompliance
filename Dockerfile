FROM python:3.11-slim

LABEL maintainer="Kadhiravan E.G."
LABEL description="CloudCompliance — SOC2 Evidence Report Generator"
LABEL org.opencontainers.image.source=https://github.com/KADHIRAVANEG/terraform-aws-cloudcompliance

WORKDIR /app

COPY cloudcompliance/ ./cloudcompliance/
COPY compliance/ ./compliance/
COPY pyproject.toml .
COPY README.md .
COPY LICENSE .

RUN pip install --no-cache-dir rich && \
    pip install --no-cache-dir .

VOLUME ["/app/terraform"]

ENTRYPOINT ["cloudcompliance"]
