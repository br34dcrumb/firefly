FROM python:3.13-slim-bookworm

COPY docker/install-deps.sh /tmp/install-deps.sh
RUN sh /tmp/install-deps.sh && rm /tmp/install-deps.sh

WORKDIR /opt/firefly
COPY pyproject.toml README.md ./
COPY firefly ./firefly
RUN pip install --no-cache-dir ".[extract]"

# Firmware is hostile input: never analyse it as root.
RUN useradd --create-home firefly && mkdir -p /data/in /data/out && chown firefly /data/out
USER firefly
WORKDIR /data/out

ENTRYPOINT ["firefly"]
CMD ["--help"]
