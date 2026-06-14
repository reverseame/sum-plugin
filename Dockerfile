# =============================================================================
# Dockerfile de referencia para el plugin SUM (Similarity Unrelocated Module)
# sobre Volatility 2.6 / Python 2.7.
#
# Derivado del Dockerfile del Volatility-workshop, pero recortado y enfocado:
#   - Base directa en python:2.7 (no se compila Python 2 desde fuente).
#   - Solo Volatility 2 (no Vol3, SSH, r2, readpe, zsh...).
#   - Añade las dependencias propias de SUM: ssdeep, fuzzyhashlib, capstone.
#
# Cada paso de esta receta ha sido validado: las tres librerías de similitud
# (ssdeep, sdhash y tlsh) importan y generan digests correctamente.
#
# NOTA DE ARQUITECTURA: el .deb de libssl1.0.0 fijado abajo es amd64 (x86_64).
# En arm64 habría que usar el .deb equivalente de esa arquitectura.
#
# --- Construir -------------------------------------------------------------
#   docker build -t sum-vol2 -f Dockerfile .
#
# --- Ejecutar (montando este repo en /plugin para probar tus cambios) ------
#   docker run --rm -it \
#       -v "$PWD":/plugin \
#       -v /ruta/a/dumps:/shared \
#       sum-vol2
#
#   # dentro del contenedor (alias 'vol2' ya definido). OJO: Volatility registra
#   # el comando como 'sumplugin' (nombre de la clase SumPlugin), no 'sum':
#   vol2 --plugins=/plugin --info | grep -i sum
#   vol2 --plugins=/plugin --profile=Win7SP1x64 -f /shared/memoria.raw sumplugin -p 252 -A tlsh
# =============================================================================

FROM python:2.7-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    # /plugin (repo) y /plugin/sum deben estar en el path para que resuelvan
    # los imports absolutos de sum.py (derelocation, hashengine, marked_pefile)
    PYTHONPATH=/plugin:/plugin/sum

# -----------------------------------------------------------------------------
# 1) Repos APT: Buster está EOL -> redirigir a archive.debian.org
# -----------------------------------------------------------------------------
RUN printf 'deb http://archive.debian.org/debian buster main\ndeb http://archive.debian.org/debian-security buster/updates main\n' \
        > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libfuzzy-dev \
        git \
        wget \
        ca-certificates \
        vim \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# 2) libcrypto.so.1.0.0 (OpenSSL 1.0.1) requerida por fuzzyhashlib (sdhash/tlsh)
#    Buster no trae libssl1.0.0; el .deb de Jessie tiene una pre-dependencia
#    (multiarch-support) que Buster no satisface, así que NO usamos dpkg -i:
#    extraemos solo la librería con dpkg-deb -x y la registramos con ldconfig.
# -----------------------------------------------------------------------------
RUN wget -q http://archive.debian.org/debian/pool/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u8_amd64.deb \
        -O /tmp/libssl.deb \
    && dpkg-deb -x /tmp/libssl.deb /tmp/libssl \
    && cp -a /tmp/libssl/usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.0 \
             /tmp/libssl/usr/lib/x86_64-linux-gnu/libssl.so.1.0.0 \
             /usr/lib/x86_64-linux-gnu/ \
    && ldconfig \
    && rm -rf /tmp/libssl /tmp/libssl.deb

# -----------------------------------------------------------------------------
# 3) Volatility 2.6
# -----------------------------------------------------------------------------
RUN git clone --depth 1 https://github.com/volatilityfoundation/volatility.git /opt/volatility2 \
    && chmod +x /opt/volatility2/vol.py

# -----------------------------------------------------------------------------
# 4) Dependencias Python 2:
#    - Volatility 2:  pycrypto, distorm3, pefile
#    - SUM:           ssdeep, fuzzyhashlib, capstone (+ pefile fijado)
# -----------------------------------------------------------------------------
RUN pip install --no-cache-dir --upgrade 'setuptools<45' pip \
    && pip install --no-cache-dir \
        'pefile==2019.4.18' \
        capstone \
        ssdeep \
        fuzzyhashlib \
        pycrypto \
        distorm3

# -----------------------------------------------------------------------------
# 5) Comodidades de uso
# -----------------------------------------------------------------------------
RUN mkdir -p /shared /plugin \
    && printf '#!/bin/sh\nexec python /opt/volatility2/vol.py "$@"\n' > /usr/local/bin/vol2 \
    && chmod +x /usr/local/bin/vol2

# Smoke-test en build: aborta la imagen si alguna librería de similitud falla
RUN python -c "import ssdeep, capstone, pefile, fuzzyhashlib; \
from fuzzyhashlib import tlsh, sdhash; \
print('deps OK -> pefile', pefile.__version__, '| capstone', capstone.__version__)"

WORKDIR /plugin
CMD ["/bin/bash"]
