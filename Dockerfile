# =============================================================================
# Reference Dockerfile for the SUM (Similarity Unrelocated Module) plugin on
# Volatility 3 / Python 3.
#
# Unlike the Volatility 2 image (see the volatility2-latest branch), every
# dependency installs cleanly from PyPI on Debian, so all three similarity
# algorithms (tlsh, ssdeep, sdhash) are available.
#
# --- Build -----------------------------------------------------------------
#   docker build -t sum-vol3 -f Dockerfile .
#
# --- Run -------------------------------------------------------------------
#   docker run --rm -it -v /path/to/dumps:/shared sum-vol3 \
#       -f /shared/memory.raw sumplugin.SumPlugin --pid 252 --algorithm tlsh
#
# The entrypoint is Volatility 3 with this plugin's directory already on the
# plugin path, so you only pass the image (-f) and the plugin invocation.
# =============================================================================

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1

# Build toolchain + libfuzzy (ssdeep / sdhash) + libffi (capstone deps)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libfuzzy-dev \
        libffi-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Volatility 3 (provides the `vol` entrypoint) + the plugin's dependencies.
# tlsh is required (default algorithm); ssdeep/fuzzyhashlib enable the optional
# ssdeep and sdhash algorithms.
RUN pip install --no-cache-dir \
        volatility3 \
        capstone \
        pefile \
        py-tlsh \
        ssdeep \
        fuzzyhashlib

# The plugin and its (already checked-out) submodules
COPY . /opt/sum-plugin

# Fail the build early if any required dependency is missing
RUN python3 -c "import capstone, pefile, tlsh; print('deps OK -> pefile', pefile.__version__, '| capstone', capstone.__version__, '| tlsh', tlsh.__version__)"

VOLUME ["/shared"]
WORKDIR /shared

# vol with the plugin directory pre-registered; user supplies -f and the plugin
ENTRYPOINT ["vol", "-p", "/opt/sum-plugin"]
CMD ["--help"]
