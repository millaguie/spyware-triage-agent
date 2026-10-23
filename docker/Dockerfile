# Tools for sta: MVT, androidqf, pymobiledevice3, APKiD (with YARA), adb and usbmuxd.
# The code and the cases are not in the image: compose.yaml mounts the repo.
FROM python:3.13-slim-trixie AS build
# Some pymobiledevice3 dependencies (lzfse) have no wheel and need a compiler.
# Versions are pinned in requirements.txt and requirements-image.txt. The
# build context is the repo root (see compose.yaml).
COPY requirements.txt requirements-image.txt /tmp/
# saf (sysdiagnose analysis framework) has no release: pinned by commit, in its
# own venv so its dependencies do not mix with sta's. Same commit as install.sh.
ARG SAF_COMMIT=2962575f0e114093f3d7da3cad20f8bc99f94cb6
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev git \
 && python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt -r /tmp/requirements-image.txt \
 && python -m venv /opt/saf \
 && /opt/saf/bin/pip install --no-cache-dir "git+https://github.com/EC-DIGIT-CSIRC/sysdiagnose@${SAF_COMMIT}"

FROM python:3.13-slim-trixie
ARG ANDROIDQF_VERSION=1.8.3
ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends adb usbmuxd libusb-1.0-0 age libmagic1 \
      ca-certificates curl procps unzip \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/venv /opt/venv
COPY --from=build /opt/saf /opt/saf
RUN ln -s /opt/saf/bin/saf /usr/local/bin/saf

# androidqf publishes no image; take the release binary and check its sha256.
# The sums are written here (same as install.sh), not read from the release.
ARG ANDROIDQF_SHA256_AMD64=59e6071fd41c4cee71f31f9a179ac3ebf9e783cece8422d89a73452335369ebe
ARG ANDROIDQF_SHA256_ARM64=c2c729058e4cb96150e98b0a9f1ab211e179743a4e5d64dd37a3e9f3fd49d619
RUN set -eu; \
    arch="${TARGETARCH:-amd64}"; \
    case "$arch" in amd64) sum="$ANDROIDQF_SHA256_AMD64" ;; arm64) sum="$ANDROIDQF_SHA256_ARM64" ;; *) echo "unsupported $arch"; exit 1 ;; esac; \
    asset="androidqf_linux_${arch}_${ANDROIDQF_VERSION}"; \
    cd /tmp && curl -fsSLO "https://github.com/mvt-project/androidqf/releases/download/v${ANDROIDQF_VERSION}/$asset"; \
    echo "$sum  $asset" | sha256sum -c -; \
    install -m 0755 "$asset" /usr/local/bin/androidqf; rm -f /tmp/*

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1
COPY docker/entrypoint.sh docker/exec.sh /usr/local/lib/sta/
ENTRYPOINT ["/usr/local/lib/sta/entrypoint.sh"]
CMD ["sleep", "infinity"]
