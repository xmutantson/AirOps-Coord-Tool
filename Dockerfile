# syntax=docker/dockerfile:1.7

########################
# Build rtl_airband (with NFM)
########################
FROM debian:bookworm-slim AS airband-builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates git cmake build-essential pkg-config \
    libconfig++-dev librtlsdr-dev libfftw3-dev libmp3lame-dev libshout3-dev \
 && update-ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt
RUN set -eux; \
    git clone --depth 1 https://github.com/rtl-airband/RTLSDR-Airband /src; \
    git -C /src fetch --tags --depth 1 || true; \
    cd /src; \
    cmake . \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DPLATFORM=generic \
      -DNFM=ON; \
    make -j"$(nproc)"; \
    make install; \
    strip /usr/local/bin/rtl_airband || true


########################
# Final image
########################
FROM python:3.10.14-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    sqlite3 openssl iproute2 wget ca-certificates \
    direwolf ax25-tools alsa-utils \
    rtl-sdr multimon-ng ffmpeg socat \
    libconfig++9v5 libfftw3-double3 librtlsdr0 libmp3lame0 libshout3 \
    iputils-ping \
 && rm -rf /var/lib/apt/lists/*

COPY --from=airband-builder /usr/local/bin/rtl_airband /usr/local/bin/rtl_airband
RUN /usr/local/bin/rtl_airband -h >/dev/null 2>&1 || true

# UDP defaults that match NFM=ON (float32@16k)
ENV AOCT_SAME_UDP_FMT=f32le \
    AOCT_SAME_UDP_RATE=16000

ARG PAT_VERSION=0.18.0
RUN set -e; \
  arch="$(dpkg --print-architecture)"; \
  if [ "$arch" = "amd64" ]; then url="https://github.com/la5nta/pat/releases/download/v$PAT_VERSION/pat_${PAT_VERSION}_linux_amd64.deb"; \
  elif [ "$arch" = "arm64" ]; then url="https://github.com/la5nta/pat/releases/download/v$PAT_VERSION/pat_${PAT_VERSION}_linux_arm64.deb"; \
  elif [ "$arch" = "armhf" ]; then url="https://github.com/la5nta/pat/releases/download/v$PAT_VERSION/pat_${PAT_VERSION}_linux_armhf.deb"; \
  elif [ "$arch" = "i386" ]; then url="https://github.com/la5nta/pat/releases/download/v$PAT_VERSION/pat_${PAT_VERSION}_linux_i386.deb"; \
  else echo "Unsupported architecture: $arch"; exit 1; fi; \
  wget -O /tmp/pat.deb "$url"; \
  dpkg -i /tmp/pat.deb || apt-get -fy install; \
  rm -f /tmp/pat.deb

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      libcairo2 \
      libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
      libgdk-pixbuf2.0-0 \
      libffi8 libffi-dev \
      shared-mime-info fonts-dejavu-core; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      i386|armhf) \
        apt-get install -y --no-install-recommends \
          build-essential pkg-config \
          zlib1g-dev libjpeg62-turbo-dev libpng-dev libtiff5-dev \
          libwebp-dev libopenjp2-7-dev libfreetype6-dev liblcms2-dev ;; \
      *) : ;; \
    esac; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

RUN pip install --no-cache-dir waitress

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    if [ "$arch" = "i386" ] || [ "$arch" = "armhf" ]; then \
      apt-get purge -y \
        build-essential pkg-config \
        zlib1g-dev libjpeg62-turbo-dev libpng-dev libtiff5-dev \
        libwebp-dev libopenjp2-7-dev libfreetype6-dev liblcms2-dev || true; \
      apt-get autoremove -y; \
    fi

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 5150
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
