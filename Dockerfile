# Single-stage runtime image with PAT and Python app
FROM python:3.10.14-slim

# Install runtime OS packages (minimal, plus for pat .deb installs)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    sqlite3 openssl iproute2 wget ca-certificates \
    direwolf ax25-tools alsa-utils \
 && rm -rf /var/lib/apt/lists/*

# Install PAT for supported architectures
ARG PAT_VERSION=0.18.0
RUN set -e; \
  arch="$(dpkg --print-architecture)"; \
  if [ "$arch" = "amd64" ]; then \
    url="https://github.com/la5nta/pat/releases/download/v$PAT_VERSION/pat_${PAT_VERSION}_linux_amd64.deb"; \
  elif [ "$arch" = "arm64" ]; then \
    url="https://github.com/la5nta/pat/releases/download/v$PAT_VERSION/pat_${PAT_VERSION}_linux_arm64.deb"; \
  elif [ "$arch" = "armhf" ]; then \
    url="https://github.com/la5nta/pat/releases/download/v$PAT_VERSION/pat_${PAT_VERSION}_linux_armhf.deb"; \
  elif [ "$arch" = "i386" ]; then \
    url="https://github.com/la5nta/pat/releases/download/v$PAT_VERSION/pat_${PAT_VERSION}_linux_i386.deb"; \
  else \
    echo "Unsupported architecture: $arch"; exit 1; \
  fi; \
  wget -O /tmp/pat.deb "$url"; \
  dpkg -i /tmp/pat.deb || apt-get -fy install; \
  rm -f /tmp/pat.deb

WORKDIR /app

# Copy application code and install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Production WSGI server
RUN pip install --no-cache-dir waitress

# Entrypoint and expose
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 5150
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
