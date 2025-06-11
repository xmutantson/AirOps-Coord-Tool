FROM python:3.10.14-slim

RUN apt-get update \
 && apt-get install -y sqlite3 openssl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Install waitress for production WSGI
RUN pip install --no-cache-dir waitress

# Copy & set entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 5150

ENTRYPOINT ["entrypoint.sh"]
