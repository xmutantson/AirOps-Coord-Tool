FROM python:3.10.14-slim

# Optional: install sqlite3 CLI if you need to use it in the container
RUN apt-get update && apt-get install -y sqlite3 && rm -rf /var/lib/apt/lists/*

# Set working directory inside container
WORKDIR /app

# Copy only requirements first for caching
COPY requirements.txt .

# Install Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Now copy all code and assets
COPY . .

# Make sure container listens on this port (matches app.py port)
EXPOSE 5150

# Run your app
CMD ["python", "app.py"]
