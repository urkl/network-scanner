FROM python:3.11-slim

# Namesti sistemske odvisnosti in build tools
RUN apt-get update && apt-get install -y \
    nmap \
    net-tools \
    iputils-ping \
    gcc \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Nastavi delovno mapo
WORKDIR /app

# Kopiraj requirements in jih namesti
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopiraj aplikacijo
COPY . .

# Expose port
EXPOSE 5000

# Zaženi aplikacijo
CMD ["python", "app.py"]
