FROM python:3.11-slim

# Namesti sistemske odvisnosti in build tools
RUN apt-get update && apt-get install -y \
    nmap \
    net-tools \
    iputils-ping \
    gcc \
    python3-dev \
    build-essential \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Nastavi časovni pas
ENV TZ=Europe/Ljubljana
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

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
