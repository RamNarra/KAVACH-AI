FROM python:3.11-slim

# Install system dependencies (Java JRE, wget, unzip)
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jre \
    wget \
    unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Apktool
RUN mkdir -p /opt/apktool \
    && wget -q -O /opt/apktool/apktool.jar https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar \
    && chmod +x /opt/apktool/apktool.jar \
    && echo '#!/bin/bash\nexec java -jar /opt/apktool/apktool.jar "$@"' > /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool

# Install JADX
RUN mkdir -p /opt/jadx \
    && wget -q -O /tmp/jadx.zip https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && rm /tmp/jadx.zip \
    && chmod +x /opt/jadx/bin/jadx

# Add JADX to PATH
ENV PATH="/opt/jadx/bin:${PATH}"

# Set working directory
WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
COPY . .

# Expose port (Cloud Run uses PORT env var, defaults to 8080)
EXPOSE 8080

# Start command
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
