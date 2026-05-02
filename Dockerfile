FROM python:3.11-slim

# Install system dependencies for YARA
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    libssl-dev \
    automake \
    libtool \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY discord_security_bot.py .
COPY rules.yar .
COPY custom_signatures.json .
COPY whitelist.json .
COPY quarantine_db.py .
COPY quarantine_ui.py .

# Copy testing framework (optional - for validation)
COPY standalone_scanner.py .
COPY test_real_samples.py .
COPY test_real_urls.py .

# Create necessary directories
RUN mkdir -p /app/logs /app/quarantine_storage

# Set permissions for quarantine storage
RUN chmod 700 /app/quarantine_storage

# Set environment variables (override these when running)
ENV DISCORD_TOKEN=""
ENV VT_API_KEY=""
ENV YARA_RULES_PATH="rules.yar"
ENV CUSTOM_SIGNATURES_FILE="custom_signatures.json"

# Threshold configuration (based on testing results)
# URL Scanner: threshold 25 achieves 90% accuracy
# File Scanner: threshold 15 recommended (or use lower than URLs)
ENV URL_DETECTION_THRESHOLD="25"
ENV FILE_DETECTION_THRESHOLD="15"

# Run the bot
CMD ["python", "-u", "discord_security_bot.py"]
