# Use official Python 3.10 slim (bookworm) as base image for predictable dependencies
FROM python:3.10-slim-bookworm

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PORT=9000

# Set working directory
WORKDIR /app

# Install build dependencies required for liboqs
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libssl-dev \
    pkg-config \
    python3-dev \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs (Open Quantum Safe C library)
RUN git clone -b 0.10.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cd /tmp/liboqs \
    && mkdir build && cd build \
    && cmake -DOQS_USE_OPENSSL=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/liboqs

# Configure dynamic linker to find liboqs
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/liboqs.conf && ldconfig

# Copy requirements first to leverage Docker cache
COPY web_demo/requirements.txt /app/web_demo/requirements.txt

# Create and activate virtual environment to install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
# Note: liboqs-python requires the liboqs C library we just built
RUN pip install --no-cache-dir -r web_demo/requirements.txt \
    # gevent + gevent-websocket required for flask-sock WebSocket support under gunicorn
    && pip install --no-cache-dir psutil gunicorn gevent gevent-websocket

# Copy the rest of the application
COPY . /app/

# Expose port (Render sets the PORT env var dynamically, but we default to 9000 to match server.py)
EXPOSE $PORT

# Start command
# gevent worker is required for flask-sock WebSocket support (eventlet breaks RFC 6455 framing)
CMD gunicorn -k gevent -w 1 --timeout 300 --bind 0.0.0.0:$PORT --chdir web_demo "server:app"
