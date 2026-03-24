# Base image
FROM debian:bookworm-slim

# Disable apt confirmations
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    wget \
    libcrypto++-dev \
    libasio-dev \
    ca-certificates \
    entr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Donwloand crow framework
RUN wget -O /usr/local/include/crow_all.h https://github.com/CrowCpp/Crow/releases/download/v1.3.1/crow_all.h

# Copy src code
COPY . /app/

# Compile server
# RUN g++ server.cpp -o server -std=c++17 -pthread -lcryptopp -O3
RUN g++ backend.cpp -o backend.out -std=c++17 -lcryptopp -O3

# Port config
EXPOSE 18080

# Run server
CMD ["./backend.out"]