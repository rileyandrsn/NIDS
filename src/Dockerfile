# Use Ubuntu base with build tools
FROM ubuntu:22.04

# Install required packages
RUN apt update && apt install -y \
    build-essential \
    libpcap-dev \
    iproute2 \
    tcpdump \
    xz-utils \
    make

# Set working directory inside container
WORKDIR /app

# Copy source code and Makefile into container
COPY ./src /app

# Build the OSNIDS binary
RUN make

# Optional: Default interface if not provided by user
ENV INTERFACE=eth0

# Entrypoint (can be overridden)
CMD ["./OSNIDS", "-i", "eth0"]
