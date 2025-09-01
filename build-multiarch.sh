#!/bin/bash
# Multi-architecture Docker build script

# Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t msp-ec2-monitor:latest \
  --push \
  .

# For local build without push (single platform)
# docker buildx build --platform linux/$(uname -m) -t msp-ec2-monitor:latest --load .