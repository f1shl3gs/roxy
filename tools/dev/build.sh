#!/usr/bin/env bash

docker buildx build -t dev:latest --build-arg SSH_PUB_KEY="$(cat ~/.ssh/id_rsa.pub)" --platform linux/arm64 .