#!/usr/bin/env bash

docker buildx build -t dev:latest --platform linux/arm64 .