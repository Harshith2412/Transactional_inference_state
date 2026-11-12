#!/usr/bin/env bash
set -euo pipefail

image="tis-stage15a-linux:local"
docker build -f tools/stage15a-linux.Dockerfile -t "$image" .
docker run --rm --privileged \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  --cap-add ALL \
  -v "$PWD:/workspace" \
  "$image" bash tools/stage15a_linux_probe.sh
