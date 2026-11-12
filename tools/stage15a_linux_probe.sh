#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "HOST_UNSUPPORTED_FOR_NATIVE_CHECKPOINT"
  exit 2
fi
echo "kernel=$(uname -r) architecture=$(uname -m)"
command -v criu >/dev/null && criu --version || echo "CRIU_UNAVAILABLE"
command -v criu >/dev/null && criu check || true
command -v dmtcp_launch >/dev/null && dmtcp_launch --version || echo "DMTCP_UNAVAILABLE"
PYTHONPATH=src python3 -c 'from transactional_inference_state.stage15a import environment_probe,backend_probes; print(environment_probe()); print(backend_probes())'
