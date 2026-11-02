#!/usr/bin/env bash
set -euo pipefail
if [[ $(id -u) != 0 ]]; then
  echo 'Run as root inside a dedicated Ubuntu/Debian Linux lab.' >&2
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3 iproute2 nftables frr tcpdump golang-go gcc libc6-dev make ca-certificates iputils-ping procps git
go version
python3 --version
echo 'Dependencies installed. Build with make build, then run python3 -m netlab doctor.'
