#!/usr/bin/env bash
# Install apt packages on a CI runner, surviving a stalled package mirror.
#
# The runner's mirror sometimes serves a download at a few kB/s, and a job then reaches its time
# limit inside the install step without having run anything. Each attempt here is cut off after
# five minutes and retried. apt keeps the packages it already fetched, so a retry resumes on a new
# connection instead of starting over.
#
# Usage: apt-install.sh [apt-get install options] package...
set -euo pipefail

for attempt in 1 2 3; do
  if sudo timeout 300 apt-get update &&
     sudo timeout 300 apt-get install -y "$@"; then
    exit 0
  fi
  echo "::warning::package install attempt ${attempt} failed or stalled"
  # A cut-off attempt can leave a package half configured; finish that before trying again.
  sudo dpkg --configure -a || true
done
echo "::error::package install failed after 3 attempts"
exit 1
