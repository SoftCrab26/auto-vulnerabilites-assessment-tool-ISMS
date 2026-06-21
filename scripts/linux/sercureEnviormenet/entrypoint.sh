#!/usr/bin/env bash
set -euo pipefail

if [[ ! -x "$1" ]]; then
	echo "linux-check executable is missing or not executable: $1" >&2
	echo "Build it on the host: cd scripts/linux && GOOS=linux GOARCH=\$(go env GOARCH) go build -o bin/linux-check ." >&2
	exit 127
fi

exec "$@"
