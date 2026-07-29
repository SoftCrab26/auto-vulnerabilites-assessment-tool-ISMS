#!/usr/bin/env bash
set -euo pipefail

target="${1:-/usr/local/bin/linux-check}"
if [[ $# -eq 0 ]]; then
	set -- "$target"
fi

if [[ ! -x "$target" ]]; then
	echo "linux-check executable is missing or not executable: $target" >&2
	echo "Build it on the host: cd scripts/linux && GOOS=linux GOARCH=\$(go env GOARCH) go build -o bin/linux-check ." >&2
	exit 127
fi

exec "$@"
