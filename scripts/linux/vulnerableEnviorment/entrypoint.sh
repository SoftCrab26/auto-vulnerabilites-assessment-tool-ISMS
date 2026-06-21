#!/usr/bin/env bash
set -euo pipefail

start_listener() {
	local name="$1"
	local port="$2"

	if ss -lntup 2>/dev/null | grep -q ":${port}"; then
		return 0
	fi

	bash -c "exec -a '${name}' ncat -lk 0.0.0.0 '${port}' >/dev/null 2>&1" &
}

start_listener sshd 22
start_listener named 53
start_listener snmpd 161
start_listener vsftpd 21
start_listener httpd 80
start_listener mysqld 3306
start_listener postgres 5432
start_listener telnet 23
start_listener finger 79
start_listener nfsd 2049
start_listener automount 20048
start_listener rpcbind 111
start_listener ypserv 834
start_listener tftp 69
start_listener talk 517
start_listener ntalk 518
start_listener sendmail 25
start_listener rshd 514
start_listener echo 7
start_listener discard 9
start_listener daytime 13
start_listener chargen 19

sleep 1

if [[ ! -x "$1" ]]; then
	echo "linux-check executable is missing or not executable: $1" >&2
	echo "Build it on the host: cd scripts/linux && GOOS=linux GOARCH=\$(go env GOARCH) go build -o bin/linux-check ." >&2
	exit 127
fi

exec "$@"
