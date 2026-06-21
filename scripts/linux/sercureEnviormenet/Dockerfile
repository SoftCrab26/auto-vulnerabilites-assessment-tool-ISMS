FROM rockylinux:9

RUN dnf -y install \
		coreutils \
		findutils \
		iproute \
		nmap-ncat \
		passwd \
		procps-ng \
		shadow-utils \
		sudo \
		which \
	&& dnf clean all

COPY entrypoint.sh /usr/local/bin/linux-secure-entrypoint.sh

RUN mkdir -p /etc/ssh /etc/pam.d /etc/security /etc/samba /etc/vsftpd /out \
	&& printf '%s\n' \
		'PermitRootLogin no' \
		'PasswordAuthentication yes' \
		> /etc/ssh/sshd_config \
	&& printf '%s\n' \
		'password requisite pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=' \
		'auth required pam_faillock.so preauth silent deny=5 unlock_time=900' \
		'auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900' \
		> /etc/pam.d/system-auth \
	&& printf '%s\n' \
		'minlen = 8' \
		'ucredit = -1' \
		'lcredit = -1' \
		'dcredit = -1' \
		'ocredit = -1' \
		> /etc/security/pwquality.conf \
	&& printf '%s\n' \
		'PASS_MIN_LEN 8' \
		'PASS_MAX_DAYS 90' \
		'PASS_MIN_DAYS 1' \
		'UMASK 022' \
		'ENCRYPT_METHOD SHA512' \
		>> /etc/login.defs \
	&& printf '%s\n' \
		'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' \
		'TMOUT=600' \
		'export TMOUT' \
		'readonly TMOUT' \
		'umask 022' \
		> /etc/profile \
	&& printf '%s\n' \
		'set autologout=10' \
		> /etc/csh.cshrc \
	&& printf '%s\n' \
		'anonymous_enable=NO' \
		> /etc/vsftpd/vsftpd.conf \
	&& printf '%s\n' \
		'[public]' \
		'guest ok = no' \
		'map to guest = never' \
		> /etc/samba/smb.conf \
	&& useradd -m -u 2000 auditor \
	&& usermod -p '$6$secure$wS3z2W6L6D3HY4.3lxKqF1LkEf4bWpR7Qd43u1s2kPS6qgSKoT4GXfRrQqNlh9Mz.JqKxkHXKSR8cFdfLl7PR0' auditor \
	&& chmod 644 /etc/passwd \
	&& chmod 400 /etc/shadow \
	&& chmod 644 /etc/hosts \
	&& chmod +x /usr/local/bin/linux-secure-entrypoint.sh

WORKDIR /out

ENTRYPOINT ["/usr/local/bin/linux-secure-entrypoint.sh"]
CMD ["/usr/local/bin/linux-check"]
