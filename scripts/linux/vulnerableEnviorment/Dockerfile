FROM rockylinux:9

RUN dnf -y install \
		iproute \
		nmap-ncat \
		procps-ng \
		sudo \
		which \
	&& dnf clean all

COPY entrypoint.sh /usr/local/bin/linux-vulnerable-entrypoint.sh

RUN mkdir -p /etc/ssh /etc/pam.d /etc/security /etc/samba /etc/vsftpd /out \
	&& printf '%s\n' \
		'PermitRootLogin yes' \
		'PasswordAuthentication yes' \
		> /etc/ssh/sshd_config \
	&& printf '%s\n' \
		'password sufficient pam_unix.so' \
		> /etc/pam.d/system-auth \
	&& printf '%s\n' \
		'minlen = 6' \
		'ucredit = 0' \
		'lcredit = 0' \
		'dcredit = 0' \
		'ocredit = 0' \
		> /etc/security/pwquality.conf \
	&& printf '%s\n' \
		'PASS_MIN_LEN 6' \
		'PASS_MAX_DAYS 99999' \
		'PASS_MIN_DAYS 0' \
		'UMASK 002' \
		'ENCRYPT_METHOD MD5' \
		>> /etc/login.defs \
	&& printf '%s\n' \
		'PATH=.:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' \
		'TMOUT=900' \
		'export TMOUT' \
		'umask 002' \
		> /etc/profile \
	&& printf '%s\n' \
		'set autologout=30' \
		> /etc/csh.cshrc \
	&& printf '%s\n' \
		'anonymous_enable=YES' \
		> /etc/vsftpd/vsftpd.conf \
	&& printf '%s\n' \
		'[public]' \
		'guest ok = yes' \
		'map to guest = bad user' \
		> /etc/samba/smb.conf \
	&& useradd -m -u 2000 legacyadmin \
	&& useradd -m -u 0 -o uidzero \
	&& usermod -p '$1$legacy$Hq8zyu49Zpxb5p2WbBHMn0' root \
	&& usermod -p '$1$legacy$Hq8zyu49Zpxb5p2WbBHMn0' legacyadmin \
	&& chmod 644 /etc/shadow \
	&& chmod 777 /tmp \
	&& chmod +x /usr/local/bin/linux-vulnerable-entrypoint.sh

WORKDIR /out

ENTRYPOINT ["/usr/local/bin/linux-vulnerable-entrypoint.sh"]
CMD ["/usr/local/bin/linux-check"]
