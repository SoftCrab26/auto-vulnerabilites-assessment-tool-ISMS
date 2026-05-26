############################
# U-01 root 원격접속 제한
############################
cat /etc/ssh/sshd_config
cat /etc/pam.d/login
cat /etc/securetty

rm -rf
############################
# U-02 패스워드 복잡성
############################
cat /etc/pam.d/system-auth
cat /etc/security/pwquality.conf
cat /etc/login.defs

############################
# U-03 계정 잠금 임계값
############################
cat /etc/pam.d/system-auth
faillog
pam_tally2 -u root

############################
# U-04 패스워드 파일 보호
############################
cat /etc/passwd
cat /etc/shadow
ls -l /etc/passwd
ls -l /etc/shadow

############################
# U-05 PATH 환경변수 점검
############################
echo $PATH
cat /etc/profile
cat ~/.bash_profile
cat ~/.profile

############################
# U-06 소유자 없는 파일
############################
find / -nouser -o -nogroup 2>/dev/null

############################
# U-07 passwd 권한
############################
ls -l /etc/passwd

############################
# U-08 shadow 권한
############################
ls -l /etc/shadow

############################
# U-09 hosts 권한
############################
ls -l /etc/hosts

############################
# U-10 inetd/xinetd 권한
############################
ls -l /etc/inetd.conf
ls -l /etc/xinetd.conf
ls -ld /etc/xinetd.d

############################
# U-11 syslog 권한
############################
ls -l /etc/syslog.conf
ls -l /etc/rsyslog.conf

############################
# U-12 services 권한
############################
ls -l /etc/services

############################
# U-13 SUID/SGID 파일
############################
find / -perm -4000 2>/dev/null
find / -perm -2000 2>/dev/null

############################
# U-14 시작파일 권한
############################
ls -al /etc/profile
ls -al ~/.profile
ls -al ~/.bash_profile
ls -al ~/.bashrc

############################
# U-15 world writable 파일
############################
find / -type f -perm -2 2>/dev/null

############################
# U-16 device 파일 점검
############################
find /dev -type f

############################
# U-17 rhosts 사용금지
############################
find / -name .rhosts 2>/dev/null
find / -name hosts.equiv 2>/dev/null
cat /etc/hosts.equiv

############################
# U-18 접속 IP 제한
############################
cat /etc/hosts.allow
cat /etc/hosts.deny
iptables -L
firewall-cmd --list-all

############################
# U-19 finger 서비스
############################
ps -ef | grep finger
systemctl status finger
netstat -antp | grep 79

############################
# U-20 anonymous ftp
############################
cat /etc/vsftpd/vsftpd.conf
ps -ef | grep ftp

############################
# U-21 r 계열 서비스
############################
ps -ef | egrep "rsh|rlogin|rexec"
netstat -antp | egrep "513|514"

############################
# U-22 cron 권한
############################
ls -l /etc/crontab
ls -ld /etc/cron.*

############################
# U-23 DoS 취약 서비스
############################
ps -ef | egrep "echo|discard|daytime|chargen"
netstat -antp

############################
# U-24 NFS 비활성화
############################
ps -ef | grep nfs
systemctl status nfs-server

############################
# U-25 NFS 접근통제
############################
cat /etc/exports

############################
# U-26 automountd 제거
############################
ps -ef | grep automount
systemctl status autofs

############################
# U-27 RPC 서비스
############################
rpcinfo -p
ps -ef | grep rpc

############################
# U-28 NIS/NIS+
############################
ps -ef | egrep "yp|nis"
domainname

############################
# U-29 tftp/talk
############################
ps -ef | egrep "tftp|talk"
netstat -antp | egrep "69|517|518"

############################
# U-30 sendmail 버전
############################
sendmail -d0.1 -bv root

############################
# U-31 스팸 릴레이
############################
cat /etc/mail/sendmail.cf

############################
# U-32 일반사용자 sendmail 실행
############################
ls -l /usr/sbin/sendmail

############################
# U-33 DNS 패치
############################
named -v
rpm -qa | grep bind

############################
# U-34 DNS zone transfer
############################
cat /etc/named.conf

############################
# U-35 디렉터리 리스팅
############################
cat /etc/httpd/conf/httpd.conf
grep -i indexes /etc/httpd/conf/httpd.conf

############################
# U-36 웹 프로세스 권한
############################
ps -ef | egrep "httpd|apache|nginx"

############################
# U-37 상위 디렉터리 접근
############################
grep -i "AllowOverride" /etc/httpd/conf/httpd.conf
grep -i "Options" /etc/httpd/conf/httpd.conf

############################
# U-38 불필요 파일 제거
############################
find /var/www -name "*.bak"
find /var/www -name "*.old"

############################
# U-39 심볼릭 링크 사용
############################
find /var/www -type l -ls

############################
# U-40 파일 업로드/다운로드 제한
############################
cat /etc/httpd/conf/httpd.conf
grep -Ri upload /var/www

############################
# U-41 웹서비스 영역 분리
############################
df -h
mount

############################
# U-42 최신 패치
############################
uname -a
cat /etc/os-release
rpm -qa
yum check-update
dnf check-update

############################
# U-43 로그 검토
############################
last
lastlog
cat /var/log/secure
cat /var/log/messages

############################
# U-44 UID 0 계정
############################
awk -F: '$3==0 {print $1}' /etc/passwd

############################
# U-45 su 제한
############################
cat /etc/pam.d/su
grep wheel /etc/group

############################
# U-46 패스워드 최소길이
############################
grep PASS_MIN_LEN /etc/login.defs
cat /etc/security/pwquality.conf

############################
# U-47 패스워드 최대 사용기간
############################
grep PASS_MAX_DAYS /etc/login.defs
chage -l root

############################
# U-48 패스워드 최소 사용기간
############################
grep PASS_MIN_DAYS /etc/login.defs
chage -l root

############################
# U-49 불필요 계정
############################
cat /etc/passwd

############################
# U-50 관리자 그룹 최소화
############################
grep wheel /etc/group
grep sudo /etc/group

############################
# U-51 존재하지 않는 GID
############################
cat /etc/passwd
cat /etc/group

############################
# U-52 동일 UID
############################
cut -d: -f3 /etc/passwd | sort | uniq -d

############################
# U-53 shell 점검
############################
cat /etc/passwd
cat /etc/shells

############################
# U-54 session timeout
############################
cat /etc/profile
grep TMOUT /etc/profile

############################
# U-55 hosts.lpd
############################
ls -l /etc/hosts.lpd

############################
# U-56 umask
############################
umask
grep -i umask /etc/profile
grep -Ri umask /etc

############################
# U-57 홈디렉토리 권한
############################
ls -ld /home/*
ls -ld /root

############################
# U-58 홈디렉토리 존재
############################
cat /etc/passwd

############################
# U-59 숨김파일
############################
find / -name ".*" 2>/dev/null

############################
# U-60 ssh 사용
############################
systemctl status sshd
ps -ef | grep sshd
netstat -antp | grep 22

############################
# U-61 ftp 서비스
############################
systemctl status vsftpd
ps -ef | grep ftp

############################
# U-62 ftp shell 제한
############################
cat /etc/passwd
cat /etc/shells

############################
# U-63 ftpusers 권한
############################
ls -l /etc/ftpusers

############################
# U-64 ftpusers 설정
############################
cat /etc/ftpusers

############################
# U-65 at 파일 권한
############################
ls -l /etc/at.allow
ls -l /etc/at.deny

############################
# U-66 snmp 서비스
############################
ps -ef | grep snmp
systemctl status snmpd
netstat -antp | grep 161

############################
# U-67 snmp community
############################
cat /etc/snmp/snmpd.conf

############################
# U-68 로그인 경고문
############################
cat /etc/motd
cat /etc/issue
cat /etc/issue.net

############################
# U-69 NFS 설정 접근제한
############################
ls -l /etc/exports

############################
# U-70 expn vrfy 제한
############################
grep -i "noexpn" /etc/mail/sendmail.cf
grep -i "novrfy" /etc/mail/sendmail.cf

############################
# U-71 apache 정보숨김
############################
grep -i "ServerTokens" /etc/httpd/conf/httpd.conf
grep -i "ServerSignature" /etc/httpd/conf/httpd.conf

############################
# U-72 로깅 설정
############################
cat /etc/rsyslog.conf
cat /etc/syslog.conf
systemctl status rsyslog
