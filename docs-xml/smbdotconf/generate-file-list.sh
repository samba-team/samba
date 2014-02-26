#!/bin/sh
#
# This is the fallback table for when we use the docs-xml build
# system.  When build as part of the main waf build, these are set to
# the full correct path for the system.
#
echo "<!DOCTYPE section [
<!ENTITY pathconfig.SCRIPTSBINDIR        '\${prefix}/sbin'>
<!ENTITY pathconfig.LOCKDIR              '\${prefix}/var/lock'>
<!ENTITY pathconfig.NCALRPCDIR           '\${prefix}/var/run/ncalrpc'>
<!ENTITY pathconfig.PIDDIR               '\${prefix}/var/run'>
<!ENTITY pathconfig.STATEDIR             '\${prefix}/var/locks'>
<!ENTITY pathconfig.PRIVATE_DIR          '\${prefix}/private'>
<!ENTITY pathconfig.SMB_PASSWD_FILE      '\${prefix}/private/smbpasswd'>
<!ENTITY pathconfig.WINBINDD_SOCKET_DIR  '\${prefix}/var/run/winbindd'>
<!ENTITY pathconfig.WINBINDD_PRIVILEGED_SOCKET_DIR '\${prefix}/var/lib/winbindd_privileged'>
<!ENTITY pathconfig.CACHEDIR             '\${prefix}/var/cache'>
<!ENTITY pathconfig.NTP_SIGND_SOCKET_DIR '\${prefix}/var/lib/ntp_signd'>
]>"

DIR=.
if [ "x$1" != "x" ]
then
	DIR="$1"
fi

OLD=`pwd`
cd $DIR

echo "<section>"
for I in `find . -mindepth 2 -type f -name '*.xml' | sort -t/ -k3 | xargs`
do 
	cat $I
done
echo "</section>"


cd $OLD
