#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_setpassword.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

. `dirname $0`/../../../testprogs/blackbox/subunit.sh

samba_tool="./bin/samba-tool"

rm -rf $PREFIX/simple-dc
mkdir -p $PREFIX/simple-dc

testit "simple-dc" $PYTHON $BINDIR/samba-tool domain provision --server-role="dc" --domain=FOO --realm=foo.example.com --domain-sid=S-1-5-21-4177067393-1453636373-93818738 --targetdir=$PREFIX/simple-dc --use-ntvfs

testit "user add" $PYTHON $samba_tool user create --configfile=$PREFIX/simple-dc/etc/smb.conf testuser testp@ssw0Rd

testit "setpassword" $PYTHON $samba_tool user setpassword --configfile=$PREFIX/simple-dc/etc/smb.conf testuser --newpassword=testp@ssw0Rd

testit "setpassword" $PYTHON $samba_tool user setpassword --configfile=$PREFIX/simple-dc/etc/smb.conf testuser --newpassword=testp@ssw0Rd --must-change-at-next-login

testit "setpassword" $PYTHON $samba_tool user setpassword --configfile=$PREFIX/simple-dc/etc/smb.conf testuser --newpassword=Täst123 --must-change-at-next-login

testit "passwordsettings" $PYTHON $samba_tool domain passwordsettings set --quiet --configfile=$PREFIX/simple-dc/etc/smb.conf --complexity=default --history-length=default --min-pwd-length=default --min-pwd-age=default --max-pwd-age=default --store-plaintext=on

exit $failed
