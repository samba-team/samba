#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_s3upgrade.sh PREFIX
EOF
exit 1;
fi

PREFIX=`pwd`"/$1"
shift 1

samba4bindir="$BINDIR"
samba_tool="$samba4bindir/samba-tool"
samba_net="$samba4bindir/net"
testparm="$samba4bindir/testparm"

. `dirname $0`/../../../testprogs/blackbox/subunit.sh

rm -rf $PREFIX/samba3-upgrade
mkdir -p $PREFIX/samba3-upgrade
cp -a $SRCDIR/testdata/samba3 $PREFIX/samba3-upgrade

# Test 1 (s3 member)
cat - > $PREFIX/samba3-upgrade/samba3/smb1.conf <<EOF
[global]
   workgroup = SAMBA
   security = user
   netbiosname = S3UPGRADE
   passdb backend = tdbsam:$PREFIX/samba3-upgrade/samba3/passdb.tdb
   private dir = $PREFIX/samba3-upgrade/samba3
   lock directory = $PREFIX/samba3-upgrade/samba3
   state directory = $PREFIX/samba3-upgrade/samba3
   cache directory = $PREFIX/samba3-upgrade/samba3
   pid directory = $PREFIX/samba3-upgrade/samba3
   usershare path = $PREFIX/samba3-upgrade/samba3
   ncalrpc dir = $PREFIX/samba3-upgrade/samba3

   debug level = 0
EOF

testit "samba3-upgrade-member" $samba_tool domain classicupgrade $PREFIX/samba3-upgrade/samba3/smb1.conf --targetdir=$PREFIX/samba3-upgrade/s4_1 --dbdir=$PREFIX/samba3-upgrade/samba3 --use-ntvfs
testit "samba3-upgrade-member-getlocalsid" $samba_net getlocalsid s3upgrade -s $PREFIX/samba3-upgrade/s4_1/etc/smb.conf

# Test 2 (s3 dc)
cat - > $PREFIX/samba3-upgrade/samba3/smb2.conf <<EOF
[global]
   workgroup = SAMBA
   netbiosname = S3UPGRADE
   security = user
   realm = s3.samba.example.com
   passdb backend = tdbsam:$PREFIX/samba3-upgrade/samba3/passdb.tdb
   private dir = $PREFIX/samba3-upgrade/samba3
   lock directory = $PREFIX/samba3-upgrade/samba3
   state directory = $PREFIX/samba3-upgrade/samba3
   cache directory = $PREFIX/samba3-upgrade/samba3
   pid directory = $PREFIX/samba3-upgrade/samba3
   usershare path = $PREFIX/samba3-upgrade/samba3
   ncalrpc dir = $PREFIX/samba3-upgrade/samba3
   debug level = 0
   domain logons = yes
EOF

mv $PREFIX/samba3-upgrade/samba3/wins.dat2 $PREFIX/samba3-upgrade/samba3/wins.dat

# Upgrade NT4-like domains in samba3upgrade
testit "samba3-upgrade-dc" $samba_tool domain classicupgrade $PREFIX/samba3-upgrade/samba3/smb2.conf --targetdir=$PREFIX/samba3-upgrade/s4_2 --dbdir=$PREFIX/samba3-upgrade/samba3 --use-ntvfs
testit "samba3-upgrade-dc-getlocalsid" $samba_net getlocalsid samba -s $PREFIX/samba3-upgrade/s4_2/etc/smb.conf
testit "samba3-upgrade-dc-getdomainsid" $samba_net getdomainsid -s $PREFIX/samba3-upgrade/s4_2/etc/smb.conf

#Run final test without a wins.dat
rm -f $PREFIX/samba3-upgrade/samba3/wins.dat

# Test 3 (s3 dc using testparm hook)
cat - > $PREFIX/samba3-upgrade/samba3/smb3.conf <<EOF
[global]
   workgroup = SAMBA
   netbiosname = S3UPGRADE
   security = user
   realm = s3.samba.example.com
   passdb backend = tdbsam:$PREFIX/samba3-upgrade/samba3/passdb.tdb
   private dir = $PREFIX/samba3-upgrade/samba3
   lock directory = $PREFIX/samba3-upgrade/samba3
   state directory = $PREFIX/samba3-upgrade/samba3
   cache directory = $PREFIX/samba3-upgrade/samba3
   pid directory = $PREFIX/samba3-upgrade/samba3
   usershare path = $PREFIX/samba3-upgrade/samba3
   ncalrpc dir = $PREFIX/samba3-upgrade/samba3
   debug level = 0
   domain logons = yes
EOF

testit "samba3-upgrade-testparm" $samba_tool domain classicupgrade $PREFIX/samba3-upgrade/samba3/smb2.conf --targetdir=$PREFIX/samba3-upgrade/s4_3 --testparm=$testparm --use-ntvfs
testit "samba3-upgrade-testparm-getlocalsid" $samba_net getlocalsid samba -s $PREFIX/samba3-upgrade/s4_3/etc/smb.conf
testit "samba3-upgrade-testparm-getdomainsid" $samba_net getdomainsid -s $PREFIX/samba3-upgrade/s4_3/etc/smb.conf

rm -rf $PREFIX/samba3-upgrade

exit $failed
