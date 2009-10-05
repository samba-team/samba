#!/bin/bash

set -x

. `dirname $0`/vars

namedtmp=`mktemp named.conf.ad.XXXXXXXXX`
cp `dirname $0`/named.conf.ad.template $namedtmp
sed -i "s/DNSDOMAIN/$DNSDOMAIN/g" $namedtmp
sed -i "s/SERVERIP/$server_ip/g" $namedtmp
chmod a+r $namedtmp
mv $namedtmp $PREFIX/private/named.conf
sudo rndc reconfig
`dirname $0`/unvampire_ad.sh
sudo $PREFIX/bin/net vampire $DNSDOMAIN -Uadministrator%$pass -s $PREFIX/etc/smb.conf -d2 || exit 1
PRIVATEDIR=$PREFIX/private sudo -E scripting/bin/setup_dns.sh $machine $DNSDOMAIN $machine_ip || exit 1
