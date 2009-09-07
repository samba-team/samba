#!/bin/bash
# example script to setup DNS for a vampired domain

[ $# = 3 ] || {
    echo "Usage: setup_dns.sh HOSTNAME DOMAIN IP"
    exit 1
}

HOSTNAME="$1"
DOMAIN="$2"
IP="$3"

RSUFFIX=$(echo $DOMAIN | sed s/[\.]/,DC=/g)

PRIVATEDIR=$(bin/testparm --section-name=global --parameter-name='private dir' --suppress-prompt 2> /dev/null)

OBJECTGUID=$(bin/ldbsearch -H "$PRIVATEDIR/sam.ldb" -b "CN=NTDS Settings,CN=$HOSTNAME,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=$RSUFFIX" objectguid|grep ^objectGUID| cut -d: -f2)

echo "Found objectGUID $OBJECTGUID"

echo "Running kinit for BLU\$@VSOFS8.COM"
bin/samba4kinit -e arcfour-hmac-md5 -k -t "$PRIVATEDIR/secrets.keytab" BLU\$@VSOFS8.COM || exit 1
echo "Adding $HOSTNAME.$DOMAIN"
scripting/bin/nsupdate-gss --noverify $HOSTNAME $DOMAIN $IP 300 || exit 1
echo "Adding $OBJECTGUID.$DOMAIN => $HOSTNAME.$DOMAIN"
scripting/bin/nsupdate-gss --noverify --ntype="CNAME" $OBJECTGUID $DOMAIN $HOSTNAME.$DOMAIN 300 || exit 1
echo "Checking"
host $HOSTNAME.$DOMAIN
host $OBJECTGUID.$DOMAIN
