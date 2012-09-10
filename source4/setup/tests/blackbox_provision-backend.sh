#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_provision.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

. `dirname $0`/../../../testprogs/blackbox/subunit.sh

testit "openldap-backend" $PYTHON $BINDIR/samba-tool domain provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend --use-ntvfs
testit "openldap-mmr-backend" $PYTHON $BINDIR/samba-tool domain provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-mmr-backend --ol-mmr-urls="ldap://s4dc1.test:9000,ldap://s4dc2.test:9000" --username=samba-admin --password=linux --adminpass=linux --ldapadminpass=linux --use-ntvfs
testit "fedora-ds-backend" $PYTHON $BINDIR/samba-tool domain provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend --use-ntvfs

reprovision() {
        $PYTHON $BINDIR/samba-tool domain provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend-reprovision --use-ntvfs
        $PYTHON $BINDIR/samba-tool domain provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend-reprovision --use-ntvfs
}

testit "reprovision-backend" reprovision

exit $failed
