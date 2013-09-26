#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_provision.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
export TEST_LDAP="yes"
shift 1
. `dirname $0`/../../../testprogs/blackbox/subunit.sh

testit "openldap-backend" $PYTHON $BINDIR/samba-tool domain provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend --slapd-path=/dev/null --use-ntvfs --ldap-dryrun-mode
testit "openldap-mmr-backend" $PYTHON $BINDIR/samba-tool domain provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-mmr-backend --ol-mmr-urls="ldap://s4dc1.test:9000,ldap://s4dc2.test:9000" --adminpass=linux --ldapadminpass=linux --slapd-path=/dev/null --use-ntvfs --ldap-dryrun-mode
testit "fedora-ds-backend" $PYTHON $BINDIR/samba-tool domain provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend --slapd-path=/dev/null --use-ntvfs --ldap-dryrun-mode

reprovision() {
        $PYTHON $BINDIR/samba-tool domain provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend-reprovision --use-ntvfs --ldap-dryrun-mode --slapd-path=/dev/null
       $PYTHON $BINDIR/samba-tool domain provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend-reprovision --use-ntvfs --ldap-dryrun-mode --slapd-path=/dev/null
}

testit "reprovision-backend" reprovision

exit $failed
