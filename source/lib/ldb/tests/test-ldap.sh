#!/bin/sh

export PATH=/usr/local/sbin:/usr/sbin:/sbin:$PATH
SCHEMA_NEEDED="core nis cosine inetorgperson openldap"

# setup needed schema files
for f in $SCHEMA_NEEDED; do
    if [ ! -r tests/schema/$f.schema ]; then
	mkdir -p tests/schema
	if [ -r /etc/ldap/schema/$f.schema ]; then
	    ln -s /etc/ldap/schema/$f.schema tests/schema/$f.schema
	    continue;
	fi
	if [ -r /etc/openldap/schema/$f.schema ]; then
	    ln -s /etc/openldap/schema/$f.schema tests/schema/$f.schema
	    continue;
	fi

	echo "ERROR: you need the following OpenLDAP schema files in tests/schema/"
	for f in $SCHEMA_NEEDED; do
	    echo "  $f.schema"
	done
	exit 1
    fi
done

export LDB_URL=`tests/ldapi_url.sh`

PATH=bin:$PATH
export PATH

if [ -z "$LDBDIR" ]; then
    LDBDIR="."
    export LDBDIR
fi

. $LDBDIR/tests/init_slapd.sh
. $LDBDIR/tests/start_slapd.sh

. $LDBDIR/tests/test-generic.sh
