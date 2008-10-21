#!/bin/sh
# install miscellaneous files

SRCDIR="$1"
SETUPDIR="$2"

cd $SRCDIR || exit 1

echo "Installing setup templates"
mkdir -p $SETUPDIR || exit 1
cp setup/schema-map-* $SETUPDIR || exit 1
cp setup/DB_CONFIG $SETUPDIR || exit 1
cp setup/provision-backend $SETUPDIR || exit 1
cp setup/provision $SETUPDIR || exit 1
cp setup/newuser $SETUPDIR || exit 1
cp setup/*.inf $SETUPDIR || exit 1
cp setup/*.ldif $SETUPDIR || exit 1
cp setup/*.reg $SETUPDIR || exit 1
cp setup/*.zone $SETUPDIR || exit 1
cp setup/*.conf $SETUPDIR || exit 1
cp setup/*.php $SETUPDIR || exit 1
cp setup/*.txt $SETUPDIR || exit 1
cp setup/provision.smb.conf.dc $SETUPDIR || exit 1
cp setup/provision.smb.conf.member $SETUPDIR || exit 1
cp setup/provision.smb.conf.standalone $SETUPDIR || exit 1

exit 0
