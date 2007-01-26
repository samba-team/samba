#!/bin/sh

FROM=$1
VERSION=$2

svn export $FROM samba-$VERSION

( cd samba-$VERSION || exit 1
  (cd source && ./autogen.sh ) || exit 1
  rm -rf webapps/qooxdoo-*-sdk/frontend/framework/.cache || exit 1
) || exit 1

tar -zcf samba-$VERSION.tar.gz samba-$VERSION
