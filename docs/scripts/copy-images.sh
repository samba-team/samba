#!/bin/sh
ROLE="$1"
XMLFILE="$2"
FROM="$3"
TO="$4"

for x in `xsltproc --stringparam prepend "" --stringparam append "" --stringparam role "$ROLE" xslt/find-image-dependencies.xsl "$XMLFILE"`
do
	test -f $FROM/$x || make $FROM/$x || exit 1
	cp -u $FROM/$x $TO/$x || exit 1
done
exit
