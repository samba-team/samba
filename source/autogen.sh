#! /bin/sh

# Run this script to build samba from CVS.

## first try the default names
AUTOHEADER="autoheader"
AUTOCONF="autoconf"

if which $AUTOCONF > /dev/null
then
    :
else
    echo "$0: need autoconf 2.53 or later to build samba from CVS" >&2
    exit 1
fi

##
## what version do we need?
##
if [ `$AUTOCONF --version | head -1 | cut -d.  -f 2` -lt 53 ]; then

	## maybe it's installed under a different name (e.g. RedHat 7.3)

	AUTOCONF="autoconf-2.53"
	AUTOHEADER="autoheader-2.53"

fi

echo "$0: running $AUTOHEADER"
$AUTOHEADER || exit 1

echo "$0: running $AUTOCONF"
$AUTOCONF || exit 1

echo "Now run ./configure and then make."
exit 0
