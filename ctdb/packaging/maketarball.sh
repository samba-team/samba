#!/bin/sh
#
# Copyright (C) Michael Adam 2009
#
# Create CTDB source tarball of the current git branch HEAD.
# The version is extracted from the spec file...
# The first extra argument will be added as an additional version.

DIRNAME=$(dirname $0)
TOPDIR=${DIRNAME}/..
RPMDIR=${DIRNAME}/RPM
SPECFILE=${RPMDIR}/ctdb.spec

EXTRA_SUFFIX="$1"

VERSION=$(grep ^Version ${SPECFILE} | sed -e 's/^Version:\ \+//')

if [ "x${EXTRA_SUFFIX}" != "x" ]; then
	VERSION="${VERSION}-${EXTRA_SUFFIX}"
fi

if echo | gzip -c --rsyncable - > /dev/null 2>&1 ; then
	GZIP="gzip -9 --rsyncable"
else
	GZIP="gzip -9"
fi

pushd ${TOPDIR}
echo -n "Creating ctdb-${VERSION}.tar.gz ... "
git archive --prefix=ctdb-${VERSION}/ HEAD | ${GZIP} \
	> ${TOPDIR}/ctdb-${VERSION}.tar.gz
RC=$?
popd

echo "Done."

if [ $RC -ne 0 ]; then
        echo "Creation of tarball failed."
        exit 1
fi

exit 0
