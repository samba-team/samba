#!/bin/sh
#
# Copyright (C) Michael Adam 2008
#
# Script to determine the samba version and create the SPEC file from template

DIRNAME=$(dirname $0)
TOPDIR=${DIRNAME}/../..
SRCDIR=${TOPDIR}/source3
VERSION_H=${SRCDIR}/include/autoconf/version.h
SPECFILE=${DIRNAME}/samba.spec

##
## determine the samba version and create the SPEC file
##
pushd ${SRCDIR}
./script/mkversion.sh
popd
if [ ! -f ${VERSION_H} ] ; then
	echo "Error creating version.h"
	exit 1
fi

VERSION=`grep "^#define SAMBA_VERSION_OFFICIAL_STRING " ${VERSION_H} | awk '{print $3}'`
vendor_version=`grep "^#define SAMBA_VERSION_VENDOR_SUFFIX " ${VERSION_H} | awk '{print $3}'`
if test "x${vendor_version}"  != "x" ; then
	VERSION="${VERSION}-${vendor_version}"
fi
vendor_patch=`grep "^#define SAMBA_VERSION_VENDOR_PATCH " ${VERSION_H} | awk '{print $3}'`
if test "x${vendor_patch}" != "x" ; then
	VERSION="${VERSION}-${vendor_patch}"
fi
VERSION=`echo ${VERSION} | sed 's/-/_/g'`
VERSION=`echo ${VERSION} | sed 's/\"//g'`
echo "VERSION: ${VERSION}"

# to build a release-rpm, set USE_GITHASH="no"
# in the environmet
#
if test "x$USE_GITHASH" = "xno" ; then
	GITHASH=""
	echo "GITHASH: not used"
else
	GITHASH=".$(git log --pretty=format:%h -1)"
	echo "GITHASH: ${GITHASH}"
fi

if test "x$BUILD_GPFS" = "xno"; then
	echo "GPFS: not build by default"
	PGPFS_DEFAULT="%{?_with_gpfs: 1} %{?!_with_gpfs: 0}"
else
	echo "GPFS: build by default"
	PGPFS_DEFAULT="%{?_with_no_gpfs: 0} %{?!_with_no_gpfs: 1}"
fi

sed \
	-e "s/PVERSION/${VERSION}/g" \
	-e "s/GITHASH/${GITHASH}/g" \
	-e "s/PGPFS_NO_DEFAULT/${PGPFS_NO_DEFAULT}/g" \
	-e "s/PGPFS_DEFAULT/${PGPFS_DEFAULT}/g" \
	< ${SPECFILE}.tmpl \
	> ${SPECFILE}

