#!/bin/sh
#
# Copyright (C) Michael Adam 2008
#
# Script to determine the samba version and create the SPEC file from template

DIRNAME=$(dirname $0)
TOPDIR=${DIRNAME}/../..
SRCDIR=${TOPDIR}/source
VERSION_H=${SRCDIR}/include/version.h
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

VERSION=`grep SAMBA_VERSION_OFFICIAL_STRING ${VERSION_H} | awk '{print $3}'`
vendor_version=`grep SAMBA_VERSION_VENDOR_SUFFIX ${VERSION_H} | awk '{print $3}'`
if test "x${vendor_version}"  != "x" ; then
	VERSION="${VERSION}-${vendor_version}"
fi
VERSION=`echo ${VERSION} | sed 's/-/_/g'`
VERSION=`echo ${VERSION} | sed 's/\"//g'`
echo "VERSION: ${VERSION}"
sed -e s/PVERSION/${VERSION}/g \
	< ${SPECFILE}.tmpl \
	> ${SPECFILE}

