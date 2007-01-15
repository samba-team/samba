#!/bin/sh
#

SELF=$0
SELFDIR=`dirname ${SELF}`

SRCDIR=$1
BUILDDIR=$2
DESTDIR=$3

CMD=$4
FILE=$5
shift 5

test -z "${SRCDIR}" && {
	echo "${SELF}:SRCDIR: '${SRCDIR}'" >&2;
	exit 1;
}

test -z "${BUILDDIR}" && {
	echo "${SELF}:BUILDDIR: '${BUILDDIR}'" >&2;
	exit 1;
}

test -z "${DESTDIR}" && {
	echo "${SELF}:DESTDIR: '${DESTDIR}'" >&2;
	exit 1;
}

test -z "${CMD}" && {
	echo "${SELF}:CMD: '${CMD}'" >&2;
	exit 1;
}

test -z "${FILE}" && {
	echo "${SELF}:FILE: '${FILE}'" >&2;
	exit 1;
}

CURDIR=`pwd`

cd ${SRCDIR} && {
	ABS_SRCDIR=`pwd`
	cd ${CURDIR}
} || {
	echo "${SELF}:cannot cd into '${SRCDIR}'" >&2;
	exit 1;
}

cd ${BUILDDIR} && {
	ABS_BUILDDIR=`pwd`
	cd ${CURDIR}
} || {
	echo "${SELF}:cannot cd into '${BUILDDIR}'" >&2;
	exit 1;
}

cd ${DESTDIR} && {
	${ABS_BUILDDIR}/${CMD} ${ABS_SRCDIR}/${FILE} >&2 || exit 1;
	cd ${CURDIR}
} || {
	echo "${SELF}:cannot cd into '${BUILDDIR}'" >&2;
	exit 1;
}

exit 0;
