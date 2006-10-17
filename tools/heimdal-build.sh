#!/bin/sh
# Fetches, builds and store the result of a heimdal build
# Version: $Id$

fetchmethod=wget	   #options are: wget, curl, ftp, afs
resultdir=
email=heimdal-build-log@it.su.se
baseurl=ftp://ftp.pdc.kth.se/pub/heimdal/src
afsdir=/afs/pdc.kth.se/public/ftp/pub/heimdal/src
keeptree=no
passhrase=
builddir=
noemail=
cputimelimit=3600

# Add some bonus paths, to find sendmail and other tools
# on interesting platforms.
PATH="${PATH}:/usr/sbin:/usr/bin:/usr/libexec:/usr/lib"
PATH="${PATH}:/usr/local/bin:/usr/local/sbin"

# no more use configurabled part below (hopefully)

usage="[--current] [--release version] [--cvs SourceRepository] [--cvs-flags] [--result-directory dir] [--fetch-method wget|ftp|curl|cvs] --keep-tree] [--autotools] [--passhrase string] [--no-email] [--build-dir dir] [--cputime]"

date=`date +%Y%m%d`
if [ "$?" != 0 ]; then
    echo "have no sane date, punting"
    exit 1
fi

hostname=`hostname`
if [ "$?" != 0 ]; then
    echo "have no sane hostname, punting"
    exit 1
fi

version=`grep "^# Version: " "$0" | cut -f2- -d:`
if [ "X${version}" = X ]; then
    echo "Can not figure out what version I am"
    exit 1
fi

dir=
hversion=
cvsroot=
cvsflags=
autotools=no

while true
do
	case $1 in
	--autotools)
		autotools=yes
		shift
		;;
	--build-dir)
		builddir="$2"
		shift 2
		;;
	--current)
		dir="snapshots/"
		hversion="heimdal-${date}"
		shift
		;;
	--cputime)
		cputimelimit="$2"
		shift 2
		;;
	--release)
		hversion="heimdal-$2"
		shift 2
		;;
	--cvs)
		hversion="heimdal-cvs-${date}"
		cvsroot=$2
		fetchmethod=cvs
		shift 2
		;;
	--cvs-flags)
		cvsflags="$2"
		shift 2
		;;
	--result-directory)
		resultdir="$2"
		if [ ! -d "$resultdir" ]; then
		    echo "$resultdir doesn't exists"
		    exit 1
		fi
		shift 2
		;;
	--fetch-method)
		fetchmethod="$2"
		shift 2
		;;
	--keep-tree)
		keeptree=yes
		shift
		;;
	--passphrase)
		passhrase="$2"
		shift 2
		;;
	--no-email)
		noemail="yes"
		shift
		;;
	--version)
		echo "Version: $version"
		exit 0
		;;
	-*)
		echo "unknown option: $1"
		break
		;;
	*)
		break
		;;
	esac
done
if test $# -gt 0; then
	echo $usage
	exit 1
fi

if [ "X${hversion}" = X ]; then
	echo "no version given"
	exit 0
fi

hfile="${hversion}.tar.gz"
url="${baseurl}/${dir}${hfile}"
afsfile="${afsdir}/${dir}${hfile}"
unpack=yes

# Limit cpu seconds this all can take
ulimit -t "$cputimelimit" > /dev/null 2>&1

if [ "X${builddir}" != X ]; then
	echo "Changing build dir to ${builddir}"
	cd "${builddir}"
fi

echo "Removing old source" 
rm -rf ${hversion}

echo "Fetching ${hversion} using $fetchmethod"
case "$fetchmethod" in
wget|ftp)
	${fetchmethod} $url > /dev/null
	res=$?
	;;
curl)
	${fetchmethod} -o ${hfile} ${url} > /dev/null
	res=$?
	;;
afs)
	cp ${afsfile} ${hfile}
	res=$?
	;;
cvs)
	cvs ${cvsflags} -d "${cvsroot}" co -P -d ${hversion} heimdal
	res=$?
	unpack=no
	autotools=yes
	;;
*)
	echo "unknown fetch method"
	;;
esac

if [ "X$res" != X0 ]; then
	echo "Failed to download the tar-ball"
	exit 1
fi

confflags=
case "${hversion}" in
    0.7*)
	#true for Mac OS X, but how about the rest?
	confflags="--enable-shared --disable-static"
	;;
esac

if [ X"$unpack" = Xyes ]; then
	echo Unpacking source
	(gzip -dc ${hfile} | tar xf -) || exit 1
fi

if [ X"$autotools" = Xyes ]; then
	echo "Autotooling (via fix-export)"
	env DATEDVERSION="cvs-${date}" ${hversion}/fix-export ${hversion}
fi

cd ${hversion} || exit 1

mkdir socket_wrapper_dir
SOCKET_WRAPPER_DIR=`pwd`/socket_wrapper_dir
export SOCKET_WRAPPER_DIR

echo "Configuring and building ($hversion)"
./configure --enable-socket-wrapper ${confflags} > ab.txt 2>&1
if [ $? != 0 ] ; then
    echo Configure failed
    status=${status:-configure}
fi
make all >> ab.txt 2>&1
if [ $? != 0 ] ; then
    echo Make all failed
    status=${status:-make all}
fi
make check >> ab.txt 2>&1
if [ $? != 0 ] ; then
    echo Make check failed
    status=${status:-make check}
fi
status=${status:-ok}

if [ "X${resultdir}" != X ] ; then
	cp ab.txt "${resultdir}/ab-${hversion}-${hostname}-${date}.txt"
fi

if [ "X${noemail}" = X ] ; then
	cat > email-header <<EOF
From: ${USER:-unknown-user}@${hostname}
To: <heimdal-build-log@it.su.se>
Subject: heimdal-build-log SPAM COOKIE
X-heimdal-build: kaka-till-love

Version: $version
Machine: `uname -a`
Status: $status
EOF

	if [ "X$passhrase" != X ] ; then
		cat >> email-header <<EOF
autobuild-passphrase: ${passhrase}
EOF
	fi
		cat >> email-header <<EOF
------L-O-G------------------------------------
EOF

	cat email-header ab.txt | sendmail "${email}"
fi

cd ..
if [ X"$keeptree" != Xyes ] ; then
    rm -rf ${hversion}
fi
rm -f ${hfile}

exit 0
