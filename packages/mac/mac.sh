#!/bin/sh
# $Id$

dbase=`dirname $0`
base=`cd $dbase && pwd`
echo $base
config=${base}/../../configure

destdir=`pwd`/destdir
builddir=`pwd`/builddir
imgdir=`pwd`/imgdir

rm -rf ${destdir} ${builddir} ${imgdir} || exit 1
mkdir ${destdir} || exit 1
mkdir ${builddir} || exit 1
mkdir ${imgdir} || exit 1

cd ${builddir} || exit 1

version=`sh ${config} --help 2>/dev/null | head -1 | sed 's/.*Heimdal \([^ ]*\).*/\1/'`

env \
  CFLAGS="-arch i386 -arch ppc" \
  LDFLAGS="-arch i386 -arch ppc" \
  ${config} > log || exit 1
make all > /dev/null || exit 1
make check > /dev/null || exit 1
make install DESTDIR=${destdir} > /dev/null || exit 1 

replace="s,[@]VERSION[@],${version},g"

sed -e $replace < ${base}/Info.plist.in > ./Info.plist

/Developer/Tools/packagemaker \
    -build \
    -ds \
    -f ${destdir} \
    -p ${imgdir}/Heimdal.pkg \
    -r ${base}/Resources \
    -i ./Info.plist || exit 1

cd $base
/usr/bin/hdiutil create -volname "Heimdal-${version}" -srcfolder ${imgdir} "heimdal-${version}.dmg" || exit 1

exit 0
