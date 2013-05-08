#!/bin/sh

# this script installs a private copy of python in the same prefix as Samba

if [ $# -lt 1 ]; then
cat <<EOF
Usage: install_with_python.sh PREFIX [CONFIGURE OPTIONS]
EOF
exit 1;
fi

PREFIX="$1"
shift

LD_LIBRARY_PATH=$PREFIX/python/lib:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH

VERSION="Python-2.6.5"

do_install_python() {
       mkdir -p python_install || exit 1
       rsync -avz samba.org::ftp/tridge/python/$VERSION.tar python_install || exit 1
       cd python_install || exit 1;
       rm -rf $VERSION || exit 1
       tar -xf $VERSION.tar || exit 1
       cd $VERSION || exit 1
       ./configure --prefix=$PREFIX/python --enable-shared --disable-ipv6 || exit 1
       make || exit 1
       make install || exit 1
       cd ../.. || exit 1
       rm -rf python_install || exit 1
}

if [ ! -d $PREFIX/python ]; then
   # needs to be installed
   do_install_python
fi

PYTHON=$PREFIX/python/bin/python
export PYTHON

`dirname $0`/configure --prefix=$PREFIX $@ || exit 1
make -j || exit 1
make install || exit 1
