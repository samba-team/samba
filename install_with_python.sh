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
       set -e
       mkdir -p python_install
       rsync -avz samba.org::ftp/tridge/python/$VERSION.tar python_install
       cd python_install
       rm -rf $VERSION

       # Verify that the download hasn't been corrupted
       # This checks Python-2.6.5, while more hashes my be added later.
       if command -v sha256sum
       then
            echo "2f1ec5e52d122bf1864529c1bbac7fe6afc10e3a083217b3a7bff5ded37efcc3  Python-2.6.5.tar" > checksums.sha256
            sha256sum --status -c checksums.sha256
       else
            echo "c83cf77f32463c3949b85c94f661c090  Python-2.6.5.tar" > checksums.md5
            md5sum --status -c checksums.md5
       fi

       tar -xf $VERSION.tar
       cd $VERSION
       ./configure --prefix=$PREFIX/python --enable-shared --disable-ipv6
       make
       make install
       cd ../..
       rm -rf python_install
}

cleanup_install_python() {
       rm -rf python_install
       exit 1
}

if [ ! -d $PREFIX/python ]; then
   trap "cleanup_install_python" 0
   # needs to be installed
   do_install_python
fi

PYTHON=$PREFIX/python/bin/python
export PYTHON

`dirname $0`/configure --prefix=$PREFIX $@ || exit 1
make -j || exit 1
make install || exit 1
