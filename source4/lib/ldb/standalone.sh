#!/bin/sh

cd ../replace
make clean

cd ../talloc
make clean

cd ../tdb
make clean

cd ../ldb
make clean

./autogen.sh

mkdir build
cd  build

../configure
make
