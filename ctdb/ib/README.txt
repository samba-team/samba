Compilation
===========

For the configure script, please set the OFED include & library path by e.g.:

export CFLAGS="-I/usr/local/ofed/include -L/usr/local/ofed/lib"

After then:

./configure --enable-infiniband
