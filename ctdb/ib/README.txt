Compilation
===========

For the configure script, please set the OFED include & library path by e.g.:

export CFLAGS="-I/usr/local/ofed/include -L/usr/local/ofed/lib"

After then:

./configure --enable-infiniband

Example for testing
===================
bin/ctdb_test --transport ib --nlist ../2nodes_rm.txt --listen 10.0.0.1
bin/ctdb_test --transport ib --nlist ../2nodes_rm.txt --listen 10.0.0.2

where 2nodes_rm.txt:
10.0.0.1
10.0.0.2
