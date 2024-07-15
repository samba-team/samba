#!/bin/sh

 ./ctdb/tests/local_daemons.sh "$PREFIX_ABS/clusteredmember" onnode all 'net ads keytab create --option="sync machine password script=" --configfile=$CTDB_BASE/lib/server.conf'
