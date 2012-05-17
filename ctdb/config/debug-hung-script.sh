#!/bin/sh

. $CTDB_BASE/functions
loadconfig

echo "Pstree output for the hung script:"
pstree -p -a $1
