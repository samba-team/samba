#!/bin/bash
#

set -e
set -u

lo=$(find -mindepth 1 -maxdepth 1)
for o in $lo; do
	mkdir -p ctdb
	mv $o ctdb/
done

exit 0

