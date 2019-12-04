#!/bin/sh -eux
#
# A very simple check script to confirm we still provide binaries
# that look like the targets oss-fuzz wants.
#
# A much stronger check is availble in oss-fuzz via
# infra/helper.py check_build samba
#

# oss-fuzz provides an OUT variable, so for clarity this script
# uses the same.  See build_samba.sh
OUT=$1

# build_samba.sh will have put a non-zero number of fuzzers here.  If
# there are none, this will fail as it becomes literally fuzz_*
for bin in $OUT/fuzz_*
do
    # Confirm that the chrpath was reset to lib/ in the same directory
    # as the binary
    chrpath -l $bin | grep 'RUNPATH=$ORIGIN/lib'

    # Confirm that we link to at least some libraries in this
    # directory (shows that the libraries were found and copied).
    ldd $bin | grep "$OUT/lib"
done
