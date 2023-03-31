#!/bin/sh -eux
#
# A very simple check script to confirm we still provide binaries
# that look like the targets oss-fuzz wants.
#
# A much stronger check is available in oss-fuzz via
# infra/helper.py check_build samba
#

# oss-fuzz provides an OUT variable, so for clarity this script
# uses the same.  See build_samba.sh
OUT=$1

# build_samba.sh will have put a non-zero number of fuzzers here.  If
# there are none, this will fail as it becomes literally fuzz_*

seeds_found=no

for bin in $OUT/fuzz_*; do
	# we only want to look at the elf files, not the zips
	if [ ${bin%_seed_corpus.zip} != $bin ]; then
		continue
	fi
	# Confirm that the chrpath was reset to lib/ in the same directory
	# as the binary.  RPATH (not RUNPATH) is critical, otherwise
	# libraries used by libraries won't be found on the oss-fuzz
	# target host.
	chrpath -l $bin | grep 'RPATH=$ORIGIN/lib'

	# Confirm that we link to at least some libraries in this
	# directory (shows that the libraries were found and copied).
	ldd $bin | grep "$OUT/lib"
	num_libs=$(ldd $bin | grep -v ld-linux | grep -v linux-vdso | grep -v "$OUT/lib" | wc -l)

	if [ 0$num_libs -ne 0 ]; then
		echo "some libraries not linked to $ORIGIN/lib, oss-fuzz will fail!"
		exit 1
	fi

	if [ -f ${bin}_seed_corpus.zip ]; then
		seeds_found=yes
	fi
done

if [ $seeds_found = no ]; then
	echo "no seed zip files were found!"
	exit 1
fi
