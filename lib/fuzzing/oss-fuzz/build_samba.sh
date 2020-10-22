#!/bin/sh
#
# This is not a general-purpose build script, but instead one specific
# to the Google oss-fuzz compile environment.
#
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/#Requirements
#
# https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/README.md#provided-environment-variables
#
# This file is run by
# https://github.com/google/oss-fuzz/blob/master/projects/samba/build.sh
# which does nothing else.
#
# We have to push to oss-fuzz CFLAGS into the waf ADDITIONAL_CFLAGS
# as otherwise waf's configure fails linking the first test binary
#
# CFLAGS are supplied by the caller, eg the oss-fuzz compile command
#
# Additional arguments are passed to configure, to allow this to be
# tested in autobuild.py
#

# Ensure we give good trace info, fail right away and fail with unset
# variables
set -e
set -x
set -u

# It is critical that this script, just as the rest of Samba's GitLab
# CI docker has LANG set to en_US.utf8 (oss-fuzz fails to set this)
. /etc/default/locale
export LANG
export LC_ALL

ADDITIONAL_CFLAGS="$CFLAGS"
export ADDITIONAL_CFLAGS
CFLAGS=""
export CFLAGS
LD="$CXX"
export LD

# Use the system Python, not the OSS-Fuzz provided statically linked
# and instrumented Python, because we can't statically link.

PYTHON=/usr/bin/python3
export PYTHON

# $SANITIZER is provided by the oss-fuzz "compile" command
#
# We need to add the waf configure option as otherwise when we also
# get (eg) -fsanitize=address via the CFLAGS we will fail to link
# correctly

case "$SANITIZER" in
    address)
	SANITIZER_ARG='--address-sanitizer'
	;;
    undefined)
	SANITIZER_ARG='--undefined-sanitizer'
	;;
    coverage)
	# Thankfully clang operating as ld has no objection to the
	# cc style options, so we can just set ADDITIONAL_LDFLAGS
	# to ensure the coverage build is done, despite waf splitting
	# the compile and link phases.
	ADDITIONAL_LDFLAGS="${ADDITIONAL_LDFLAGS:-} $COVERAGE_FLAGS"
	export ADDITIONAL_LDFLAGS

	SANITIZER_ARG=''
       ;;
esac

# $LIB_FUZZING_ENGINE is provided by the oss-fuzz "compile" command
#

./configure -C --without-gettext --enable-debug --enable-developer \
            --enable-libfuzzer \
	    $SANITIZER_ARG \
	    --disable-warnings-as-errors \
	    --abi-check-disable \
	    --fuzz-target-ldflags="$LIB_FUZZING_ENGINE" \
	    --nonshared-binary=ALL \
	    "$@" \
	    LINK_CC="$CXX"

make -j

# Make a directory for the system shared libraries to be copied into
mkdir -p $OUT/lib

# We can't static link to all the system libs with waf, so copy them
# to $OUT/lib and set the rpath to point there.  This is similar to how
# firefox handles this.

for x in bin/fuzz_*
do
    # Copy any system libraries needed by this fuzzer to $OUT/lib.

    # We run ldd on $x, the fuzz_binary in bin/ which has not yet had
    # the RUNPATH altered.  This is clearer for debugging in local
    # development builds as $OUT is not cleaned between runs.
    #
    # Otherwise trying to re-run this can see cp can fail with:
    # cp: '/out/lib/libgcc_s.so.1' and '/out/lib/libgcc_s.so.1' are the same file
    # which is really confusing!

    # The cut for ( and ' ' removes the special case references to:
    # 	linux-vdso.so.1 =>  (0x00007ffe8f2b2000)
    #   /lib64/ld-linux-x86-64.so.2 (0x00007fc63ea6f000)

    ldd $x | cut -f 2 -d '>' | cut -f 1 -d \( | cut -f 2 -d  ' ' | xargs -i cp \{\} $OUT/lib/

    cp $x $OUT/
    bin=`basename $x`

    # Changing RPATH (not RUNPATH, but we can't tell here which was
    # set) is critical, otherwise libraries used by libraries won't be
    # found on the oss-fuzz target host.  Sadly this is only possible
    # with clang or ld.bfd on Ubuntu 16.04 (this script is only run on
    # that).
    #
    # chrpath --convert only allows RPATH to be changed to RUNPATH,
    # not the other way around, and we really don't want RUNPATH.
    #
    # This means the copied libraries are found on the runner
    chrpath -r '$ORIGIN/lib' $OUT/$bin

    # Truncate the original binary to save space
    echo -n > $x

done

# Grap the seeds dictionary from github and put the seed zips in place
# beside their executables.

wget https://gitlab.com/samba-team/samba-fuzz-seeds/-/jobs/artifacts/master/download?job=zips \
     -O seeds.zip

# We might not have unzip, but we do have python
$PYTHON -mzipfile -e seeds.zip  $OUT
rm -f seeds.zip
