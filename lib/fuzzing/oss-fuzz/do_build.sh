#!/bin/sh
#
# This is not a general-purpose build script, but instead one specific
# to the Google oss-fuzz compile environment.
#
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/#Requirements
#
# https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/README.md#provided-environment-variables
#
# This file is run by build_samba.sh, which is run by
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
if [ -f /etc/default/locale ]; then
	. /etc/default/locale
elif [ -f /etc/locale.conf ]; then
	. /etc/locale.conf
fi
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

# --disable-new-dtags linker flag creates fuzzer binaries with RPATH
# header instead of RUNPATH header. Modern linkers use RUNPATH by
# default.
LINK_CC="$CXX" ./configure -C --without-gettext --enable-debug --enable-developer \
	--enable-libfuzzer \
	$SANITIZER_ARG \
	--disable-warnings-as-errors \
	--abi-check-disable \
	"--fuzz-target-ldflags=-Wl,--disable-new-dtags $LIB_FUZZING_ENGINE" \
	--nonshared-binary=ALL \
	"$@"

make -j

# Make a directory for the system shared libraries to be copied into
mkdir -p $OUT/lib

# oss-fuzz would prefer for all the binaries put into $OUT to be
# statically linked.
#
# We can't static link to all the system libs with waf, so copy the
# libraries we need to $OUT/lib and set the rpath to point there.
# This is similar to how firefox handles this.
#
# NOTE on RPATH vs RUNPATH:
#
# RUNPATH appears to be the more modern version, and so modern ld.bfd
# and ld.gold only set RUNPATH.  RUNPATH makes sense on most systems,
# but not for our hack.
#
# If we use RUNPATH, we can get an error like this:
# Step #6: Error occurred while running fuzz_nmblib_parse_packet:
# Step #6: /workspace/out/coverage/fuzz_nmblib_parse_packet: error while loading shared libraries: libavahi-common.so.3: cannot open shared object file: No such file or directory
#
# This is because the full contents of $OUT are copied to yet another
# host, which otherwise does not have much of linux at all.  oss-fuzz
# prefers a static binary because that will 'just work', but we can't
# do that, so we need to use linker tricks.
#
# If the linker used RUNPATH (eg ld.bfd on Ubuntu 18.04 and later, ld.gold):
# * bin=fuzz_nmblib_parse_packet
# * OUT=/tmp/3/b12207/prefix/samba-fuzz
# * chrpath -r '$ORIGIN/lib' $OUT/$bin'
# * ldd $OUT/$bin
#	linux-vdso.so.1 (0x00007ffd4b7a5000)
#	libasan.so.5 => /tmp/3/b12207/prefix/samba-fuzz/lib/libasan.so.5 (0x00007ff25bdd0000)
#	libldap_r-2.4.so.2 => /tmp/3/b12207/prefix/samba-fuzz/lib/libldap_r-2.4.so.2 (0x00007ff25bd7a000)
#	liblber-2.4.so.2 => /tmp/3/b12207/prefix/samba-fuzz/lib/liblber-2.4.so.2 (0x00007ff25bd69000)
#	libunwind-x86_64.so.8 => /tmp/3/b12207/prefix/samba-fuzz/lib/libunwind-x86_64.so.8 (0x00007ff25bd47000)
#	libunwind.so.8 => /tmp/3/b12207/prefix/samba-fuzz/lib/libunwind.so.8 (0x00007ff25bd2a000)
#	libgnutls.so.30 => /tmp/3/b12207/prefix/samba-fuzz/lib/libgnutls.so.30 (0x00007ff25bb54000)
#	libdl.so.2 => /tmp/3/b12207/prefix/samba-fuzz/lib/libdl.so.2 (0x00007ff25bb4c000)
#	libz.so.1 => /tmp/3/b12207/prefix/samba-fuzz/lib/libz.so.1 (0x00007ff25bb30000)
#	libjansson.so.4 => /tmp/3/b12207/prefix/samba-fuzz/lib/libjansson.so.4 (0x00007ff25bb21000)
#	libresolv.so.2 => /tmp/3/b12207/prefix/samba-fuzz/lib/libresolv.so.2 (0x00007ff25bb05000)
#	libsystemd.so.0 => /tmp/3/b12207/prefix/samba-fuzz/lib/libsystemd.so.0 (0x00007ff25ba58000)
#	libpthread.so.0 => /tmp/3/b12207/prefix/samba-fuzz/lib/libpthread.so.0 (0x00007ff25ba35000)
#	libicuuc.so.66 => /tmp/3/b12207/prefix/samba-fuzz/lib/libicuuc.so.66 (0x00007ff25b84d000)
#	libicui18n.so.66 => /tmp/3/b12207/prefix/samba-fuzz/lib/libicui18n.so.66 (0x00007ff25b54e000)
#	libcap.so.2 => /tmp/3/b12207/prefix/samba-fuzz/lib/libcap.so.2 (0x00007ff25b545000)
#	libbsd.so.0 => /tmp/3/b12207/prefix/samba-fuzz/lib/libbsd.so.0 (0x00007ff25b52b000)
#	libnsl.so.1 => /tmp/3/b12207/prefix/samba-fuzz/lib/libnsl.so.1 (0x00007ff25b50e000)
#	libc.so.6 => /tmp/3/b12207/prefix/samba-fuzz/lib/libc.so.6 (0x00007ff25b31c000)
#	librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007ff25b2f2000)
#	libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007ff25b1a3000)
#	libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007ff25b188000)
#	libsasl2.so.2 => /usr/lib/x86_64-linux-gnu/libsasl2.so.2 (0x00007ff25b16b000)
#	libgssapi.so.3 => /usr/lib/x86_64-linux-gnu/libgssapi.so.3 (0x00007ff25b126000)
#	liblzma.so.5 => /lib/x86_64-linux-gnu/liblzma.so.5 (0x00007ff25b0fd000)
#	/lib64/ld-linux-x86-64.so.2 (0x00007ff25ea0c000)
#	libp11-kit.so.0 => /usr/lib/x86_64-linux-gnu/libp11-kit.so.0 (0x00007ff25afc5000)
#	libidn2.so.0 => /usr/lib/x86_64-linux-gnu/libidn2.so.0 (0x00007ff25afa4000)
#	libunistring.so.2 => /usr/lib/x86_64-linux-gnu/libunistring.so.2 (0x00007ff25ae22000)
#	libtasn1.so.6 => /usr/lib/x86_64-linux-gnu/libtasn1.so.6 (0x00007ff25ae0c000)
#	libnettle.so.7 => /usr/lib/x86_64-linux-gnu/libnettle.so.7 (0x00007ff25add2000)
#	libhogweed.so.5 => /usr/lib/x86_64-linux-gnu/libhogweed.so.5 (0x00007ff25ad9a000)
#	libgmp.so.10 => /usr/lib/x86_64-linux-gnu/libgmp.so.10 (0x00007ff25ad14000)
#	liblz4.so.1 => /usr/lib/x86_64-linux-gnu/liblz4.so.1 (0x00007ff25acf3000)
#	libgcrypt.so.20 => /usr/lib/x86_64-linux-gnu/libgcrypt.so.20 (0x00007ff25abd5000)
#	libicudata.so.66 => /usr/lib/x86_64-linux-gnu/libicudata.so.66 (0x00007ff259114000)
#	libstdc++.so.6 => /usr/lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007ff258f33000)
#	libheimntlm.so.0 => /usr/lib/x86_64-linux-gnu/libheimntlm.so.0 (0x00007ff258f25000)
#	libkrb5.so.26 => /usr/lib/x86_64-linux-gnu/libkrb5.so.26 (0x00007ff258e92000)
#	libasn1.so.8 => /usr/lib/x86_64-linux-gnu/libasn1.so.8 (0x00007ff258deb000)
#	libcom_err.so.2 => /lib/x86_64-linux-gnu/libcom_err.so.2 (0x00007ff258de4000)
#	libhcrypto.so.4 => /usr/lib/x86_64-linux-gnu/libhcrypto.so.4 (0x00007ff258dac000)
#	libroken.so.18 => /usr/lib/x86_64-linux-gnu/libroken.so.18 (0x00007ff258d93000)
#	libffi.so.7 => /usr/lib/x86_64-linux-gnu/libffi.so.7 (0x00007ff258d85000)
#	libgpg-error.so.0 => /lib/x86_64-linux-gnu/libgpg-error.so.0 (0x00007ff258d62000)
#	libwind.so.0 => /usr/lib/x86_64-linux-gnu/libwind.so.0 (0x00007ff258d38000)
#	libheimbase.so.1 => /usr/lib/x86_64-linux-gnu/libheimbase.so.1 (0x00007ff258d26000)
#	libhx509.so.5 => /usr/lib/x86_64-linux-gnu/libhx509.so.5 (0x00007ff258cd8000)
#	libsqlite3.so.0 => /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 (0x00007ff258bad000)
#	libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007ff258b72000)
#
# Note how all the dependencies of libc and gnutls are not forced to
# $OUT/lib (via the magic $ORIGIN variable, meaning the directory of
# the binary).  These will not be found on the target system!
#
# If the linker used RPATH however
# * bin=fuzz_nmblib_parse_packet
# * OUT=/tmp/3/b22/prefix/samba-fuzz
# * chrpath -r '$ORIGIN/lib' $OUT/$bin'
# * ldd $OUT/$bin
#	linux-vdso.so.1 =>  (0x00007ffef85c7000)
#	libasan.so.2 => /tmp/3/b22/prefix/samba-fuzz/lib/libasan.so.2 (0x00007f3668b4f000)
#	libldap_r-2.4.so.2 => /tmp/3/b22/prefix/samba-fuzz/lib/libldap_r-2.4.so.2 (0x00007f36688fe000)
#	liblber-2.4.so.2 => /tmp/3/b22/prefix/samba-fuzz/lib/liblber-2.4.so.2 (0x00007f36686ef000)
#	libunwind-x86_64.so.8 => /tmp/3/b22/prefix/samba-fuzz/lib/libunwind-x86_64.so.8 (0x00007f36684d0000)
#	libunwind.so.8 => /tmp/3/b22/prefix/samba-fuzz/lib/libunwind.so.8 (0x00007f36682b5000)
#	libgnutls.so.30 => /tmp/3/b22/prefix/samba-fuzz/lib/libgnutls.so.30 (0x00007f3667f85000)
#	libdl.so.2 => /tmp/3/b22/prefix/samba-fuzz/lib/libdl.so.2 (0x00007f3667d81000)
#	libz.so.1 => /tmp/3/b22/prefix/samba-fuzz/lib/libz.so.1 (0x00007f3667b67000)
#	libjansson.so.4 => /tmp/3/b22/prefix/samba-fuzz/lib/libjansson.so.4 (0x00007f366795a000)
#	libresolv.so.2 => /tmp/3/b22/prefix/samba-fuzz/lib/libresolv.so.2 (0x00007f366773f000)
#	libsystemd.so.0 => /tmp/3/b22/prefix/samba-fuzz/lib/libsystemd.so.0 (0x00007f366be2f000)
#	libpthread.so.0 => /tmp/3/b22/prefix/samba-fuzz/lib/libpthread.so.0 (0x00007f3667522000)
#	libicuuc.so.55 => /tmp/3/b22/prefix/samba-fuzz/lib/libicuuc.so.55 (0x00007f366718e000)
#	libicui18n.so.55 => /tmp/3/b22/prefix/samba-fuzz/lib/libicui18n.so.55 (0x00007f3666d2c000)
#	libcap.so.2 => /tmp/3/b22/prefix/samba-fuzz/lib/libcap.so.2 (0x00007f3666b26000)
#	libbsd.so.0 => /tmp/3/b22/prefix/samba-fuzz/lib/libbsd.so.0 (0x00007f3666911000)
#	libnsl.so.1 => /tmp/3/b22/prefix/samba-fuzz/lib/libnsl.so.1 (0x00007f36666f8000)
#	libc.so.6 => /tmp/3/b22/prefix/samba-fuzz/lib/libc.so.6 (0x00007f366632e000)
#	libm.so.6 => /tmp/3/b22/prefix/samba-fuzz/lib/libm.so.6 (0x00007f3666025000)
#	libgcc_s.so.1 => /tmp/3/b22/prefix/samba-fuzz/lib/libgcc_s.so.1 (0x00007f3665e0f000)
#	libsasl2.so.2 => /tmp/3/b22/prefix/samba-fuzz/lib/libsasl2.so.2 (0x00007f3665bf4000)
#	libgssapi.so.3 => /tmp/3/b22/prefix/samba-fuzz/lib/libgssapi.so.3 (0x00007f36659b3000)
#	liblzma.so.5 => /tmp/3/b22/prefix/samba-fuzz/lib/liblzma.so.5 (0x00007f3665791000)
#	/lib64/ld-linux-x86-64.so.2 (0x00007f366bc93000)
#	libp11-kit.so.0 => /tmp/3/b22/prefix/samba-fuzz/lib/libp11-kit.so.0 (0x00007f366552d000)
#	libidn.so.11 => /tmp/3/b22/prefix/samba-fuzz/lib/libidn.so.11 (0x00007f36652fa000)
#	libtasn1.so.6 => /tmp/3/b22/prefix/samba-fuzz/lib/libtasn1.so.6 (0x00007f36650e7000)
#	libnettle.so.6 => /tmp/3/b22/prefix/samba-fuzz/lib/libnettle.so.6 (0x00007f3664eb1000)
#	libhogweed.so.4 => /tmp/3/b22/prefix/samba-fuzz/lib/libhogweed.so.4 (0x00007f3664c7e000)
#	libgmp.so.10 => /tmp/3/b22/prefix/samba-fuzz/lib/libgmp.so.10 (0x00007f36649fe000)
#	libselinux.so.1 => /tmp/3/b22/prefix/samba-fuzz/lib/libselinux.so.1 (0x00007f36647dc000)
#	librt.so.1 => /tmp/3/b22/prefix/samba-fuzz/lib/librt.so.1 (0x00007f36645d4000)
#	libgcrypt.so.20 => /tmp/3/b22/prefix/samba-fuzz/lib/libgcrypt.so.20 (0x00007f36642f3000)
#	libicudata.so.55 => /tmp/3/b22/prefix/samba-fuzz/lib/libicudata.so.55 (0x00007f366283c000)
#	libstdc++.so.6 => /tmp/3/b22/prefix/samba-fuzz/lib/libstdc++.so.6 (0x00007f36624ba000)
#	libheimntlm.so.0 => /tmp/3/b22/prefix/samba-fuzz/lib/libheimntlm.so.0 (0x00007f36622b1000)
#	libkrb5.so.26 => /tmp/3/b22/prefix/samba-fuzz/lib/libkrb5.so.26 (0x00007f3662027000)
#	libasn1.so.8 => /tmp/3/b22/prefix/samba-fuzz/lib/libasn1.so.8 (0x00007f3661d85000)
#	libcom_err.so.2 => /tmp/3/b22/prefix/samba-fuzz/lib/libcom_err.so.2 (0x00007f3661b81000)
#	libhcrypto.so.4 => /tmp/3/b22/prefix/samba-fuzz/lib/libhcrypto.so.4 (0x00007f366194e000)
#	libroken.so.18 => /tmp/3/b22/prefix/samba-fuzz/lib/libroken.so.18 (0x00007f3661738000)
#	libffi.so.6 => /tmp/3/b22/prefix/samba-fuzz/lib/libffi.so.6 (0x00007f3661530000)
#	libpcre.so.3 => /tmp/3/b22/prefix/samba-fuzz/lib/libpcre.so.3 (0x00007f36612c0000)
#	libgpg-error.so.0 => /tmp/3/b22/prefix/samba-fuzz/lib/libgpg-error.so.0 (0x00007f36610ac000)
#	libwind.so.0 => /tmp/3/b22/prefix/samba-fuzz/lib/libwind.so.0 (0x00007f3660e83000)
#	libheimbase.so.1 => /tmp/3/b22/prefix/samba-fuzz/lib/libheimbase.so.1 (0x00007f3660c74000)
#	libhx509.so.5 => /tmp/3/b22/prefix/samba-fuzz/lib/libhx509.so.5 (0x00007f3660a29000)
#	libsqlite3.so.0 => /tmp/3/b22/prefix/samba-fuzz/lib/libsqlite3.so.0 (0x00007f3660754000)
#	libcrypt.so.1 => /tmp/3/b22/prefix/samba-fuzz/lib/libcrypt.so.1 (0x00007f366051c000)
#
# See how the runtime linker seems to honour the RPATH for
# dependencies of dependencies in this case.  This helps us us lot.

for x in bin/fuzz_*; do
	# Copy any system libraries needed by this fuzzer to $OUT/lib.

	# We run ldd on $x, the fuzz_binary in bin/ which has not yet had
	# the RPATH altered.  This is clearer for debugging in local
	# development builds as $OUT is not cleaned between runs.
	#
	# Otherwise trying to re-run this can see cp can fail with:
	# cp: '/out/lib/libgcc_s.so.1' and '/out/lib/libgcc_s.so.1' are the same file
	# which is really confusing!

	# The cut for ( and ' ' removes the special case references to:
	# 	linux-vdso.so.1 =>  (0x00007ffe8f2b2000)
	#   /lib64/ld-linux-x86-64.so.2 (0x00007fc63ea6f000)

	ldd $x | cut -f 2 -d '>' | cut -f 1 -d \( | cut -f 2 -d ' ' | xargs -i cp \{\} $OUT/lib/

	cp $x $OUT/
	bin=$(basename $x)

	# This means the copied libraries are found on the runner.
	#
	# The binaries should we built with RPATH, not RUNPATH, to allow
	# libraries used by libraries to be found. This command retains the
	# RPATH/RUNPATH header and only changes the path. We later verify this
	# in the check_build.sh script.
	chrpath -r '$ORIGIN/lib' $OUT/$bin

	# Truncate the original binary to save space
	echo -n >$x

done

# Strip RUNPATH: or RPATH: entries from shared libraries copied over to $OUT/lib.
# When those libraries get loaded and have further dependencies, a RUNPATH: header
# will cause the dynamic linker to search in the runpath, and not in $OUT/lib,
# and there's no way it will be found in the fuzzing env.
#
# So how is the indirect dependency found in $OUT/lib? Well, suppose the fuzzer binary
# links library A which links library B. During linking, both A and B as listed in the
# executable file's runtime dependencies (This was pioneered in Fedora 13 in 2010, but
# is common behavior now). So we have the fuzzer binary with RPATH set to $OUT/lib, and
# a dependency on library B, and it will therefore find library B in $OUT/lib. On the
# hand, if we keep the RUNPATH in library A, and load A first, it will try loading
# library B as a dependency of A from the wrong place.
chrpath -d $OUT/lib/*

# Grab the seeds dictionary from github and put the seed zips in place
# beside their executables.

wget https://gitlab.com/samba-team/samba-fuzz-seeds/-/jobs/artifacts/master/download?job=zips \
	-O seeds.zip

# We might not have unzip, but we do have python
$PYTHON -mzipfile -e seeds.zip $OUT
rm -f seeds.zip
