#!/bin/sh -e

# We have to push to oss-fuzz CFLAGS into the waf ADDITIONAL_CFLAGS
# as otherwise waf's configure fails linking the first test binary
ADDITIONAL_CFLAGS=$CFLAGS
export ADDITIONAL_CFLAGS
CFLAGS=""
export CFLAGS
LD=$CXX
export LD

./configure -C --without-gettext --enable-debug --enable-developer \
            --address-sanitizer --enable-libfuzzer \
	    --disable-warnings-as-errors \
	    --abi-check-disable \
	    --fuzz-target-ldflags=$LIB_FUZZING_ENGINE \
	    --nonshared-binary=ALL LINK_CC=$CXX

make -j

cp bin/fuzz_* $OUT/
