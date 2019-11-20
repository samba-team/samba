#!/bin/sh -e

# This will be copied into $SRC, being the root of the source tree by
# build_image.sh

exec lib/fuzzing/oss-fuzz/build_samba.sh
