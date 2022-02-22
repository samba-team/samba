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
# Additional arguments are passed to configure, to allow this to be
# tested in autobuild.py
#

# Ensure we give good trace info, fail right away and fail with unset
# variables
set -e
set -x
set -u

"$(dirname "${0}")"/do_build.sh "$@"
"$(dirname "${0}")"/check_build.sh "${OUT}"