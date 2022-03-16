# This file can be sourced using
#
# source selftest/devel_env.sh
#
# So that you can run 'make test' on your box with better
# debugging and without syncs slowing down the tests.
#
export TDB_NO_FSYNC=1
export NMBD_DONT_LOG_STDOUT=1
export SMBD_DONT_LOG_STDOUT=1
export WINBINDD_DONT_LOG_STDOUT=1
