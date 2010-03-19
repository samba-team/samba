# . these into your shell to allow you to run with socketwrapper
# outside the test environment

export SELFTEST_INTERFACES=127.0.0.6/8,127.0.0.7/8,127.0.0.8/8,127.0.0.9/8,127.0.0.10/8,127.0.0.11/8
export SOCKET_WRAPPER_DEFAULT_IFACE=6
export SOCKET_WRAPPER_DIR=./st/w
export UID_WRAPPER=1
export NSS_WRAPPER_PASSWD=st/dc/passwd
export NSS_WRAPPER_GROUP=st/dc/passwd
