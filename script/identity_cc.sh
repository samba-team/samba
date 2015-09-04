#!/bin/sh

#An "identity cross-execute" script
#It can be used for testing the cross-build infrastructure
#as follows:
#./configure --cross-compile --cross-execute=./script/identity_cc.sh
#If the build is actually a native build, then the configuration
#result should be just like running ./configure without --cross-compile.

eval "$@"
