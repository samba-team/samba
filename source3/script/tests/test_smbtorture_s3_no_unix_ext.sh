#!/bin/bash
# this runs test_smbtorture_s3 with disabled unix extensions

if [ -z "$SERVERCONFFILE" ] ; then
    echo \$SERVERCONFFILE not defined
    exit 1
fi
inject=${SERVERCONFFILE%/*}/global_inject.conf

echo "unix extensions = no" > ${inject}
$(dirname $0)/test_smbtorture_s3.sh $*
ret=$?
> ${inject}
exit $ret
