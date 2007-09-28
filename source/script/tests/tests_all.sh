#!/bin/sh
SCRIPTDIR=`dirname $0`
. $SCRIPTDIR/test_functions.sh

$SCRIPTDIR/test_local_s3.sh
$SCRIPTDIR/test_smbtorture_s3.sh 
plantest "smbclient" dc $SCRIPTDIR/test_smbclient_s3.sh \$SERVER \$SERVER_IP
