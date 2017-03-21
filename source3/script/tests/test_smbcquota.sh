#!/bin/sh
# Unix SMB/CIFS implementation.
# Tests for smbcquotas
# Copyright (C) Noel Power 2017

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

#
# Blackbox test wrapper for smbcquota
#
if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_smbcquota.sh SERVER DOMAIN USERNAME PASSWORD LOCAL_PATH SMBCQUOTAS
EOF
exit 1;
fi

SERVER=$1
DOMAIN=$2
USERNAME=$3
PASSWORD=$4
ENVDIR=`dirname $5`
SMBCQUOTAS="$VALGRIND $6"
shift 6

TEST_SMBCQUOTAS=`dirname $0`/test_smbcquota.py

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh


testit "smbcquotas" ${TEST_SMBCQUOTAS} ${SERVER} ${DOMAIN} ${USERNAME} ${PASSWORD} ${ENVDIR} ${SMBCQUOTAS} || failed=`expr $failed + 1`

testok $0 $failed
