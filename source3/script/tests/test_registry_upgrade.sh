#!/bin/sh
#
# Test for registry upgrades.
#
# Copyright (C) 2011 Björn Baumbach <bb@sernet.de>

if [ $# -lt 2 ]; then
    echo "Usage: test_registry_upgrade.sh NET DBWRAP_TOOL"
    exit 1
fi

SCRIPT_DIR=$(dirname $0)
BASE_DIR="${SCRIPT_DIR}/../../.."

NET="$1"
DBWRAP_TOOL="$2 --persistent"
DATADIR="${BASE_DIR}/testdata/samba3"
WORKSPACE="${PREFIX}/registry_upgrade"
CONFIG_FILE="${WORKSPACE}/smb.conf"
CONFIGURATION="--configfile=${CONFIG_FILE}"

NETCMD="$NET $CONFIGURATION"

incdir="${BASE_DIR}/testprogs/blackbox"
. $incdir/subunit.sh

failed=0

REGPATH="HKLM\Software\Samba"

LOGDIR_PREFIX="registry_upgrade"

registry_check()
(
    CHECKNO="$1"
    CHECKDIFF="$2"
    REGVER=""
    ALLOWEDERR="INFO: version =|Check database:|overwrite registry format version 0 with 1|no INFO/version found"

    test "x$CHECKNO" = "x0" && {
        REGVER="--reg-version=1"
    }

    echo "Registry check $CHECKNO" | tee -a $LOG
    CHECK="$($NETCMD registry check $REGVER 2>&1)"
    RC=$?

    ERRORSTR="$(echo "$CHECK" | grep -vE $ALLOWEDERR )"
    test "x$RC" = "x0" || {
        echo "upgrade check $CHECKNO failed:" | tee -a $LOG
        return 1
    }

    test "x$ERRORSTR" = "x" || {
        echo "upgrade check $CHECKNO failed:" | tee -a $LOG
        echo "reason: $CHECK" | tee -a $LOG
        return 1
    }

    test "x$CHECKDIFF" = "xcheckdiff" && {
        $NETCMD registry export 'HKLM' $WORKSPACE/export_${CHECKNO}.reg >> $LOG
        test "x$?" = "x0" || {
            echo "Error: 'net registry export HKLM' failed" | tee -a $LOG
        }

        diff -q $WORKSPACE/export_0.reg $WORKSPACE/export_${CHECKNO}.reg >> $LOG
        test "x$?" = "x0" || {
            echo "Error: $WORKSPACE/export_0.reg differs from $WORKSPACE/export_${CHECKNO}.reg" | tee -a  $LOG
            return 1
        }
    }

    return 0
)

registry_upgrade()
{
    echo registry_upgrade $1 | tee -a $LOG

    cp -v $DATADIR/registry.tdb $WORKSPACE/registry.tdb >> $LOG 2>&1

    REGISTRY="${WORKSPACE}/registry.tdb"

    test -e $REGISTRY || {
        echo "Error: Database file not available" | tee -a $LOG
        return 1
    }

    # create config file
    echo '[global]' > ${CONFIG_FILE}
    echo "	state directory = ${WORKSPACE}" >> ${CONFIG_FILE}
    echo "	private directory = ${WORKSPACE}" >> ${CONFIG_FILE}
    echo "	lock directory = ${WORKSPACE}" >> ${CONFIG_FILE}

    # set database INFO/version to 1
    #$DBWRAP_TOOL $REGISTRY store 'INFO/version' uint32 1
    #test "x$?" = "x0" || {
    #    echo "Error: Can not set INFO/version" >> $LOG
    #    return 1
    #}

    # check original registry.tdb
    echo "$REGISTRY" | tee -a $LOG
    registry_check 0
    test "x$?" = "x0" || {
        echo "Error: initial 'registry_check 0' failed" | tee -a $LOG
        return 1
    }

    # trigger upgrade
    echo "$NETCMD registry enumerate $REGPATH" >> $LOG
    $NETCMD registry enumerate $REGPATH >> $LOG
    test "x$?" = "x0" || {
        echo "Error: 'net registry enumerate $REGPATH' failed" | tee -a $LOG
        return 1
    }

    # check upgraded database
    registry_check 1
    test "x$?" = "x0" || {
        echo "Error: 'registry_check 1' after upgrade failed" | tee -a $LOG
        return 1
    }

    # export database for diffs
    $NETCMD registry export 'HKLM' $WORKSPACE/export_0.reg | tee -a $LOG
    test "x$?" = "x0" || {
        echo "Error 'net registry export' failed" | tee -a $LOG
        return 1
    }

    # remove version string
    $DBWRAP_TOOL $REGISTRY delete INFO/version | tee -a $LOG
    test "x$?" = "x0" || {
        echo "Error: Can not remove INFO/version key from registry" | tee -a $LOG
        return 1
    }

    # trigger upgrade on upgraded database
    echo "$NETCMD registry enumerate $REGPATH" >> $LOG
    $NETCMD registry enumerate $REGPATH >> $LOG 2>&1
    test "x$?" = "x0" || {
        echo "Error: 'net registry enumerate $REGPATH' failed" | tee -a $LOG
        return 1
    }

    # check upgraded database again
    registry_check 2 checkdiff
    test "x$?" = "x0" || {
        echo "Error: 'registry_check 2' after upgrade failed" | tee -a $LOG
        return 1
    }

    # set database INFO/version to version 2
    $DBWRAP_TOOL $REGISTRY store 'INFO/version' uint32 2
    test "x$?" = "x0" || {
        echo "Error: Can not set INFO/version" | tee -a $LOG
        return 1
    }

    # trigger upgrade
    $NETCMD registry enumerate $REGPATH >> $LOG
    test "x$?" = "x0" || {
        echo "Error: 'net registry enumerate $REGPATH' failed" | tee -a $LOG
        return 1
    }

    # check upgraded database again
    registry_check 3 checkdiff
    test "x$?" = "x0" || {
        echo "Error: 'registry_check 3' after upgrade failed" | tee -a $LOG
        return 1
    }
}

# remove old logs
for OLDDIR in $(find ${PREFIX} -type d -name "${LOGDIR_PREFIX}_*") ; do
	echo "removing old directory ${OLDDIR}"
	rm -rf ${OLDDIR}
done

# remove old workspace
rm -rf $WORKSPACE

mkdir $WORKSPACE

DIR=$(mktemp -d ${PREFIX}/${LOGDIR_PREFIX}_XXXXXX)
LOG=$DIR/log

testit "registry_upgrade" registry_upgrade || failed=`expr $failed + 1`

if [ $failed -eq 0 ]; then
    rm -r $DIR
fi

testok $0 $failed

