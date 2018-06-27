#!/bin/sh

# Simple test that a DB from a backup file cannot be untarred and started
# manually (you have to run the samba-tool 'backup restore' command instead).

if [ $# -lt 1 ]; then
cat <<EOF
Usage: $0 PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

DBPATH=$PREFIX/start-backup
mkdir -p $DBPATH

. `dirname $0`/../../../testprogs/blackbox/subunit.sh

do_provision()
{
    $PYTHON $BINDIR/samba-tool domain provision \
           --domain=FOO --realm=foo.example.com --use-ntvfs \
           --targetdir=$DBPATH --option="pid directory = $DBPATH"
}

add_backup_marker()
{
# manually add the backup marker that the backup cmd usually adds
    $BINDIR/ldbmodify \
       -H tdb://$DBPATH/private/sam.ldb <<EOF
dn: @SAMBA_DSDB
changetype: modify
add: backupDate
backupDate: who-knows-when
-

EOF
}

start_backup()
{
    # start samba in interactive mode (if we don't, samba daemonizes and so the
    # command's exit status is always zero (success), regardless of whether
    # samba actually starts up or not). However, this means if this assertion
    # were ever to fail (i.e. samba DOES startup from a backup file), then the
    # test case would just hang. So we use a max-run-time of 5 secs so that
    # samba will self-destruct in the bad case (max_runtime_handler() returns
    # zero/success in this case, which allows us to tell the good case from the
    # bad case).
    OPTS="--maximum-runtime=5 -i"

    # redirect logs to stderr (which we'll then redirect to stdout so we can
    # capture it in a bash variable)
    OPTS="$OPTS --debug-stderr"

    # start samba and capture the debug output
    OUTPUT=$($BINDIR/samba -s $DBPATH/etc/smb.conf $OPTS 2>&1)
    if [ $? -eq 0 ] ; then
        echo "ERROR: Samba should not have started successfully"
        return 1
    fi

    # check the reason we're failing is because prime_ldb_databases() is
    # detecting that this is a backup DB (and not some other reason)
    echo "$OUTPUT" | grep "failed to start: Database is a backup"
}

# setup a DB and manually mark it as being a "backup"
testit "provision" do_provision
testit "add-backup-marker" add_backup_marker

# check that Samba won't start using this DB (because it's a backup)
testit "start-samba-backup" start_backup

rm -rf $DBPATH

exit $failed
