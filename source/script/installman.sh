#!/bin/sh
MANDIR=$1
SRCDIR=$2

echo Installing man pages in $MANDIR

for d in $MANDIR $MANDIR/man1 $MANDIR/man5 $MANDIR/man7 $MANDIR/man8; do
if [ ! -d $d ]; then
mkdir $d
if [ ! -d $d ]; then
  echo Failed to make directory $d
  exit 1
fi
fi
done

cp $SRCDIR../docs/*.1 $MANDIR/man1
cp $SRCDIR../docs/*.5 $MANDIR/man5
cp $SRCDIR../docs/*.8 $MANDIR/man8
cp $SRCDIR../docs/*.7 $MANDIR/man7
echo Setting permissions on man pages
chmod 0644 $MANDIR/man1/smbstatus.1
chmod 0644 $MANDIR/man1/smbclient.1
chmod 0644 $MANDIR/man1/smbrun.1
chmod 0644 $MANDIR/man1/testparm.1
chmod 0644 $MANDIR/man1/testprns.1
chmod 0644 $MANDIR/man1/smbtar.1
chmod 0644 $MANDIR/man5/smb.conf.5
chmod 0644 $MANDIR/man7/samba.7
chmod 0644 $MANDIR/man8/smbd.8
chmod 0644 $MANDIR/man8/nmbd.8

echo Man pages installed
exit 0

