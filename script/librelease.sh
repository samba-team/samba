#!/bin/bash
# make a release of a Samba library

if [ ! -d ".git" ]; then
	echo "Run this script from the top-level directory in the"
	echo "repository"
	exit 1
fi

if [ $# -lt 1 ]; then
    echo "Usage: librelease.sh <LIBNAMES>"
    exit 1
fi

umask 0022

release_lib() {
    lib="$1"
    srcdir="$2"
    ftpdir="$3"

    pushd $srcdir

    echo "Releasing library $lib"

    echo "building release tarball"
    tgzname=$(make dist 2>&1 | grep ^Created | cut -d' ' -f2)
    [ -f "$tgzname" ] || {
	echo "Failed to create tarball"
	exit 1
    }
    tarname=$(basename $tgzname .gz)
    echo "Tarball: $tarname"
    gunzip -f $tgzname || exit 1
    [ -f "$tarname" ] || {
	echo "Failed to decompress tarball $tarname"
	exit 1
    }

    tagname=$(basename $tarname .tar)
    echo "tagging as $tagname"
    git tag -u $GPG_KEYID -s "$tagname" -m "$lib: tag release $tagname" || {
	exit 1
    }

    echo "signing"
    rm -f "$tarname.asc"
    gpg -u "$GPG_USER" --detach-sign --armor $tarname || {
	exit 1
    }
    [ -f "$tarname.asc" ] || {
	echo "Failed to create signature $tarname.asc"
	exit 1
    }
    echo "compressing"
    gzip -f -9 $tarname
    [ -f "$tgzname" ] || {
	echo "Failed to compress $tgzname"
	exit 1
    }

    [ -z "$ftpdir" ] && {
        popd
        return 0
    }

    echo "Push git tag $tagname"
    git push ssh://git.samba.org/data/git/samba.git refs/tags/$tagname:refs/tags/$tagname || {
	exit 1
    }

    echo "Transferring for FTP"
    rsync -Pav $tarname.asc $tgzname master.samba.org:~ftp/pub/$ftpdir/ || {
	exit 1
    }
    rsync master.samba.org:~ftp/pub/$ftpdir/$tarname.*

    popd
}

for lib in $*; do
    case $lib in
	talloc | tdb | ntdb | tevent | ldb)
	    [ -z "$GPG_USER" ] && {
	        GPG_USER='Samba Library Distribution Key <samba-bugs@samba.org>'
	    }

	    [ -z "$GPG_KEYID" ] && {
	        GPG_KEYID='13084025'
	    }

	    release_lib $lib "lib/$lib" $lib
	    ;;
	samba)
	    [ -z "$GPG_USER" ] && {
	        GPG_USER='6568B7EA'
	    }

	    [ -z "$GPG_KEYID" ] && {
	        GPG_KEYID='6568B7EA'
	    }

	    # for now we don't upload
	    release_lib $lib "." ""
	    ;;
	*)
	    echo "Unknown library $lib"
	    exit 1
    esac
done
