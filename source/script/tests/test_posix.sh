#!/bin/sh

# this runs the file serving tests that are expected to pass with the
# current posix ntvfs backend

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_posix.sh UNC USERNAME PASSWORD <first>
EOF
exit 1;
fi

unc="$1"
username="$2"
password="$3"
start="$4"
shift 3

testit() {
   trap "rm -f test.$$" EXIT

   cmdline="$*"
   if ! $cmdline > test.$$; then
       cat test.$$;
       rm -f test.$$;
       echo "TEST FAILED - $cmdline";
       exit 1;
   fi
   rm -f test.$$;
}


tests="BASE-FDPASS BASE-LOCK1 BASE-LOCK2 BASE-LOCK3 BASE-LOCK4"
tests="$tests BASE-LOCK5 BASE-LOCK6 BASE-LOCK7 BASE-UNLINK BASE-ATTR"
tests="$tests BASE-NEGNOWAIT BASE-DIR1 BASE-DIR2 BASE-VUID"
tests="$tests BASE-DENY1 BASE-DENY2 BASE-TCON BASE-TCONDEV BASE-RW1"
tests="$tests BASE-DENY3 BASE-XCOPY BASE-OPEN BASE-DENYDOS"
tests="$tests BASE-DELETE BASE-PROPERTIES BASE-MANGLE"
tests="$tests BASE-CHKPATH BASE-SECLEAK BASE-TRANS2"
tests="$tests BASE-NTDENY1 BASE-NTDENY2  BASE-RENAME BASE-OPENATTR"
tests="$tests RAW-QFSINFO RAW-QFILEINFO RAW-SFILEINFO-BUG RAW-SFILEINFO"
tests="$tests RAW-LOCK RAW-MKDIR RAW-SEEK RAW-CONTEXT RAW-MUX RAW-OPEN RAW-WRITE"
tests="$tests RAW-UNLINK RAW-READ RAW-CLOSE RAW-IOCTL RAW-SEARCH RAW-CHKPATH RAW-RENAME"
tests="$tests RAW-EAS RAW-STREAMS RAW-ACLS"
tests="$tests LOCAL-ICONV LOCAL-TALLOC LOCAL-MESSAGING LOCAL-BINDING LOCAL-IDTREE"

soon="BASE-CHARSET RAW-OPLOCK RAW-NOTIFY BASE-DELAYWRITE"

for t in $tests; do
    if [ ! -z "$start" -a "$start" != $t ]; then
	continue;
    fi
    start=""
    echo Testing $t
    testit $VALGRIND bin/smbtorture $unc -U"$username"%"$password" $t
done
