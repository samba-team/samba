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
   cmdline="$*"
   if ! $cmdline > test.$$ 2>&1; then
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
tests="$tests BASE-DENY2 BASE-TCON BASE-TCONDEV BASE-RW1"
tests="$tests BASE-DENY3 BASE-XCOPY BASE-OPEN"
tests="$tests BASE-DELETE BASE-PROPERTIES BASE-MANGLE"
tests="$tests BASE-CHKPATH BASE-SECLEAK"
tests="$tests RAW-QFSINFO RAW-QFILEINFO RAW-SFILEINFO-BUG"
tests="$tests RAW-LOCK RAW-MKDIR RAW-SEEK RAW-CONTEXT BASE-RENAME"


soon="BASE-DENY1 BASE-DEFER_OPEN BASE-OPENATTR BASE-CHARSET"
soon="$soon RAW-SFILEINFO RAW-SEARCH RAW-OPEN RAW-OPLOCK RAW-NOTIFY RAW-MUX RAW-IOCTL"
soon="$soon RAW-CHKPATH RAW-UNLINK RAW-READ RAW-WRITE RAW-RENAME RAW-CLOSE BASE-TRANS2"

for t in $tests; do
    if [ ! -z "$start" -a "$start" != $t ]; then
	continue;
    fi
    start=""
    echo Testing $t
    testit bin/smbtorture $unc -U"$username"%"$password" $t
done
