#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_traffic_summary.sh
EOF
exit 1;
fi

PREFIX="$1"
shift 1
ARGS=$@

. `dirname $0`/../../testprogs/blackbox/subunit.sh

script_dir=`dirname $0`/..
input="$script_dir/testdata/traffic_summary.pdml"
expected="$script_dir/testdata/traffic_summary.expected"
output="$(mktemp $TMPDIR/traffic_summary.XXXXXXXXXXX)"
ts="$script_dir/traffic_summary.pl"

traffic_summary() {

    $ts $input >$output
    if [ "$?" != "0" ]; then
        return 1
    fi

    diff $output $expected
    if [ "$?" != "0" ]; then
        return 1
    fi
}

# Check the required perl modules for traffic_summary
# skip the tests if they are not installed
perl -MXML::Twig -e 1
if [ "$?" != "0" ]; then
    subunit_start_test "traffic_summary"
    subunit_skip_test "traffic_summary" <<EOF
perl module XML::Twig not installed
EOF
else
    testit "traffic_summary" traffic_summary
fi

exit $failed
