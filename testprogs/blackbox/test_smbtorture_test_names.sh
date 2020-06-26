#!/bin/sh

#Tests if the --fullname parameter passed to smbtorture is working as expected.

if [ $# -ne 1 ]; then
cat <<EOF
Usage: test_smbtorture_test_names.sh SMBTORTURE
EOF
exit 1;
fi

SMBTORTURE="$1 //a/b"

. `dirname $0`/subunit.sh

failed=0

testit_grep "with_shortname local.smbtorture.level1.level2.level3.always_pass" \
            '^success: always_pass$' \
            $SMBTORTURE local.smbtorture.level1.level2.level3.always_pass || failed=`expr $failed + 1`
testit_grep "with_shortname local.smbtorture.level1.level2.level3" \
            '^success: always_pass$' \
            $SMBTORTURE local.smbtorture.level1.level2.level3 || failed=`expr $failed + 1`
testit_grep "with_shortname local.smbtorture.level1.level2"\
            '^success: level3.always_pass$' \
            $SMBTORTURE local.smbtorture.level1.level2 || failed=`expr $failed + 1`
testit_grep "with_shortname local.smbtorture.level1" \
            '^success: level2.level3.always_pass$' \
            $SMBTORTURE local.smbtorture.level1 || failed=`expr $failed + 1`
testit_grep "with_fullname local.smbtorture.level1.level2.level3.always_pass" \
            '^success: local.smbtorture.level1.level2.level3.always_pass$' \
            $SMBTORTURE --fullname local.smbtorture.level1.level2.level3.always_pass || failed=`expr $failed + 1`
testit_grep "with_fullname local.smbtorture.level1.level2.level3" \
            '^success: local.smbtorture.level1.level2.level3.always_pass$' \
            $SMBTORTURE --fullname local.smbtorture.level1.level2.level3 || failed=`expr $failed + 1`
testit_grep "with_fullname local.smbtorture.level1.level2" \
            '^success: local.smbtorture.level1.level2.level3.always_pass$' \
            $SMBTORTURE --fullname local.smbtorture.level1.level2 || failed=`expr $failed + 1`
testit_grep "with_fullname local.smbtorture.level1" \
            '^success: local.smbtorture.level1.level2.level3.always_pass$' \
            $SMBTORTURE --fullname local.smbtorture.level1 || failed=`expr $failed + 1`

testok $0 $failed
