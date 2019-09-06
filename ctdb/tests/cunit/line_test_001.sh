#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

tfile="${CTDB_TEST_TMP_DIR}/line.$$"

remove_files ()
{
	rm -f "$tfile"
}

test_cleanup remove_files

> "$tfile"

ok_null
unit_test line_test "$tfile"

printf "\0" > "$tfile"

required_result 1 <<EOF

EOF

unit_test line_test "$tfile"

echo -n "hello" > "$tfile"

ok_null
unit_test line_test "$tfile"

cat <<EOF > "$tfile"
hello
world
EOF

required_result 2 << EOF
hello
world
EOF
unit_test line_test "$tfile"

required_result 2 << EOF
hello
world
EOF
unit_test line_test "$tfile"

cat <<EOF > "$tfile"
This is a really long long line full of random words and hopefully it will be read properly by the line test program and identified as a single line
EOF

required_result 1 <<EOF
This is a really long long line full of random words and hopefully it will be read properly by the line test program and identified as a single line
EOF
unit_test line_test "$tfile"

cat <<EOF > "$tfile"
line number one
line number two
line number one
line number two
line number one
EOF

required_result 5 <<EOF
line number one
line number two
line number one
line number two
line number one
EOF
unit_test line_test "$tfile" 64

cat <<EOF > "$tfile"
this is line number one
this is line number two
this is line number three
this is line number four
this is line number five
EOF

required_result 5 <<EOF
this is line number one
this is line number two
this is line number three
this is line number four
this is line number five
EOF
unit_test line_test "$tfile" 64
