#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "confirm that getvar matches listvar"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

# Squash whitespace for predictable output
result_filter ()
{
	sed -e 's|[[:space:]][[:space:]]*| |g'
}

$CTDB -d $CTDB_DEBUGLEVEL listvars |
	while read variable equals value ; do
		# Variable, as per listvars
		ok "${variable} = ${value}"
		simple_test "$variable"

		# Uppercase variable
		v_upper=$(echo "$variable" | tr "a-z" "A-Z")
		ok "${v_upper} = ${value}"
		simple_test "$v_upper"

		# Lowercase variable
		v_lower=$(echo "$variable" | tr "A-Z" "a-z")
		ok "${v_lower} = ${value}"
		simple_test "$v_lower"
	done
