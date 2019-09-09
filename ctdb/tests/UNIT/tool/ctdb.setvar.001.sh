#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "get a variable, change its value"

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
	tail -n 1 |
	{
		read variable equals value

		# Increment original variable
		newvalue=$((value + 1))
		ok_null
		simple_test "$variable" "$newvalue"

		ok "${variable} = ${newvalue}"
		simple_test_other getvar "$variable"

		# Increment uppercase variable
		v_upper=$(echo "$variable" | tr "a-z" "A-Z")
		newvalue=$((newvalue + 1))
		ok_null
		simple_test "$v_upper" "$newvalue"

		ok "${variable} = ${newvalue}"
		simple_test_other getvar "$variable"

		# Put back original, lowercase
		v_lower=$(echo "$variable" | tr "A-Z" "a-z")
		ok_null
		simple_test "$v_lower" "$value"

		ok "${variable} = ${value}"
		simple_test_other getvar "$variable"
	}
