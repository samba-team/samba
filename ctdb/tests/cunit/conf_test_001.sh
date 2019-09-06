#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

conffile="${CTDB_TEST_TMP_DIR}/config.$$"

remove_files ()
{
	rm -f "$conffile"
}

test_cleanup remove_files

ok_null
unit_test conf_test 1

ok <<EOF
conf: unknown section [section1]
EOF
unit_test conf_test 2

ok <<EOF
conf: option "key1" already exists
EOF
unit_test conf_test 3

ok <<EOF
conf: option "key1" already exists
EOF
unit_test conf_test 4

ok_null
unit_test conf_test 5

ok <<EOF
[section1]
	key1 = foobar # temporary
	key2 = 20 # temporary
	key3 = false # temporary
EOF
unit_test conf_test 6

ok <<EOF
conf: validation for option "key1" failed
conf: validation for option "key2" failed
conf: validation for option "key3" failed
EOF
unit_test conf_test 7

cat > "$conffile" <<EOF
[section1]
EOF

required_error EINVAL <<EOF
conf: validation for section [section1] failed
[section1]
	# key1 = default
EOF
unit_test conf_test 8 "$conffile"

cat > "$conffile" <<EOF
[section1]
    key1 = unknown
EOF

required_error EINVAL <<EOF
conf: validation for section [section1] failed
[section1]
	# key1 = default
EOF
unit_test conf_test 8 "$conffile"

cat > "$conffile" <<EOF
[section1]
    key1 =
EOF

required_error EINVAL <<EOF
conf: empty value [section1] -> "key1"
[section1]
	# key1 = value1
	# key2 = 10
	key3 = false # temporary
EOF
unit_test conf_test 9 "$conffile"

cat > "$conffile" <<EOF
[section1]
    key3 =
EOF

required_error EINVAL <<EOF
conf: empty value [section1] -> "key3"
[section1]
	# key1 = value1
	# key2 = 10
	key3 = false # temporary
EOF
unit_test conf_test 9 "$conffile"

cat > "$conffile" <<EOF

[section1]
    key1 = value2  
    key2 =     20  # comment
key3    =    false
EOF

ok <<EOF
[section1]
	key1 = value2
	key2 = 20
	# key3 = true
EOF
unit_test conf_test 9 "$conffile"

cat > "$conffile" <<EOF
[section1]
key1 = value2  
EOF

ok <<EOF
[section1]
	key1 = value2
	# key2 = 10
	# key3 = true
EOF
unit_test conf_test 9 "$conffile"

cat > "$conffile" <<EOF
[section2]
    foo = bar
EOF

required_error EINVAL <<EOF
conf: unknown section [section2]
conf: unknown section for option "foo"
[section1]
	# key1 = value1
	# key2 = 10
	key3 = false # temporary
EOF
unit_test conf_test 10 "$conffile"

cat > "$conffile" <<EOF
[section1]
    key1 = value2
    foo = bar
    key2 = 20
EOF

required_error EINVAL <<EOF
conf: unknown option [section1] -> "foo"
[section1]
	# key1 = value1
	# key2 = 10
	key3 = false # temporary
EOF
unit_test conf_test 10 "$conffile"

cat > "$conffile" <<EOF
[section1]
    key1 = value2
    key2 = 20
    key3 = false
EOF

touch "${conffile}.reload"

ok <<EOF
[section1]
	# key1 = value1
	# key2 = 10
	# key3 = true
EOF
unit_test conf_test 11 "$conffile"

cat > "$conffile" <<EOF
[section1]
    key1 = value2
    key2 = 20
    key3 = false
EOF

cat > "${conffile}.reload" <<EOF
[section1]
    key1 = value3
EOF

ok <<EOF
[section1]
	key1 = value3
	# key2 = 10
	# key3 = true
EOF
unit_test conf_test 11 "$conffile"
