#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

scriptdir="${CTDB_TEST_TMP_DIR}/scriptdir"
mkdir -p "${scriptdir}"

scriptdir=$(cd "$scriptdir" && echo "$PWD")

test_cleanup "rm -rf ${scriptdir}"

# Invalid path
invalid="${scriptdir}/notfound"
ok <<EOF
Script list ${invalid} failed with result=$(errcode ENOENT)
EOF
unit_test event_script_test list "${invalid}"

# Empty directory
ok <<EOF
No scripts found
EOF
unit_test event_script_test list "$scriptdir"

# Invalid script, doesn't end in ".script"
touch "${scriptdir}/prog"

ok <<EOF
No scripts found
EOF
unit_test event_script_test list "$scriptdir"

# Is not found because enabling "prog" actually looks for "prog.script"
ok <<EOF
Script enable ${scriptdir} prog completed with result=$(errcode ENOENT)
EOF
unit_test event_script_test enable "$scriptdir" "prog"

required_result 1 <<EOF
EOF
unit_test test -x "${scriptdir}/prog"

# Is not found because enabling "prog" actually looks for "prog.script"
ok <<EOF
Script disable ${scriptdir} prog completed with result=$(errcode ENOENT)
EOF
unit_test event_script_test disable "$scriptdir" "prog"

# Valid script
touch "$scriptdir/11.foo.script"

ok <<EOF
11.foo
EOF
unit_test event_script_test list "$scriptdir"

ok <<EOF
Script enable ${scriptdir} 11.foo completed with result=0
EOF
unit_test event_script_test enable "$scriptdir" "11.foo"

ok <<EOF
EOF
unit_test test -x "${scriptdir}/11.foo.script"

ok <<EOF
Script disable ${scriptdir} 11.foo.script completed with result=0
EOF
unit_test event_script_test disable "$scriptdir" "11.foo.script"

required_result 1 <<EOF
EOF
unit_test test -x "${scriptdir}/11.foo.script"

# Multiple scripts
touch "${scriptdir}/22.bar.script"

ok <<EOF
11.foo
22.bar
EOF
unit_test event_script_test list "$scriptdir"

# Symlink to existing file
ln -s "${scriptdir}/prog" "${scriptdir}/33.link.script"

ok <<EOF
11.foo
22.bar
33.link
EOF
unit_test event_script_test list "$scriptdir"

ok <<EOF
Script enable ${scriptdir} 33.link completed with result=$(errcode EINVAL)
EOF
unit_test event_script_test enable "$scriptdir" "33.link"


ok <<EOF
Script disable ${scriptdir} 33.link.script completed with result=$(errcode EINVAL)
EOF
unit_test event_script_test disable "$scriptdir" "33.link.script"

# Dangling symlink
rm "${scriptdir}/33.link.script"
ln -s "${scriptdir}/nosuchfile" "${scriptdir}/33.link.script"

ok <<EOF
11.foo
22.bar
33.link
EOF
unit_test event_script_test list "$scriptdir"

ok <<EOF
Script enable ${scriptdir} 33.link completed with result=$(errcode ENOENT)
EOF
unit_test event_script_test enable "$scriptdir" "33.link"


ok <<EOF
Script disable ${scriptdir} 33.link.script completed with result=$(errcode ENOENT)
EOF
unit_test event_script_test disable "$scriptdir" "33.link.script"

exit 0
