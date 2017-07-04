#!/bin/sh
#
# Test for 'samba-tool user edit'

if [ $# -lt 3 ]; then
cat <<EOF
Usage: edit.sh SERVER USERNAME PASSWORD
EOF
exit 1;
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"

STpath=$(pwd)
. $STpath/testprogs/blackbox/subunit.sh

# create editor.sh
# this has to be hard linked to /tmp or 'samba-tool user edit' cannot find it
tmpeditor=$(mktemp --suffix .sh -p $STpath/bin samba-tool-editor-XXXXXXXX)

cat >$tmpeditor <<-'EOF'
#!/usr/bin/env bash
user_ldif="$1"
SED=$(which sed)
$SED -i -e 's/userAccountControl: 512/userAccountControl: 514/' $user_ldif
EOF

chmod +x $tmpeditor

failed=0

# Create a test user
subunit_start_test "Create_User"
output=$(${STpath}/source4/scripting/bin/samba-tool user create sambatool1 --random-password \
-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD")
status=$?
if [ "x$status" = "x0" ]; then
    subunit_pass_test "Create_User"
else
    echo "$output" | subunit_fail_test "Create_User"
    failed=$((failed + 1))
fi

# Edit test user
subunit_start_test "Edit_User"
output=$(${STpath}/source4/scripting/bin/samba-tool user edit sambatool1 --editor=$tmpeditor \
-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD")
status=$?
if [ "x$status" = "x0" ]; then
    subunit_pass_test "Edit_User"
else
    echo "$output" | subunit_fail_test "Edit_User"
    failed=$((failed + 1))
fi

# Delete test user
subunit_start_test "Delete_User"
output=$(${STpath}/source4/scripting/bin/samba-tool user delete sambatool1 \
-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD")
status=$?
if [ "x$status" = "x0" ]; then
    subunit_pass_test "Delete_User"
else
    echo "$output" | subunit_fail_test "Delete_User"
    failed=$((failed + 1))
fi

rm -f $tmpeditor

exit $failed
