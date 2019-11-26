#!/bin/sh
#
# Test for 'samba-tool group edit'

if [ $# -lt 3 ]; then
cat <<EOF
Usage: group_edit.sh SERVER USERNAME PASSWORD
EOF
exit 1;
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"

STpath=$(pwd)
. $STpath/testprogs/blackbox/subunit.sh

display_name="Users in Göttingen"
display_name_b64="VXNlcnMgaW4gR8O2dHRpbmdlbg=="
display_name_new="Users in Goettingen"
# attribute value including control character
# echo -e "test \a string" | base64
display_name_con_b64="dGVzdCAHIHN0cmluZwo="

tmpeditor=$(mktemp --suffix .sh -p $STpath/bin samba-tool-editor-XXXXXXXX)
chmod +x $tmpeditor

create_test_group() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		group add testgroup1 \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

delete_test_group() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		group delete testgroup1 \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

create_test_user() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		user create testuser1 --random-password \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

delete_test_user() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		user delete testuser1 \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

add_member() {
	user_dn=$($PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		user show testuser1 --attributes=dn \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD" | \
		grep ^dn: | cut -d' ' -f2)

	# create editor.sh
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
group_ldif="\$1"

grep -v '^$' \$group_ldif > \${group_ldif}.tmp
echo "member: $user_dn" >> \${group_ldif}.tmp

mv \${group_ldif}.tmp \$group_ldif
EOF

	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		group edit testgroup1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

get_member() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		group listmembers testgroup1 \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

# Test edit group - add base64 attributes
add_attribute_base64() {
	# create editor.sh
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
group_ldif="\$1"

grep -v '^$' \$group_ldif > \${group_ldif}.tmp
echo "displayName:: $display_name_b64" >> \${group_ldif}.tmp

mv \${group_ldif}.tmp \$group_ldif
EOF

	$PYTHON ${STpath}/source4/scripting/bin/samba-tool group edit \
		testgroup1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

get_attribute_base64() {
	${STpath}/bin/ldbsearch '(sAMAccountName=testgroup1)' displayName \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

delete_attribute() {
	# create editor.sh
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
group_ldif="\$1"

grep -v '^displayName' \$group_ldif >> \${group_ldif}.tmp
mv \${group_ldif}.tmp \$group_ldif
EOF
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool group edit \
		testgroup1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

# Test edit group - add base64 attribute value including control character
add_attribute_base64_control() {
	# create editor.sh
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
group_ldif="\$1"

grep -v '^$' \$group_ldif > \${group_ldif}.tmp
echo "displayName:: $display_name_con_b64" >> \${group_ldif}.tmp

mv \${group_ldif}.tmp \$group_ldif
EOF
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool group edit \
		testgroup1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

get_attribute_base64_control() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool group show \
		testgroup1 --attributes=displayName \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

get_attribute_force_no_base64() {
       # LDB_FLAG_FORCE_NO_BASE64_LDIF should be used here.
       $PYTHON ${STpath}/source4/scripting/bin/samba-tool group show \
               testgroup1 --attributes=displayName \
               -H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

# Test edit group - change base64 attribute value including control character
change_attribute_base64_control() {
	# create editor.sh
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
group_ldif="\$1"

sed -i -e 's/displayName:: $display_name_con_b64/displayName: $display_name/' \
	\$group_ldif
EOF
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool group edit \
		testgroup1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

# Test edit group - change attributes with LDB_FLAG_FORCE_NO_BASE64_LDIF
change_attribute_force_no_base64() {
	# create editor.sh
	# Expects that the original attribute is available as clear text,
	# because the LDB_FLAG_FORCE_NO_BASE64_LDIF should be used here.
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
group_ldif="\$1"

sed -i -e 's/displayName: $display_name/displayName: $display_name_new/' \
	\$group_ldif
EOF

	$PYTHON ${STpath}/source4/scripting/bin/samba-tool group edit \
		testgroup1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

get_changed_attribute_force_no_base64() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool group show \
		 testgroup1 --attributes=displayName \
		 -H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

failed=0

testit "create_test_group" create_test_group || failed=`expr $failed + 1`
testit "create_test_user" create_test_user || failed=`expr $failed + 1`
testit "add_member" add_member || failed=`expr $failed + 1`
testit_grep "get_member" "^testuser1" get_member || failed=`expr $failed + 1`
testit "add_attribute_base64" add_attribute_base64 || failed=`expr $failed + 1`
testit_grep "get_attribute_base64" "^displayName:: $display_name_b64" get_attribute_base64 || failed=`expr $failed + 1`
testit "delete_attribute" delete_attribute || failed=`expr $failed + 1`
testit "add_attribute_base64_control" add_attribute_base64_control || failed=`expr $failed + 1`
testit_grep "get_attribute_base64_control" "^displayName:: $display_name_con_b64" get_attribute_base64_control || failed=`expr $failed + 1`
testit "change_attribute_base64_control" change_attribute_base64_control || failed=`expr $failed + 1`
testit_grep "get_attribute_base64" "^displayName:: $display_name_b64" get_attribute_base64 || failed=`expr $failed + 1`
testit_grep "get_attribute_force_no_base64" "^displayName: $display_name" get_attribute_force_no_base64 || failed=`expr $failed + 1`
testit "change_attribute_force_no_base64" change_attribute_force_no_base64 || failed=`expr $failed + 1`
testit_grep "get_changed_attribute_force_no_base64" "^displayName: $display_name_new" get_changed_attribute_force_no_base64 || failed=`expr $failed + 1`
testit "delete_test_group" delete_test_group || failed=`expr $failed + 1`
testit "delete_test_user" delete_test_user || failed=`expr $failed + 1`

rm -f $tmpeditor

exit $failed
