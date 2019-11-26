#!/bin/sh
#
# Test for 'samba-tool contact edit'

if [ $# -lt 3 ]; then
cat <<EOF
Usage: contact_edit.sh SERVER USERNAME PASSWORD
EOF
exit 1;
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"

STpath=$(pwd)
. $STpath/testprogs/blackbox/subunit.sh

display_name="Björn"
display_name_b64="QmrDtnJu"
display_name_new="Renamed Bjoern"
# attribute value including control character
# echo -e "test \a string" | base64
display_name_con_b64="dGVzdCAHIHN0cmluZwo="

tmpeditor=$(mktemp --suffix .sh -p $STpath/bin samba-tool-editor-XXXXXXXX)
chmod +x $tmpeditor

create_test_contact() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		contact create testcontact1 \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

# Test edit contact - add base64 attributes
add_attribute_base64() {
	# create editor.sh
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
contact_ldif="\$1"

grep -v '^$' \$contact_ldif > \${contact_ldif}.tmp
echo "displayName:: $display_name_b64" >> \${contact_ldif}.tmp

mv \${contact_ldif}.tmp \$contact_ldif
EOF

	$PYTHON ${STpath}/source4/scripting/bin/samba-tool contact edit \
		testcontact1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

get_attribute_base64() {
	${STpath}/bin/ldbsearch '(&(objectClass=contact)(name=testcontact1))' \
		displayName \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

delete_attribute() {
	# create editor.sh
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
contact_ldif="\$1"

grep -v '^displayName' \$contact_ldif >> \${contact_ldif}.tmp
mv \${contact_ldif}.tmp \$contact_ldif
EOF
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool contact edit \
		testcontact1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

# Test edit contact - add base64 attribute value including control character
add_attribute_base64_control() {
	# create editor.sh
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
contact_ldif="\$1"

grep -v '^$' \$contact_ldif > \${contact_ldif}.tmp
echo "displayName:: $display_name_con_b64" >> \${contact_ldif}.tmp

mv \${contact_ldif}.tmp \$contact_ldif
EOF
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool contact edit \
		testcontact1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

get_attribute_base64_control() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool contact show \
		testcontact1 --attributes=displayName \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

get_attribute_force_no_base64() {
       # LDB_FLAG_FORCE_NO_BASE64_LDIF should be used here.
       $PYTHON ${STpath}/source4/scripting/bin/samba-tool contact show \
               testcontact1 --attributes=displayName \
               -H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

# Test edit contact - change base64 attribute value including control character
change_attribute_base64_control() {
	# create editor.sh
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
contact_ldif="\$1"

sed -i -e 's/displayName:: $display_name_con_b64/displayName: $display_name/' \
	\$contact_ldif
EOF
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool contact edit \
		testcontact1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

# Test edit contact - change attributes with LDB_FLAG_FORCE_NO_BASE64_LDIF
change_attribute_force_no_base64() {
	# create editor.sh
	# Expects that the original attribute is available as clear text,
	# because the LDB_FLAG_FORCE_NO_BASE64_LDIF should be used here.
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
contact_ldif="\$1"

sed -i -e 's/displayName: $display_name/displayName: $display_name_new/' \
	\$contact_ldif
EOF

	$PYTHON ${STpath}/source4/scripting/bin/samba-tool contact edit \
		testcontact1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

get_changed_attribute_force_no_base64() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool contact show \
		 testcontact1 --attributes=displayName \
		 -H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

delete_contact() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		contact delete testcontact1 \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

failed=0

testit "create_test_contact" create_test_contact || failed=`expr $failed + 1`
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
testit "delete_contact" delete_contact || failed=`expr $failed + 1`

rm -f $tmpeditor

exit $failed
