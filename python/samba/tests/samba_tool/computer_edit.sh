#!/bin/sh
#
# Test for 'samba-tool computer edit'

if [ $# -lt 3 ]; then
cat <<EOF
Usage: computer_edit.sh SERVER USERNAME PASSWORD
EOF
exit 1;
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"

STpath=$(pwd)
. $STpath/testprogs/blackbox/subunit.sh

display_name="Björns laptop"
display_name_b64="QmrDtnJucyBsYXB0b3A="
display_name_new="Bjoerns new laptop"
# attribute value including control character
# echo -e "test \a string" | base64
display_name_con_b64="dGVzdCAHIHN0cmluZwo="

tmpeditor=$(mktemp --suffix .sh -p $STpath/bin samba-tool-editor-XXXXXXXX)
chmod +x $tmpeditor

create_test_computer() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		computer create testmachine1 \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

edit_computer() {
	# create editor.sh
	# enable computer account
	cat >$tmpeditor <<-'EOF'
#!/usr/bin/env bash
computer_ldif="$1"
SED=$(which sed)
$SED -i -e 's/userAccountControl: 4098/userAccountControl: 4096/' $computer_ldif
EOF

	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		computer edit testmachine1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

# Test edit computer - add base64 attributes
add_attribute_base64() {
	# create editor.sh
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
computer_ldif="\$1"

grep -v '^$' \$computer_ldif > \${computer_ldif}.tmp
echo "displayName:: $display_name_b64" >> \${computer_ldif}.tmp

mv \${computer_ldif}.tmp \$computer_ldif
EOF

	$PYTHON ${STpath}/source4/scripting/bin/samba-tool computer edit \
		testmachine1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

get_attribute_base64() {
	${STpath}/bin/ldbsearch '(sAMAccountName=testmachine1$)' displayName \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

delete_attribute() {
	# create editor.sh
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
computer_ldif="\$1"

grep -v '^displayName' \$computer_ldif >> \${computer_ldif}.tmp
mv \${computer_ldif}.tmp \$computer_ldif
EOF
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool computer edit \
		testmachine1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

# Test edit computer - add base64 attribute value including control character
add_attribute_base64_control() {
	# create editor.sh
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
computer_ldif="\$1"

grep -v '^$' \$computer_ldif > \${computer_ldif}.tmp
echo "displayName:: $display_name_con_b64" >> \${computer_ldif}.tmp

mv \${computer_ldif}.tmp \$computer_ldif
EOF
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool computer edit \
		testmachine1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

get_attribute_base64_control() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool computer show \
		testmachine1 --attributes=displayName \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

get_attribute_force_no_base64() {
	# LDB_FLAG_FORCE_NO_BASE64_LDIF should be used here.
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool computer show \
		testmachine1 --attributes=displayName \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

# Test edit computer - change base64 attribute value including control character
change_attribute_base64_control() {
	# create editor.sh
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
computer_ldif="\$1"

sed -i -e 's/displayName:: $display_name_con_b64/displayName: $display_name/' \
	\$computer_ldif
EOF
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool computer edit \
		testmachine1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

# Test edit computer - change attributes with LDB_FLAG_FORCE_NO_BASE64_LDIF
change_attribute_force_no_base64() {
	# create editor.sh
	# Expects that the original attribute is available as clear text,
	# because the LDB_FLAG_FORCE_NO_BASE64_LDIF should be used here.
	cat >$tmpeditor <<EOF
#!/usr/bin/env bash
computer_ldif="\$1"

sed -i -e 's/displayName: $display_name/displayName: $display_name_new/' \
	\$computer_ldif
EOF

	$PYTHON ${STpath}/source4/scripting/bin/samba-tool computer edit \
		testmachine1 --editor=$tmpeditor \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

get_changed_attribute_force_no_base64() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool computer show \
		 testmachine1 --attributes=displayName \
		 -H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

delete_computer() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		computer delete testmachine1 \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

failed=0

testit "create_test_computer" create_test_computer || failed=`expr $failed + 1`
testit "edit_computer" edit_computer || failed=`expr $failed + 1`
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
testit "delete_computer" delete_computer || failed=`expr $failed + 1`

rm -f $tmpeditor

exit $failed
