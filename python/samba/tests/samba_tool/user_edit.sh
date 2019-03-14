#!/bin/sh
#
# Test for 'samba-tool user edit'

if [ $# -lt 3 ]; then
cat <<EOF
Usage: user_edit.sh SERVER USERNAME PASSWORD
EOF
exit 1;
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"

STpath=$(pwd)
. $STpath/testprogs/blackbox/subunit.sh

tmpeditor=$(mktemp --suffix .sh -p $STpath/bin samba-tool-editor-XXXXXXXX)
chmod +x $tmpeditor

create_test_user() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		user create sambatool1 --random-password \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

edit_user() {
	# create editor.sh
	cat >$tmpeditor <<-'EOF'
#!/usr/bin/env bash
user_ldif="$1"
SED=$(which sed)
$SED -i -e 's/userAccountControl: 512/userAccountControl: 514/' $user_ldif
EOF

	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
	user edit sambatool1 --editor=$tmpeditor \
	-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

delete_user() {
	$PYTHON ${STpath}/source4/scripting/bin/samba-tool \
		user delete sambatool1 \
		-H "ldap://$SERVER" "-U$USERNAME" "--password=$PASSWORD"
}

failed=0

testit "create_test_user" create_test_user || failed=`expr $failed + 1`
testit "edit_user" edit_user || failed=`expr $failed + 1`
testit "delete_user" delete_user || failed=`expr $failed + 1`

rm -f $tmpeditor

exit $failed
