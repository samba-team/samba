#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_provision.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

. `dirname $0`/../../../testprogs/blackbox/subunit.sh

#Prepare an empty smb.conf to ensure it is overwritten
rm -rf $PREFIX/simple-default
mkdir -p $PREFIX/simple-default/etc
touch $PREFIX/simple-default/etc/smb.conf
testit "simple-default" $PYTHON $BINDIR/samba-tool domain provision --domain=FOO --realm=foo.example.com --targetdir=$PREFIX/simple-default --use-ntvfs
#And try with just whitespace
rm -rf $PREFIX/simple-dc
mkdir -p $PREFIX/simple-dc/etc
echo "  " > $PREFIX/simple-dc/etc/smb.conf
testit "simple-dc" $PYTHON $BINDIR/samba-tool domain provision --server-role="dc" --domain=FOO --realm=foo.example.com --domain-sid=S-1-5-21-4177067393-1453636373-93818738 --targetdir=$PREFIX/simple-dc --use-ntvfs
#The rest of these tests are with no smb.conf file present

rm -rf $PREFIX/simple-dc
testit "simple-dc-guids" $PYTHON $BINDIR/samba-tool domain provision --server-role="dc" --domain=FOO --realm=foo.example.com --domain-sid=S-1-5-21-4177067393-1453636373-93818738 --domain-guid=6054d36d-2bfd-44f1-a9cd-32cfbb06480b --ntds-guid=b838f255-c8aa-4fe8-9402-b7d61ca3bd1b --invocationid=6d4cff9a-2bbf-4b4c-98a2-36242ddb0bd6 --targetdir=$PREFIX/simple-dc --use-ntvfs
rm -rf $PREFIX/simple-dc-2008r2-schema
testit "simple-dc-2008r2-schema" $PYTHON $BINDIR/samba-tool domain provision --server-role="dc" --domain=FOO --realm=foo.example.com --targetdir=$PREFIX/simple-dc-2008r2-schema --use-ntvfs --base-schema=2008_R2
rm -rf $PREFIX/simple-member
testit "simple-member" $PYTHON $BINDIR/samba-tool domain provision --server-role="member" --domain=FOO --realm=foo.example.com --targetdir=$PREFIX/simple-member --use-ntvfs
rm -rf $PREFIX/simple-standalone
testit "simple-standalone" $PYTHON $BINDIR/samba-tool domain provision --server-role="standalone" --domain=FOO --realm=foo.example.com --targetdir=$PREFIX/simple-standalone --use-ntvfs
rm -rf $PREFIX/blank-dc
testit "blank-dc" $PYTHON $BINDIR/samba-tool domain provision --server-role="dc" --domain=FOO --realm=foo.example.com --domain-sid=S-1-5-21-4177067393-1453636373-93818738 --targetdir=$PREFIX/blank-dc --blank --use-ntvfs

reprovision() {
	$PYTHON $BINDIR/samba-tool domain provision --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/simple-default" --use-ntvfs
}

testit "reprovision" reprovision

V_2012_R2=69
V_2008_R2=47

check_baseschema() {
	ldbsearch="ldbsearch"
	if [ -x "$BINDIR/ldbsearch" ]; then
	    ldbsearch="$BINDIR/ldbsearch"
	fi

	base=$($ldbsearch -H $PREFIX/$1/private/sam.ldb -s base dn)
	dom=$(echo "$base" | grep "dn: " | cut -d " " -f 2);

	if [ -z "$dom" ]; then
		echo "Unexpected ldbsearch output: $base";
	fi

	version=$($ldbsearch -H $PREFIX/$1/private/sam.ldb -s base \
		  "objectVersion" -b "CN=SCHEMA,CN=CONFIGURATION,$dom");
	version_num=$(echo "$version" | grep "objectVersion: " | cut -d " " -f 2);

	if [ "$version_num" -eq "$2" ]; then
		return 0;
	fi

	echo "Fail: schema version $version_num != $2";
	return 1;
}

tname="schema version"
testit "$tname simple-default" check_baseschema simple-default $V_2012_R2
testit "$tname simple-dc" check_baseschema simple-dc $V_2012_R2
testit "$tname simple-member" check_baseschema simple-member $V_2012_R2
testit "$tname simple-standalone" check_baseschema simple-standalone $V_2012_R2
testit "$tname simple-dc-2008r2-schema" check_baseschema simple-dc-2008r2-schema $V_2008_R2

rm -rf $PREFIX/simple-default
rm -rf $PREFIX/simple-dc
rm -rf $PREFIX/blank-dc
rm -rf $PREFIX/simple-member
rm -rf $PREFIX/simple-standalone
rm -rf $PREFIX/partitions-only-dc

exit $failed
