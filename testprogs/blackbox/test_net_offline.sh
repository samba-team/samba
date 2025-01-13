if [ $# -lt 4 ]; then
	cat <<EOF
Usage: test_net_offline.sh DC_SERVER DC_USERNAME DC_PASSWORD PREFIX_ABS
EOF
	exit 1
fi

DC_SERVER=$1
DC_USERNAME=$2
DC_PASSWORD=$3
BASEDIR=$4

HOSTNAME=$(dd if=/dev/urandom bs=1 count=32 2>/dev/null | sha1sum | cut -b 1-10)

RUNDIR=$(pwd)
cd $BASEDIR
WORKDIR=$(mktemp -d -p .)
WORKDIR=$(basename $WORKDIR)
ODJFILE="$BASEDIR/$WORKDIR/odj_provision.txt"

cp -a client/* $WORKDIR/
sed -ri "s@(dir|directory) = (.*)/client/@\1 = \2/$WORKDIR/@" $WORKDIR/client.conf
sed -ri "s/netbios name = .*/netbios name = $HOSTNAME/" $WORKDIR/client.conf
rm -f $WORKDIR/private/secrets.tdb
cd $RUNDIR

failed=0

net_tool="$BINDIR/net --configfile=$BASEDIR/$WORKDIR/client.conf --option=security=ads"
samba_texpect="$BINDIR/texpect"

# Load test functions
. $(dirname $0)/subunit.sh

netbios=$(grep "netbios name" $BASEDIR/$WORKDIR/client.conf | cut -f2 -d= | awk '{$1=$1};1')

# 0. Test with machine_name != lp_netbios_name()

NONLOCALMACHINE=win11

testit "provision with non local machine name" \
	${VALGRIND} ${net_tool} offlinejoin provision domain="${REALM}" machine_name="${NONLOCALMACHINE}" savefile="${ODJFILE}" -U"${DC_USERNAME}%${DC_PASSWORD}" || \
	failed=$((failed + 1))

testit "net rpc user delete" \
	${VALGRIND} ${net_tool} rpc user delete "${NONLOCALMACHINE}$" -U"${DC_USERNAME}%${DC_PASSWORD}" -S "${DC_SERVER}" || \
	failed=$((failed + 1))

rm -f "${ODJFILE}"

# 1. Test w/o dcname

testit "provision without dcname" $VALGRIND $net_tool offlinejoin provision domain=$REALM machine_name=$netbios savefile=$ODJFILE -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

testit "requestodj" $VALGRIND $net_tool offlinejoin requestodj loadfile=$ODJFILE || failed=$(expr $failed + 1)

testit "testjoin" $VALGRIND $net_tool ads testjoin -P --use-kerberos=required || failed=$(expr $failed + 1)

rm -f $ODJFILE

testit "leave" $VALGRIND $net_tool ads leave  -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

# 2. Test with dcname

testit "provision with dcname" $VALGRIND $net_tool offlinejoin provision domain=$REALM machine_name=$netbios savefile=$ODJFILE dcname=$DC_SERVER -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

testit "requestodj" $VALGRIND $net_tool offlinejoin requestodj loadfile=$ODJFILE || failed=$(expr $failed + 1)

testit "testjoin" $VALGRIND $net_tool ads testjoin -P --use-kerberos=required || failed=$(expr $failed + 1)

rm -f $ODJFILE

testit "leave" $VALGRIND $net_tool ads leave  -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

# 3. Test with defpwd

testit "provision with dcname and default password" $VALGRIND $net_tool offlinejoin provision domain=$REALM machine_name=$netbios savefile=$ODJFILE dcname=$DC_SERVER defpwd -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

testit "requestodj" $VALGRIND $net_tool offlinejoin requestodj loadfile=$ODJFILE || failed=$(expr $failed + 1)

testit "testjoin" $VALGRIND $net_tool ads testjoin -P --use-kerberos=required || failed=$(expr $failed + 1)

rm -f $ODJFILE

testit "leave" $VALGRIND $net_tool ads leave  -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

test_compose_odj() {
	local mode=$1
	local composeargv=()

	# Retrieve the necessary information to compose the ODJ blob
	# The machine needs to be correctly joined at this point
	local netbios_domain_name=$($net_tool ads lookup | awk -F': ' '/^Pre-Win2k Domain/ {print $2}')
	local domain_sid=$($net_tool getdomainsid | awk -F': ' "/^SID for domain $netbios_domain_name/ {print \$2}")
	local domain_guid=$($net_tool ads lookup | awk -F': ' '/^GUID/ {print $2}')
	local forest_name=$($net_tool ads lookup | awk -F': ' '/^Forest/ {print $2}')
	local dc_name=$($net_tool ads info | awk -F': ' '/^LDAP server name/ {print $2}')
	local dc_address=$($net_tool ads info | awk -F': ' '/^LDAP server:/ {print $2}')
	local ret=1
	local out=""

	composeargv=( \
		"domain_sid=${domain_sid}" \
		"domain_guid=${domain_guid}" \
		"forest_name=${forest_name}" \
		"-S ${dc_name}" \
		"-I ${dc_address}" \
		"savefile=${ODJFILE}"
	)
	case $mode in
	machacct)
		cmd='$net_tool offlinejoin composeodj ${composeargv[@]} -P 2>&1'
		out=$(eval $cmd)
		ret=$?
	;;
	stdinfd)
		cmd='echo ${netbios} | $net_tool offlinejoin composeodj ${composeargv[@]} -U${netbios^^}\$ 2>&1'
		out=$(PASSWD_FD=0 eval $cmd)
		ret=$?
	;;
	callback)
		tmpfile=$BASEDIR/$WORKDIR/composeodj_password_script
		cat >$tmpfile <<EOF
expect Password for [${netbios_domain_name^^}\\${netbios^^}\$]:
send $netbios\n
EOF
		cmd='$samba_texpect -v $tmpfile $net_tool offlinejoin composeodj ${composeargv[@]} 2>&1'
		out=$(eval $cmd)
		ret=$?
		rm -f $tmpfile
	;;
	*)
		out="Unknown mode '$mode'"
	;;
	esac

	if [ $ret -ne 0 ]; then
		echo "Failed to compose ODJ blob: $out"
		return 1
	fi
}

# 4. Test composeodj

modes=("machacct" "stdinfd" "callback")
for mode in "${modes[@]}"; do

	defpwd="defpwd"
	if [ "$mode" == "machacct" ]; then
		defpwd=""
	fi

	testit "provision[$mode]" $VALGRIND $net_tool offlinejoin provision domain=$REALM machine_name=$netbios savefile=$ODJFILE $defpwd -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

	testit "requestodj [$mode]" $VALGRIND $net_tool offlinejoin requestodj loadfile=$ODJFILE || failed=$(expr $failed + 1)

	testit "testjoin [$mode]" $VALGRIND $net_tool ads testjoin -P --use-kerberos=required || failed=$(expr $failed + 1)

	testit "removeodjblob [$mode]" rm $ODJFILE || failed=$(expr $failed + 1)

	testit "composeodj [$mode]" test_compose_odj $mode || failed=$(expr $failed + 1)

	testit "removesecretsdb [$mode]" rm $BASEDIR/$WORKDIR/private/secrets.tdb || failed=$(expr $failed + 1)

	testit "requestodj [$mode]" $VALGRIND $net_tool offlinejoin requestodj loadfile=$ODJFILE || failed=$(expr $failed + 1)

	testit "removeodjblob [$mode]" rm $ODJFILE || failed=$(expr $failed + 1)

	testit "testjoin [$mode]" $VALGRIND $net_tool ads testjoin -P --use-kerberos=required || failed=$(expr $failed + 1)

	testit "leave [$mode]" $VALGRIND $net_tool ads leave  -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)
done

rm -rf $BASEDIR/$WORKDIR

exit $failed
