#!/bin/bash

if [ $# -lt 1 ]; then
	cat <<EOF
Usage: test_alias_membership.sh PREFIX
EOF
	exit 1
fi

PREFIX=$1
ADDC_CONFIGFILE="$PREFIX/ad_dc/etc/smb.conf"
shift 5
failed=0

. "$(dirname "$0")/subunit.sh"
. "$(dirname "$0")/common_test_fns.inc"

net_tool="${BINDIR}/net"
wbinfo="${BINDIR}/wbinfo"

# Create the following membership structure and test if exactly the 9 users
# are listed as members of the alias A1.
#
#  A1
#  |- A1U1
#  |- A1U2
#  |
#  |- G1
#  |  |- G1U1
#  |  |- G1U2
#  |
#  |- G2
#  |  |- G2U1
#  |  |- G2U2
#  |  |
#  |  |- G3
#  |     |- G3U1
#  |     |- G3U2
#  |
#  |- LG1
#     |- user1
#
#
# Local entities:
#
# Alias: A1
# Group: LG1
# User:  user1 (no need to create, already available)
#
# Domain entities:
#
# Group: ADDOMAIN/G1 ADDOMAIN/G2 ADDOMAIN/G3
# User: ADDOMAIN/A1U1 ADDOMAIN/A1U2
#       ADDOMAIN/G1U1 ADDOMAIN/G1U2
#       ADDOMAIN/G2U1 ADDOMAIN/G2U2
#       ADDOMAIN/G3U1 ADDOMAIN/G3U2


LOCALPREFIX="IDMAPRIDMEMBER"

function create_group() {
	_group_name="${1}"
	GNUPGHOME="${PREFIX}/ad_dc/gnupg" "${PYTHON}" "${BINDIR}/samba-tool" \
		group add "${_group_name}" --configfile="${ADDC_CONFIGFILE}"
	_ret=$?
	if [ ${_ret} -ne 0 ]; then
		echo "Failed to create group ${_group_name}"
		return 1
	fi
	return 0
}

function delete_group() {
	_group_name="${1}"
	GNUPGHOME="${PREFIX}/ad_dc/gnupg" "${PYTHON}" "${BINDIR}/samba-tool" \
		group delete "${_group_name}" --configfile="${ADDC_CONFIGFILE}"
	_ret=$?
	if [ ${_ret} -ne 0 ]; then
		echo "Failed to delete group ${_group_name}"
		return 1
	fi
	return 0
}

function create_user() {
	_user_name="${1}"
	_password="${2}"
	GNUPGHOME="${PREFIX}/ad_dc/gnupg" "${PYTHON}" "${BINDIR}/samba-tool" \
		user create "${_user_name}" "${_password}" \
		--configfile="${ADDC_CONFIGFILE}"
	_ret=$?
	if [ ${_ret} -ne 0 ]; then
		echo "Failed to create user ${_user_name}"
		return 1
	fi
	return 0
}

function delete_user() {
	_user_name="${1}"
	GNUPGHOME="${PREFIX}/ad_dc/gnupg" "${PYTHON}" "${BINDIR}/samba-tool" \
		user delete "${_user_name}" --configfile="${ADDC_CONFIGFILE}"
	_ret=$?
	if [ ${_ret} -ne 0 ]; then
		echo "Failed to delete user ${_user_name}"
		return 1
	fi
	return 0
}

for G in G1 G2 G3
do
	testit "create group '$G'" create_group "${G}" || failed=$((failed + 1))
done

for U in G1U1 G1U2 G2U1 G2U2 G3U1 G3U2 A1U1 A1U2
do
	testit "create user '$U'" create_user "${U}" Passw0rd.7 || failed=$((failed + 1))
done

while read -a line
do
	group=${line[0]}
	member=${line[1]}
	testit "add member '$member' to group '$group'" "$PYTHON" "$BINDIR/samba-tool" group addmembers --configfile="$ADDC_CONFIGFILE" "$group" "$member" || failed=$((failed + 1))
done <<___MEMBERS
G1 G1U1
G1 G1U2
G2 G2U1
G2 G2U2
G2 G3
G3 G3U1
G3 G3U2
___MEMBERS

testit "net sam createlocalgroup A1" "$VALGRIND" "$net_tool" sam createlocalgroup A1 || failed=$((failed + 1))
testit "net createdomaingroup LG1" "$VALGRIND" "$net_tool" sam createdomaingroup LG1 || failed=$((failed + 1))
testit "net sam addmem user1 to LG1" "$VALGRIND" "$net_tool" sam addmem LG1 "${LOCALPREFIX}\user1" || failed=$((failed + 1))

for M in "ADDOMAIN\A1U1" "ADDOMAIN\A1U2" "ADDOMAIN\G1" "ADDOMAIN\G2" "${LOCALPREFIX}\LG1"
do
	testit "net sam addmem $M to A1" "$VALGRIND" "$net_tool" sam addmem A1 "$M" || failed=$((failed + 1))
done

# do not use testit_grep (that would call 9 times wbinfo) but use grep on the
# stored output
a1_alias=$( "$wbinfo" --group-info A1 )

for U in ADDOMAIN/a1u1 "${LOCALPREFIX}/user1" ADDOMAIN/g1u1 ADDOMAIN/g1u2 ADDOMAIN/g2u1 ADDOMAIN/g2u2 ADDOMAIN/g3u1 ADDOMAIN/g3u2 ADDOMAIN/a1u2;
do
	count=$(echo "$a1_alias" | grep -c "$U")
	testit "User $U is in alias" test "$count" -eq 1 || failed=$((failed + 1))
done

# check that there are exactly 8 commas separating the 9 users
count=$(echo "$a1_alias" | grep -o , | wc -l)
testit "There are 9 users" test "$count" -eq 8 || failed=$((failed + 1))

# cleanup

for M in "ADDOMAIN\A1U1" "ADDOMAIN\A1U2" "ADDOMAIN\G1" "ADDOMAIN\G2" "${LOCALPREFIX}\LG1"
do
	testit "net sam delmem $M from A1" "$VALGRIND" "$net_tool" sam delmem A1 "$M" || failed=$((failed + 1))
done
testit "net sam delmem user1 from LG1" "$VALGRIND" "$net_tool" sam delmem LG1 "${LOCALPREFIX}\user1" || failed=$((failed + 1))
testit "net sam deletelocalgroup A1" "$VALGRIND" "$net_tool" sam deletelocalgroup A1 || failed=$((failed + 1))
testit "net sam deletedomaingroup LG1" "$VALGRIND" "$net_tool" sam deletedomaingroup LG1 || failed=$((failed + 1))

while read -a line
do
	group=${line[0]}
	member=${line[1]}
	testit "del member '$member' from group '$group'" "$PYTHON" "$BINDIR/samba-tool" group removemembers --configfile="$ADDC_CONFIGFILE" "$group" "$member" || failed=$((failed + 1))
done <<___MEMBERS
G1 G1U1
G1 G1U2
G2 G2U1
G2 G2U2
G2 G3
G3 G3U1
G3 G3U2
___MEMBERS

for G in G1 G2 G3
do
	testit "delete group '$G'" delete_group "${G}" || failed=$((failed + 1))
done

for U in G1U1 G1U2 G2U1 G2U2 G3U1 G3U2 A1U1 A1U2
do
	testit "delete user '$U'" delete_user "${U}" || failed=$((failed + 1))
done

exit $failed
