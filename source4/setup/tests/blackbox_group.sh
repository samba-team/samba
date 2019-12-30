#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_group.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

. `dirname $0`/../../../testprogs/blackbox/subunit.sh


rm -rf $PREFIX/simple-dc
mkdir -p $PREFIX
testit "simple-dc" $PYTHON $BINDIR/samba-tool domain provision --server-role="dc" --domain=FOO --realm=foo.example.com --domain-sid=S-1-5-21-4177067393-1453636373-93818738 --targetdir=$PREFIX/simple-dc --use-ntvfs
samba_tool="./bin/samba-tool"

CONFIG="--configfile=$PREFIX/simple-dc/etc/smb.conf"

#creation of two test users
testit "user add" $PYTHON $samba_tool user create $CONFIG --given-name="User" --surname="Tester" --initial="UT" testuser testp@ssw0Rd
testit "user add" $PYTHON $samba_tool user create $CONFIG --given-name="User1" --surname="Tester" --initial="UT" testuser1 testp@ssw0Rd

# test samba-tool user getgroups command
user_getgroups_primary_only() {
	res=$($PYTHON $samba_tool user getgroups $CONFIG testuser)

	primary_group=$(echo $res)
	echo $primary_group | grep -q "^Domain Users$" || return 1
}
testit "user getgroups primary only" user_getgroups_primary_only

#test creation of six different groups
testit "group add" $PYTHON $samba_tool group add $CONFIG --group-scope='Domain' --group-type='Security' --description='DomainSecurityGroup' --mail-address='dsg@samba.org' --notes='Notes' dsg
testit "group add" $PYTHON $samba_tool group add $CONFIG --group-scope='Global' --group-type='Security' --description='GlobalSecurityGroup' --mail-address='gsg@samba.org' --notes='Notes' gsg
testit "group add" $PYTHON $samba_tool group add $CONFIG --group-scope='Universal' --group-type='Security' --description='UniversalSecurityGroup' --mail-address='usg@samba.org' --notes='Notes' usg
testit "group add" $PYTHON $samba_tool group add $CONFIG --group-scope='Domain' --group-type='Distribution' --description='DomainDistributionGroup' --mail-address='ddg@samba.org' --notes='Notes' ddg
testit "group add" $PYTHON $samba_tool group add $CONFIG --group-scope='Global' --group-type='Distribution' --description='GlobalDistributionGroup' --mail-address='gdg@samba.org' --notes='Notes' gdg
testit "group add" $PYTHON $samba_tool group add $CONFIG --group-scope='Universal' --group-type='Distribution' --description='UniversalDistributionGroup' --mail-address='udg@samba.org' --notes='Notes' udg

#test adding test users to all groups by their username
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG dsg testuser,testuser1
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG gsg testuser,testuser1
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG usg testuser,testuser1
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG ddg testuser,testuser1
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG gdg testuser,testuser1
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG udg testuser,testuser1

# test samba-tool user getgroups command
user_getgroups() {
	groups="dsg gsg usg ddg gdg udg"

	res=$($PYTHON $samba_tool user getgroups $CONFIG testuser)
	for g in $groups ; do
		echo "$res" | grep -q "^${g}$" || return 1
	done

	# the users primary group is expected in the first line
	primary_group=$(echo "$res" | head -1)
	echo $primary_group | grep -q "^Domain Users$" || return 1
}
testit "user getgroups" user_getgroups

# test samba-tool user getgroups --full-dn command
user_getgroups_full_dn() {
	groups="dsg gsg usg ddg gdg udg"

	res=$($PYTHON $samba_tool user getgroups --full-dn $CONFIG testuser)
	for g in $groups ; do
		group_dn=$($PYTHON $samba_tool group show $CONFIG $g --attributes=dn)
		echo "$res" | grep -q "^${group_dn}$" || return 1
	done

	# the users primary group is expected in the first line
	primary_group=$(echo "$res" | head -1)
	group_dn=$($PYTHON $samba_tool group show $CONFIG "Domain Users" --attributes=dn)
	echo $primary_group | grep -q "^${group_dn}$" || return 1
}
testit "user getgroups full-dn" user_getgroups

# test settings a users primary group
user_getgroups_primary_first() {
	expected_primary_group=$1
	res=$($PYTHON $samba_tool user getgroups $CONFIG testuser)

	# the users primary group is expected in the first line
	primary_group=$(echo "$res" | head -1)
	echo $primary_group | grep -q "^${expected_primary_group}$" || return 1
}
testit "user setprimarygroup" $PYTHON $samba_tool user setprimarygroup $CONFIG testuser dsg
testit "user getgroups primary first" user_getgroups_primary_first dsg
testit "user setprimarygroup" $PYTHON $samba_tool user setprimarygroup $CONFIG testuser gsg
testit "user getgroups primary first" user_getgroups_primary_first gsg

# reset group (without testit, because I do not know how to quote the groupname)
$PYTHON $samba_tool user setprimarygroup $CONFIG testuser 'Domain Users'

#test removing test users from all groups by their username
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG dsg testuser,testuser1
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG gsg testuser,testuser1
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG usg testuser,testuser1
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG ddg testuser,testuser1
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG gdg testuser,testuser1
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG udg testuser,testuser1

# creation of two test contacts
testit "contact create" $PYTHON $samba_tool contact create $CONFIG --given-name="Con" --surname="Tester" --initial="CT" testcontact
testit "contact create" $PYTHON $samba_tool contact create $CONFIG --given-name="Con1" --surname="Tester" --initial="CT" testcontact1

# test adding test contacts to all groups by their cn
testit "group addmembers contact" $PYTHON $samba_tool group addmembers $CONFIG dsg testcontact,testcontact1 --object-types=contact
testit "group addmembers contact" $PYTHON $samba_tool group addmembers $CONFIG gsg testcontact,testcontact1 --object-types=contact
testit "group addmembers contact" $PYTHON $samba_tool group addmembers $CONFIG usg testcontact,testcontact1 --object-types=contact
testit "group addmembers contact" $PYTHON $samba_tool group addmembers $CONFIG ddg testcontact,testcontact1 --object-types=contact
testit "group addmembers contact" $PYTHON $samba_tool group addmembers $CONFIG gdg testcontact,testcontact1 --object-types=contact
testit "group addmembers contact" $PYTHON $samba_tool group addmembers $CONFIG udg testcontact,testcontact1 --object-types=contact

# test removing test contacts from all groups by their cn
testit "group removemembers contact" $PYTHON $samba_tool group removemembers $CONFIG dsg testcontact,testcontact1 --object-types=contact
testit "group removemembers contact" $PYTHON $samba_tool group removemembers $CONFIG gsg testcontact,testcontact1 --object-types=contact
testit "group removemembers contact" $PYTHON $samba_tool group removemembers $CONFIG usg testcontact,testcontact1 --object-types=contact
testit "group removemembers contact" $PYTHON $samba_tool group removemembers $CONFIG ddg testcontact,testcontact1 --object-types=contact
testit "group removemembers contact" $PYTHON $samba_tool group removemembers $CONFIG gdg testcontact,testcontact1 --object-types=contact
testit "group removemembers contact" $PYTHON $samba_tool group removemembers $CONFIG udg testcontact,testcontact1 --object-types=contact

# should not find test contact, because --object-types=user is specified
testit_expect_failure "group addmembers contact failure" $PYTHON $samba_tool group addmembers $CONFIG dsg testcontact --object-types=user

# test add contact with --object-types=all
testit "group addmembers contact object-type all" $PYTHON $samba_tool group addmembers $CONFIG dsg testcontact --object-types=all

# test remove contact with --object-types=all
testit "group removemembers contact object-type all" $PYTHON $samba_tool group removemembers $CONFIG dsg testcontact --object-types=all

# add test contact by DN
testit "group addmembers contact dn" $PYTHON $samba_tool group addmembers $CONFIG dsg --member-dn=CN=testcontact,DC=foo,DC=example,DC=com

# remove test contact by DN
testit "group removemembers contact dn" $PYTHON $samba_tool group removemembers $CONFIG dsg --member-dn=CN=testcontact,DC=foo,DC=example,DC=com

# delete test contacts
testit "contact delete" $PYTHON $samba_tool contact delete $CONFIG testcontact
testit "contact delete" $PYTHON $samba_tool contact delete $CONFIG testcontact1

# creation of two test contacts with the same name in different OUs
testit "ou create" $PYTHON $samba_tool ou create $CONFIG OU=tconou1
testit "ou create" $PYTHON $samba_tool ou create $CONFIG OU=tconou2
testit "contact create ou" $PYTHON $samba_tool contact create $CONFIG testcontact --ou=OU=tconou1
testit "contact create ou" $PYTHON $samba_tool contact create $CONFIG testcontact --ou=OU=tconou2

# expect failure here, since there are multiple results for testcontact
testit_expect_failure "group addmembers contact same name failure" $PYTHON $samba_tool group addmembers $CONFIG dsg testcontact

# add both contacts by DN
testit "group addmembers contact dn" $PYTHON $samba_tool group addmembers $CONFIG dsg --member-dn=CN=testcontact,OU=tconou1,DC=foo,DC=example,DC=com --member-dn=CN=testcontact,OU=tconou2,DC=foo,DC=example,DC=com

# remove both contacts by DN
testit "group removemembers contact dn" $PYTHON $samba_tool group removemembers $CONFIG dsg --member-dn=CN=testcontact,OU=tconou1,DC=foo,DC=example,DC=com --member-dn=CN=testcontact,OU=tconou2,DC=foo,DC=example,DC=com

# delete both contacts by DN
testit "contact delete" $PYTHON $samba_tool contact delete $CONFIG CN=testcontact,OU=tconou1
testit "contact delete" $PYTHON $samba_tool contact delete $CONFIG CN=testcontact,OU=tconou2

#test adding test users to all groups by their cn
#testit "group addmembers" $samba_tool group addmembers $CONFIG dsg "User UT. Tester,User1 UT. Tester"
#testit "group addmembers" $samba_tool group addmembers $CONFIG gsg "User UT. Tester,User1 UT. Tester"
#testit "group addmembers" $samba_tool group addmembers $CONFIG usg "User UT. Tester,User1 UT. Tester"
#testit "group addmembers" $samba_tool group addmembers $CONFIG ddg "User UT. Tester,User1 UT. Tester"
#testit "group addmembers" $samba_tool group addmembers $CONFIG gdg "User UT. Tester,User1 UT. Tester"
#testit "group addmembers" $samba_tool group addmembers $CONFIG udg "User UT. Tester,User1 UT. Tester"

#test removing test users from all groups by their cn
#testit "group removemembers" $samba_tool group removemembers $CONFIG dsg "User UT. Tester,User1 UT. Tester"
#testit "group removemembers" $samba_tool group removemembers $CONFIG gsg "User UT. Tester,User1 UT. Tester"
#testit "group removemembers" $samba_tool group removemembers $CONFIG usg "User UT. Tester,User1 UT. Tester"
#testit "group removemembers" $samba_tool group removemembers $CONFIG ddg "User UT. Tester,User1 UT. Tester"
#testit "group removemembers" $samba_tool group removemembers $CONFIG gdg "User UT. Tester,User1 UT. Tester"
#testit "group removemembers" $samba_tool group removemembers $CONFIG ugg "User UT. Tester,User1 UT. Tester"

# delete test users
testit "user delete" $PYTHON $samba_tool user delete $CONFIG testuser
testit "user delete" $PYTHON $samba_tool user delete $CONFIG testuser1

# creation of two new test users without spaces in cn
# testit fails when spaces are used in arguments
testit "user add" $PYTHON $samba_tool user create $CONFIG --given-name="User" --surname="Tester" --initial="UT" --use-username-as-cn testuser testp@ssw0Rd
testit "user add" $PYTHON $samba_tool user create $CONFIG --given-name="User1" --surname="Tester" --initial="UT" --use-username-as-cn testuser1 testp@ssw0Rd

# test adding test users to all groups by their DN
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG dsg --member-dn=CN=testuser,CN=Users,DC=foo,DC=example,DC=com

testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG dsg --member-dn=CN=testuser1,CN=Users,DC=foo,DC=example,DC=com
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG gsg --member-dn=CN=testuser,CN=Users,DC=foo,DC=example,DC=com
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG gsg --member-dn=CN=testuser1,CN=Users,DC=foo,DC=example,DC=com
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG usg --member-dn=CN=testuser,CN=Users,DC=foo,DC=example,DC=com
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG usg --member-dn=CN=testuser1,CN=Users,DC=foo,DC=example,DC=com
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG ddg --member-dn=CN=testuser,CN=Users,DC=foo,DC=example,DC=com
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG ddg --member-dn=CN=testuser1,CN=Users,DC=foo,DC=example,DC=com

# add two members by DN and listofmembers in one call
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG gdg --member-dn=CN=testuser,CN=Users,DC=foo,DC=example,DC=com testuser1

# add two members by DN with one call
testit "group addmembers" $PYTHON $samba_tool group addmembers $CONFIG udg --member-dn=CN=testuser,CN=Users,DC=foo,DC=example,DC=com --member-dn=CN=testuser1,CN=Users,DC=foo,DC=example,DC=com

# test removing test users from all groups by their DN
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG dsg --member-dn=CN=testuser,CN=Users,DC=foo,DC=example,DC=com
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG dsg --member-dn=CN=testuser1,CN=Users,DC=foo,DC=example,DC=com
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG gsg --member-dn=CN=testuser,CN=Users,DC=foo,DC=example,DC=com
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG gsg --member-dn=CN=testuser1,CN=Users,DC=foo,DC=example,DC=com
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG usg --member-dn=CN=testuser,CN=Users,DC=foo,DC=example,DC=com
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG usg --member-dn=CN=testuser1,CN=Users,DC=foo,DC=example,DC=com
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG ddg --member-dn=CN=testuser,CN=Users,DC=foo,DC=example,DC=com
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG ddg --member-dn=CN=testuser1,CN=Users,DC=foo,DC=example,DC=com

# remove two members by DN and listofmembers in one call
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG gdg --member-dn=CN=testuser,CN=Users,DC=foo,DC=example,DC=com testuser1

# remove two members by DN with one call
testit "group removemembers" $PYTHON $samba_tool group removemembers $CONFIG udg --member-dn=CN=testuser,CN=Users,DC=foo,DC=example,DC=com --member-dn=CN=testuser1,CN=Users,DC=foo,DC=example,DC=com

# test --member-base-dn option - expect failure here, due to invalid base
testit_expect_failure "group addmembers with invalid search member base" $PYTHON $samba_tool group addmembers $CONFIG dsg testcontact --member-base-dn=OU=doesnotexist,DC=foo,DC=example,DC=com

# test --member-base-dn option
testit "group addmembers with member search base" $PYTHON $samba_tool group addmembers $CONFIG dsg testuser --member-base-dn=CN=Users,DC=foo,DC=example,DC=com
testit "group removemembers with member search base" $PYTHON $samba_tool group removemembers $CONFIG dsg testuser --member-base-dn=CN=Users,DC=foo,DC=example,DC=com

#test deletion of the groups
testit "group delete" $PYTHON $samba_tool group delete $CONFIG dsg
testit "group delete" $PYTHON $samba_tool group delete $CONFIG gsg
testit "group delete" $PYTHON $samba_tool group delete $CONFIG usg
testit "group delete" $PYTHON $samba_tool group delete $CONFIG ddg
testit "group delete" $PYTHON $samba_tool group delete $CONFIG gdg
testit "group delete" $PYTHON $samba_tool group delete $CONFIG udg

# delete test users
testit "user delete" $PYTHON $samba_tool user delete $CONFIG testuser
testit "user delete" $PYTHON $samba_tool user delete $CONFIG testuser1

#test listing of all groups
testit "group list" $PYTHON $samba_tool group list $CONFIG

#test listing of members of a particular group
testit "group listmembers" $PYTHON $samba_tool group listmembers $CONFIG Users

exit $failed
