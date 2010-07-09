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
testit "simple-dc" $PYTHON ./setup/provision --server-role="dc" --domain=FOO --realm=foo.example.com --domain-sid=S-1-5-21-4177067393-1453636373-93818738 --targetdir=$PREFIX/simple-dc
net="./bin/net"

CONFIG="--configfile=$PREFIX/simple-dc/etc/smb.conf"

#creation of two test subjects
testit "newuser" $net newuser $CONFIG --given-name="User" --surname="Tester" --initial="UT" testuser testp@ssw0Rd
testit "newuser" $net newuser $CONFIG --given-name="User1" --surname="Tester" --initial="UT" testuser1 testp@ssw0Rd

#test creation of six different groups
testit "group add" $net group add $CONFIG --group-scope='Domain' --group-type='Security' --description='DomainSecurityGroup' --mail-address='dsg@samba.org' --notes='Notes' dsg
testit "group add" $net group add $CONFIG --group-scope='Global' --group-type='Security' --description='GlobalSecurityGroup' --mail-address='gsg@samba.org' --notes='Notes' gsg
testit "group add" $net group add $CONFIG --group-scope='Universal' --group-type='Security' --description='UniversalSecurityGroup' --mail-address='usg@samba.org' --notes='Notes' usg
testit "group add" $net group add $CONFIG --group-scope='Domain' --group-type='Distribution' --description='DomainDistributionGroup' --mail-address='ddg@samba.org' --notes='Notes' ddg
testit "group add" $net group add $CONFIG --group-scope='Global' --group-type='Distribution' --description='GlobalDistributionGroup' --mail-address='gdg@samba.org' --notes='Notes' gdg
testit "group add" $net group add $CONFIG --group-scope='Universal' --group-type='Distribution' --description='UniversalDistributionGroup' --mail-address='udg@samba.org' --notes='Notes' udg

#test adding test users to all groups by their username
testit "group addmembers" $net group addmembers $CONFIG dsg newuser,newuser1
testit "group addmembers" $net group addmembers $CONFIG gsg newuser,newuser1
testit "group addmembers" $net group addmembers $CONFIG usg newuser,newuser1
testit "group addmembers" $net group addmembers $CONFIG ddg newuser,newuser1
testit "group addmembers" $net group addmembers $CONFIG gdg newuser,newuser1
testit "group addmembers" $net group addmembers $CONFIG udg newuser,newuser1

#test removing test users from all groups by their username
testit "group removemembers" $net group removemembers $CONFIG dsg newuser,newuser1
testit "group removemembers" $net group removemembers $CONFIG gsg newuser,newuser1
testit "group removemembers" $net group removemembers $CONFIG usg newuser,newuser1
testit "group removemembers" $net group removemembers $CONFIG ddg newuser,newuser1
testit "group removemembers" $net group removemembers $CONFIG gdg newuser,newuser1
testit "group removemembers" $net group removemembers $CONFIG udg newuser,newuser1

#test adding test users to all groups by their cn
#testit "group addmembers" $net group addmembers $CONFIG dsg "User UT. Tester,User1 UT. Tester"
#testit "group addmembers" $net group addmembers $CONFIG gsg "User UT. Tester,User1 UT. Tester"
#testit "group addmembers" $net group addmembers $CONFIG usg "User UT. Tester,User1 UT. Tester"
#testit "group addmembers" $net group addmembers $CONFIG ddg "User UT. Tester,User1 UT. Tester"
#testit "group addmembers" $net group addmembers $CONFIG gdg "User UT. Tester,User1 UT. Tester"
#testit "group addmembers" $net group addmembers $CONFIG udg "User UT. Tester,User1 UT. Tester"

#test removing test users from all groups by their cn
#testit "group removemembers" $net group removemembers $CONFIG dsg "User UT. Tester,User1 UT. Tester"
#testit "group removemembers" $net group removemembers $CONFIG gsg "User UT. Tester,User1 UT. Tester"
#testit "group removemembers" $net group removemembers $CONFIG usg "User UT. Tester,User1 UT. Tester"
#testit "group removemembers" $net group removemembers $CONFIG ddg "User UT. Tester,User1 UT. Tester"
#testit "group removemembers" $net group removemembers $CONFIG gdg "User UT. Tester,User1 UT. Tester"
#testit "group removemembers" $net group removemembers $CONFIG ugg "User UT. Tester,User1 UT. Tester"

#test deletion of the groups
testit "group delete" $net group delete $CONFIG dsg
testit "group delete" $net group delete $CONFIG gsg
testit "group delete" $net group delete $CONFIG usg
testit "group delete" $net group delete $CONFIG ddg
testit "group delete" $net group delete $CONFIG gdg
testit "group delete" $net group delete $CONFIG udg

exit $failed
