echo "Adding base elements"
bin/ldbadd tests/test.ldif

echo "Modifying elements"
bin/ldbmodify tests/test-modify.ldif

echo "Showing modified record"
bin/ldbsearch '(uid=uham)'
