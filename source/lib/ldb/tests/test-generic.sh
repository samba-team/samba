echo "Adding base elements"
bin/ldbadd tests/test.ldif || exit 1

echo "Modifying elements"
bin/ldbmodify tests/test-modify.ldif || exit 1

echo "Showing modified record"
bin/ldbsearch '(uid=uham)'  || exit 1

echo "Starting ldbtest"
time bin/ldbtest -r 1000 -s 100  || exit 1

echo "Adding index"
bin/ldbadd tests/test-index.ldif  || exit 1

echo "Starting ldbtest indexed"
time bin/ldbtest -r 1000 -s 5000  || exit 1
