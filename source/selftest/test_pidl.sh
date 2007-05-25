#!/bin/sh
if [ ! -n "$PERL" ]
then
	PERL=perl
fi

incdir=`dirname $0`
. $incdir/test_functions.sh

if test x"${PIDL_TESTS_SKIP}" = x"yes"; then
   echo "Skipping pidl tests - PIDL_TESTS_SKIP=yes"
elif $PERL -e 'eval require Test::More;' > /dev/null 2>&1; then
  for f in pidl/tests/*.pl; do
     plantest "$f" none $PERL $f
  done
else 
   echo "Skipping pidl tests - Test::More not installed"
fi
