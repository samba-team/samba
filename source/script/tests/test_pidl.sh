#!/bin/sh
PERL=perl
$PERL -Ibuild/pidl ./build/pidl/tests/ndr_simple.pl
$PERL -Ibuild/pidl ./build/pidl/tests/ndr_align.pl
$PERL -Ibuild/pidl ./build/pidl/tests/ndr_alloc.pl
$PERL -Ibuild/pidl ./build/pidl/tests/ndr_refptr.pl
$PERL -Ibuild/pidl ./build/pidl/tests/ndr_string.pl
$PERL -Ibuild/pidl ./build/pidl/tests/ndr_array.pl
