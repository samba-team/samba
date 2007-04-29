#!/usr/bin/perl

use Test::More tests => 3;
use FindBin qw($RealBin);
use lib $RealBin;
use Samba4;

my $s = new Samba4($RealBin."/../bin", undef, $RealBin."/../setup");

ok($s);

is($RealBin."/../bin", $s->{bindir});

ok($s->write_ldb_file("tmpldb", "
dn: a=b
a: b
c: d
"));

unlink("tmpldb");
