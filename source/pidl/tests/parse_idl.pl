#!/usr/bin/perl
# Some simple tests for pidls parsing routines
# (C) 2005 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;

use Test::Simple tests => 26;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";
use Parse::Pidl::IDL;
use Parse::Pidl::NDR;

sub testok($$)
{
	my ($name, $data) = @_;
	
	my $pidl = Parse::Pidl::IDL::parse_string($data, "<$name>");
	
	ok (defined($pidl), $name);
	return $pidl
}

sub testfail($$)
{
	my ($name, $data) = @_;
	
	my $pidl = Parse::Pidl::IDL::parse_string($data, "<$name>");
	
	ok ((not defined $pidl), $name);
}

testok "test1", "interface test { void Test(); }; ";
testok "voidtest", "interface test { int Testx(void); }; ";
testfail "voidtest", "interface test { Test(); }; ";
testok "argtest", "interface test { int Test(int a, long b, uint32 c); }; ";
testok "array1", "interface test { int Test(int a[]); };";
testok "array2", "interface test { int Test(int a[2]); };";
testok "array3", "interface test { int Test(int a[b]); };";
testfail "array4", "interface test { int Test(int[] a); };";
testok "ptr1", "interface test { int Test(int *a); };";
testok "ptr2", "interface test { int Test(int **a); };";
testok "ptr3", "interface test { int Test(int ***a); };";
testfail "empty1", "interface test { };";
testfail "empty2", "";
testok "attr1", "[uuid(\"myuuid\"),attr] interface test { int Test(int ***a); };";
testok "attr2", "interface test { [public] int Test(); };";
testok "multfn", "interface test { int test1(); int test2(); };";
testok "multif", "interface test { int test1(); }; interface test2 { int test2(); };";
testok "tdstruct1", "interface test { typedef struct { } foo; };";
testok "tdstruct2", "interface test { typedef struct { int a; } foo; };";
testok "tdstruct3", "interface test { typedef struct { int a; int b; } foo; };";
testfail "tdstruct4", "interface test { typedef struct { int a, int b; } foo; };";
testok "tdunion1", "interface test { typedef union { } a; };";
testok "tdunion2", "interface test { typedef union { int a; } a; };";
testok "typedef1", "interface test { typedef int a; };";
testfail "typedef2", "interface test { typedef x; };";
testok "tdenum1", "interface test { typedef enum { A=1, B=2, C} a; };";
