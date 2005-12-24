#!/usr/bin/perl
# Some simple tests for pidl
# (C) 2005 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;

use Test::Simple tests => 4;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";
use Parse::Pidl::IDL;
use Parse::Pidl::NDR;
use Parse::Pidl::Samba4::NDR::Parser;

my $pidl = Parse::Pidl::IDL::parse_string(
"interface test { void Test(); }; ", "<test>");
ok (defined($pidl));
my $pndr = Parse::Pidl::NDR::Parse($pidl);
ok(defined($pndr));
my ($header,$parser) = Parse::Pidl::Samba4::NDR::Parser($pndr);
ok(defined($header));
ok(defined($parser));


#Parse::Pidl::Test::test_idl(
#	# Name
#	'UInt8',
#	
#	# Settings
#	\%settings,
#	
#	
#	# C Test
#	'
#	uint8_t data[] = { 0x02 };
#	uint8_t result;
#	DATA_BLOB b;
#	struct ndr_pull *ndr;
#
#	b.data = data;
#	b.length = 1;
#	ndr = ndr_pull_init_blob(&b, mem_ctx);
#
#	if (NT_STATUS_IS_ERR(ndr_pull_uint8(ndr, NDR_SCALARS, &result)))
#		return 1;
#
#	if (result != 0x02) 
#		return 2;
#');
