#!/usr/bin/perl
# Some simple tests for pidl
# (C) 2005 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;

use Test::Simple tests => 6;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";
use Parse::Pidl::IDL;
use Parse::Pidl::NDR;
use Parse::Pidl::Samba4::NDR::Parser;
use Parse::Pidl::Samba4::Header;

my $pidl = Parse::Pidl::IDL::parse_string(
"interface test { void Test(); }; ", "<test>");
ok (defined($pidl));
my $pndr = Parse::Pidl::NDR::Parse($pidl);
ok(defined($pndr));
my $header = Parse::Pidl::Samba4::Header::Parse($pidl);
ok(defined($header));
my ($ndrheader,$parser) = Parse::Pidl::Samba4::NDR::Parser::Parse($pndr, "foo");
ok(defined($parser));
ok(defined($ndrheader));

my $outfile = "test";

#my $cflags = $ENV{CFLAGS};
my $cflags = "-Iinclude -I.";

open CC, "|cc -x c -o $outfile $cflags -";
#open CC, ">foo";
print CC "#include \"includes.h\"";
print CC $header;
print CC $ndrheader;
print CC $parser;
print CC
	'
int main(int argc, const char **argv)
{
 	uint8_t data[] = { 0x02 };
 	uint8_t result;
 	DATA_BLOB b;
 	struct ndr_pull *ndr;
	TALLOC_CTX *mem_ctx = talloc_init(NULL);
 
 	b.data = data;
 	b.length = 1;
 	ndr = ndr_pull_init_blob(&b, mem_ctx);
 
 	if (NT_STATUS_IS_ERR(ndr_pull_uint8(ndr, NDR_SCALARS, &result)))
 		return 1;
 
 	if (result != 0x02) 
 		return 2;

	talloc_free(mem_ctx);
	
	return 0;
}
';
close CC;

ok(-f $outfile);
