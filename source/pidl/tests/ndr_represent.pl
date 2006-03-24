#!/usr/bin/perl
# NDR represent_as() / transmit_as() tests
# (C) 2006 Jelmer Vernooij. Published under the GNU GPL
use strict;

use Test::More tests => 1 * 8;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";
use lib "$RealBin";
use Util qw(test_samba4_ndr);

SKIP: {
	skip "represent_as() is not finished yet", 8;

test_samba4_ndr('represent_as-simple', 
'
	void bla([in,represent_as(foo)] uint8 x);
',
'
	uint8_t expected[] = { 0x0D };
	DATA_BLOB in_blob = { expected, 1 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&in_blob, NULL);
	struct bla r;

	if (NT_STATUS_IS_ERR(ndr_pull_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	if (r != 13)
		return 2;
',
'
#include <core/nterr.h>
typedef int foo;

NTSTATUS ndr_uint8_to_foo(uint8_t from, foo *to)
{
	*to = from;
	return NT_STATUS_OK;
}

NTSTATUS ndr_foo_to_uint8(foo from, uint8_t *to)
{
	*to = from;
	return NT_STATUS_OK;
}
'
);

}
