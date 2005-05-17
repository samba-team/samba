#!/usr/bin/perl
# NDR alignment tests
# (C) 2005 Jelmer Vernooij. Published under the GNU GPL
use strict;

use FindBin qw($RealBin);
use lib "$RealBin/..";
use test;

my %settings = (
	'IDL-Arguments' => ['--quiet', '--parse', '--parser=ndr_test.c', '--header=ndr_test.h'],
	'IncludeFiles' => ['ndr_test.h'],
	'ExtraFiles' => ['ndr_test.c'],
);

Test::test_idl('align-uint8-uint16', \%settings,
'
	typedef [public] struct { 
		uint8 x;
		uint16 y;
	} bla;
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct bla r;
	uint8_t expected[] = { 0x0D, 0x00, 0xbe, 0xef };
	DATA_BLOB expected_blob = { expected, 4 };
	DATA_BLOB result_blob;
	r.x = 13;
	r.y = 0xbeef;

	if (NT_STATUS_IS_ERR(ndr_push_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	result_blob = ndr_push_blob(ndr);
	
	if (!data_blob_equal(&result_blob, &expected_blob)) 
		return 2;
');
