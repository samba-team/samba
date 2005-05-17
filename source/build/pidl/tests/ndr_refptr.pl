#!/usr/bin/perl
# Simple tests for pidl's handling of ref pointers, based
# on tridge's ref_notes.txt
use strict;

use FindBin qw($RealBin);
use lib "$RealBin/..";
use test;

my %settings = (
	'IDL-Arguments' => ['--quiet', '--parse', '--parser=ndr_test.c', '--header=ndr_test.h'],
	'IncludeFiles' => ['ndr_test.h'],
	'ExtraFiles' => ['ndr_test.c'],
);

Test::test_idl("noptr-push", \%settings, 
'	typedef struct {
		uint16 x;
	} xstruct;

	[public] uint16 echo_TestRef([in] xstruct foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	uint16_t v = 13;
	struct echo_TestRef r;
	r.in.foo.x = v; 

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, ndr_flags, &r)))
		return 1;

	if (ndr->offset != 2)
		return 2;

	if (ndr->data[0] != 13 || ndr->data[1] != 0) 
		return 3;
');

Test::test_idl("ptr-embedded-push", \%settings,
'   typedef struct {
		short *x;
	} xstruct;

	uint16 echo_TestRef([in] xstruct foo);
',
'
	uint16_t v = 13;
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo.x = &v; 

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, ndr_flags, &r)))
		return 1;

	if (ndr->offset != 6)
		return 2;

	if (ndr->data[0] == 0 && ndr->data[1] == 0 && 
	    ndr->data[2] == 0 && ndr->data[3] == 0)
		return 3;

	if (ndr->data[4] != 13 || ndr->data[5] != 0)
		return 4;
');

Test::test_idl("ptr-embedded-push-null", \%settings,
'   typedef struct {
		short *x;
	} xstruct;

	uint16 echo_TestRef([in] xstruct foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo.x = NULL; 

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, ndr_flags, &r)))
		return 1;

	if (ndr->offset != 4)
		return 2;

	if (ndr->data[0] != 0 || ndr->data[1] != 0 || 
	    ndr->data[2] != 0 || ndr->data[3] != 0)
		return 3;
');

Test::test_idl("refptr-embedded-push", \%settings,
'
	typedef struct {
		[ref] short *x;
	} xstruct;

	uint16 echo_TestRef([in] xstruct foo);
',
'
	uint16_t v = 13;
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo.x = &v; 

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, ndr_flags, &r)))
		return 1;

	if (ndr->offset != 6)
		return 2;

	if (ndr->data[0] == 0 && ndr->data[1] == 0 && 
	    ndr->data[2] == 0 && ndr->data[3] == 0)
		return 3;

	if (ndr->data[4] != 13 || ndr->data[5] != 0)
		return 4;
');

Test::test_idl("refptr-embedded-push-null", \%settings,
'
	typedef struct {
		[ref] short *x;
	} xstruct;

	uint16 echo_TestRef([in] xstruct foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo.x = NULL; 

	if (NT_STATUS_IS_OK(ndr_push_echo_TestRef(ndr, ndr_flags, &r)))
		return 1;
	/* Windows gives [client runtime error 0x6f4] */
');

Test::test_idl("ptr-top-push", \%settings,
'
	typedef struct {
		short x;
	} xstruct;

	uint16 echo_TestRef([in] xstruct *foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	struct xstruct s;
	s.x = 13;
	r.in.foo = &s;

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, ndr_flags, &r)))
		return 1;

	if (ndr->offset != 2)
		return 2;

	if (ndr->data[0] != 13 || ndr->data[1] != 0)
		return 3;
');

Test::test_idl("ptr-top-push-null", \%settings,
'
	typedef struct {
		short x;
	} xstruct;

	uint16 echo_TestRef([in] xstruct *foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo = NULL;

	if (NT_STATUS_IS_OK(ndr_push_echo_TestRef(ndr, ndr_flags, &r)))
		return 1;

	/* Windows gives [client runtime error 0x6f4] */
');


Test::test_idl("refptr-top-push", \%settings,
'
	typedef struct {
		short x;
	} xstruct;

	uint16 echo_TestRef([in,ref] xstruct *foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	struct xstruct s;
	s.x = 13;
	r.in.foo = &s;

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, ndr_flags, &r)))
		return 1;

	if (ndr->offset != 2)
		return 2;

	if (ndr->data[0] != 13 || ndr->data[1] != 0)
		return 3;
');

Test::test_idl("refptr-top-push-null", \%settings,
'
	typedef struct {
		short x;
	} xstruct;

	uint16 echo_TestRef([in,ref] xstruct *foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo = NULL;

	if (NT_STATUS_IS_OK(ndr_push_echo_TestRef(ndr, ndr_flags, &r)))
		return 1;

	/* Windows gives [client runtime error 0x6f4] */
');


Test::test_idl("uniqueptr-top-push", \%settings,
'	typedef struct {
		short x;
	} xstruct;

	uint16 echo_TestRef([in,unique] xstruct *foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	struct xstruct s;
	s.x = 13;
	r.in.foo = &s;

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, ndr_flags, &r)))
		return 1;

	if (ndr->offset != 6)
		return 2;

	if (ndr->data[0] == 0 && ndr->data[1] == 0 && 
	    ndr->data[2] == 0 && ndr->data[3] == 0)
		return 3;

	if (ndr->data[4] != 13 || ndr->data[5] != 0)
		return 4;
');

Test::test_idl("uniqueptr-top-push-null", \%settings,
'	typedef struct {
		short x;
	} xstruct;

	uint16 echo_TestRef([in,unique] xstruct *foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo = NULL;

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, ndr_flags, &r)))
		return 1;

	if (ndr->offset != 4)
		return 2;

	if (ndr->data[0] != 0 || ndr->data[1] != 0 || 
	    ndr->data[2] != 0 || ndr->data[3] != 0)
		return 3;
');


#----------------------------------------------------
#	typedef struct {
#		short x;
#	} xstruct;
#
#	uint16 echo_TestRef([out] xstruct foo);
#
#        [idl compiler error]
#
#----------------------------------------------------
#	typedef struct {
#		short x;
#	} xstruct;
#
#	void echo_TestRef([out] xstruct *foo);
#
#	xstruct r;
#	echo_TestRef(&r);
#	r.x -> 13;
#
#	[0D 00]
#
#
#	echo_TestRef(NULL);
#
#	[client runtime error 0x6f4]
#
#----------------------------------------------------
#	typedef struct {
#		short x;
#	} xstruct;
#
#	void echo_TestRef([out,ref] xstruct *foo);
#
#	xstruct r;
#	echo_TestRef(&r);
#	r.x -> 13;
#
#	[0D 00]
#
#
#	echo_TestRef(NULL);
#
#	[client runtime error 0x6f4]
#
#----------------------------------------------------
#	typedef struct {
#		short x;
#	} xstruct;
#
#	void echo_TestRef([out,unique] xstruct *foo);
#
#        [idl compiler error]
#
#
#----------------------------------------------------
#	void echo_TestRef([in] short **foo);
#
#	short v = 13;
#	short *pv = &v;
#
#	echo_TestRef(&pv);
#
#	[PP PP PP PP 0D 00]
#
#
#	short *pv = NULL;
#
#	echo_TestRef(&pv);
#
#	[00 00 00 00]
#
#
#	echo_TestRef(NULL);
#	
#	[client runtime error 0x6f4]
#
#
#----------------------------------------------------
#	void echo_TestRef([in,ref] short **foo);
#
#	short v = 13;
#	short *pv = &v;
#
#	echo_TestRef(&pv);
#
#	[PP PP PP PP 0D 00]
#
#
#	short *pv = NULL;
#
#	echo_TestRef(&pv);
#
#	[00 00 00 00]
#
#
#	echo_TestRef(NULL);
#	
#	[client runtime error 0x6f4]
