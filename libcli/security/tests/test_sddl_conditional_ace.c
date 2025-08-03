/*
 * Unit tests for conditional ACE SDDL.
 *
 *  Copyright (C) Catalyst.NET Ltd 2023
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include "cmocka.h"

#include "lib/util/attr.h"
#include "includes.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "libcli/security/conditional_ace.h"
#include "librpc/gen_ndr/conditional_ace.h"

/*
 * Some of the test strings break subunit, so we only print those if
 * stdout is a terminal.
 */
#define debug_message(...)  do {			\
		if (isatty(1)) {			\
			print_message(__VA_ARGS__);	\
				}			\
	} while(0)

#define debug_fail(x, ...) debug_message("\033[1;31m" x "\033[0m", __VA_ARGS__)
#define debug_ok(x, ...) debug_message("\033[1;32m" x "\033[0m", __VA_ARGS__)

#define ACEINT64(x, b, s) CONDITIONAL_ACE_TOKEN_INT64,			\
		(x & 0xff), ((x >> 8) & 0xff), ((x >> 16) & 0xff),	\
		((x >> 24) & 0xff), (((uint64_t)x >> 32) & 0xff), (((uint64_t)x >> 40) & 0xff), \
		(((uint64_t)x >> 48) & 0xff), (((uint64_t)x >> 56) & 0xff), b, s


static void print_error_message(const char *sddl,
				const char *message,
				size_t message_offset)
{
	print_message("%s\n\033[1;33m %*c\033[0m\n", sddl,
		      (int)message_offset, '^');
	print_message("%s\n", message);
}

static void test_sddl_compile(void **state)
{
	/*
	 * Example codes:
	 *
	 *    CONDITIONAL_ACE_LOCAL_ATTRIBUTE,	2,0,0,0,     'x',0,
	 *    ^attr byte code			^	       ^
	 *			 32 bit little-endian length   |
	 *					       utf-16, little endian
	 *
	 *     CONDITIONAL_ACE_TOKEN_EQUAL
	 *     ^ op byte code with no following data
	 */
	static const char *sddl = "(x==41 &&(x >@device.x ) )";
	static const uint8_t ace[] = {
		'a', 'r', 't', 'x',
		CONDITIONAL_ACE_LOCAL_ATTRIBUTE, 2, 0, 0, 0, 'x', 0,
		ACEINT64(41,
			 CONDITIONAL_ACE_INT_SIGN_NONE,
			 CONDITIONAL_ACE_INT_BASE_10),
		CONDITIONAL_ACE_TOKEN_EQUAL,
		CONDITIONAL_ACE_LOCAL_ATTRIBUTE, 2, 0, 0, 0, 'x', 0,
		CONDITIONAL_ACE_DEVICE_ATTRIBUTE, 2, 0, 0, 0, 'x', 0,
		CONDITIONAL_ACE_TOKEN_GREATER_THAN,
		CONDITIONAL_ACE_TOKEN_AND, 0,0,0,0,
	};

	size_t i;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct ace_condition_script *s = NULL;
	const char *message = NULL;
	size_t message_offset;
	bool ok;
	DATA_BLOB compiled;
	size_t length;

	s = ace_conditions_compile_sddl(mem_ctx,
					ACE_CONDITION_FLAG_ALLOW_DEVICE,
					sddl,
					&message,
					&message_offset,
					&length);
	if (message != NULL) {
		print_error_message(sddl, message, message_offset);
	}
	if (s == NULL) {
		debug_fail("%s\n", sddl);
		TALLOC_FREE(mem_ctx);
		fail();
	}

	ok = conditional_ace_encode_binary(mem_ctx, s, &compiled);
	assert_true(ok);

	assert_true(compiled.length <= ARRAY_SIZE(ace));
	for (i = 0; i < compiled.length; i++) {
		assert_int_equal(compiled.data[i], ace[i]);
	}
	TALLOC_FREE(mem_ctx);
}

static void test_sddl_compile2(void **state)
{
	/* this one is from Windows, not hand-calculated */
	static const char *sddl = "(@USER.Project Any_of 1))";
	static const uint8_t ace[] = ("artx\xf9\x0e\x00\x00\x00P\x00r"
				      "\x00o\x00j\x00""e\x00""c\x00t\x00"
				      "\x04\x01\x00\x00\x00\x00\x00\x00"
				      "\x00\x03\x02\x88\x00");
	size_t i;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct ace_condition_script *s = NULL;
	const char *message = NULL;
	size_t message_offset;
	bool ok;
	DATA_BLOB compiled;
	size_t length;

	s = ace_conditions_compile_sddl(mem_ctx,
					ACE_CONDITION_FLAG_ALLOW_DEVICE,
					sddl,
					&message,
					&message_offset,
					&length);
	if (message != NULL) {
		print_error_message(sddl, message, message_offset);
	}
	if (s == NULL) {
		debug_fail("%s\n", sddl);
		TALLOC_FREE(mem_ctx);
		fail();
	}

	ok = conditional_ace_encode_binary(mem_ctx, s, &compiled);
	assert_true(ok);

	assert_true(compiled.length <= ARRAY_SIZE(ace));
	for (i = 0; i < compiled.length; i++) {
		assert_int_equal(compiled.data[i], ace[i]);
	}
	TALLOC_FREE(mem_ctx);
}

static void test_full_sddl_compile(void **state)
{
	/*
	 * This one is from Windows, and annotated by hand.
	 *
	 * We have the bytes of a full security descriptor, in
	 * "relative" form, which is the same as the its NDR
	 * representation.
	 *
	 * *In general* we can't necessarily assert that Samba's NDR
	 * will be the same as Windows, because they could e.g. put
	 * the two ACLs in the reverse order which is also legitimate
	 * (there are hints this may vary on Windows). But in this
	 * particular case Samba and the Windows 2022 sample agree, so
	 * we can compare the bytes here.
	 *
	 * We can assert that unpacking these bytes as a security
	 * descriptor should succeed and give us exactly the same
	 * descriptor as parsing the SDDL.
	 */
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct security_descriptor sec_desc_windows = {};
	struct security_descriptor *sec_desc_samba = NULL;
	DATA_BLOB sd_ndr = {};
	DATA_BLOB sd_win_push = {};
	DATA_BLOB sd_samba_push = {};
	bool ok;
	enum ndr_err_code ndr_err;
	const char *sddl = "D:(XA;;CCDCLCSWRPWP;;;MP;"\
		"(@RESOURCE.c))S:(RA;;;;;WD;(\"colOIr\",TU,0xe,29925))";

	uint8_t sd_bytes[] = {
		1,	    /*	0  version */
		0,	    /*	1  reserved */
		20, 128,    /*	2  control */
		0, 0, 0, 0, /*	4  owner (null relative pointer == no owner) */
		0, 0, 0, 0, /*	8  group */
		20, 0, 0, 0,/* 12  SACL	 */
		92, 0, 0, 0,/* 16  DACL, i.e. pointer to 92 below */

		/*  20	SACL (from pointer above) */
		4,	    /* 20 revision (ADS) */
		0,	    /* 21 reserved */
		72, 0,	    /* 22 size --> takes us to 92 */
		1, 0,	    /* 24 ace count */
		0, 0,	    /* 26 reserved */

		/*  now come SACL aces, of which there should be one */
		18,	    /* 28 ace type (SEC_ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE) */
		0,	    /* 29 ace flags */
		64, 0,	    /* 30 ace size (from start of ACE, again adds to ending at 92) */
		0, 0, 0, 0, /* 32 mask */

		/*  here's the ACE SID */
		1,		   /* 36 revision */
		1,		   /* 37 sub-auth count */
		0, 0, 0, 0, 0, 1,  /* 38 big endian ident auth */
		0, 0, 0, 0,	   /* 44 the sub-auth  (so SID is S-1-1-0 (everyone), mandatory with RA ace) */

		/*  here starts the actual claim, at 48 */
		20, 0, 0, 0,	   /* 48 pointer to name (relative to claim, at 68) */
		2, 0,		   /* 52 value type (uint64) */
		0, 0,		   /* 54 reserved */
		14, 0, 0, 0,	   /* 56 flags (case-sensitive|deny-only|disabled-by-default -- the "0xe" in the SDDL) */
		1, 0, 0, 0,	   /* 60 value count */
		34, 0, 0, 0,	   /* 64 array of pointers, 1-long, points to 48 + 34 == 82 */
				   /* 68 utf-16 letters "colOIr\0", indicated by name pointer at 48 */
		'c', 0,
		'o', 0,
		'l', 0,
		'O', 0,		   /* unlike conditional ACE strings, this is nul-terminated. */
		'I', 0,		   /*	where does the next thing start:	*/
		'r', 0,		   /*	6 letters + '\0' * 2 = 14. 68 + 14 = 82 */
		0, 0,
				   /* 82 is the value pointed to at 64 above (LE uint64) */
		229, 116, 0, 0, 0, 0, 0, 0, /* this equals 229 + 116 * 256 == 29925, as we see in the SDDL. */

		/*  88 the claim has ended. the ace has NEARLY ended, but we need to round up: */

		0, 0,		   /* 90 two bytes of padding to get to a multiple of 4. */
		/* The ace and SACL have ended */

		/*  92 the DACL starts. */
		2,		/* 92 version (NT) */
		0,		/* 93 reserved	*/
		40, 0,		/* 94 size */
		1, 0,		/* 96 ace count */
		0, 0,		/* 98 reserved */
		/*  100 the DACL aces start */
		9,		/* 100	ace type (SEC_ACE_TYPE_ACCESS_ALLOWED_CALLBACK) */
		0,		/* 101	flags */
		32, 0,		/* 102	ace size (ending at 132) */
		63, 0, 0, 0,	/* 104	mask (let's assume CCDCLCSWRPWP as in sddl, not checked, but it's the right number of bits) */
		/*  108 the ACE sid */
		1,		/* 108 version */
		1,		/* 109 sub-auths */
		0, 0, 0, 0, 0, 16,/* 110 bigendian 16 identauth */
		0, 33, 0, 0,	/* 116 sub-auth 1, 33 << 8 == 8448;  "S-1-16-8448" == "ML_MEDIUM_PLUS" == "MP" */
		/*  120 here starts the callback */
		97, 114, 116, 120, /* 120 'artx' */
		250,		  /* 124 0xfa CONDITIONAL_ACE_RESOURCE_ATTRIBUTE token */
		2, 0, 0, 0,	  /* 125 length 2 (bytes) */
		'c', 0,		   /* 129 utf-16 "c" -- NOT nul-terminated */
		0		  /* 131 padding to bring length to a multiple of 4 (132) */
	};
	sd_ndr.length = 132;
	sd_ndr.data = sd_bytes;

	sec_desc_samba = sddl_decode(mem_ctx, sddl, NULL);
	assert_non_null(sec_desc_samba);
	ndr_err = ndr_pull_struct_blob(
		&sd_ndr, mem_ctx, &sec_desc_windows,
		(ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));

	/*
	 * look, we munge the DACL version byte before comparing,
	 * because Samba currently always does version 4.
	 */
	sec_desc_windows.dacl->revision = SECURITY_ACL_REVISION_ADS;
	sd_bytes[92] = SECURITY_ACL_REVISION_ADS;

	/* push the structures back into blobs for 3-way comparisons. */
	ndr_err = ndr_push_struct_blob(
		&sd_win_push, mem_ctx,
		&sec_desc_windows,
		(ndr_push_flags_fn_t)ndr_push_security_descriptor);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));

	ndr_err = ndr_push_struct_blob(
		&sd_samba_push, mem_ctx,
		sec_desc_samba,
		(ndr_push_flags_fn_t)ndr_push_security_descriptor);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));

	assert_int_equal(sd_samba_push.length, sd_win_push.length);
	assert_int_equal(sd_samba_push.length, sd_ndr.length);
	assert_memory_equal(sd_samba_push.data,
			    sd_win_push.data,
			    sd_win_push.length);
	assert_memory_equal(sd_win_push.data,
			    sd_ndr.data,
			    sd_ndr.length);

	ok = security_descriptor_equal(sec_desc_samba, &sec_desc_windows);
	assert_true(ok);
	talloc_free(mem_ctx);
}


static void debug_conditional_ace_stderr(TALLOC_CTX *mem_ctx,
					 struct ace_condition_script *program)
{
	char * debug_string = debug_conditional_ace(mem_ctx, program);

	if (debug_string != NULL) {
		fputs(debug_string, stderr);
		TALLOC_FREE(debug_string);
	} else {
		print_message("failed to debug!\n");
	}
}


static void test_full_sddl_ra_encode(void **state)
{
	/*
	 * This is an example from Windows that Samba once had trouble
	 * with.
	 */
	bool ok;
	enum ndr_err_code ndr_err;
	char *sddl = NULL;
	struct dom_sid domain_sid;
	uint8_t win_bytes[] = {
		0x01, 0x00, 0x14, 0x80, /* descriptor header */
		0x00, 0x00, 0x00, 0x00, /* NULL owner pointer */
		0x00, 0x00, 0x00, 0x00, /* NULL group pointer */
		0x14, 0x00, 0x00, 0x00, /* SACL at 0x14 (20) */
		0x58, 0x01, 0x00, 0x00, /* DACL at 0x158 (344) */
		/* SACL starts here (20) */
		0x02, 0x00, /* rev 2, NT */
		0x44, 0x01, /* size 0x0144 (324) -- ends at 344 */
		0x01, 0x00, /* ace count */
		0x00, 0x00, /* reserved */
		/* ace starts here, 28 */
		0x12, 0x00, /* ace type, flags: 0x12(18) is resource attribute	*/
		0x3c, 0x01, /* ACE size 0x13c == 316, from ACE start, end at 344 */
		0x00, 0x00, 0x00, 0x00, /*ACE mask */
		0x01, 0x01,  /* SID S-1-<identauth>-<1 subauth>) */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, /* -1- indent auth */
		0x00, 0x00, 0x00, 0x00,	 /* -0	-> S-1-1-0, world */
		/* claim starts here, 48 */
		0x28, 0x00, 0x00, 0x00, /* pointer to name 40 (from claim start 48) = 88 */
		0x10, 0x00,		/* type octet string */
		0x00, 0x00,		/* empty */
		0x00, 0x00, 0x00, 0x00, /* zero flags */
		0x06, 0x00, 0x00, 0x00, /* value count */
		/* array of 6 value pointers (at claim + 16, 64) */
		0xf2, 0x00, 0x00, 0x00,	 /* value 0xf2 = 242 from claim (48) == 290 */
		0xf8, 0x00, 0x00, 0x00,	 /* 0xf8, 248 */
		0x0d, 0x01, 0x00, 0x00,	 /* 0x10d, 269 */
		0x14, 0x01, 0x00, 0x00,	 /* 0x114, 276 */
		0x1a, 0x01, 0x00, 0x00,	 /* 0x11a, 282 */
		0x21, 0x01, 0x00, 0x00,	 /* 0x121, 289 */
		/* here's the name, at 88 */
		'c', 0x00,
		'o', 0x00,
		'l', 0x00,
		'O', 0x00,
		'I', 0x00,
		'r', 0x00,  /* the following lines are all \x16 */
		/* 100 */
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		/* 150 */
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		/* 200 */
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		/* 250 */
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		/* 280 */
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00,  /* 286 */
		'r', 0x00,
		0x00, 0x00,   /* name is nul-terminated */
		/* 290, first octet string blob */
		0x02, 0x00, 0x00, 0x00, /* length 2 */
		0x00, 0x77,		/* 2 blob bytes */
		/* second blob @ 48 + 248 == 296 */
		0x11, 0x00, 0x00, 0x00, /* length 0x11 = 17 */
		0x00, 0x77, 0x77, 0x71, 0x83, 0x68, 0x96, 0x62, 0x95, 0x93,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
		/* third blob at 269 + 48 == 317 */
		0x03, 0x00, 0x00, 0x00,
		0x00, 0x77, 0x77,
		/* fourth blob, 276 + 48 == 324 */
		0x02, 0x00, 0x00, 0x00,
		0x00, 0x77,
		/* fifth blob, 282 + 48 == 330 */
		0x03, 0x00, 0x00, 0x00,
		0x00, 0x77, 0x77,
		/* last blob 289 + 48 == 337 */
		0x03, 0x00, 0x00, 0x00,
		0x00, 0x77, 0x77,
		/* claim ends */
		/* 344 DACL starts */
		0x02, 0x00, /* rev 2 (NT) */
		0x28, 0x00, /* size 40, ending at 384 */
		0x01, 0x00, /* ace count */
		0x00, 0x00,
		/* ACE starts here, 352 */
		0x09, 0x00, /* type 9, access allowed callback */
		0x20, 0x00, /* size 32 */
		0x3f, 0x00, 0x00, 0x00, /*mask */
		0x01, 0x01, /* S-1-... (1 subauth) */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x10, /*...-16-...*/
		0x00, 0x21, 0x00, 0x00, /* -5356. S-1-16-5376 */
		'a', 'r', 't', 'x',
		0xfa, /* resource attr */
		0x02, 0x00, 0x00, 0x00, /*name is 2 bytes long (i.e. 1 UTF-16) */
		'c', 0x00, /* name is "c" */
		/* here we're at 383, but need to round to a multiple of 4 with zeros: */
		0x00
	};
	DATA_BLOB win_blob = {
		.data = win_bytes,
		.length = sizeof(win_bytes)
	};

	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct security_descriptor sec_desc_windows = {};
	struct security_descriptor *sec_desc_samba = NULL;

	ndr_err = ndr_pull_struct_blob(
		&win_blob, mem_ctx, &sec_desc_windows,
		(ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));

	string_to_sid(&domain_sid, "S-1-2-3");
	sddl = sddl_encode(mem_ctx, &sec_desc_windows, &domain_sid);
	assert_non_null(sddl);
	sec_desc_samba = sddl_decode(mem_ctx, sddl, &domain_sid);

	/* hack the acl revision numbers */
	sec_desc_windows.dacl->revision = SECURITY_ACL_REVISION_ADS;
	sec_desc_windows.sacl->revision = SECURITY_ACL_REVISION_ADS;
	ok = security_descriptor_equal(sec_desc_samba, &sec_desc_windows);
	assert_true(ok);
	talloc_free(mem_ctx);
}


static void test_full_sddl_ra_escapes(void **state)
{
	/*
	 * This is the security descriptor described in
	 * test_full_sddl_ra_encode(), with SDDL.
	 */
	enum ndr_err_code ndr_err;
	const char *sddl = (
		"D:(XA;;CCDCLCSWRPWP;;;MP;(@RESOURCE.c))S:(RA;;;;;WD;(\""
		"colOIr%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016"
		"%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016"
		"%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016"
		"%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016"
		"%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016"
		"%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016"
		"%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016"
		"%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016"
		"%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016"
		"%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016%0016"
		"%0016%0016%0016%0016%0016%0016r\","
		"TX,0x0,"
		"0077,00,0077,00,0077,00,00,00,0077,00,0077,"
		"00,0077,007777,007777,0077,007777,0077,007777,"
		"007770,0077,00,0077,00,00,00,0077,00,0077,00,"
		"0077,007777,007777,0077,007777,0077,007777,007777))");
	uint8_t win_bytes[] = {
		0x01, 0x00, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0xb0, 0x02, 0x00, 0x00,
		0x02, 0x00, 0x9c, 0x02, 0x01, 0x00, 0x00, 0x00, 0x12, 0x00,
		0x94, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa8, 0x00,
		0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x26, 0x00, 0x00, 0x00, 0x9e, 0x01, 0x00, 0x00, 0xa4, 0x01,
		0x00, 0x00, 0xa9, 0x01, 0x00, 0x00, 0xaf, 0x01, 0x00, 0x00,
		0xb4, 0x01, 0x00, 0x00, 0xba, 0x01, 0x00, 0x00, 0xbf, 0x01,
		0x00, 0x00, 0xc4, 0x01, 0x00, 0x00, 0xc9, 0x01, 0x00, 0x00,
		0xcf, 0x01, 0x00, 0x00, 0xd4, 0x01, 0x00, 0x00, 0xda, 0x01,
		0x00, 0x00, 0xdf, 0x01, 0x00, 0x00, 0xe5, 0x01, 0x00, 0x00,
		0xec, 0x01, 0x00, 0x00, 0xf3, 0x01, 0x00, 0x00, 0xf9, 0x01,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x06, 0x02, 0x00, 0x00,
		0x0d, 0x02, 0x00, 0x00, 0x14, 0x02, 0x00, 0x00, 0x1a, 0x02,
		0x00, 0x00, 0x1f, 0x02, 0x00, 0x00, 0x25, 0x02, 0x00, 0x00,
		0x2a, 0x02, 0x00, 0x00, 0x2f, 0x02, 0x00, 0x00, 0x34, 0x02,
		0x00, 0x00, 0x3a, 0x02, 0x00, 0x00, 0x3f, 0x02, 0x00, 0x00,
		0x45, 0x02, 0x00, 0x00, 0x4a, 0x02, 0x00, 0x00, 0x50, 0x02,
		0x00, 0x00, 0x57, 0x02, 0x00, 0x00, 0x5e, 0x02, 0x00, 0x00,
		0x64, 0x02, 0x00, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x71, 0x02,
		0x00, 0x00, 0x78, 0x02, 0x00, 0x00, 0x63, 0x00, 0x6f, 0x00,
		0x6c, 0x00, 0x4f, 0x00, 0x49, 0x00, 0x72, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00,
		0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x16, 0x00, 0x72, 0x00,
		0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x77, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x77, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x77,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x77, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x00, 0x77, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x77, 0x03, 0x00, 0x00, 0x00, 0x00, 0x77, 0x77,
		0x03, 0x00, 0x00, 0x00, 0x00, 0x77, 0x77, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x77, 0x03, 0x00, 0x00, 0x00, 0x00, 0x77, 0x77,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x77, 0x03, 0x00, 0x00, 0x00,
		0x00, 0x77, 0x77, 0x03, 0x00, 0x00, 0x00, 0x00, 0x77, 0x70,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x77, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x77, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x77, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x77, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x77,
		0x03, 0x00, 0x00, 0x00, 0x00, 0x77, 0x77, 0x03, 0x00, 0x00,
		0x00, 0x00, 0x77, 0x77, 0x02, 0x00, 0x00, 0x00, 0x00, 0x77,
		0x03, 0x00, 0x00, 0x00, 0x00, 0x77, 0x77, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x77, 0x03, 0x00, 0x00, 0x00, 0x00, 0x77, 0x77,
		0x03, 0x00, 0x00, 0x00, 0x00, 0x77, 0x77, 0x00, 0x02, 0x00,
		0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x20, 0x00,
		0x3f, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x10, 0x00, 0x21, 0x00, 0x00, 0x61, 0x72, 0x74, 0x78,
		0xfa, 0x02, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00};
	DATA_BLOB win_blob = {
		.data = win_bytes,
		.length = sizeof(win_bytes)
	};

	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct security_descriptor sec_desc_windows = {};
	struct security_descriptor *sec_desc_samba = sddl_decode(mem_ctx, sddl,
								 NULL);
	assert_non_null(sec_desc_samba);
	ndr_err = ndr_pull_struct_blob(
		&win_blob, mem_ctx, &sec_desc_windows,
		(ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	TALLOC_FREE(mem_ctx);
}

static void test_round_trips(void **state)
{
	/*
	 * These expressions should parse into proper conditional
	 * ACEs, which then encode into an equivalent SDDL string,
	 * which then parses again into the same conditional ACE.
	 */
	static const char *sddl[] = {
		"(0>-0)",
		"(0>+0)",
		("(Member_of{SID(AA)})"),
		("(a Contains @USER.b == @device.c)"),
		("(a == @user.b == @resource.c)"),
		("(@Device.bb <= -00624677746777766777767)"),
		("(@Device.bb == 0624677746777766777767)"),
		("(@Device.%025cɜ == 3)"),
		("(17pq == 3||2a==@USER.7)"),
		("(x==1 && x >= 2 && @User.Title == @User.shoes || "
		 "Member_of{SID(CD)} && !(Member_of_Any{ 3 }) || "
		 "Device_Member_of{SID(BA), 7, 1, 3} "
		 "|| Exists hooly)"),
		("(!(!(!(!(!((!(x==1))))))))"),
		("(@User.a == {})"),
		("(Member_of{})"),
		("(Member_of {SID(S-1-33-5), "
		 "SID(BO)} && @Device.Bitlocker)"),
		"(@USER.ad://ext/AuthenticationSilo == \"siloname\")",
		"(@User.Division==\"Finance\" || @User.Division ==\"Sales\")",
		"(@User.Title == @User.Title)",
		"(@User.Title == \"PM\")",
		"(OctetStringType==#01020300)",
		"(@User.Project Any_of @Resource.Project)",
		"(@user.x==1 &&(@user.x >@user.x ) )",
		"(x==1) ",
		"( x Contains 3)",
		"( x < 3)",
		"(x Any_of 3)",
		"( x == SID(BA))",
		"((x) == SID(BA))",
		"(OctetStringType==#1#2#3###))",
		"(@user.x == 00)",
		"(@user.x == 01)",
		"(@user.x == -00)",
		"(@user.x == -01)",
		"(@user.x == 0x0)",
		"(@user.x == 0x1)",
		"(@user.x == -0x0)",
		"(@user.x == -0x1)",
	};
	size_t i, length;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	bool failed = false;
	bool ok;
	for (i = 0; i < ARRAY_SIZE(sddl); i++) {
		struct ace_condition_script *s1 = NULL;
		struct ace_condition_script *s2 = NULL;
		struct ace_condition_script *s3 = NULL;
		const char *message = NULL;
		size_t message_offset;
		const char *resddl1 = NULL;
		const char *resddl2 = NULL;
		DATA_BLOB e1, e2, e3;
		fputs("=======================\n", stderr);
		s1 = ace_conditions_compile_sddl(mem_ctx,
						 ACE_CONDITION_FLAG_ALLOW_DEVICE,
						 sddl[i],
						 &message,
						 &message_offset,
						 &length);
		if (s1 == NULL) {
			debug_fail("%s\n", sddl[i]);
			failed = true;
			print_error_message(sddl[i], message, message_offset);
			continue;
		}
		if (false) {
			debug_conditional_ace_stderr(mem_ctx, s1);
		}
		ok = conditional_ace_encode_binary(mem_ctx, s1, &e1);
		if (! ok) {
			failed = true;
			debug_fail("%s could not encode\n", sddl[i]);
			continue;
		}

		s2 = parse_conditional_ace(mem_ctx, e1);
		if (s2 == NULL) {
			debug_fail("%s failed to decode ace\n", sddl[i]);
			failed = true;
			continue;
		}

		ok = conditional_ace_encode_binary(mem_ctx, s2, &e2);
		if (! ok) {
			failed = true;
			debug_fail("%s could not re-encode\n", sddl[i]);
			continue;
		}
		if (data_blob_cmp(&e1, &e2) != 0) {
			failed = true;
		}

		resddl1 = sddl_from_conditional_ace(mem_ctx, s1);
		if (resddl1 == NULL) {
			failed = true;
			debug_fail("could not re-make SDDL of %s\n", sddl[i]);
			continue;
		}
		resddl2 = sddl_from_conditional_ace(mem_ctx, s2);
		if (resddl2 == NULL) {
			failed = true;
			debug_fail("could not re-make SDDL of %s\n", sddl[i]);
			continue;
		}
		if (strcmp(resddl1, resddl2) != 0) {
			print_message("SDDL 2: %s\n", resddl2);
			failed = true;
		}
		print_message("SDDL: '%s' -> '%s'\n", sddl[i], resddl1);
		s3 = ace_conditions_compile_sddl(mem_ctx,
						 ACE_CONDITION_FLAG_ALLOW_DEVICE,
						 resddl1,
						 &message,
						 &message_offset,
						 &length);
		if (s3 == NULL) {
			debug_fail("resddl: %s\n", resddl1);
			failed = true;
			print_error_message(resddl1, message, message_offset);
			continue;
		}
		ok = conditional_ace_encode_binary(mem_ctx, s3, &e3);
		if (! ok) {
			failed = true;
			debug_fail("%s could not encode\n", resddl1);
			continue;
		}
		if (data_blob_cmp(&e1, &e3) != 0) {
			debug_fail("'%s' and '%s' compiled differently\n", sddl[i], resddl1);
			failed = true;
		}
	}
	assert_false(failed);
	TALLOC_FREE(mem_ctx);
}

static void test_a_number_of_valid_strings(void **state)
{
	/*
	 * These expressions should parse into proper conditional ACEs.
	 */
	static const char *sddl[] = {
		"(@User.TEETH == \"5\")",
		"(x==1) ",
		"( x Contains 3)",
		"( x < 3)",
		"(x Any_of 3)",
		"( x == SID(BA))",
		"(x ANY_Of 3)",
		"((x) == SID(BA))",
		"(x==1 && x >= 2)", /* logical consistency not required */
	};
	size_t i, length;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	bool failed = false;
	for (i = 0; i < ARRAY_SIZE(sddl); i++) {
		struct ace_condition_script *s = NULL;
		const char *message = NULL;
		size_t message_offset;

		s = ace_conditions_compile_sddl(mem_ctx,
						ACE_CONDITION_FLAG_ALLOW_DEVICE,
						sddl[i],
						&message,
						&message_offset,
						&length);
		if (s == NULL) {
			debug_fail("%s\n", sddl[i]);
			failed = true;
		} else if (length != strlen(sddl[i])) {
			debug_fail("%s failed to consume whole string\n",
				   sddl[i]);
			failed = true;
		}
		if (message != NULL) {
			print_error_message(sddl[i], message, message_offset);
		} else if (s == NULL) {
			print_message("failed without message\n");
		}
	}
	assert_false(failed);
	TALLOC_FREE(mem_ctx);
}


static void test_a_number_of_invalid_strings(void **state)
{
	/*
	 * These expressions should fail to parse.
	 */
	static const char *sddl[] = {
		/* '!' is only allowed before parens or @attr */
		"(!!! !!!  !!! Not_Member_of{SID(AA)}))",
		/* overflowing numbers can't be sensibly interpreted */
		("(@Device.bb == 055555624677746777766777767)"),
		("(@Device.bb == 0x624677746777766777767)"),
		("(@Device.bb == 624677746777766777767)"),
		/* insufficient arguments */
		"(!)",
		"(x >)",
		"(> 3)",
		/* keyword as local attribute name */
		"( Member_of Contains 3)",
		/* no parens */
		" x < 3",
		/* wants '==' */
		"( x = SID(BA))",
		/* invalid SID strings */
		"( x == SID(ZZ))",
		"( x == SID(S-1-))",
		"( x == SID())",
		/* literal on LHS */
		"(\"x\" == \"x\")",
		/* odd number of digits following '#' */
		"(OctetStringType==#1#2#3##))",
		/* empty expression */
		"()",
		/* relational op with with complex RHS */
		"(@Device.bb == (@USER.x < 62))",
		/* hex‐escapes that should be literals */
		("(@Device.%002e == 3)"),
		("(@Device.%002f == 3)"),
		("(@Device.%003a == 3)"),
		/* trailing comma in composite */
		"(Member_of{SID(AA),})",
		/* missing comma between elements of a composite */
		"(Member_of{SID(AA) SID(AC)})",
		/* unexpected comma in composite */
		"(Member_of{,})",
	};
	size_t i, length;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	bool failed_to_fail = false;
	for (i = 0; i < ARRAY_SIZE(sddl); i++) {
		struct ace_condition_script *s = NULL;
		const char *message = NULL;
		size_t message_offset;
		s = ace_conditions_compile_sddl(mem_ctx,
						ACE_CONDITION_FLAG_ALLOW_DEVICE,
						sddl[i],
						&message,
						&message_offset,
						&length);
		if (s != NULL) {
			print_message("unexpected success: ");
			debug_fail("%s\n", sddl[i]);
			failed_to_fail = true;
		}
		if (message != NULL) {
			print_error_message(sddl[i], message, message_offset);
		} else if (s == NULL) {
			print_message("failed without message\n");
		}
	}
	assert_false(failed_to_fail);
	TALLOC_FREE(mem_ctx);
}


static void test_a_number_of_invalid_full_sddl_strings(void **state)
{
	/*
	 * These ones are complete SDDL sentences and should fail to parse,
	 * with specific message snippets.
	 */
	static struct {
		const char *sddl;
		const char *snippet;
		ssize_t offset;
	} cases[] = {
		{
			"O:SYG:SYD:(A;;;;ZZ)(XA;OICI;CR;;;WD;(Member_of {WD}))",
			"malformed ACE with only 4 ';'",
			11
		},
		{
			"O:SYG:SYD:QQ(A;;;;ZZ)(XA;OICI;CR;;;WD;(Member_of {WD}))",
			"expected '[OGDS]:' section start",
			10
		}
	};
	size_t i;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	bool failed_to_fail = false;
	bool message_wrong = false;
	enum ace_condition_flags ace_condition_flags = \
		ACE_CONDITION_FLAG_ALLOW_DEVICE;
	struct dom_sid domain_sid;
	string_to_sid(&domain_sid, "S-1-2-3");

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct security_descriptor *sd = NULL;
		const char *message = NULL;
		size_t message_offset;
		sd = sddl_decode_err_msg(mem_ctx,
					 cases[i].sddl,
					 &domain_sid,
					 ace_condition_flags,
					 &message,
					 &message_offset);
		if (sd != NULL) {
			print_message("unexpected success: ");
			debug_fail("%s\n", cases[i].sddl);
			failed_to_fail = true;
		}
		if (cases[i].snippet != NULL) {
			if (message != NULL) {
				char *c = strstr(message, cases[i].snippet);
				print_error_message(cases[i].sddl,
						    message,
						    message_offset);
				if (c == NULL) {
					message_wrong = true;
					print_message("expected '%s'\n",
						      cases[i].snippet);
				}
			} else {
				message_wrong = true;
				print_error_message(cases[i].sddl,
						    "NO MESSAGE!",
						    message_offset);
				print_message("expected '%s', got no message!\n",
					      cases[i].snippet);
			}
		} else {
			print_message("no assertion about message, got '%s'\n",
				      message);
		}
		if (cases[i].offset >= 0) {
			if (cases[i].offset != message_offset) {
				message_wrong = true;
				print_message("expected offset %zd, got %zu\n",
					      cases[i].offset,
					      message_offset);
			}
		} else {
			print_message("no assertion about offset, got '%zu\n",
				      message_offset);
		}
	}
	assert_false(failed_to_fail);
	assert_false(message_wrong);
	TALLOC_FREE(mem_ctx);
}


static void test_valid_strings_with_trailing_crap(void **state)
{
	/*
	 * These expressions should parse even though they have
	 * trailing bytes that look bad.
	 *
	 *  ace_conditions_compile_sddl() will return when it has
	 *  found a complete expression, and tell us how much it used.
	 */
	static struct {
		const char *sddl;
		size_t length;
	} pairs[] = {
		{"(x==1 &&(x < 5 )) )", 18},
		{"(x==1) &&", 7},
		{"(x)) ", 3},
	};
	size_t i, length;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	bool failed = false;
	for (i = 0; i < ARRAY_SIZE(pairs); i++) {
		struct ace_condition_script *s = NULL;
		const char *message = NULL;
		size_t message_offset;
		s = ace_conditions_compile_sddl(mem_ctx,
						ACE_CONDITION_FLAG_ALLOW_DEVICE,
						pairs[i].sddl,
						&message,
						&message_offset,
						&length);

		if (s == NULL) {
			debug_fail("%s\n", pairs[i].sddl);
			failed = true;
		} else if (pairs[i].length == length) {
			debug_ok("%s\n", pairs[i].sddl);
		} else {
			debug_fail("expected to consume %zu bytes, actual %zu\n",
				   pairs[i].length, length);
			failed = true;
		}
		if (message != NULL) {
			print_error_message(pairs[i].sddl, message, message_offset);
		} else if (s == NULL) {
			print_message("failed without message\n");
		}
	}
	assert_false(failed);
	TALLOC_FREE(mem_ctx);
}


int main(_UNUSED_ int argc, _UNUSED_ const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_a_number_of_invalid_full_sddl_strings),
		cmocka_unit_test(test_full_sddl_ra_encode),
		cmocka_unit_test(test_full_sddl_ra_escapes),
		cmocka_unit_test(test_full_sddl_compile),
		cmocka_unit_test(test_round_trips),
		cmocka_unit_test(test_a_number_of_invalid_strings),
		cmocka_unit_test(test_a_number_of_valid_strings),
		cmocka_unit_test(test_valid_strings_with_trailing_crap),
		cmocka_unit_test(test_sddl_compile),
		cmocka_unit_test(test_sddl_compile2),
	};
	if (!isatty(1)) {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}
	return cmocka_run_group_tests(tests, NULL, NULL);
}
