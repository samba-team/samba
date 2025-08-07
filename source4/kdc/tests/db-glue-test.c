/*
 * Unit tests for source4/kdc/db-glue.c
 *
 * Copyright (C) Gary Lockyer 2025
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

/*
 * from cmocka.c:
 * These headers or their equivalents should be included prior to
 * including
 * this header file.
 *
 * #include <stdarg.h>
 * #include <stddef.h>
 * #include <setjmp.h>
 *
 * This allows test applications to use custom definitions of C standard
 * library functions and types.
 *
 */

#include <stdint.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include "../../../third_party/cmocka/cmocka.h"

#include "../db-glue.c"
#include "krb5-protos.h"
#include "ldb.h"
#include "samdb/samdb.h"
#include "sdb.h"
#include "talloc.h"
#include "util/data_blob.h"
#include "util/debug.h"

/******************************************************************************
 * Over ridden functions
 ******************************************************************************
 */
int dsdb_functional_level(struct ldb_context *ldb)
{
	return 1;
}

int certificate_binding_enforcement = 0;
int lpcfg_strong_certificate_binding_enforcement(
	struct loadparm_context *lp_ctx)
{
	return certificate_binding_enforcement;
}

int certificate_backdating_compensation = 0;
int lpcfg_certificate_backdating_compensation(
	struct loadparm_context *lp_ctx)
{
	return certificate_backdating_compensation;
}

/******************************************************************************
 * Test helper functions
 *****************************************************************************/
static void add_msDS_KeyCredentialLink(struct ldb_message *msg,
				       size_t size,
				       uint8_t *data)
{
	DATA_BLOB key_cred_val = {.length = size, .data = data};
	char *hex_value = data_blob_hex_string_upper(msg, &key_cred_val);
	size_t hex_len = strlen(hex_value);
	char *binary_dn = talloc_asprintf(
		msg, "B:%zu:%s:DC=EXAMPLE,DC=COM", hex_len, hex_value);
	TALLOC_FREE(hex_value);

	/* Add the data to msDS-KeyCredentialLink */
	ldb_msg_add_string(msg, "msDS-KeyCredentialLink", binary_dn);
}

static struct ldb_val *get_ldb_string(TALLOC_CTX *mem_ctx, const char * str) {
	char *string = talloc_asprintf(
		mem_ctx, "%s", str);

	size_t len = strlen(string);

	struct ldb_val *value = talloc_zero(mem_ctx, struct ldb_val);

	value->data = (uint8_t *) string;
	value->length = len;
	return value;
}

static void add_altSecurityIdentities(struct ldb_message *msg,
				      const char *str)
{
	/* Add the data to altSecurityIdentities */
	ldb_msg_add_string(msg, "altSecurityIdentities", str);
}

static void add_whenCreated(struct ldb_message *msg,
			    time_t created)
{
	char* ts = ldb_timestring(msg, created);
	assert_non_null(ts);
	ldb_msg_add_string(msg, "whenCreated", ts);
}

static void add_empty_msDS_KeyCredentialLink_DN(TALLOC_CTX *mem_ctx,
						struct ldb_message *msg)
{
	char *binary_dn = talloc_asprintf(msg, "B:0::DC=EXAMPLE,DC=COM");

	/* Add the data to msDS-KeyCredentialLink */
	ldb_msg_add_string(msg, "msDS-KeyCredentialLink", binary_dn);
}

static void add_empty_altSecurities(
	TALLOC_CTX *mem_ctx,
	struct ldb_message *msg)
{
	/* Add an empty altSecurityIdentities */
	ldb_msg_add_string(msg, "altSecurityIdentifiers", "");
}

static struct ldb_message *create_ldb_message(TALLOC_CTX *mem_ctx)
{
	DATA_BLOB sid_val = data_blob_null;
	struct dom_sid sid = {};
	struct ldb_message_element *el = NULL;
	unsigned int flags = UF_NORMAL_ACCOUNT;
	DATA_BLOB flags_val = data_blob_null;

	struct ldb_message *msg = ldb_msg_new(mem_ctx);
	ldb_msg_add_string(msg, "sAMAccountName", "testUser");

	string_to_sid(&sid, "S-1-5-21-4231626423-2410014848-2360679739-513");
	ndr_push_struct_blob(&sid_val,
			     mem_ctx,
			     &sid,
			     (ndr_push_flags_fn_t)ndr_push_dom_sid);
	ldb_msg_add_value(msg, "objectSid", &sid_val, &el);

	flags_val = data_blob_talloc_zero(mem_ctx, sizeof(flags));
	memcpy(flags_val.data, &flags, sizeof(flags));
	ldb_msg_add_value(msg,
			  "msDS-User-Account-Control-Computed",
			  &flags_val,
			  &el);
	return msg;
}

static struct samba_kdc_db_context *create_kdc_db_ctx(TALLOC_CTX *mem_ctx)
{

	struct samba_kdc_db_context *kdc_db_ctx = NULL;

	/* set up an lp_ctx */
	struct loadparm_context *lp_ctx = loadparm_init(mem_ctx);
	assert_non_null(lp_ctx);

	/* Set up the kdc_db_context */
	kdc_db_ctx = talloc_zero(mem_ctx, struct samba_kdc_db_context);
	kdc_db_ctx->lp_ctx = lp_ctx;

	kdc_db_ctx->current_nttime_ull = talloc_zero(kdc_db_ctx,
						     unsigned long long);

	return kdc_db_ctx;
}

static krb5_principal get_principal(TALLOC_CTX *mem_ctx,
				    krb5_context krb5_ctx,
				    const char *name)
{
	krb5_principal principal = NULL;
	char *principle_name = NULL;

	principle_name = talloc_strdup(mem_ctx, "atestuser@test.samba.org");
	assert_int_equal(
		0, smb_krb5_parse_name(krb5_ctx, principle_name, &principal));
	assert_non_null(principal);
	return principal;
}

/******************************************************************************
 * Test Data
 *****************************************************************************/
/* clang-format off */
/* clang format tends to mangle the layout so turn it of for the test data   */

static uint8_t BCRYPT_KEY_CREDENTIAL_LINK[] = {
	0x00, 0x02, 0x00, 0x00,		/* version 2                         */
	0x1C, 0x01, 0x03,		/* Key Material                      */
	'R', 'S', 'A', '1',		/* RSA public key                    */
	0x00, 0x08, 0x00, 0x00,		/* bit length, 2048                  */
	0x04, 0x00, 0x00, 0x00,		/* public exponent length            */
	0x00, 0x01, 0x00, 0x00,		/* modulus length, 256               */
	0x00, 0x00, 0x00, 0x00,		/* prime one length                  */
	0x00, 0x00, 0x00, 0x00,		/* prime two length                  */
	0x01, 0x02, 0x03, 0x04,		/* public exponent                   */
					/* modulus                           */
	0x9A, 0x9E, 0xF6, 0x5D, 0xE2, 0x92, 0xD6, 0xD0,
	0xE5, 0xB3, 0xC4, 0x35, 0xB1, 0x5B, 0x36, 0xF3,
	0x9E, 0x83, 0x7B, 0xA9, 0x34, 0xAB, 0xD9, 0x67,
	0xE1, 0x1C, 0x75, 0x43, 0xE5, 0xB6, 0x48, 0x9B,
	0x6E, 0xCD, 0x8D, 0xFC, 0x30, 0x5F, 0x4C, 0xB6,
	0x8E, 0xA0, 0x69, 0xA4, 0x07, 0x21, 0xE7, 0xD7,
	0xA1, 0x74, 0x4A, 0x29, 0xBC, 0xC9, 0x5D, 0x78,
	0x70, 0xC4, 0x3B, 0xE4, 0x20, 0x54, 0xBC, 0xD0,
	0xAA, 0xFF, 0x21, 0x44, 0x54, 0xFC, 0x09, 0x08,
	0x2A, 0xCC, 0xDE, 0x44, 0x68, 0xED, 0x9F, 0xB2,
	0x3E, 0xF7, 0xED, 0x82, 0xD7, 0x2D, 0x28, 0x74,
	0x42, 0x2A, 0x2F, 0x55, 0xA2, 0xE0, 0xDA, 0x45,
	0xF1, 0x08, 0xC0, 0x83, 0x8C, 0x95, 0x81, 0x6D,
	0x92, 0xCC, 0xA8, 0x5D, 0xA4, 0xB8, 0x06, 0x8C,
	0x76, 0xF5, 0x68, 0x94, 0xE7, 0x60, 0xE6, 0xF4,
	0xEE, 0x40, 0x50, 0x28, 0x6C, 0x82, 0x47, 0x89,
	0x07, 0xE7, 0xBC, 0x0D, 0x56, 0x5D, 0xDA, 0x86,
	0x57, 0xE2, 0xCE, 0xD3, 0x19, 0xA1, 0xA2, 0x7F,
	0x56, 0xF8, 0x99, 0x8B, 0x4A, 0x71, 0x32, 0x6A,
	0x57, 0x3B, 0xF9, 0xE5, 0x2D, 0x39, 0x35, 0x6E,
	0x13, 0x3E, 0x84, 0xDC, 0x5C, 0x96, 0xE1, 0x75,
	0x38, 0xC3, 0xAA, 0x23, 0x5B, 0x68, 0xBE, 0x41,
	0x52, 0x49, 0x72, 0x7A, 0xF6, 0x2A, 0x8F, 0xC5,
	0xC5, 0xE0, 0x6C, 0xDB, 0x99, 0xD1, 0xA8, 0x84,
	0x5F, 0x70, 0x21, 0x87, 0x2E, 0xA0, 0xD2, 0x68,
	0xD3, 0x76, 0x5C, 0x9E, 0xD4, 0x9C, 0xB5, 0xE1,
	0x72, 0x9D, 0x17, 0x8B, 0xDC, 0x11, 0x55, 0x09,
	0x90, 0x8D, 0x96, 0xF3, 0x68, 0x34, 0xDD, 0x50,
	0x63, 0xAC, 0x4A, 0x74, 0xA7, 0xAF, 0x0D, 0xDC,
	0x15, 0x06, 0x07, 0xD7, 0x5A, 0xB3, 0x86, 0x1A,
	0x54, 0x96, 0xE0, 0xFA, 0x66, 0x25, 0x31, 0xF5,
	0xB4, 0xC7, 0x97, 0xC7, 0x7C, 0x70, 0x94, 0xE3,
	0x01, 0x00, 0x04, 0x01,		/* key usage                         */
	0x01, 0x00, 0x05, 0x00,		/* key source                        */
};

static uint8_t BCRYPT_MODULUS[] = {
	0x9A, 0x9E, 0xF6, 0x5D, 0xE2, 0x92, 0xD6, 0xD0,
	0xE5, 0xB3, 0xC4, 0x35, 0xB1, 0x5B, 0x36, 0xF3,
	0x9E, 0x83, 0x7B, 0xA9, 0x34, 0xAB, 0xD9, 0x67,
	0xE1, 0x1C, 0x75, 0x43, 0xE5, 0xB6, 0x48, 0x9B,
	0x6E, 0xCD, 0x8D, 0xFC, 0x30, 0x5F, 0x4C, 0xB6,
	0x8E, 0xA0, 0x69, 0xA4, 0x07, 0x21, 0xE7, 0xD7,
	0xA1, 0x74, 0x4A, 0x29, 0xBC, 0xC9, 0x5D, 0x78,
	0x70, 0xC4, 0x3B, 0xE4, 0x20, 0x54, 0xBC, 0xD0,
	0xAA, 0xFF, 0x21, 0x44, 0x54, 0xFC, 0x09, 0x08,
	0x2A, 0xCC, 0xDE, 0x44, 0x68, 0xED, 0x9F, 0xB2,
	0x3E, 0xF7, 0xED, 0x82, 0xD7, 0x2D, 0x28, 0x74,
	0x42, 0x2A, 0x2F, 0x55, 0xA2, 0xE0, 0xDA, 0x45,
	0xF1, 0x08, 0xC0, 0x83, 0x8C, 0x95, 0x81, 0x6D,
	0x92, 0xCC, 0xA8, 0x5D, 0xA4, 0xB8, 0x06, 0x8C,
	0x76, 0xF5, 0x68, 0x94, 0xE7, 0x60, 0xE6, 0xF4,
	0xEE, 0x40, 0x50, 0x28, 0x6C, 0x82, 0x47, 0x89,
	0x07, 0xE7, 0xBC, 0x0D, 0x56, 0x5D, 0xDA, 0x86,
	0x57, 0xE2, 0xCE, 0xD3, 0x19, 0xA1, 0xA2, 0x7F,
	0x56, 0xF8, 0x99, 0x8B, 0x4A, 0x71, 0x32, 0x6A,
	0x57, 0x3B, 0xF9, 0xE5, 0x2D, 0x39, 0x35, 0x6E,
	0x13, 0x3E, 0x84, 0xDC, 0x5C, 0x96, 0xE1, 0x75,
	0x38, 0xC3, 0xAA, 0x23, 0x5B, 0x68, 0xBE, 0x41,
	0x52, 0x49, 0x72, 0x7A, 0xF6, 0x2A, 0x8F, 0xC5,
	0xC5, 0xE0, 0x6C, 0xDB, 0x99, 0xD1, 0xA8, 0x84,
	0x5F, 0x70, 0x21, 0x87, 0x2E, 0xA0, 0xD2, 0x68,
	0xD3, 0x76, 0x5C, 0x9E, 0xD4, 0x9C, 0xB5, 0xE1,
	0x72, 0x9D, 0x17, 0x8B, 0xDC, 0x11, 0x55, 0x09,
	0x90, 0x8D, 0x96, 0xF3, 0x68, 0x34, 0xDD, 0x50,
	0x63, 0xAC, 0x4A, 0x74, 0xA7, 0xAF, 0x0D, 0xDC,
	0x15, 0x06, 0x07, 0xD7, 0x5A, 0xB3, 0x86, 0x1A,
	0x54, 0x96, 0xE0, 0xFA, 0x66, 0x25, 0x31, 0xF5,
	0xB4, 0xC7, 0x97, 0xC7, 0x7C, 0x70, 0x94, 0xE3,
};

static uint8_t BCRYPT_EXPONENT[] = {
	0x01, 0x02, 0x03, 0x04,
};

static uint8_t TPM_KEY_CREDENTIAL_LINK[] = {
	0x00, 0x02, 0x00, 0x00,		/* version 2			     */
	0x50, 0x01, 0x03,		/* Key Material			     */
	0x50, 0x43, 0x50, 0x4D,		/* Magic value PCPM		     */
	0x2E, 0x00, 0x00, 0x00,		/* header length		     */
	0x02, 0x00, 0x00, 0x00,		/* type TPM 2.0			     */
	0x00, 0x00, 0x00, 0x00,		/* flags			     */
	0x00, 0x00, 0x00, 0x00,		/* public_length		     */
	0x00, 0x00, 0x00, 0x00,		/* private length		     */
	0x00, 0x00, 0x00, 0x00,		/* migration public length	     */
	0x00, 0x00, 0x00, 0x00,		/* migration private length	     */
	0x00, 0x00, 0x00, 0x00,		/* policy digest list length	     */
	0x00, 0x00, 0x00, 0x00,		/* PCR binding length		     */
	0x00, 0x00, 0x00, 0x00,		/* PCR digest length		     */
	0x00, 0x00, 0x00, 0x00,		/* Encrypted secret length	     */
	0x00, 0x00, 0x00, 0x00,		/* TPM 1.2 hostage blob length	     */
	0x00, 0x00,			/* PCRA Algorithm Id		     */
	0x18, 0x01,			/* size 280 bytes		     */
	0x00, 0x01,			/* type				     */
	0x00, 0x0B,			/* hash algorithm		     */
	0x00, 0x05, 0x24, 0x72,		/* attributes			     */
	0x00, 0x00,			/* auth policy			     */
	0x00, 0x10,			/* algorithm			     */
	0x00, 0x14,			/* scheme			     */
	0x00, 0x0B,			/*hash algorithm		     */
	0x08, 0x00,			/* key bits		             */
	0x01, 0x02, 0x03, 0x04,		/* exponent			     */
	0x01, 0x00,			/* modulus size 256 bytes	     */
	0x9A, 0x9E, 0xF6, 0x5D, 0xE2, 0x92, 0xD6, 0xD0,
	0xE5, 0xB3, 0xC4, 0x35, 0xB1, 0x5B, 0x36, 0xF3,
	0x9E, 0x83, 0x7B, 0xA9, 0x34, 0xAB, 0xD9, 0x67,
	0xE1, 0x1C, 0x75, 0x43, 0xE5, 0xB6, 0x48, 0x9B,
	0x6E, 0xCD, 0x8D, 0xFC, 0x30, 0x5F, 0x4C, 0xB6,
	0x8E, 0xA0, 0x69, 0xA4, 0x07, 0x21, 0xE7, 0xD7,
	0xA1, 0x74, 0x4A, 0x29, 0xBC, 0xC9, 0x5D, 0x78,
	0x70, 0xC4, 0x3B, 0xE4, 0x20, 0x54, 0xBC, 0xD0,
	0xAA, 0xFF, 0x21, 0x44, 0x54, 0xFC, 0x09, 0x08,
	0x2A, 0xCC, 0xDE, 0x44, 0x68, 0xED, 0x9F, 0xB2,
	0x3E, 0xF7, 0xED, 0x82, 0xD7, 0x2D, 0x28, 0x74,
	0x42, 0x2A, 0x2F, 0x55, 0xA2, 0xE0, 0xDA, 0x45,
	0xF1, 0x08, 0xC0, 0x83, 0x8C, 0x95, 0x81, 0x6D,
	0x92, 0xCC, 0xA8, 0x5D, 0xA4, 0xB8, 0x06, 0x8C,
	0x76, 0xF5, 0x68, 0x94, 0xE7, 0x60, 0xE6, 0xF4,
	0xEE, 0x40, 0x50, 0x28, 0x6C, 0x82, 0x47, 0x89,
	0x07, 0xE7, 0xBC, 0x0D, 0x56, 0x5D, 0xDA, 0x86,
	0x57, 0xE2, 0xCE, 0xD3, 0x19, 0xA1, 0xA2, 0x7F,
	0x56, 0xF8, 0x99, 0x8B, 0x4A, 0x71, 0x32, 0x6A,
	0x57, 0x3B, 0xF9, 0xE5, 0x2D, 0x39, 0x35, 0x6E,
	0x13, 0x3E, 0x84, 0xDC, 0x5C, 0x96, 0xE1, 0x75,
	0x38, 0xC3, 0xAA, 0x23, 0x5B, 0x68, 0xBE, 0x41,
	0x52, 0x49, 0x72, 0x7A, 0xF6, 0x2A, 0x8F, 0xC5,
	0xC5, 0xE0, 0x6C, 0xDB, 0x99, 0xD1, 0xA8, 0x84,
	0x5F, 0x70, 0x21, 0x87, 0x2E, 0xA0, 0xD2, 0x68,
	0xD3, 0x76, 0x5C, 0x9E, 0xD4, 0x9C, 0xB5, 0xE1,
	0x72, 0x9D, 0x17, 0x8B, 0xDC, 0x11, 0x55, 0x09,
	0x90, 0x8D, 0x96, 0xF3, 0x68, 0x34, 0xDD, 0x50,
	0x63, 0xAC, 0x4A, 0x74, 0xA7, 0xAF, 0x0D, 0xDC,
	0x15, 0x06, 0x07, 0xD7, 0x5A, 0xB3, 0x86, 0x1A,
	0x54, 0x96, 0xE0, 0xFA, 0x66, 0x25, 0x31, 0xF5,
	0xB4, 0xC7, 0x97, 0xC7, 0x7C, 0x70, 0x94, 0xE3,
	0x01, 0x00, 0x04, 0x01,		/* key usage			     */
	0x01, 0x00, 0x05, 0x00,		/* key source                        */
};

static uint8_t TPM_MODULUS[] = {
	0x9A, 0x9E, 0xF6, 0x5D, 0xE2, 0x92, 0xD6, 0xD0,
	0xE5, 0xB3, 0xC4, 0x35, 0xB1, 0x5B, 0x36, 0xF3,
	0x9E, 0x83, 0x7B, 0xA9, 0x34, 0xAB, 0xD9, 0x67,
	0xE1, 0x1C, 0x75, 0x43, 0xE5, 0xB6, 0x48, 0x9B,
	0x6E, 0xCD, 0x8D, 0xFC, 0x30, 0x5F, 0x4C, 0xB6,
	0x8E, 0xA0, 0x69, 0xA4, 0x07, 0x21, 0xE7, 0xD7,
	0xA1, 0x74, 0x4A, 0x29, 0xBC, 0xC9, 0x5D, 0x78,
	0x70, 0xC4, 0x3B, 0xE4, 0x20, 0x54, 0xBC, 0xD0,
	0xAA, 0xFF, 0x21, 0x44, 0x54, 0xFC, 0x09, 0x08,
	0x2A, 0xCC, 0xDE, 0x44, 0x68, 0xED, 0x9F, 0xB2,
	0x3E, 0xF7, 0xED, 0x82, 0xD7, 0x2D, 0x28, 0x74,
	0x42, 0x2A, 0x2F, 0x55, 0xA2, 0xE0, 0xDA, 0x45,
	0xF1, 0x08, 0xC0, 0x83, 0x8C, 0x95, 0x81, 0x6D,
	0x92, 0xCC, 0xA8, 0x5D, 0xA4, 0xB8, 0x06, 0x8C,
	0x76, 0xF5, 0x68, 0x94, 0xE7, 0x60, 0xE6, 0xF4,
	0xEE, 0x40, 0x50, 0x28, 0x6C, 0x82, 0x47, 0x89,
	0x07, 0xE7, 0xBC, 0x0D, 0x56, 0x5D, 0xDA, 0x86,
	0x57, 0xE2, 0xCE, 0xD3, 0x19, 0xA1, 0xA2, 0x7F,
	0x56, 0xF8, 0x99, 0x8B, 0x4A, 0x71, 0x32, 0x6A,
	0x57, 0x3B, 0xF9, 0xE5, 0x2D, 0x39, 0x35, 0x6E,
	0x13, 0x3E, 0x84, 0xDC, 0x5C, 0x96, 0xE1, 0x75,
	0x38, 0xC3, 0xAA, 0x23, 0x5B, 0x68, 0xBE, 0x41,
	0x52, 0x49, 0x72, 0x7A, 0xF6, 0x2A, 0x8F, 0xC5,
	0xC5, 0xE0, 0x6C, 0xDB, 0x99, 0xD1, 0xA8, 0x84,
	0x5F, 0x70, 0x21, 0x87, 0x2E, 0xA0, 0xD2, 0x68,
	0xD3, 0x76, 0x5C, 0x9E, 0xD4, 0x9C, 0xB5, 0xE1,
	0x72, 0x9D, 0x17, 0x8B, 0xDC, 0x11, 0x55, 0x09,
	0x90, 0x8D, 0x96, 0xF3, 0x68, 0x34, 0xDD, 0x50,
	0x63, 0xAC, 0x4A, 0x74, 0xA7, 0xAF, 0x0D, 0xDC,
	0x15, 0x06, 0x07, 0xD7, 0x5A, 0xB3, 0x86, 0x1A,
	0x54, 0x96, 0xE0, 0xFA, 0x66, 0x25, 0x31, 0xF5,
	0xB4, 0xC7, 0x97, 0xC7, 0x7C, 0x70, 0x94, 0xE3,
};

static uint8_t TPM_EXPONENT[] = {
	0x01, 0x02, 0x03, 0x04,
};

static uint8_t DER_KEY_CREDENTIAL_LINK[] = {
	0x00, 0x02, 0x00, 0x00,		/* version 2			     */
	0x26, 0x01, 0x03,		/* Key Material			     */
	0x30, 0x82, 0x01, 0x22,		/* Sequence 290 bytes, 2 elements    */
	0x30, 0x0d,			/* Sequence 13 bytes, 2 elem	     */
	0x06, 0x09,			/* OID 9 bytes, 1.2.840.113549.1.1.1 */
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
	0x05, 0x00,			/* Null				     */
	0x03, 0x82, 0x01, 0x0f, 0x00,	/* Bit string, 2160 bits, 0 unused   */
	0x30, 0x82, 0x01, 0x0a,		/* Sequence 266 bytes, 2 elements    */
	0x02, 0x82, 0x01, 0x01, 0x00,	/* Integer 2048 bit, 257 bytes       */
					/* MODULUS is 257 bytes as it's most */
					/* significant byte is 0b10111101    */
					/* which has bit 8 set, which        */
					/* DER Integer encoding uses as the  */
					/* sign bit, so need the leading 00  */
					/* byte to prevent the value being   */
					/* interpreted as a negative integer */
	0xbd, 0xae, 0x45, 0x8b, 0x17, 0xcd, 0x3e, 0x62,
	0x71, 0x66, 0x67, 0x7f, 0xa2, 0x46, 0xc4, 0x47,
	0x78, 0x79, 0xf2, 0x8c, 0xd4, 0x2e, 0x0c, 0xa0,
	0x90, 0x1c, 0xf6, 0x33, 0xe1, 0x94, 0x89, 0xb9,
	0x44, 0x15, 0xe3, 0x29, 0xe7, 0xb6, 0x91, 0xca,
	0xab, 0x7e, 0xc6, 0x25, 0x60, 0xe3, 0x7a, 0xc4,
	0x09, 0x97, 0x8a, 0x4e, 0x79, 0xcb, 0xa6, 0x1f,
	0xf8, 0x29, 0x3f, 0x8a, 0x0d, 0x45, 0x58, 0x9b,
	0x0e, 0xbf, 0xa5, 0xfa, 0x1c, 0xa2, 0x5e, 0x31,
	0xa1, 0xe7, 0xba, 0x7e, 0x17, 0x62, 0x03, 0x79,
	0xc0, 0x07, 0x48, 0x11, 0x8b, 0xfa, 0x58, 0x17,
	0x56, 0x1a, 0xa1, 0x62, 0xd2, 0x02, 0x02, 0x2a,
	0x64, 0x8d, 0x8c, 0x53, 0xfa, 0x28, 0x7c, 0x89,
	0x18, 0x34, 0x70, 0x64, 0xa7, 0x08, 0x10, 0xc9,
	0x3b, 0x1b, 0x2c, 0x23, 0x88, 0x9c, 0x35, 0x50,
	0x78, 0xd1, 0x89, 0x33, 0xce, 0x82, 0xb2, 0x84,
	0xf4, 0x99, 0xd8, 0x3e, 0x67, 0x11, 0xa1, 0x5c,
	0x1a, 0x64, 0xb8, 0x6a, 0x3e, 0xe6, 0x95, 0x2e,
	0x47, 0x33, 0x51, 0x7e, 0xb7, 0x62, 0xb4, 0x08,
	0x2c, 0xc4, 0x87, 0x52, 0x00, 0x9e, 0x28, 0xf2,
	0x16, 0x9f, 0x1b, 0xc1, 0x3a, 0x93, 0x6d, 0xa3,
	0x38, 0x9b, 0x34, 0x39, 0x88, 0x85, 0xea, 0x38,
	0xad, 0xc2, 0x2b, 0xc3, 0x7c, 0x15, 0xcb, 0x8f,
	0x15, 0x37, 0xed, 0x88, 0x62, 0x5c, 0x34, 0x75,
	0x6f, 0xb0, 0xeb, 0x5c, 0x42, 0x6a, 0xcd, 0x03,
	0xcc, 0x49, 0xbc, 0xb4, 0x78, 0x14, 0xe1, 0x5e,
	0x98, 0x83, 0x6f, 0xe7, 0x19, 0xa8, 0x43, 0xcb,
	0xca, 0x07, 0xb2, 0x4e, 0xa4, 0x36, 0x60, 0x95,
	0xac, 0x6f, 0xe2, 0x1d, 0x3a, 0x33, 0xf6, 0x0e,
	0x94, 0xae, 0xfb, 0xd2, 0xac, 0x9f, 0xc2, 0x9f,
	0x5b, 0x77, 0x8f, 0x46, 0x3c, 0xee, 0x13, 0x27,
	0x19, 0x8e, 0x68, 0x71, 0x27, 0x3f, 0x50, 0x59,
	0x02, 0x03, 0x01, 0x00, 0x01,	/* INTEGER, 3 bytes EXPONENT	     */
	0x01, 0x00, 0x04, 0x01,		/* key usage                         */
	0x01, 0x00, 0x05, 0x00,		/* key source                        */
};

static uint8_t DER_MODULUS[] = {
	0xbd, 0xae, 0x45, 0x8b, 0x17, 0xcd, 0x3e, 0x62,
	0x71, 0x66, 0x67, 0x7f, 0xa2, 0x46, 0xc4, 0x47,
	0x78, 0x79, 0xf2, 0x8c, 0xd4, 0x2e, 0x0c, 0xa0,
	0x90, 0x1c, 0xf6, 0x33, 0xe1, 0x94, 0x89, 0xb9,
	0x44, 0x15, 0xe3, 0x29, 0xe7, 0xb6, 0x91, 0xca,
	0xab, 0x7e, 0xc6, 0x25, 0x60, 0xe3, 0x7a, 0xc4,
	0x09, 0x97, 0x8a, 0x4e, 0x79, 0xcb, 0xa6, 0x1f,
	0xf8, 0x29, 0x3f, 0x8a, 0x0d, 0x45, 0x58, 0x9b,
	0x0e, 0xbf, 0xa5, 0xfa, 0x1c, 0xa2, 0x5e, 0x31,
	0xa1, 0xe7, 0xba, 0x7e, 0x17, 0x62, 0x03, 0x79,
	0xc0, 0x07, 0x48, 0x11, 0x8b, 0xfa, 0x58, 0x17,
	0x56, 0x1a, 0xa1, 0x62, 0xd2, 0x02, 0x02, 0x2a,
	0x64, 0x8d, 0x8c, 0x53, 0xfa, 0x28, 0x7c, 0x89,
	0x18, 0x34, 0x70, 0x64, 0xa7, 0x08, 0x10, 0xc9,
	0x3b, 0x1b, 0x2c, 0x23, 0x88, 0x9c, 0x35, 0x50,
	0x78, 0xd1, 0x89, 0x33, 0xce, 0x82, 0xb2, 0x84,
	0xf4, 0x99, 0xd8, 0x3e, 0x67, 0x11, 0xa1, 0x5c,
	0x1a, 0x64, 0xb8, 0x6a, 0x3e, 0xe6, 0x95, 0x2e,
	0x47, 0x33, 0x51, 0x7e, 0xb7, 0x62, 0xb4, 0x08,
	0x2c, 0xc4, 0x87, 0x52, 0x00, 0x9e, 0x28, 0xf2,
	0x16, 0x9f, 0x1b, 0xc1, 0x3a, 0x93, 0x6d, 0xa3,
	0x38, 0x9b, 0x34, 0x39, 0x88, 0x85, 0xea, 0x38,
	0xad, 0xc2, 0x2b, 0xc3, 0x7c, 0x15, 0xcb, 0x8f,
	0x15, 0x37, 0xed, 0x88, 0x62, 0x5c, 0x34, 0x75,
	0x6f, 0xb0, 0xeb, 0x5c, 0x42, 0x6a, 0xcd, 0x03,
	0xcc, 0x49, 0xbc, 0xb4, 0x78, 0x14, 0xe1, 0x5e,
	0x98, 0x83, 0x6f, 0xe7, 0x19, 0xa8, 0x43, 0xcb,
	0xca, 0x07, 0xb2, 0x4e, 0xa4, 0x36, 0x60, 0x95,
	0xac, 0x6f, 0xe2, 0x1d, 0x3a, 0x33, 0xf6, 0x0e,
	0x94, 0xae, 0xfb, 0xd2, 0xac, 0x9f, 0xc2, 0x9f,
	0x5b, 0x77, 0x8f, 0x46, 0x3c, 0xee, 0x13, 0x27,
	0x19, 0x8e, 0x68, 0x71, 0x27, 0x3f, 0x50, 0x59,
};

static uint8_t DER_EXPONENT[] = {
	0x01, 0x00, 0x01,
};

/* clang-format on */
/******************************************************************************
 * Tests
 *****************************************************************************/

/*
 * Test samba_kdc_message2entry behaviour when passed an empty message.
 */
static void empty_message2entry(void **state)
{

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_context krb5_ctx = NULL;
	struct samba_kdc_db_context *kdc_db_ctx = NULL;
	struct ldb_context *ldb_ctx = ldb_init(mem_ctx, NULL);

	krb5_principal principal = NULL;
	struct ldb_dn *realm_dn = NULL;
	struct ldb_message *msg = NULL;

	krb5_kvno kvno = 0;
	enum samba_kdc_ent_type ent_type = SAMBA_KDC_ENT_TYPE_CLIENT;
	unsigned int flags = 0;

	struct sdb_entry entry = {};
	krb5_error_code err = 0;

	/* Set up */
	kdc_db_ctx = create_kdc_db_ctx(mem_ctx);
	realm_dn = ldb_dn_new(mem_ctx, ldb_ctx, "TEST.SAMBA.ORG");

	smb_krb5_init_context_common(&krb5_ctx);
	assert_non_null(krb5_ctx);

	principal = get_principal(mem_ctx,
				  krb5_ctx,
				  "atestuser@test.samba.org");

	msg = ldb_msg_new(mem_ctx);

	err = samba_kdc_message2entry(krb5_ctx,
				      kdc_db_ctx,
				      mem_ctx,
				      principal,
				      ent_type,
				      flags,
				      kvno,
				      realm_dn,
				      msg,
				      &entry);

	/* Expect ENOENT as there is no SAMAccountName, among others */
	assert_int_equal(ENOENT, err);

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}

/*
 * Test samba_kdc_message2entry behaviour with minimum required elements.
 */
static void minimal_message2entry(void **state)
{

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_context krb5_ctx = NULL;
	struct samba_kdc_db_context *kdc_db_ctx = create_kdc_db_ctx(mem_ctx);
	struct ldb_context *ldb_ctx = ldb_init(mem_ctx, NULL);
	struct ldb_dn *realm_dn = ldb_dn_new(mem_ctx,
					     ldb_ctx,
					     "TEST.SAMBA.ORG");
	struct ldb_message *msg = NULL;

	krb5_principal principal = NULL;

	enum samba_kdc_ent_type ent_type = SAMBA_KDC_ENT_TYPE_CLIENT;
	unsigned int flags = 0;
	krb5_kvno kvno = 0;

	struct sdb_entry entry = {};
	krb5_error_code err = 0;
	time_t now = time(NULL);

	/* Set up */
	smb_krb5_init_context_common(&krb5_ctx);
	assert_non_null(krb5_ctx);
	principal = get_principal(mem_ctx,
				  krb5_ctx,
				  "atestuser@test.samba.org");

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_whenCreated(msg, now);

	err = samba_kdc_message2entry(krb5_ctx,
				      kdc_db_ctx,
				      mem_ctx,
				      principal,
				      ent_type,
				      flags,
				      kvno,
				      realm_dn,
				      msg,
				      &entry);

	/* Expect the ldb message to be loaded */
	assert_int_equal(0, err);
	assert_null(entry.pub_keys.keys);
	assert_int_equal(0, entry.pub_keys.len);

	krb5_free_principal(krb5_ctx, principal);
	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}
/*
 * Test samba_kdc_message2entry mapping of an empty msDS-KeyCredentialLink
 * binary dn
 */
static void empty_binary_dn_message2entry(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_context krb5_ctx = NULL;
	struct samba_kdc_db_context *kdc_db_ctx = create_kdc_db_ctx(mem_ctx);
	struct ldb_context *ldb_ctx = ldb_init(mem_ctx, NULL);
	struct ldb_dn *realm_dn = ldb_dn_new(mem_ctx,
					     ldb_ctx,
					     "TEST.SAMBA.ORG");
	struct ldb_message *msg = NULL;

	krb5_principal principal = NULL;

	enum samba_kdc_ent_type ent_type = SAMBA_KDC_ENT_TYPE_CLIENT;
	unsigned int flags = 0;
	krb5_kvno kvno = 0;

	struct sdb_entry entry = {};
	krb5_error_code err = 0;
	time_t now = time(NULL);

	/* Set up */
	smb_krb5_init_context_common(&krb5_ctx);
	kdc_db_ctx->samdb = ldb_ctx;
	assert_non_null(krb5_ctx);
	principal = get_principal(mem_ctx,
				  krb5_ctx,
				  "atestuser@test.samba.org");

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_empty_msDS_KeyCredentialLink_DN(mem_ctx, msg);
	add_whenCreated(msg, now);

	err = samba_kdc_message2entry(krb5_ctx,
				      kdc_db_ctx,
				      mem_ctx,
				      principal,
				      ent_type,
				      flags,
				      kvno,
				      realm_dn,
				      msg,
				      &entry);

	/* Expect the ldb message to be loaded */
	assert_int_equal(0, err);
	assert_null(entry.pub_keys.keys);
	assert_int_equal(0, entry.pub_keys.len);

	krb5_free_principal(krb5_ctx, principal);
	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}

/*
 * Test samba_kdc_message2entry mapping of msDS-KeyCredentialLink.
 */
static void msDS_KeyCredentialLink_message2entry(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_context krb5_ctx = NULL;
	struct samba_kdc_db_context *kdc_db_ctx = create_kdc_db_ctx(mem_ctx);
	struct ldb_context *ldb_ctx = ldb_init(mem_ctx, NULL);
	struct ldb_dn *realm_dn = ldb_dn_new(mem_ctx,
					     ldb_ctx,
					     "TEST.SAMBA.ORG");
	struct ldb_message *msg = NULL;

	krb5_principal principal = NULL;

	enum samba_kdc_ent_type ent_type = SAMBA_KDC_ENT_TYPE_CLIENT;
	unsigned int flags = 0;
	krb5_kvno kvno = 0;

	struct sdb_entry entry = {};
	krb5_error_code err = 0;
	time_t now = time(NULL);

	/* Set up */
	smb_krb5_init_context_common(&krb5_ctx);
	kdc_db_ctx->samdb = ldb_ctx;
	assert_non_null(krb5_ctx);
	principal = get_principal(mem_ctx,
				  krb5_ctx,
				  "atestuser@test.samba.org");

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_msDS_KeyCredentialLink(msg,
				   sizeof(BCRYPT_KEY_CREDENTIAL_LINK),
				   BCRYPT_KEY_CREDENTIAL_LINK);
	add_whenCreated(msg, now);

	err = samba_kdc_message2entry(krb5_ctx,
				      kdc_db_ctx,
				      mem_ctx,
				      principal,
				      ent_type,
				      flags,
				      kvno,
				      realm_dn,
				      msg,
				      &entry);

	/* Expect the ldb message to be loaded */
	assert_int_equal(0, err);
	assert_non_null(entry.pub_keys.keys);
	assert_int_equal(1, entry.pub_keys.len);

	assert_int_equal(2048, entry.pub_keys.keys[0].bit_size);

	assert_int_equal(sizeof(BCRYPT_MODULUS),
			 entry.pub_keys.keys[0].modulus.length);
	assert_memory_equal(BCRYPT_MODULUS,
			    entry.pub_keys.keys[0].modulus.data,
			    sizeof(BCRYPT_MODULUS));

	assert_int_equal(sizeof(BCRYPT_EXPONENT),
			 entry.pub_keys.keys[0].exponent.length);
	assert_memory_equal(BCRYPT_EXPONENT,
			    entry.pub_keys.keys[0].exponent.data,
			    sizeof(BCRYPT_EXPONENT));

	krb5_free_principal(krb5_ctx, principal);
	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}

/*
 * Test get_key_trust_public_keys
 * handling of an invalid version number
 */
static void invalid_version_keycredlink(void **state)
{
	/* clang-format off */
	uint8_t KEY_CREDENTIAL_LINK[] = {
		0x01, 0x02, 0x00, 0x00, /* Invalid version                   */
		0x18, 0x00, 0x03,	/* Key Material                      */
		'R',  'S',  'A',  '1',	/* RSA public key                    */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x04, 0x01, /* key usage (KEY_USAGE_NGC)         */
		0x01, 0x00, 0x05, 0x00, /* key source (KEY_SOURCE_AD)        */
	};
	/* clang-format on */

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct ldb_context *ldb = ldb_init(mem_ctx, NULL);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_msDS_KeyCredentialLink(msg,
				   sizeof(KEY_CREDENTIAL_LINK),
				   KEY_CREDENTIAL_LINK);

	err = get_key_trust_public_keys(mem_ctx, ldb, msg,  &entry);

	/* Expect the key credential link to be ignored */
	assert_int_equal(0, err);
	assert_null(entry.pub_keys.keys);
	assert_int_equal(0, entry.pub_keys.len);

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}

/*
 * Test get_key_trust_public_keys
 * handling of duplicate key material
 */
static void duplicate_key_material_keycredlink(void **state)
{
	/* clang-format off */
	uint8_t KEY_CREDENTIAL_LINK[] = {
		0x00, 0x02, 0x00, 0x00,	/* Invalid version                   */
		0x18, 0x00, 0x03,	/* Key Material                      */
		'R',  'S',  'A',  '1',	/* RSA public key                    */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x18, 0x00, 0x03,	/* Key Material, a duplicate         */
		'R',  'S',  'A',  '1',	/* RSA public key                    */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x04, 0x01, /* key usage (KEY_USAGE_NGC)	     */
		0x01, 0x00, 0x05, 0x00, /* key source (KEY_SOURCE_AD)        */
	};
	/* clang-format on */

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct ldb_context *ldb = ldb_init(mem_ctx, NULL);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_msDS_KeyCredentialLink(msg,
				   sizeof(KEY_CREDENTIAL_LINK),
				   KEY_CREDENTIAL_LINK);

	err = get_key_trust_public_keys(mem_ctx, ldb, msg, &entry);

	/* Expect the key credential link to be ignored */
	assert_int_equal(0, err);
	assert_null(entry.pub_keys.keys);
	assert_int_equal(0, entry.pub_keys.len);

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}

/*
 * Test get_key_trust_public_keys
 * handling of duplicate key usage entries
 */
static void duplicate_key_usage_keycredlink(void **state)
{
	/* clang-format off */
	uint8_t KEY_CREDENTIAL_LINK[] = {
		0x00, 0x02, 0x00, 0x00, /* Invalid version                   */
		0x18, 0x00, 0x03,	/* Key Material                      */
		'R',  'S',  'A',  '1',	/* RSA public key                    */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x04, 0x01,	/* key usage (KEY_USAGE_NGC)	     */
		0x01, 0x00, 0x04, 0x01, /* key usage duplicate               */
		0x01, 0x00, 0x05, 0x00, /* key source (KEY_SOURCE_AD)        */
	};
	/* clang-format on */

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct ldb_context *ldb = ldb_init(mem_ctx, NULL);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_msDS_KeyCredentialLink(msg,
				   sizeof(KEY_CREDENTIAL_LINK),
				   KEY_CREDENTIAL_LINK);

	err = get_key_trust_public_keys(mem_ctx, ldb, msg, &entry);

	/* Expect the key credential link to be ignored */
	assert_int_equal(0, err);
	assert_null(entry.pub_keys.keys);
	assert_int_equal(0, entry.pub_keys.len);

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}

/*
 * Test get_key_trust_public_keys
 * handling of invalid key usage entries
 */
static void invalid_key_usage_keycredlink(void **state)
{
	/* clang-format off */
	uint8_t KEY_CREDENTIAL_LINK[] = {
		0x00, 0x02, 0x00, 0x00, /* Invalid version                   */
		0x18, 0x00, 0x03,	/* Key Material                      */
		'R',  'S',  'A',  '1',	/* RSA public key                    */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x04, 0xFE, /* key usage invalid		     */
		0x01, 0x00, 0x05, 0x00, /* key source (KEY_SOURCE_AD)        */
	};
	/* clang-format on */

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct ldb_context *ldb = ldb_init(mem_ctx, NULL);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_msDS_KeyCredentialLink(msg,
				   sizeof(KEY_CREDENTIAL_LINK),
				   KEY_CREDENTIAL_LINK);

	err = get_key_trust_public_keys(mem_ctx, ldb, msg, &entry);

	/* Expect the key credential link to be ignored */
	assert_int_equal(0, err);
	assert_null(entry.pub_keys.keys);
	assert_int_equal(0, entry.pub_keys.len);

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}

/*
 * Test get_key_trust_public_keys
 * handling of invalid key usage entries
 */
static void invalid_key_material_keycredlink(void **state)
{
	/* clang-format off */
	uint8_t KEY_CREDENTIAL_LINK[] = {
		0x00, 0x02, 0x00, 0x00, /* version 2                         */
		0x18, 0x00, 0x03,	/* Key Material                      */
		'R',  'S',  'A',  '2',	/* RSA private key                   */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x04, 0x01, /* key usage			     */
		0x01, 0x00, 0x05, 0x00, /* key source                        */
	};
	/* clang-format on */

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct ldb_context *ldb = ldb_init(mem_ctx, NULL);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};

	/* Create the ldb_message */
	msg = ldb_msg_new(mem_ctx);
	add_msDS_KeyCredentialLink(msg,
				   sizeof(KEY_CREDENTIAL_LINK),
				   KEY_CREDENTIAL_LINK);

	err = get_key_trust_public_keys(mem_ctx, ldb, msg, &entry);

	/* Expect the key credential link to be ignored */
	assert_int_equal(0, err);
	assert_null(entry.pub_keys.keys);
	assert_int_equal(0, entry.pub_keys.len);

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}

/*
 * Test get_key_trust_public_keys can unpack BCRYPT
 * key material.
 *
 */
static void keycred_bcrypt_key_material(void **state)
{

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct ldb_context *ldb = ldb_init(mem_ctx, NULL);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_msDS_KeyCredentialLink(msg,
				   sizeof(BCRYPT_KEY_CREDENTIAL_LINK),
				   BCRYPT_KEY_CREDENTIAL_LINK);

	err = get_key_trust_public_keys(mem_ctx, ldb, msg, &entry);

	assert_int_equal(0, err);
	assert_non_null(entry.pub_keys.keys);
	assert_int_equal(1, entry.pub_keys.len);

	assert_int_equal(2048, entry.pub_keys.keys[0].bit_size);

	assert_int_equal(sizeof(BCRYPT_MODULUS),
			 entry.pub_keys.keys[0].modulus.length);
	assert_memory_equal(BCRYPT_MODULUS,
			    entry.pub_keys.keys[0].modulus.data,
			    sizeof(BCRYPT_MODULUS));

	assert_int_equal(sizeof(BCRYPT_EXPONENT),
			 entry.pub_keys.keys[0].exponent.length);
	assert_memory_equal(BCRYPT_EXPONENT,
			    entry.pub_keys.keys[0].exponent.data,
			    sizeof(BCRYPT_EXPONENT));

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}

/*
 * Test get_key_trust_public_keys can unpack TPM 2.0
 * key material.
 *
 */
static void keycred_tpm_key_material(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct ldb_context *ldb = ldb_init(mem_ctx, NULL);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_msDS_KeyCredentialLink(msg,
				   sizeof(TPM_KEY_CREDENTIAL_LINK),
				   TPM_KEY_CREDENTIAL_LINK);

	err = get_key_trust_public_keys(mem_ctx, ldb, msg, &entry);

	assert_int_equal(0, err);
	assert_non_null(entry.pub_keys.keys);
	assert_int_equal(1, entry.pub_keys.len);

	assert_int_equal(2048, entry.pub_keys.keys[0].bit_size);

	assert_int_equal(sizeof(TPM_MODULUS),
			 entry.pub_keys.keys[0].modulus.length);
	assert_memory_equal(TPM_MODULUS,
			    entry.pub_keys.keys[0].modulus.data,
			    sizeof(TPM_MODULUS));

	assert_int_equal(sizeof(TPM_EXPONENT),
			 entry.pub_keys.keys[0].exponent.length);
	assert_memory_equal(TPM_EXPONENT,
			    entry.pub_keys.keys[0].exponent.data,
			    sizeof(TPM_EXPONENT));

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}

/*
 * Test get_key_trust_public_keys can unpack DER
 * key material.
 *
 */
static void keycred_der_key_material(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct ldb_context *ldb = ldb_init(mem_ctx, NULL);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_msDS_KeyCredentialLink(msg,
				   sizeof(DER_KEY_CREDENTIAL_LINK),
				   DER_KEY_CREDENTIAL_LINK);

	err = get_key_trust_public_keys(mem_ctx, ldb, msg, &entry);

	assert_int_equal(0, err);
	assert_non_null(entry.pub_keys.keys);
	assert_int_equal(1, entry.pub_keys.len);

	assert_int_equal(2048, entry.pub_keys.keys[0].bit_size);

	assert_int_equal(sizeof(DER_MODULUS),
			 entry.pub_keys.keys[0].modulus.length);
	assert_memory_equal(DER_MODULUS,
			    entry.pub_keys.keys[0].modulus.data,
			    sizeof(DER_MODULUS));

	assert_int_equal(sizeof(DER_EXPONENT),
			 entry.pub_keys.keys[0].exponent.length);
	assert_memory_equal(DER_EXPONENT,
			    entry.pub_keys.keys[0].exponent.data,
			    sizeof(DER_EXPONENT));

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}

/*
 * Test get_key_trust_public_keys can unpack multiple
 * key material values.
 *
 */
static void keycred_multiple(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct ldb_context *ldb = ldb_init(mem_ctx, NULL);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_msDS_KeyCredentialLink(msg,
				   sizeof(DER_KEY_CREDENTIAL_LINK),
				   DER_KEY_CREDENTIAL_LINK);
	add_msDS_KeyCredentialLink(msg,
				   sizeof(TPM_KEY_CREDENTIAL_LINK),
				   TPM_KEY_CREDENTIAL_LINK);
	add_msDS_KeyCredentialLink(msg,
				   sizeof(BCRYPT_KEY_CREDENTIAL_LINK),
				   BCRYPT_KEY_CREDENTIAL_LINK);

	err = get_key_trust_public_keys(mem_ctx, ldb, msg, &entry);

	assert_int_equal(0, err);
	assert_non_null(entry.pub_keys.keys);
	assert_int_equal(3, entry.pub_keys.len);

	/* Check DER entry */
	assert_int_equal(2048, entry.pub_keys.keys[0].bit_size);

	assert_int_equal(sizeof(DER_MODULUS),
			 entry.pub_keys.keys[0].modulus.length);
	assert_memory_equal(DER_MODULUS,
			    entry.pub_keys.keys[0].modulus.data,
			    sizeof(DER_MODULUS));

	assert_int_equal(sizeof(DER_EXPONENT),
			 entry.pub_keys.keys[0].exponent.length);
	assert_memory_equal(DER_EXPONENT,
			    entry.pub_keys.keys[0].exponent.data,
			    sizeof(DER_EXPONENT));

	/* Check TPM entry */
	assert_int_equal(2048, entry.pub_keys.keys[1].bit_size);

	assert_int_equal(sizeof(TPM_MODULUS),
			 entry.pub_keys.keys[1].modulus.length);
	assert_memory_equal(TPM_MODULUS,
			    entry.pub_keys.keys[1].modulus.data,
			    sizeof(TPM_MODULUS));

	assert_int_equal(sizeof(TPM_EXPONENT),
			 entry.pub_keys.keys[1].exponent.length);
	assert_memory_equal(TPM_EXPONENT,
			    entry.pub_keys.keys[1].exponent.data,
			    sizeof(TPM_EXPONENT));

	/* Check BCRYPT entry */
	assert_int_equal(2048, entry.pub_keys.keys[2].bit_size);

	assert_int_equal(sizeof(BCRYPT_MODULUS),
			 entry.pub_keys.keys[2].modulus.length);
	assert_memory_equal(BCRYPT_MODULUS,
			    entry.pub_keys.keys[2].modulus.data,
			    sizeof(BCRYPT_MODULUS));

	assert_int_equal(sizeof(BCRYPT_EXPONENT),
			 entry.pub_keys.keys[2].exponent.length);
	assert_memory_equal(BCRYPT_EXPONENT,
			    entry.pub_keys.keys[2].exponent.data,
			    sizeof(BCRYPT_EXPONENT));

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}



/*
 * Ensure that parse_certificate_mapping handles an empty ldb string value
 */
static void empty_string_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value = get_ldb_string(mem_ctx, "");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(ENOENT, err);
	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles an ldb string value containing
 * just the X509: tag
 */
static void header_only_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value = get_ldb_string(mem_ctx, "X509:");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(ENOENT, err);
	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles an ldb string value containing
 * a non X509 mapping
 */
static void not_x509_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value = get_ldb_string(mem_ctx, "KERBEROS:");
	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(ENOENT, err);
	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles an ldb string value without
 * a tag
 */
static void no_tag_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value = get_ldb_string(mem_ctx, "X509:No tag here");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(EINVAL, err);
	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles an ldb string value without
 * a tag close character '>'
 */
static void no_tag_close_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value = get_ldb_string(mem_ctx, "X509:<No tag close");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(EINVAL, err);
	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles an ldb string value with
 * an empty tag
 */
static void empty_tag_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value = get_ldb_string(mem_ctx, "X509:<>Empty tag");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(EINVAL, err);
	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles an ldb string value with
 * no value
 */
static void no_value_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value = get_ldb_string(mem_ctx, "X509:<I>");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(EINVAL, err);
	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles an issuer name
 *
 */
static void issuer_name_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value = get_ldb_string(mem_ctx, "X509:<I>Issuer");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(0, err);
	assert_int_equal(6, mapping.issuer_name.length);
	assert_memory_equal("Issuer", mapping.issuer_name.data, 6);
	assert_false(mapping.strong_mapping);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles duplicate issuer names
 *
 */
static void duplicate_issuer_name_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value
		= get_ldb_string(mem_ctx, "X509:<I>Issuer<I>Duplicate");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(0, err);

	/* Only use the last value in the event of duplicate values */
	assert_int_equal(9, mapping.issuer_name.length);
	assert_memory_equal("Duplicate", mapping.issuer_name.data, 9);
	assert_false(mapping.strong_mapping);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles a subject name
 *
 */
static void subject_name_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value = get_ldb_string(mem_ctx, "X509:<S>Subject");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(0, err);
	assert_int_equal(7, mapping.subject_name.length);
	assert_memory_equal("Subject", mapping.subject_name.data, 7);
	assert_false(mapping.strong_mapping);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles duplicate subject names
 *
 */
static void duplicate_subject_name_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value =
		get_ldb_string(mem_ctx, "X509:<S>Subject<S>A repeat");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(0, err);
	/* Only use the last value in the event of duplicate values */
	assert_int_equal(8, mapping.subject_name.length);
	assert_memory_equal("A repeat", mapping.subject_name.data, 8);
	assert_false(mapping.strong_mapping);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles an issuer name and subject
 * name.
 *
 */
static void issuer_and_subject_name_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value = get_ldb_string(
		mem_ctx, "X509:<S>SubjectsName<I>TheNameOfTheIssuer");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(0, err);
	assert_int_equal(12, mapping.subject_name.length);
	assert_memory_equal("SubjectsName", mapping.subject_name.data, 12);
	assert_int_equal(18, mapping.issuer_name.length);
	assert_memory_equal("TheNameOfTheIssuer", mapping.issuer_name.data, 18);
	assert_false(mapping.strong_mapping);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles a serial number
 *
 */
static void serial_number_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	uint8_t sn[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	struct ldb_val *value
		= get_ldb_string(mem_ctx, "X509:<SR>0123456789abcdef");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(0, err);
	assert_int_equal(sizeof(sn), mapping.serial_number.length);
	assert_memory_equal(sn, mapping.serial_number.data, sizeof(sn));
	/* The Serial number on it's own is not a strong mapping */
	assert_false(mapping.strong_mapping);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles multiple serial numbers
 *
 */
static void duplicate_serial_number_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	uint8_t sn[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	struct ldb_val *value
		= get_ldb_string(
			mem_ctx,
			"X509:<SR>fedcba98765410<SR>0123456789abcdef");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(0, err);
	assert_int_equal(sizeof(sn), mapping.serial_number.length);
	assert_memory_equal(sn, mapping.serial_number.data, sizeof(sn));
	/* The Serial number on it's own is not a strong mapping */
	assert_false(mapping.strong_mapping);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles a serial number and
 * issuer name
 *
 */
static void serial_number_and_issuer_name_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	uint8_t sn[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	struct ldb_val *value = get_ldb_string(
		mem_ctx, "X509:<SR>0123456789abcdef<I>TheIssuer");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(0, err);
	assert_int_equal(sizeof(sn), mapping.serial_number.length);
	assert_memory_equal(sn, mapping.serial_number.data, sizeof(sn));
	assert_int_equal(9, mapping.issuer_name.length);
	assert_memory_equal("TheIssuer", mapping.issuer_name.data, 9);
	assert_true(mapping.strong_mapping);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles an SKI (Subject Key Identifier)
 */
static void ski_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	uint8_t ski[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	struct ldb_val *value = get_ldb_string(
		mem_ctx, "X509:<SKI>0123456789abcdef");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(0, err);
	assert_int_equal(sizeof(ski), mapping.ski.length);
	assert_memory_equal(ski, mapping.ski.data, sizeof(ski));
	assert_true(mapping.strong_mapping);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles multiple
 * SKI (Subject Key Identifier) values
 */
static void duplicate_ski_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	uint8_t ski[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	struct ldb_val *value = get_ldb_string(
		mem_ctx, "X509:<SKI>010203040506<SKI>0123456789abcdef");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(0, err);
	assert_int_equal(sizeof(ski), mapping.ski.length);
	assert_memory_equal(ski, mapping.ski.data, sizeof(ski));
	assert_true(mapping.strong_mapping);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles a public key
 */
static void public_key_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	uint8_t pubkey[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	struct ldb_val *value = get_ldb_string(
		mem_ctx, "X509:<SHA1-PUKEY>0123456789abcdef");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(0, err);
	assert_int_equal(sizeof(pubkey), mapping.public_key.length);
	assert_memory_equal(pubkey, mapping.public_key.data, sizeof(pubkey));
	assert_true(mapping.strong_mapping);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles multiple public keys
 */
static void duplicate_public_key_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	uint8_t pubkey[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	struct ldb_val *value = get_ldb_string(
		mem_ctx,
		"X509:<SHA1-PUKEY>adcdefabcdefabcdef"
		"<SHA1-PUKEY>0123456789abcdef");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(0, err);
	assert_int_equal(sizeof(pubkey), mapping.public_key.length);
	assert_memory_equal(pubkey, mapping.public_key.data, sizeof(pubkey));
	assert_true(mapping.strong_mapping);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that non hex strings are rejected
 */
static void non_hex_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value = get_ldb_string(
		mem_ctx, "X509:<SHA1-PUKEY>This is not a hex string");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(EINVAL, err);
	assert_int_equal(0, mapping.public_key.length);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that odd length hex strings are rejected
 */
static void odd_length_hex_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value = get_ldb_string(
		mem_ctx, "X509:<SHA1-PUKEY>abcde");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(EINVAL, err);
	assert_int_equal(0, mapping.public_key.length);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Ensure that parse_certificate_mapping handles an RFC822 identifier
 */
static void RFC822_parse_certificate_mapping(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	krb5_error_code err = 0;
	struct sdb_certificate_mapping mapping = {};
	struct ldb_val *value = get_ldb_string(
		mem_ctx, "X509:<RFC822>test@example.com");

	err = parse_certificate_mapping(value, &mapping);

	assert_int_equal(0, err);
	assert_int_equal(16, mapping.rfc822.length);
	assert_memory_equal("test@example.com", mapping.rfc822.data, 16);
	assert_false(mapping.strong_mapping);

	sdb_certificate_mapping_free(&mapping);
	TALLOC_FREE(mem_ctx);
}


/*
 * Test get_certificate_mapping handles multiple entries
 *
 */
static void multiple_cert_mappings(void **state)
{

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct loadparm_context *lp_ctx = loadparm_init(mem_ctx);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};
	uint8_t ski[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

	time_t now = time(NULL);
	const int backdate = 26280000;  /* Fifty years */
	const int expected_val_cert_start = now - (backdate * 60);

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_altSecurityIdentities(msg,
				  "X509:<SKI>0123456789abcdef");
	add_altSecurityIdentities(msg,
			          "X509:<RFC822>test@example.com");
	add_whenCreated(msg, now);

	certificate_binding_enforcement = 1;
	certificate_backdating_compensation = backdate;
	err = get_certificate_mappings(mem_ctx, lp_ctx, msg, &entry);

	assert_int_equal(0, err);

	assert_int_equal(2, entry.mappings.len);
	assert_int_equal(1, entry.mappings.enforcement_mode);
	assert_int_equal(
		expected_val_cert_start,
		entry.mappings.valid_certificate_start);

	assert_int_equal(sizeof(ski), entry.mappings.mappings[0].ski.length);
	assert_memory_equal(
		ski, entry.mappings.mappings[0].ski.data, sizeof(ski));
	assert_true(entry.mappings.mappings[0].strong_mapping);

	assert_int_equal(16, entry.mappings.mappings[1].rfc822.length);
	assert_memory_equal(
		"test@example.com", entry.mappings.mappings[1].rfc822.data, 16);
	assert_false(entry.mappings.mappings[1].strong_mapping);

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}


/*
 * Test get_certificate_mapping handles a single entry
 *
 */
static void single_cert_mapping(void **state)
{

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct loadparm_context *lp_ctx = loadparm_init(mem_ctx);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};
	uint8_t ski[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

	time_t now = time(NULL);
	const int backdate = 525600;  /* One year */
	const int expected_val_cert_start = now - (backdate * 60);

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_altSecurityIdentities(msg,
				  "X509:<SKI>0123456789abcdef");
	add_whenCreated(msg, now);

	certificate_binding_enforcement = 2;
	certificate_backdating_compensation = backdate;
	err = get_certificate_mappings(mem_ctx, lp_ctx, msg, &entry);

	assert_int_equal(0, err);

	assert_int_equal(1, entry.mappings.len);
	assert_int_equal(2, entry.mappings.enforcement_mode);
	assert_int_equal(
		expected_val_cert_start,
		entry.mappings.valid_certificate_start);

	assert_int_equal(sizeof(ski), entry.mappings.mappings[0].ski.length);
	assert_memory_equal(
		ski, entry.mappings.mappings[0].ski.data, sizeof(ski));
	assert_true(entry.mappings.mappings[0].strong_mapping);

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}


/*
 * Test get_certificate_mapping handles an ldb message with no
 * altSecurityIdentities attribute
 *
 */
static void cert_mapping_no_altSecurityIdentities(void **state)
{

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct loadparm_context *lp_ctx = loadparm_init(mem_ctx);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};

	time_t now = time(NULL);
	const int backdate = 10080;  /* 1 week */
	const int expected_val_cert_start = now - (backdate * 60);

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_whenCreated(msg, now);

	certificate_binding_enforcement = 0;
	certificate_backdating_compensation = backdate;
	err = get_certificate_mappings(mem_ctx, lp_ctx, msg, &entry);

	assert_int_equal(0, err);

	assert_int_equal(0, entry.mappings.len);
	assert_int_equal(0, entry.mappings.enforcement_mode);
	assert_int_equal(
		expected_val_cert_start,
		entry.mappings.valid_certificate_start);

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}


/*
 * Test get_certificate_mapping handles an ldb message with an
 * altSecurityIdentities attribute containing no X509 entries
 *
 */
static void no_X509_altSecurityIdentities(void **state)
{

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct loadparm_context *lp_ctx = loadparm_init(mem_ctx);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};

	time_t now = time(NULL);
	const int backdate = 1440;  /* 24 hours */
	const int expected_val_cert_start = now - (backdate * 60);

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_altSecurityIdentities(msg,
				  "KERBEROS:0123456789abcdef");
	add_altSecurityIdentities(msg,
				  "ANOTHER:0123456789abcdef");
	add_whenCreated(msg, now);

	certificate_binding_enforcement = 0;
	certificate_backdating_compensation = backdate;
	err = get_certificate_mappings(mem_ctx, lp_ctx, msg, &entry);

	assert_int_equal(0, err);

	assert_int_equal(0, entry.mappings.len);
	assert_int_equal(0, entry.mappings.enforcement_mode);
	assert_int_equal(
		expected_val_cert_start,
		entry.mappings.valid_certificate_start);


	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}


/*
 * Test get_certificate_mapping handles an ldb message with an
 * altSecurityIdentities attribute containing X509,and KERBEROS
 * entries.
 *
 */
static void mixed_altSecurityIdentities(void **state)
{

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct loadparm_context *lp_ctx = loadparm_init(mem_ctx);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};
	uint8_t ski[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

	time_t now = time(NULL);
	const int backdate = 10;
	const int expected_val_cert_start = now - (backdate * 60);

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_altSecurityIdentities(msg,
				  "X509:<SKI>0123456789abcdef");
	add_altSecurityIdentities(msg,
				  "KERBEROS:0123456789abcdef");
	add_altSecurityIdentities(msg,
			          "X509:<RFC822>test@example.com");
	add_whenCreated(msg, now);

	certificate_binding_enforcement = 0;
	certificate_backdating_compensation = backdate;
	err = get_certificate_mappings(mem_ctx, lp_ctx, msg, &entry);

	assert_int_equal(0, err);

	assert_int_equal(2, entry.mappings.len);
	assert_int_equal(0, entry.mappings.enforcement_mode);
	assert_int_equal(
		expected_val_cert_start,
		entry.mappings.valid_certificate_start);

	assert_int_equal(sizeof(ski), entry.mappings.mappings[0].ski.length);
	assert_memory_equal(
		ski, entry.mappings.mappings[0].ski.data, sizeof(ski));
	assert_true(entry.mappings.mappings[0].strong_mapping);

	assert_int_equal(16, entry.mappings.mappings[1].rfc822.length);
	assert_memory_equal(
		"test@example.com", entry.mappings.mappings[1].rfc822.data, 16);
	assert_false(entry.mappings.mappings[1].strong_mapping);

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}


/*
 * Test get_certificate_mapping handles an empty
 * altSecurityIdentities attribute
 *
 */
static void cert_mapping_empty_altSecurityIdentities(void **state)
{

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	struct loadparm_context *lp_ctx = loadparm_init(mem_ctx);
	struct ldb_message *msg = NULL;
	krb5_error_code err = 0;
	struct sdb_entry entry = {};

	time_t now = time(NULL);
	const int backdate = 43800;  /* One month */
	const int expected_val_cert_start = now - (backdate * 60);

	/* Create the ldb_message */
	msg = create_ldb_message(mem_ctx);
	add_empty_altSecurities(mem_ctx, msg);
	add_whenCreated(msg, now);

	certificate_binding_enforcement = 0;
	certificate_backdating_compensation = backdate;
	err = get_certificate_mappings(mem_ctx, lp_ctx, msg, &entry);

	assert_int_equal(0, err);

	assert_int_equal(0, entry.mappings.len);
	assert_int_equal(0, entry.mappings.enforcement_mode);
	assert_int_equal(
		expected_val_cert_start,
		entry.mappings.valid_certificate_start);

	sdb_entry_free(&entry);
	TALLOC_FREE(mem_ctx);
}


int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(empty_message2entry),
		cmocka_unit_test(minimal_message2entry),
		cmocka_unit_test(empty_binary_dn_message2entry),
		cmocka_unit_test(msDS_KeyCredentialLink_message2entry),
		cmocka_unit_test(invalid_version_keycredlink),
		cmocka_unit_test(duplicate_key_material_keycredlink),
		cmocka_unit_test(duplicate_key_usage_keycredlink),
		cmocka_unit_test(invalid_key_usage_keycredlink),
		cmocka_unit_test(invalid_key_material_keycredlink),
		cmocka_unit_test(keycred_bcrypt_key_material),
		cmocka_unit_test(keycred_tpm_key_material),
		cmocka_unit_test(keycred_der_key_material),
		cmocka_unit_test(keycred_multiple),
		cmocka_unit_test(empty_string_parse_certificate_mapping),
		cmocka_unit_test(header_only_parse_certificate_mapping),
		cmocka_unit_test(not_x509_parse_certificate_mapping),
		cmocka_unit_test(no_tag_parse_certificate_mapping),
		cmocka_unit_test(no_tag_close_parse_certificate_mapping),
		cmocka_unit_test(empty_tag_parse_certificate_mapping),
		cmocka_unit_test(no_value_parse_certificate_mapping),
		cmocka_unit_test(issuer_name_parse_certificate_mapping),
		cmocka_unit_test(
			duplicate_issuer_name_parse_certificate_mapping),
		cmocka_unit_test(subject_name_parse_certificate_mapping),
		cmocka_unit_test(
			duplicate_subject_name_parse_certificate_mapping),
		cmocka_unit_test(
			issuer_and_subject_name_parse_certificate_mapping),
		cmocka_unit_test(serial_number_parse_certificate_mapping),
		cmocka_unit_test(
			duplicate_serial_number_parse_certificate_mapping),
		cmocka_unit_test(
			serial_number_and_issuer_name_parse_certificate_mapping
		),
		cmocka_unit_test(ski_parse_certificate_mapping),
		cmocka_unit_test(duplicate_ski_parse_certificate_mapping),
		cmocka_unit_test(public_key_parse_certificate_mapping),
		cmocka_unit_test(
			duplicate_public_key_parse_certificate_mapping),
		cmocka_unit_test(non_hex_parse_certificate_mapping),
		cmocka_unit_test(odd_length_hex_parse_certificate_mapping),
		cmocka_unit_test(RFC822_parse_certificate_mapping),
		cmocka_unit_test(multiple_cert_mappings),
		cmocka_unit_test(single_cert_mapping),
		cmocka_unit_test(cert_mapping_no_altSecurityIdentities),
		cmocka_unit_test(cert_mapping_empty_altSecurityIdentities),
		cmocka_unit_test(no_X509_altSecurityIdentities),
		cmocka_unit_test(mixed_altSecurityIdentities),

	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
