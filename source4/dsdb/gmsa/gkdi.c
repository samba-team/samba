/*
   Unix SMB/CIFS implementation.
   Group Key Distribution Protocol functions

   Copyright (C) Catalyst.Net Ltd 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include <ldb.h>
#include <ldb_errors.h>
#include <ldb_module.h>
#include "lib/crypto/gkdi.h"
#include "lib/util/data_blob.h"
#include "lib/util/samba_util.h"
#include "lib/util/util_str_hex.h"
#include "librpc/ndr/libndr.h"
#include "dsdb/gmsa/gkdi.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "dsdb/samdb/samdb.h"

static int gkdi_create_root_key(TALLOC_CTX *mem_ctx,
				struct ldb_context *const ldb,
				const NTTIME current_time,
				const NTTIME use_start_time,
				struct GUID *const root_key_id_out,
				struct ldb_dn **const root_key_dn_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct GUID root_key_id;
	struct ldb_message *add_msg = NULL;
	NTSTATUS status = NT_STATUS_OK;
	int ret = LDB_SUCCESS;

	*root_key_dn_out = NULL;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	add_msg = ldb_msg_new(tmp_ctx);
	if (add_msg == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	ret = ldb_msg_append_string(add_msg,
				    "objectClass",
				    "msKds-ProvRootKey",
				    LDB_FLAG_MOD_ADD);
	if (ret) {
		goto out;
	}

	{
		uint8_t root_key_data[GKDI_KEY_LEN];
		const DATA_BLOB root_key_data_blob = {
			.data = root_key_data, .length = sizeof root_key_data};

		generate_secret_buffer(root_key_data, sizeof root_key_data);

		ret = ldb_msg_append_value(add_msg,
					   "msKds-RootKeyData",
					   &root_key_data_blob,
					   LDB_FLAG_MOD_ADD);
		if (ret) {
			goto out;
		}
	}

	ret = samdb_msg_append_uint64(ldb,
				      tmp_ctx,
				      add_msg,
				      "msKds-CreateTime",
				      current_time,
				      LDB_FLAG_MOD_ADD);
	if (ret) {
		goto out;
	}

	ret = samdb_msg_append_uint64(ldb,
				      tmp_ctx,
				      add_msg,
				      "msKds-UseStartTime",
				      use_start_time,
				      LDB_FLAG_MOD_ADD);
	if (ret) {
		goto out;
	}

	{
		struct ldb_dn *domain_dn = NULL;

		ret = samdb_server_reference_dn(ldb, tmp_ctx, &domain_dn);
		if (ret) {
			goto out;
		}

		ret = ldb_msg_append_linearized_dn(add_msg,
						   "msKds-DomainID",
						   domain_dn,
						   LDB_FLAG_MOD_ADD);
		if (ret) {
			goto out;
		}
	}

	ret = ldb_msg_append_string(add_msg,
				    "msKds-Version",
				    "1",
				    LDB_FLAG_MOD_ADD);
	if (ret) {
		goto out;
	}

	ret = ldb_msg_append_string(add_msg,
				    "msKds-KDFAlgorithmID",
				    "SP800_108_CTR_HMAC",
				    LDB_FLAG_MOD_ADD);
	if (ret) {
		goto out;
	}

	ret = ldb_msg_append_string(add_msg,
				    "msKds-SecretAgreementAlgorithmID",
				    "DH",
				    LDB_FLAG_MOD_ADD);
	if (ret) {
		goto out;
	}

	{
		static const uint8_t ffc_dh_parameters[] = {
			12,  2,	  0,   0,   68,	 72,  80,  77,	0,   1,	  0,
			0,   135, 168, 230, 29,	 180, 182, 102, 60,  255, 187,
			209, 156, 101, 25,  89,	 153, 140, 238, 246, 8,	  102,
			13,  208, 242, 93,  44,	 238, 212, 67,	94,  59,  0,
			224, 13,  248, 241, 214, 25,  87,  212, 250, 247, 223,
			69,  97,  178, 170, 48,	 22,  195, 217, 17,  52,  9,
			111, 170, 59,  244, 41,	 109, 131, 14,	154, 124, 32,
			158, 12,  100, 151, 81,	 122, 189, 90,	138, 157, 48,
			107, 207, 103, 237, 145, 249, 230, 114, 91,  71,  88,
			192, 34,  224, 177, 239, 66,  117, 191, 123, 108, 91,
			252, 17,  212, 95,  144, 136, 185, 65,	245, 78,  177,
			229, 155, 184, 188, 57,	 160, 191, 18,	48,  127, 92,
			79,  219, 112, 197, 129, 178, 63,  118, 182, 58,  202,
			225, 202, 166, 183, 144, 45,  82,  82,	103, 53,  72,
			138, 14,  241, 60,  109, 154, 81,  191, 164, 171, 58,
			216, 52,  119, 150, 82,	 77,  142, 246, 161, 103, 181,
			164, 24,  37,  217, 103, 225, 68,  229, 20,  5,	  100,
			37,  28,  202, 203, 131, 230, 180, 134, 246, 179, 202,
			63,  121, 113, 80,  96,	 38,  192, 184, 87,  246, 137,
			150, 40,  86,  222, 212, 1,   10,  189, 11,  230, 33,
			195, 163, 150, 10,  84,	 231, 16,  195, 117, 242, 99,
			117, 215, 1,   65,  3,	 164, 181, 67,	48,  193, 152,
			175, 18,  97,  22,  210, 39,  110, 17,	113, 95,  105,
			56,  119, 250, 215, 239, 9,   202, 219, 9,   74,  233,
			30,  26,  21,  151, 63,	 179, 44,  155, 115, 19,  77,
			11,  46,  119, 80,  102, 96,  237, 189, 72,  76,  167,
			177, 143, 33,  239, 32,	 84,  7,   244, 121, 58,  26,
			11,  161, 37,  16,  219, 193, 80,  119, 190, 70,  63,
			255, 79,  237, 74,  172, 11,  181, 85,	190, 58,  108,
			27,  12,  107, 71,  177, 188, 55,  115, 191, 126, 140,
			111, 98,  144, 18,  40,	 248, 194, 140, 187, 24,  165,
			90,  227, 19,  65,  0,	 10,  101, 1,	150, 249, 49,
			199, 122, 87,  242, 221, 244, 99,  229, 233, 236, 20,
			75,  119, 125, 230, 42,	 170, 184, 168, 98,  138, 195,
			118, 210, 130, 214, 237, 56,  100, 230, 121, 130, 66,
			142, 188, 131, 29,  20,	 52,  143, 111, 47,  145, 147,
			181, 4,	  90,  242, 118, 113, 100, 225, 223, 201, 103,
			193, 251, 63,  46,  85,	 164, 189, 27,	255, 232, 59,
			156, 128, 208, 82,  185, 133, 209, 130, 234, 10,  219,
			42,  59,  115, 19,  211, 254, 20,  200, 72,  75,  30,
			5,   37,  136, 185, 183, 210, 187, 210, 223, 1,	  97,
			153, 236, 208, 110, 21,	 87,  205, 9,	21,  179, 53,
			59,  187, 100, 224, 236, 55,  127, 208, 40,  55,  13,
			249, 43,  82,  199, 137, 20,  40,  205, 198, 126, 182,
			24,  75,  82,  61,  29,	 178, 70,  195, 47,  99,  7,
			132, 144, 240, 14,  248, 214, 71,  209, 72,  212, 121,
			84,  81,  94,  35,  39,	 207, 239, 152, 197, 130, 102,
			75,  76,  15,  108, 196, 22,  89};
		const DATA_BLOB ffc_dh_parameters_blob = {
			discard_const_p(uint8_t, ffc_dh_parameters),
			sizeof ffc_dh_parameters};

		ret = ldb_msg_append_value(add_msg,
					   "msKds-SecretAgreementParam",
					   &ffc_dh_parameters_blob,
					   LDB_FLAG_MOD_ADD);
		if (ret) {
			goto out;
		}
	}

	ret = ldb_msg_append_string(add_msg,
				    "msKds-PublicKeyLength",
				    "2048",
				    LDB_FLAG_MOD_ADD);
	if (ret) {
		goto out;
	}

	ret = ldb_msg_append_string(add_msg,
				    "msKds-PrivateKeyLength",
				    "512",
				    LDB_FLAG_MOD_ADD);
	if (ret) {
		goto out;
	}

	{
		static const uint8_t kdf_parameters[] = {
			0,   0, 0,   0, 1,   0, 0,   0, 14,  0,
			0,   0, 0,   0, 0,   0, 'S', 0, 'H', 0,
			'A', 0, '5', 0, '1', 0, '2', 0, 0,   0,
		};
		const DATA_BLOB kdf_parameters_blob = {
			discard_const_p(uint8_t, kdf_parameters),
			sizeof kdf_parameters};

		ret = ldb_msg_append_value(add_msg,
					   "msKds-KDFParam",
					   &kdf_parameters_blob,
					   LDB_FLAG_MOD_ADD);
		if (ret) {
			goto out;
		}
	}

	{
		uint8_t guid_buf[sizeof((struct GUID_ndr_buf){}.buf)];
		const DATA_BLOB guid_blob = {.data = guid_buf,
					     .length = sizeof guid_buf};

		generate_secret_buffer(guid_buf, sizeof guid_buf);

		status = GUID_from_ndr_blob(&guid_blob, &root_key_id);
		if (!NT_STATUS_IS_OK(status)) {
			ret = ldb_operr(ldb);
			goto out;
		}
	}

	{
		struct ldb_dn *root_key_dn = NULL;

		root_key_dn = samdb_gkdi_root_key_dn(ldb,
						     tmp_ctx,
						     &root_key_id);
		if (root_key_dn == NULL) {
			ret = ldb_operr(ldb);
			goto out;
		}

		add_msg->dn = root_key_dn;
	}

	ret = dsdb_add(ldb, add_msg, 0);
	if (ret) {
		goto out;
	}

	*root_key_id_out = root_key_id;
	*root_key_dn_out = talloc_steal(mem_ctx, add_msg->dn);

out:
	talloc_free(tmp_ctx);
	return ret;
}

/*
 * The PrivateKey, PublicKey, and SecretAgreement attributes are related to the
 * public‐key functionality in GKDI. Samba doesn’t try to implement any of that,
 * so we don’t bother looking at these attributes.
 */
static const char *const root_key_attrs[] = {
	"msKds-CreateTime",
	"msKds-DomainID",
	"msKds-KDFAlgorithmID",
	"msKds-KDFParam",
	/* "msKds-PrivateKeyLength", */
	/* "msKds-PublicKeyLength", */
	"msKds-RootKeyData",
	/* "msKds-SecretAgreementAlgorithmID", */
	/* "msKds-SecretAgreementParam", */
	"msKds-UseStartTime",
	"msKds-Version",
	NULL,
};

/*
 * Create and return a new GKDI root key.
 *
 * This function goes unused.
 */
int gkdi_new_root_key(TALLOC_CTX *mem_ctx,
		      struct ldb_context *const ldb,
		      const NTTIME current_time,
		      const NTTIME use_start_time,
		      struct GUID *const root_key_id_out,
		      const struct ldb_message **const root_key_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct ldb_dn *root_key_dn = NULL;
	struct ldb_result *res = NULL;
	int ret = LDB_SUCCESS;

	*root_key_out = NULL;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	ret = gkdi_create_root_key(tmp_ctx,
				   ldb,
				   current_time,
				   use_start_time,
				   root_key_id_out,
				   &root_key_dn);
	if (ret) {
		goto out;
	}

	ret = dsdb_search_dn(
		ldb, tmp_ctx, &res, root_key_dn, root_key_attrs, 0);
	if (ret) {
		goto out;
	}

	if (res->count != 1) {
		ret = LDB_ERR_NO_SUCH_OBJECT;
		goto out;
	}

	*root_key_out = talloc_steal(mem_ctx, res->msgs[0]);

out:
	talloc_free(tmp_ctx);
	return ret;
}
