/*
   Unit tests for the encrypted secrets code in encrypted_secrets.c

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <unistd.h>
#include <cmocka.h>

int ldb_encrypted_secrets_module_init(const char *version);
#define TEST_ENCRYPTED_SECRETS
#include "../encrypted_secrets.c"

struct ldbtest_ctx {
	struct tevent_context *ev;
	struct ldb_context *ldb;
	struct ldb_module *module;

	const char *dbfile;
	const char *lockfile;   /* lockfile is separate */
	const char *keyfile;

	const char *dbpath;
};

/* -------------------------------------------------------------------------- */
/*
 * Replace the dsdb helper routines used by the operational_init function
 *
 */
int dsdb_module_search_dn(
	struct ldb_module *module,
	TALLOC_CTX *mem_ctx,
	struct ldb_result **_res,
	struct ldb_dn *basedn,
	const char * const *attrs,
	uint32_t dsdb_flags,
	struct ldb_request *parent)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_message *msg = ldb_msg_new(ldb);
	struct ldb_result  *res = talloc_zero(mem_ctx, struct ldb_result);

	msg->dn = ldb_dn_new(msg, ldb, "@SAMBA_DSDB");
	ldb_msg_add_string(
		msg,
		SAMBA_REQUIRED_FEATURES_ATTR,
		SAMBA_ENCRYPTED_SECRETS_FEATURE);

	res->msgs = talloc_array(mem_ctx, struct ldb_message*, 1);
	res->msgs[0] = msg;
	*_res = res;
	return LDB_SUCCESS;
}

int dsdb_module_reference_dn(
	struct ldb_module *module,
	TALLOC_CTX *mem_ctx,
	struct ldb_dn *base,
	const char *attribute,
	struct ldb_dn **dn,
	struct ldb_request *parent)
{
	return LDB_SUCCESS;
}
/* -------------------------------------------------------------------------- */

static void unlink_old_db(struct ldbtest_ctx *test_ctx)
{
	int ret;

	errno = 0;
	ret = unlink(test_ctx->lockfile);
	if (ret == -1 && errno != ENOENT) {
		fail();
	}

	errno = 0;
	ret = unlink(test_ctx->dbfile);
	if (ret == -1 && errno != ENOENT) {
		fail();
	}

	errno = 0;
	ret = unlink(test_ctx->keyfile);
	if (ret == -1 && errno != ENOENT) {
		fail();
	}
}

static void write_key(void **state, DATA_BLOB key) {

	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	FILE *fp = NULL;
	int written = 0;

	fp = fopen(test_ctx->keyfile, "wb");
	assert_non_null(fp);

	written = fwrite(key.data, 1, key.length, fp);
	assert_int_equal(written, key.length);
	fclose(fp);
}

static const struct ldb_module_ops eol_ops = {
	.name              = "eol",
	.search            = NULL,
	.add		   = NULL,
	.modify		   = NULL,
	.del		   = NULL,
	.rename		   = NULL,
	.init_context	   = NULL
};

static int setup(void **state)
{
	struct ldbtest_ctx *test_ctx = NULL;
	struct ldb_module *eol = NULL;
	int rc;

	test_ctx = talloc_zero(NULL, struct ldbtest_ctx);
	assert_non_null(test_ctx);

	test_ctx->ev = tevent_context_init(test_ctx);
	assert_non_null(test_ctx->ev);

	test_ctx->ldb = ldb_init(test_ctx, test_ctx->ev);
	assert_non_null(test_ctx->ldb);



        test_ctx->module = ldb_module_new(
		test_ctx,
		test_ctx->ldb,
		"encrypted_secrets",
		&ldb_encrypted_secrets_module_ops);
	assert_non_null(test_ctx->module);
	eol = ldb_module_new(test_ctx, test_ctx->ldb, "eol", &eol_ops);
	assert_non_null(eol);
	ldb_module_set_next(test_ctx->module, eol);

	test_ctx->dbfile = talloc_strdup(test_ctx, "apitest.ldb");
	assert_non_null(test_ctx->dbfile);

	test_ctx->lockfile = talloc_asprintf(test_ctx, "%s-lock",
					     test_ctx->dbfile);
	assert_non_null(test_ctx->lockfile);

	test_ctx->keyfile = talloc_strdup(test_ctx, SECRETS_KEY_FILE);
	assert_non_null(test_ctx->keyfile);

	test_ctx->dbpath = talloc_asprintf(test_ctx,
			TEST_BE"://%s", test_ctx->dbfile);
	assert_non_null(test_ctx->dbpath);

	unlink_old_db(test_ctx);

	rc = ldb_connect(test_ctx->ldb, test_ctx->dbpath, 0, NULL);
	assert_int_equal(rc, 0);
	*state = test_ctx;
	return 0;
}

static int setup_with_key(void **state)
{
	struct ldbtest_ctx *test_ctx = NULL;
	DATA_BLOB key = data_blob_null;
	uint8_t key_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	int rc;

	setup(state);
	key.data   = key_data;
	key.length = sizeof(key_data);

	write_key(state, key);

	test_ctx = talloc_get_type_abort(*state, struct ldbtest_ctx);
	{
		struct ldb_message *msg = ldb_msg_new(test_ctx->ldb);
		msg->dn = ldb_dn_new(msg, test_ctx->ldb, "@SAMBA_DSDB");
		ldb_msg_add_string(
			msg,
			SAMBA_REQUIRED_FEATURES_ATTR,
			SAMBA_ENCRYPTED_SECRETS_FEATURE);
		ldb_add(test_ctx->ldb, msg);
	}

	rc = es_init(test_ctx->module);
	assert_int_equal(rc, LDB_SUCCESS);

	return 0;
}

static int teardown(void **state)
{
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);

	unlink_old_db(test_ctx);
	talloc_free(test_ctx);
	return 0;
}
/*
 * No key file present.
 *
 * The key should be empty and encrypt_secrets should be false.
 */
static void test_no_key_file(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct es_data *data = NULL;

	int rc;

	rc = es_init(test_ctx->module);
	assert_int_equal(rc, LDB_SUCCESS);

	data = talloc_get_type(ldb_module_get_private(test_ctx->module),
			       struct es_data);

	assert_false(data->encrypt_secrets);
	assert_int_equal(0, data->keys[0].length);

}

/*
 * Key file present.
 *
 * The key should be loaded and encrypt secrets should be true;
 */
static void test_key_file(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct es_data *data = NULL;
	int rc;
	DATA_BLOB key = data_blob_null;
	uint8_t key_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

	key.data   = key_data;
	key.length = sizeof(key_data);

	write_key(state, key);


	rc = es_init(test_ctx->module);
	assert_int_equal(rc, LDB_SUCCESS);

	data = talloc_get_type(ldb_module_get_private(test_ctx->module),
			       struct es_data);

	assert_true(data->encrypt_secrets);
	assert_int_equal(16, data->keys[0].length);
	assert_int_equal(0, data_blob_cmp(&key, &data->keys[0]));

}

/*
 * Key file present, short key.
 *
 * The key should be not be loaded and an error returned.
 */
static void test_key_file_short_key(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	int rc;
	DATA_BLOB key = data_blob_null;
	uint8_t key_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};

	key.data   = key_data;
	key.length = sizeof(key_data);

	write_key(state, key);


	rc = es_init(test_ctx->module);
	assert_int_equal(rc, LDB_ERR_OPERATIONS_ERROR);
}

/*
 * Key file present, long key.
 *
 * Only the first 16 bytes of the key should be loaded.
 */
static void test_key_file_long_key(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct es_data *data = NULL;
	int rc;
	DATA_BLOB key = data_blob_null;
	uint8_t key_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0xf,
	                      0x10};

	key.data   = key_data;
	key.length = sizeof(key_data);

	write_key(state, key);

	rc = es_init(test_ctx->module);
	assert_int_equal(rc, LDB_SUCCESS);

	data = talloc_get_type(ldb_module_get_private(test_ctx->module),
			       struct es_data);

	assert_true(data->encrypt_secrets);
	assert_int_equal(16, data->keys[0].length);

	/*
	 * Should have only read the first 16 bytes of the written key
	 */
	key.length = 16;
	assert_int_equal(0, data_blob_cmp(&key, &data->keys[0]));
}

/*
 *  Test gnutls_encryption and decryption.
 */
static void test_gnutls_value_decryption(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	const struct ldb_val plain_text =
		data_blob_string_const("A text value");
	unsigned char iv_data[] = {
		0xe7, 0xa3, 0x85, 0x17, 0x45, 0x73, 0xf4, 0x25,
		0xa5, 0x56, 0xde, 0x4c,
	};
	unsigned char encrypted_data[] = {
		0xac, 0x13, 0x86, 0x94, 0x3b, 0xed, 0xf2, 0x51,
		0xec, 0x85, 0x4d, 0x00, 0x37, 0x81, 0x46, 0x15,
		0x42, 0x13, 0xb1, 0x69, 0x49, 0x10, 0xe7, 0x9e,
		0x15, 0xbd, 0x95, 0x75, 0x6b, 0x0c, 0xc0, 0xa4,
	};
	struct EncryptedSecret es = {
		.iv = {
			.data = iv_data,
			.length = sizeof(iv_data),
		},
		.header = {
			.magic = ENCRYPTED_SECRET_MAGIC_VALUE,
			.version = SECRET_ATTRIBUTE_VERSION,
			.algorithm = ENC_SECRET_AES_128_AEAD,
		},
		.encrypted = {
			.data = encrypted_data,
			.length = sizeof(encrypted_data),
		}
	};
	unsigned char es_keys_blob[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	};
	struct es_data data = {
		.encrypt_secrets = true,
		.keys[0] = {
			.data = es_keys_blob,
			.length = sizeof(es_keys_blob),
		},
		.encryption_algorithm = GNUTLS_CIPHER_AES_128_GCM,
	};
	struct PlaintextSecret *decrypted =
		talloc_zero(test_ctx, struct PlaintextSecret);
	int err = LDB_SUCCESS;

	gnutls_decrypt_aead(&err,
			    test_ctx,
			    test_ctx->ldb,
			    &es,
			    decrypted,
			    &data);
	assert_int_equal(LDB_SUCCESS, err);
	assert_int_equal(plain_text.length, decrypted->cleartext.length);
	assert_int_equal(0, data_blob_cmp(&decrypted->cleartext, &plain_text));
}

/*
 *  Test gnutls_encryption and decryption.
 */
static void test_gnutls_value_encryption(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct ldb_val plain_text = data_blob_null;
	struct ldb_val cipher_text = data_blob_null;
	struct EncryptedSecret es;

	struct es_data *data = talloc_get_type(
		ldb_module_get_private(test_ctx->module),
		struct es_data);
	int err = LDB_SUCCESS;
	int rc;

	plain_text = data_blob_string_const("A text value");
	cipher_text = gnutls_encrypt_aead(
			&err,
			test_ctx,
			test_ctx->ldb,
			plain_text,
			data);
	assert_int_equal(LDB_SUCCESS, err);

	rc = ndr_pull_struct_blob(
		&cipher_text,
		test_ctx,
		&es,
		(ndr_pull_flags_fn_t) ndr_pull_EncryptedSecret);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(rc));
	assert_true(check_header(&es));

	{
		struct PlaintextSecret *decrypted =
			talloc_zero(test_ctx, struct PlaintextSecret);
		gnutls_decrypt_aead(
			&err,
			test_ctx,
			test_ctx->ldb,
			&es,
			decrypted,
			data);
		assert_int_equal(LDB_SUCCESS, err);
		assert_int_equal(
			plain_text.length,
			decrypted->cleartext.length);
		assert_int_equal(0,
			data_blob_cmp(
				&decrypted->cleartext,
				&plain_text));
	}
}

static void test_gnutls_altered_header(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct ldb_val plain_text = data_blob_null;
	struct ldb_val cipher_text = data_blob_null;
	struct EncryptedSecret es;

	struct es_data *data = talloc_get_type(
		ldb_module_get_private(test_ctx->module),
		struct es_data);
	int err = LDB_SUCCESS;
	int rc;

	plain_text = data_blob_string_const("A text value");
	cipher_text = gnutls_encrypt_aead(
			&err,
			test_ctx,
			test_ctx->ldb,
			plain_text,
			data);
	assert_int_equal(LDB_SUCCESS, err);

	rc = ndr_pull_struct_blob(
		&cipher_text,
		test_ctx,
		&es,
		(ndr_pull_flags_fn_t) ndr_pull_EncryptedSecret);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(rc));
	assert_true(check_header(&es));

	{
		struct PlaintextSecret *decrypted =
			talloc_zero(test_ctx, struct PlaintextSecret);
		gnutls_decrypt_aead(
			&err,
			test_ctx,
			test_ctx->ldb,
			&es,
			decrypted,
			data);
		assert_int_equal(LDB_SUCCESS, err);
		assert_int_equal(
			plain_text.length,
			decrypted->cleartext.length);
		assert_int_equal(0,
			data_blob_cmp(
				&decrypted->cleartext,
				&plain_text));
	}
	es.header.flags = es.header.flags ^ 0xffffffff;
	{
		struct PlaintextSecret *decrypted =
			talloc_zero(test_ctx, struct PlaintextSecret);
		gnutls_decrypt_aead(
			&err,
			test_ctx,
			test_ctx->ldb,
			&es,
			decrypted,
			data);
		assert_int_equal(LDB_ERR_OPERATIONS_ERROR, err);
	}
}

static void test_gnutls_altered_data(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct ldb_val plain_text = data_blob_null;
	struct ldb_val cipher_text = data_blob_null;
	struct EncryptedSecret es;

	struct es_data *data = talloc_get_type(
		ldb_module_get_private(test_ctx->module),
		struct es_data);
	int err = LDB_SUCCESS;
	int rc;

	plain_text = data_blob_string_const("A text value");
	cipher_text = gnutls_encrypt_aead(
			&err,
			test_ctx,
			test_ctx->ldb,
			plain_text,
			data);
	assert_int_equal(LDB_SUCCESS, err);

	rc = ndr_pull_struct_blob(
		&cipher_text,
		test_ctx,
		&es,
		(ndr_pull_flags_fn_t) ndr_pull_EncryptedSecret);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(rc));
	assert_true(check_header(&es));

	{
		struct PlaintextSecret *decrypted =
			talloc_zero(test_ctx, struct PlaintextSecret);
		gnutls_decrypt_aead(
			&err,
			test_ctx,
			test_ctx->ldb,
			&es,
			decrypted,
			data);
		assert_int_equal(LDB_SUCCESS, err);
		assert_int_equal(
			plain_text.length,
			decrypted->cleartext.length);
		assert_int_equal(0,
			data_blob_cmp(
				&decrypted->cleartext,
				&plain_text));
	}
	es.encrypted.data[0] = es.encrypted.data[0] ^ 0xff;
	{
		struct PlaintextSecret *decrypted =
			talloc_zero(test_ctx, struct PlaintextSecret);
		gnutls_decrypt_aead(
			&err,
			test_ctx,
			test_ctx->ldb,
			&es,
			decrypted,
			data);
		assert_int_equal(LDB_ERR_OPERATIONS_ERROR, err);
	}
}

static void test_gnutls_altered_iv(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct ldb_val plain_text = data_blob_null;
	struct ldb_val cipher_text = data_blob_null;
	struct EncryptedSecret es;

	struct es_data *data = talloc_get_type(
		ldb_module_get_private(test_ctx->module),
		struct es_data);
	int err = LDB_SUCCESS;
	int rc;

	plain_text = data_blob_string_const("A text value");
	cipher_text = gnutls_encrypt_aead(
			&err,
			test_ctx,
			test_ctx->ldb,
			plain_text,
			data);
	assert_int_equal(LDB_SUCCESS, err);

	rc = ndr_pull_struct_blob(
		&cipher_text,
		test_ctx,
		&es,
		(ndr_pull_flags_fn_t) ndr_pull_EncryptedSecret);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(rc));
	assert_true(check_header(&es));

	{
		struct PlaintextSecret *decrypted =
			talloc_zero(test_ctx, struct PlaintextSecret);
		gnutls_decrypt_aead(
			&err,
			test_ctx,
			test_ctx->ldb,
			&es,
			decrypted,
			data);
		assert_int_equal(LDB_SUCCESS, err);
		assert_int_equal(
			plain_text.length,
			decrypted->cleartext.length);
		assert_int_equal(0,
			data_blob_cmp(
				&decrypted->cleartext,
				&plain_text));
	}
	es.iv.data[0] = es.iv.data[0] ^ 0xff;
	{
		struct PlaintextSecret *decrypted =
			talloc_zero(test_ctx, struct PlaintextSecret);
		gnutls_decrypt_aead(
			&err,
			test_ctx,
			test_ctx->ldb,
			&es,
			decrypted,
			data);
		assert_int_equal(LDB_ERR_OPERATIONS_ERROR, err);
	}
}

/*
 *  Test samba encryption and decryption and decryption.
 */

/*
 *  Test message encryption.
 *  Test the secret attributes of a message are encrypted and decrypted.
 *  Test that the non secret attributes are not encrypted.
 *
 */
static void test_message_encryption_decryption(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct ldb_context *ldb = test_ctx->ldb;
	const char * const secrets[] = {DSDB_SECRET_ATTRIBUTES};
	const size_t num_secrets
		= (sizeof(secrets)/sizeof(secrets[0]));
	struct ldb_message *msg = ldb_msg_new(ldb);
	const struct ldb_message *encrypted_msg = NULL;
	struct es_data *data = talloc_get_type(
		ldb_module_get_private(test_ctx->module),
		struct es_data);
	struct ldb_message_element *el = NULL;
	int ret = LDB_SUCCESS;
	size_t i;
	unsigned int j;

	msg->dn = ldb_dn_new(msg, ldb, "dc=test");
	ldb_msg_add_string(msg, "cmocka_test_name01", "value01");
	for (i=0; i < num_secrets; i++) {
		ldb_msg_add_string(
			msg,
			secrets[i],
			secrets[i]);
	}
	ldb_msg_add_string(msg, "cmocka_test_name02", "value02");

	encrypted_msg = encrypt_secret_attributes(
		&ret,
		test_ctx,
		test_ctx->ldb,
		msg,
		data);
	assert_int_equal(LDB_SUCCESS, ret);

	/*
	 * Check that all the secret attributes have been encrypted
	 *
	 */
	for (i=0; i < num_secrets; i++) {
		el = ldb_msg_find_element(encrypted_msg, secrets[i]);
		assert_non_null(el);
		for (j = 0; j < el->num_values; j++) {
			int rc = LDB_SUCCESS;
			struct ldb_val dc = decrypt_value(
				&rc,
				test_ctx,
				test_ctx->ldb,
				el->values[j],
				data);
			assert_int_equal(LDB_SUCCESS, rc);
			assert_memory_equal(
				secrets[i],
				dc.data,
				dc.length);
			TALLOC_FREE(dc.data);
		}
	}

	/*
	 * Check that the normal attributes have not been encrypted
	 */
	el = ldb_msg_find_element(encrypted_msg, "cmocka_test_name01");
	assert_non_null(el);
	assert_memory_equal(
		"value01",
		el->values[0].data,
		el->values[0].length);

	el = ldb_msg_find_element(encrypted_msg, "cmocka_test_name02");
	assert_non_null(el);
	assert_memory_equal(
		"value02",
		el->values[0].data,
		el->values[0].length);

	/*
	 * Now decrypt the message
	 */
	ret = decrypt_secret_attributes(test_ctx->ldb,
					discard_const(encrypted_msg),
					data);
	assert_int_equal(LDB_SUCCESS, ret);

	/*
	 * Check that all the secret attributes have been decrypted
	 */
	for (i=0; i < num_secrets; i++) {
		el = ldb_msg_find_element(encrypted_msg, secrets[i]);
		assert_non_null(el);
		for (j = 0; j < el->num_values; j++) {
			assert_memory_equal(
				secrets[i],
				el->values[j].data,
				el->values[j].length);
		}
	}

	/*
	 * Check that the normal attributes are intact
	 */
	el = ldb_msg_find_element(msg, "cmocka_test_name01");
	assert_non_null(el);
	assert_memory_equal(
		"value01",
		el->values[0].data,
		el->values[0].length);

	el = ldb_msg_find_element(msg, "cmocka_test_name02");
	assert_non_null(el);
	assert_memory_equal(
		"value02",
		el->values[0].data,
		el->values[0].length);

}

static void test_check_header(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);

	struct ldb_val enc = data_blob_null;
	struct EncryptedSecret *es = NULL;
	int rc;

	/*
	 * Valid EncryptedSecret
	 */
	es = makeEncryptedSecret(test_ctx->ldb, test_ctx);
	rc = ndr_push_struct_blob(
		&enc,
		test_ctx,
		es,
		(ndr_push_flags_fn_t) ndr_push_EncryptedSecret);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(rc));
	assert_true(check_header(es));
	TALLOC_FREE(enc.data);
	TALLOC_FREE(es);

	/*
	 * invalid magic value
	 */
	es = makeEncryptedSecret(test_ctx->ldb, test_ctx);
	es->header.magic = 0xca5cadee;
	rc = ndr_push_struct_blob(
		&enc,
		test_ctx,
		es,
		(ndr_push_flags_fn_t) ndr_push_EncryptedSecret);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(rc));
	assert_false(check_header(es));
	TALLOC_FREE(enc.data);
	TALLOC_FREE(es);

	/*
	 * invalid version
	 */
	es = makeEncryptedSecret(test_ctx->ldb, test_ctx);
	es->header.version = SECRET_ATTRIBUTE_VERSION + 1;
	rc = ndr_push_struct_blob(
		&enc,
		test_ctx,
		es,
		(ndr_push_flags_fn_t) ndr_push_EncryptedSecret);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(rc));
	assert_false(check_header(es));
	TALLOC_FREE(enc.data);
	TALLOC_FREE(es);

	/*
	 * invalid algorithm
	 */
	es = makeEncryptedSecret(test_ctx->ldb, test_ctx);
	es->header.algorithm = SECRET_ENCRYPTION_ALGORITHM + 1;
	rc = ndr_push_struct_blob(
		&enc,
		test_ctx,
		es,
		(ndr_push_flags_fn_t) ndr_push_EncryptedSecret);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(rc));
	assert_false(check_header(es));
	TALLOC_FREE(enc.data);
	TALLOC_FREE(es);
}

/*
 * Attempt to decrypt a message containing an unencrypted secret attribute
 * this should fail
 */
static void test_unencrypted_secret(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct ldb_context *ldb = test_ctx->ldb;
	struct ldb_message *msg = ldb_msg_new(ldb);
	struct es_data *data = talloc_get_type(
		ldb_module_get_private(test_ctx->module),
		struct es_data);
	int ret = LDB_SUCCESS;

	msg->dn = ldb_dn_new(msg, ldb, "dc=test");
	ldb_msg_add_string(msg, "unicodePwd", "value01");

	ret = decrypt_secret_attributes(test_ctx->ldb, msg, data);
	assert_int_equal(LDB_ERR_OPERATIONS_ERROR, ret);
}

/*
 *  Test full decryption of a static value with static key
 */
static void test_record_decryption(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	unsigned char plain_data[] = {
		0xe6, 0xa6, 0xb8, 0xff, 0xdf, 0x06, 0x6c, 0xe3,
		0xea, 0xd0, 0x94, 0xbb, 0x79, 0xbd, 0x0a, 0x24
	};
	unsigned char encrypted_data[] = {
		0x0c, 0x00, 0x00, 0x00, 0x33, 0x91, 0x74, 0x25,
		0x26, 0xcc, 0x0b, 0x8c, 0x21, 0xc1, 0x13, 0xe2,
		0xed, 0xad, 0x5c, 0xca, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x1a, 0xdc, 0xc9, 0x11, 0x08, 0xca, 0x2c, 0xfb,
		0xc8, 0x32, 0x6b, 0x1b, 0x25, 0x7f, 0x52, 0xbb,
		0xae, 0x9b, 0x88, 0x52, 0xb0, 0x18, 0x6d, 0x9d,
		0x9b, 0xdd, 0xcd, 0x1b, 0x5f, 0x4a, 0x5c, 0x29,
		0xca, 0x0b, 0x36, 0xaa
	};
	struct ldb_val cipher_text
		= data_blob_const(encrypted_data,
				  sizeof(encrypted_data));
	unsigned char es_keys_blob[] = {
		0x1d, 0xae, 0xf5, 0xaa, 0xa3, 0x85, 0x0d, 0x0a,
		0x8c, 0x24, 0x5c, 0x4c, 0xa7, 0x0f, 0x81, 0x79
	};
	struct es_data data = {
		.encrypt_secrets = true,
		.keys[0] = {
			.data = es_keys_blob,
			.length = sizeof(es_keys_blob),
		},
		.encryption_algorithm = GNUTLS_CIPHER_AES_128_GCM,
	};
	int err = LDB_SUCCESS;
	struct ldb_val dec = decrypt_value(&err, test_ctx, test_ctx->ldb, cipher_text,
					   &data);
	assert_int_equal(LDB_SUCCESS, err);
	assert_int_equal(sizeof(plain_data), dec.length);
	assert_memory_equal(dec.data, plain_data, sizeof(plain_data));
}


int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_no_key_file,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_key_file,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_key_file_short_key,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_key_file_long_key,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_check_header,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_gnutls_value_decryption,
			setup_with_key,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_gnutls_value_encryption,
			setup_with_key,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_gnutls_altered_header,
			setup_with_key,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_gnutls_altered_data,
			setup_with_key,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_gnutls_altered_iv,
			setup_with_key,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_message_encryption_decryption,
			setup_with_key,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_unencrypted_secret,
			setup_with_key,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_record_decryption,
			setup_with_key,
			teardown),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
