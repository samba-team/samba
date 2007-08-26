/* 
   Unix SMB/CIFS implementation.

   local testing of registry library - hives

   Copyright (C) Jelmer Vernooij 2005-2007
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/registry/registry.h"
#include "lib/cmdline/popt_common.h"
#include "torture/torture.h"
#include "librpc/gen_ndr/winreg.h"
#include "system/filesys.h"

NTSTATUS torture_temp_dir(struct torture_context *tctx, const char *prefix, 
								   const char **tempdir);

static bool test_del_nonexistant_key(struct torture_context *tctx,
									 const void *test_data)
{
	const struct hive_key *root = test_data;
	WERROR error = hive_key_del(root, "bla");
	torture_assert_werr_equal(tctx, error, WERR_NOT_FOUND, 
							  "invalid return code");

	return true;
}

static bool test_keyinfo_root(struct torture_context *tctx,
						 const void *test_data)
{
	uint32_t num_subkeys, num_values;
	const struct hive_key *root = test_data;
	WERROR error;

	/* This is a new backend. There should be no subkeys and no 
	 * values */
	error = hive_key_get_info(tctx, root, NULL, &num_subkeys, &num_values, 
							  NULL);
	torture_assert_werr_ok(tctx, error, "reg_key_num_subkeys()");

	torture_assert_int_equal(tctx, num_subkeys, 0, "New key has non-zero subkey count");

	torture_assert_werr_ok(tctx, error, "reg_key_num_values");

	torture_assert_int_equal(tctx, num_values, 0, "New key has non-zero value count");

	return true;
}

static bool test_keyinfo_nums(struct torture_context *tctx,
						 const void *test_data)
{
	uint32_t num_subkeys, num_values;
	const struct hive_key *root = test_data;
	WERROR error;
	struct hive_key *subkey;
	uint32_t data = 42;

	error = hive_key_add_name(tctx, root, "Nested Keyll", NULL, 
							 NULL, &subkey);
	torture_assert_werr_ok(tctx, error, "hive_key_add_name");

	error = hive_set_value(root, "Answer", REG_DWORD, 
				   data_blob_talloc(tctx, &data, sizeof(data)));
	torture_assert_werr_ok(tctx, error, "hive_set_value");

	/* This is a new backend. There should be no subkeys and no 
	 * values */
	error = hive_key_get_info(tctx, root, NULL, &num_subkeys, &num_values, 
							  NULL);
	torture_assert_werr_ok(tctx, error, "reg_key_num_subkeys()");

	torture_assert_int_equal(tctx, num_subkeys, 1, "subkey count");

	torture_assert_werr_ok(tctx, error, "reg_key_num_values");

	torture_assert_int_equal(tctx, num_values, 1, "value count");

	return true;
}

static bool test_add_subkey(struct torture_context *tctx,
					  const void *test_data)
{
	WERROR error;
	struct hive_key *subkey;
	const struct hive_key *root = test_data;
	TALLOC_CTX *mem_ctx = tctx;

	error = hive_key_add_name(mem_ctx, root, "Nested Key", NULL, 
							 NULL, &subkey);
	torture_assert_werr_ok(tctx, error, "hive_key_add_name");

	error = hive_key_del(root, "Nested Key");
	torture_assert_werr_ok(tctx, error, "reg_key_del");

	return true;
}

static bool test_flush_key(struct torture_context *tctx,
					  const void *test_data)
{
	const struct hive_key *root = test_data;

	torture_assert_werr_ok(tctx, hive_key_flush(root), "flush key");

	return true;
}

static bool test_del_key(struct torture_context *tctx, const void *test_data)
{
	WERROR error;
	struct hive_key *subkey;
	const struct hive_key *root = test_data;
	TALLOC_CTX *mem_ctx = tctx;

	error = hive_key_add_name(mem_ctx, root, "Nested Key", NULL, 
							 NULL, &subkey);
	torture_assert_werr_ok(tctx, error, "hive_key_add_name");

	error = hive_key_del(root, "Nested Key");
	torture_assert_werr_ok(tctx, error, "reg_key_del");

	error = hive_key_del(root, "Nested Key");
	torture_assert_werr_equal(tctx, error, WERR_NOT_FOUND, "reg_key_del");

	return true;
}

static bool test_set_value(struct torture_context *tctx,
					  const void *test_data)
{
	WERROR error;
	struct hive_key *subkey;
	const struct hive_key *root = test_data;
	TALLOC_CTX *mem_ctx = tctx;
	uint32_t data = 42;

	error = hive_key_add_name(mem_ctx, root, "YA Nested Key", NULL, 
							 NULL, &subkey);
	torture_assert_werr_ok(tctx, error, "hive_key_add_name");

	error = hive_set_value(subkey, "Answer", REG_DWORD, 
				   data_blob_talloc(mem_ctx, &data, sizeof(data)));
	torture_assert_werr_ok(tctx, error, "hive_set_value");

	return true;
}

static bool test_get_value(struct torture_context *tctx, const void *test_data)
{
	WERROR error;
	struct hive_key *subkey;
	const struct hive_key *root = test_data;
	TALLOC_CTX *mem_ctx = tctx;
	uint32_t data = 42;
	uint32_t type;
	DATA_BLOB value;

	error = hive_key_add_name(mem_ctx, root, "EYA Nested Key", NULL, 
							 NULL, &subkey);
	torture_assert_werr_ok(tctx, error, "hive_key_add_name");

	error = hive_get_value(mem_ctx, subkey, "Answer", &type, &value);
	torture_assert_werr_equal(tctx, error, WERR_NOT_FOUND, 
							  "getting missing value");

	error = hive_set_value(subkey, "Answer", REG_DWORD, 
				   data_blob_talloc(mem_ctx, &data, sizeof(data)));
	torture_assert_werr_ok(tctx, error, "hive_set_value");

	error = hive_get_value(mem_ctx, subkey, "Answer", &type, &value);
	torture_assert_werr_ok(tctx, error, "getting value");

	torture_assert(tctx, memcmp(value.data, &data, 4) == 0, "value data");

	torture_assert_int_equal(tctx, value.length, 4, "value length");
	torture_assert_int_equal(tctx, type, REG_DWORD, "value type");

	return true;
}

static bool test_del_value(struct torture_context *tctx, const void *test_data)
{
	WERROR error;
	struct hive_key *subkey;
	const struct hive_key *root = test_data;
	TALLOC_CTX *mem_ctx = tctx;
	uint32_t data = 42;
	uint32_t type;
	DATA_BLOB value;

	error = hive_key_add_name(mem_ctx, root, "EEYA Nested Key", NULL, 
							 NULL, &subkey);
	torture_assert_werr_ok(tctx, error, "hive_key_add_name");

	error = hive_set_value(subkey, "Answer", REG_DWORD, 
				   data_blob_talloc(mem_ctx, &data, sizeof(data)));
	torture_assert_werr_ok(tctx, error, "hive_set_value");

	error = hive_del_value(subkey, "Answer");
	torture_assert_werr_ok(tctx, error, "deleting value");

	error = hive_get_value(mem_ctx, subkey, "Answer", &type, &value);
	torture_assert_werr_equal(tctx, error, WERR_NOT_FOUND, "getting value");

	error = hive_del_value(subkey, "Answer");
	torture_assert_werr_equal(tctx, error, WERR_NOT_FOUND, "deleting value");

	return true;
}

static bool test_list_values(struct torture_context *tctx, 
							 const void *test_data)
{
	WERROR error;
	struct hive_key *subkey;
	const struct hive_key *root = test_data;
	TALLOC_CTX *mem_ctx = tctx;
	uint32_t data = 42;
	uint32_t type;
	DATA_BLOB value;
	const char *name;

	error = hive_key_add_name(mem_ctx, root, "AYAYA Nested Key", NULL, 
							 NULL, &subkey);
	torture_assert_werr_ok(tctx, error, "hive_key_add_name");

	error = hive_set_value(subkey, "Answer", REG_DWORD, 
				   data_blob_talloc(mem_ctx, &data, sizeof(data)));
	torture_assert_werr_ok(tctx, error, "hive_set_value");

	error = hive_get_value_by_index(mem_ctx, subkey, 0, &name, &type, &value);
	torture_assert_werr_ok(tctx, error, "getting value");

	torture_assert_str_equal(tctx, name, "Answer", "value name");
	torture_assert(tctx, memcmp(value.data, &data, 4) == 0, "value data");

	torture_assert_int_equal(tctx, value.length, 4, "value length");
	torture_assert_int_equal(tctx, type, REG_DWORD, "value type");

	error = hive_get_value_by_index(mem_ctx, subkey, 1, &name, &type, &value);
	torture_assert_werr_equal(tctx, error, WERR_NO_MORE_ITEMS, 
							  "getting missing value");

	return true;
}

static void tcase_add_tests(struct torture_tcase *tcase) 
{
	torture_tcase_add_simple_test(tcase, "del_nonexistant_key", 
								  test_del_nonexistant_key);
	torture_tcase_add_simple_test(tcase, "add_subkey", test_add_subkey);
	torture_tcase_add_simple_test(tcase, "flush_key", test_flush_key);
	torture_tcase_add_simple_test(tcase, "get_info", test_keyinfo_root);
	torture_tcase_add_simple_test(tcase, "get_info_nums", test_keyinfo_nums);
	torture_tcase_add_simple_test(tcase, "set_value", test_set_value);
	torture_tcase_add_simple_test(tcase, "get_value", test_get_value);
	torture_tcase_add_simple_test(tcase, "list_values", test_list_values);
	torture_tcase_add_simple_test(tcase, "del_key", test_del_key);
	torture_tcase_add_simple_test(tcase, "del_value", test_del_value);
}

static bool hive_setup_dir(struct torture_context *tctx, void **data)
{
	struct hive_key *key;
	WERROR error;
	const char *dirname;
	NTSTATUS status;

	status = torture_temp_dir(tctx, "hive-dir", &dirname);
	if (!NT_STATUS_IS_OK(status))
		return false;

	rmdir(dirname);

	error = reg_create_directory(tctx, dirname, &key);
	if (!W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Unable to initialize dir hive\n");
		return false;
	}

	*data = key;

	return true;
}

static bool hive_setup_ldb(struct torture_context *tctx, void **data)
{
	struct hive_key *key;
	WERROR error;
	const char *dirname;
	NTSTATUS status;

	status = torture_temp_dir(tctx, "hive-ldb", &dirname);
	if (!NT_STATUS_IS_OK(status))
		return false;

	rmdir(dirname);

	error = reg_open_ldb_file(tctx, dirname, NULL, NULL, &key);
	if (!W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Unable to initialize ldb hive\n");
		return false;
	}

	*data = key;

	return true;
}

static bool hive_setup_regf(struct torture_context *tctx, void **data)
{
	struct hive_key *key;
	WERROR error;
	const char *dirname;
	NTSTATUS status;

	status = torture_temp_dir(tctx, "hive-dir", &dirname);
	if (!NT_STATUS_IS_OK(status))
		return false;

	rmdir(dirname);

	error = reg_create_regf_file(tctx, dirname, 5, &key);
	if (!W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Unable to create new regf file\n");
		return false;
	}

	*data = key;

	return true;
}

static bool test_dir_refuses_null_location(struct torture_context *tctx)
{
	torture_assert_werr_equal(tctx, WERR_INVALID_PARAM, 
							  reg_open_directory(NULL, NULL, NULL),
							  "reg_open_directory accepts NULL location");
	return true;
}

struct torture_suite *torture_registry_hive(TALLOC_CTX *mem_ctx) 
{
	struct torture_tcase *tcase;
	struct torture_suite *suite = torture_suite_create(mem_ctx, 
													   "HIVE");

	torture_suite_add_simple_test(suite, "dir-refuses-null-location", 
								  test_dir_refuses_null_location);


	tcase = torture_suite_add_tcase(suite, "dir");
	torture_tcase_set_fixture(tcase, hive_setup_dir, NULL);
	tcase_add_tests(tcase);

	tcase = torture_suite_add_tcase(suite, "ldb");
	torture_tcase_set_fixture(tcase, hive_setup_ldb, NULL);
	tcase_add_tests(tcase);

	tcase = torture_suite_add_tcase(suite, "regf");
	torture_tcase_set_fixture(tcase, hive_setup_regf, NULL);
	tcase_add_tests(tcase);

	return suite;
}
