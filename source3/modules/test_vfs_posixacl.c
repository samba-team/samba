/*
 *  Unix SMB/CIFS implementation.
 *
 *  Unit test for vfs_posixacl
 *
 *  Copyright (C) Christof Schmitt 2020
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "vfs_posixacl.c"
#include <cmocka.h>

static void smb_acl_add_entry(struct smb_acl_t * smb_acl,
			      SMB_ACL_TAG_T tag, uint32_t id,
			      bool read, bool write, bool execute)
{
	int ret;
	struct smb_acl_entry *smb_acl_entry = NULL;
	SMB_ACL_PERMSET_T smb_permset = NULL;

	ret = sys_acl_create_entry(&smb_acl, &smb_acl_entry);
	assert_int_equal(ret, 0);

	ret = sys_acl_set_tag_type(smb_acl_entry, tag);
	assert_int_equal(ret, 0);

	if (tag == SMB_ACL_USER || tag == SMB_ACL_GROUP) {
		ret = sys_acl_set_qualifier(smb_acl_entry, &id);
		assert_int_equal(ret, 0);
	}

	ret = sys_acl_get_permset(smb_acl_entry, &smb_permset);
	assert_int_equal(ret, 0);

	if (read) {
		ret = sys_acl_add_perm(smb_permset, SMB_ACL_READ);
		assert_int_equal(ret, 0);
	}

	if (write) {
		ret = sys_acl_add_perm(smb_permset, SMB_ACL_WRITE);
		assert_int_equal(ret, 0);
	}

	if (execute) {
		ret = sys_acl_add_perm(smb_permset, SMB_ACL_EXECUTE);
		assert_int_equal(ret, 0);
	}

	ret = sys_acl_set_permset(smb_acl_entry, smb_permset);
	assert_int_equal(ret, 0);
}

static void acl_check_entry(acl_entry_t acl_entry, SMB_ACL_TAG_T tag,
			    uint32_t id,
			    bool read, bool write, bool execute)
{
	int ret;
	acl_permset_t acl_permset = NULL;
	acl_tag_t acl_tag;

	ret = acl_get_permset(acl_entry, &acl_permset);
	assert_int_equal(ret, 0);

	ret = acl_get_tag_type(acl_entry, &acl_tag);
	assert_int_equal(ret, 0);
	assert_int_equal(acl_tag, tag);

	if (tag == ACL_USER || tag == ACL_GROUP) {
		uint32_t *id_p;

		id_p = acl_get_qualifier(acl_entry);
		assert_non_null(id_p);
		assert_int_equal(*id_p, id);
	}

#ifdef HAVE_ACL_GET_PERM_NP
	ret = acl_get_perm_np(acl_permset, ACL_READ);
#else
	ret = acl_get_perm(acl_permset, ACL_READ);
#endif
	assert_int_equal(ret, read ? 1 : 0);

#ifdef HAVE_ACL_GET_PERM_NP
	ret = acl_get_perm_np(acl_permset, ACL_WRITE);
#else
	ret = acl_get_perm(acl_permset, ACL_WRITE);
#endif
	assert_int_equal(ret, write ? 1 : 0);

#ifdef HAVE_ACL_GET_PERM_NP
	ret = acl_get_perm_np(acl_permset, ACL_EXECUTE);
#else
	ret = acl_get_perm(acl_permset, ACL_EXECUTE);
#endif
	assert_int_equal(ret, execute ? 1 : 0);
}

static void test_smb_acl_to_posix_simple_acl(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct smb_acl_t *smb_acl = NULL;
	acl_t acl = NULL;
	acl_entry_t acl_entry = NULL;
	int ret;

	smb_acl = sys_acl_init(mem_ctx);
	assert_non_null(smb_acl);

	smb_acl_add_entry(smb_acl, SMB_ACL_USER_OBJ, 0, false, true, false);
	smb_acl_add_entry(smb_acl, SMB_ACL_GROUP_OBJ, 0, true, false, false);
	smb_acl_add_entry(smb_acl, SMB_ACL_OTHER, 0, false, false, true);

	acl = smb_acl_to_posix(smb_acl);
	assert_non_null(acl);

	ret = acl_get_entry(acl, ACL_FIRST_ENTRY, &acl_entry);
	assert_int_equal(ret, 1);
	acl_check_entry(acl_entry, ACL_USER_OBJ, 0, false, true, false);

	ret = acl_get_entry(acl, ACL_NEXT_ENTRY, &acl_entry);
	assert_int_equal(ret, 1);
	acl_check_entry(acl_entry, ACL_GROUP_OBJ, 0, true, false, false);

	ret = acl_get_entry(acl, ACL_NEXT_ENTRY, &acl_entry);
	assert_int_equal(ret, 1);
	acl_check_entry(acl_entry, ACL_OTHER, 0, false, false, true);

	ret = acl_get_entry(acl, ACL_NEXT_ENTRY, &acl_entry);
	assert_int_equal(ret, 0);

	ret = acl_free(acl);
	assert_int_equal(ret, 0);

	TALLOC_FREE(mem_ctx);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_smb_acl_to_posix_simple_acl),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	if (argc != 2) {
		print_error("Usage: %s smb.conf\n", argv[0]);
		exit(1);
	}

	/*
	 * Initialize enough of the Samba internals to have the
	 * mappings tests work.
	 */
	talloc_stackframe();
	lp_load_global(argv[1]);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
