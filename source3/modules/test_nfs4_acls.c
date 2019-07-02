/*
 *  Unix SMB/CIFS implementation.
 *
 *  Unit test for NFS4 ACL handling
 *
 *  Copyright (C) Christof Schmitt 2019
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

#include "nfs4_acls.c"
#include "librpc/gen_ndr/idmap.h"
#include "idmap_cache.h"
#include <cmocka.h>

struct test_sids {
	const char *sid_str;
	struct unixid unix_id;
} test_sids[] = {
	{ "S-1-5-2-123-456-789-100",	{ 1000,	ID_TYPE_UID	}},
	{ "S-1-5-2-123-456-789-101",	{ 1001,	ID_TYPE_GID	}},
	{ "S-1-5-2-123-456-789-102",	{ 1002,	ID_TYPE_BOTH	}},
	{ SID_CREATOR_OWNER,		{ 1003,	ID_TYPE_UID	}},
	{ SID_CREATOR_GROUP,		{ 1004,	ID_TYPE_GID	}},
	{ "S-1-5-2-123-456-789-103",	{ 1000,	ID_TYPE_GID	}},
	{ "S-1-5-2-123-456-789-104",	{ 1005,	ID_TYPE_BOTH	}},
	{ "S-1-5-2-123-456-789-105",	{ 1006,	ID_TYPE_BOTH	}},
	{ "S-1-5-2-123-456-789-106",	{ 1007,	ID_TYPE_BOTH	}},
};

static int group_setup(void **state)
{
	struct dom_sid *sids = NULL;
	int i;

	sids = talloc_array(NULL, struct dom_sid, ARRAY_SIZE(test_sids));
	assert_non_null(sids);

	for (i = 0; i < ARRAY_SIZE(test_sids); i++) {
		assert_true(dom_sid_parse(test_sids[i].sid_str, &sids[i]));
		idmap_cache_set_sid2unixid(&sids[i], &test_sids[i].unix_id);
	}

	*state = sids;

	return 0;

}

static int group_teardown(void **state)
{
	struct dom_sid *sids = *state;
	int i;

	for (i = 0; i < ARRAY_SIZE(test_sids); i++) {
		assert_true(idmap_cache_del_sid(&sids[i]));
	}

	TALLOC_FREE(sids);
	*state = NULL;

	return 0;
}

/*
 * Run this as first test to verify that the id mappings used by other
 * tests are available in the cache.
 */
static void test_cached_id_mappings(void **state)
{
	struct dom_sid *sids = *state;
	int i;

	for (i = 0; i < ARRAY_SIZE(test_sids); i++) {
		struct dom_sid *sid = &sids[i];
		struct unixid *unix_id = &test_sids[i].unix_id;
		uid_t uid;
		gid_t gid;

		switch(unix_id->type) {
		case ID_TYPE_UID:
			assert_true(sid_to_uid(sid, &uid));
			assert_int_equal(uid, unix_id->id);
			assert_false(sid_to_gid(sid, &gid));
			break;
		case ID_TYPE_GID:
			assert_false(sid_to_uid(sid, &uid));
			assert_true(sid_to_gid(sid, &gid));
			assert_int_equal(gid, unix_id->id);
			break;
		case ID_TYPE_BOTH:
			assert_true(sid_to_uid(sid, &uid));
			assert_int_equal(uid, unix_id->id);
			assert_true(sid_to_gid(sid, &gid));
			assert_int_equal(gid, unix_id->id);
			break;
		default:
			fail_msg("Unknown id type %d\n", unix_id->type);
			break;
		}
	}
}

static void test_empty_nfs4_to_dacl(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	struct SMB4ACL_T *nfs4_acl;
	struct security_ace *dacl_aces;
	int good_aces;
	struct smbacl4_vfs_params params = {
		.mode = e_simple,
		.do_chown = true,
		.acedup = e_merge,
		.map_full_control = true,
	};

	nfs4_acl = smb_create_smb4acl(frame);
	assert_non_null(nfs4_acl);

	assert_true(smbacl4_nfs42win(frame, &params, nfs4_acl,
				     &sids[0], &sids[1], false,
				     &dacl_aces, &good_aces));

	assert_int_equal(good_aces, 0);
	assert_null(dacl_aces);

	TALLOC_FREE(frame);
}

static void test_empty_dacl_to_nfs4(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct SMB4ACL_T *nfs4_acl;
	struct security_acl *dacl;
	struct smbacl4_vfs_params params = {
		.mode = e_simple,
		.do_chown = true,
		.acedup = e_merge,
		.map_full_control = true,
	};

	dacl = make_sec_acl(frame, SECURITY_ACL_REVISION_ADS, 0, NULL);
	assert_non_null(dacl);

	nfs4_acl = smbacl4_win2nfs4(frame, false, dacl, &params, 1001, 1002);

	assert_non_null(nfs4_acl);
	assert_int_equal(smbacl4_get_controlflags(nfs4_acl),
			 SEC_DESC_SELF_RELATIVE);
	assert_int_equal(smb_get_naces(nfs4_acl), 0);
	assert_null(smb_first_ace4(nfs4_acl));
}

struct ace_dacl_type_mapping {
	uint32_t nfs4_type;
	enum security_ace_type dacl_type;
} ace_dacl_type_mapping[] = {
	{ SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,	SEC_ACE_TYPE_ACCESS_ALLOWED   },
	{ SMB_ACE4_ACCESS_DENIED_ACE_TYPE,	SEC_ACE_TYPE_ACCESS_DENIED    },
};

static void test_acl_type_nfs4_to_dacl(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	int i;

	for (i = 0; i < ARRAY_SIZE(ace_dacl_type_mapping); i++) {
		struct SMB4ACL_T *nfs4_acl;
		SMB_ACE4PROP_T nfs4_ace;
		struct security_ace *dacl_aces;
		int good_aces;
		struct smbacl4_vfs_params params = {
			.mode = e_simple,
			.do_chown = true,
			.acedup = e_merge,
			.map_full_control = true,
		};

		nfs4_acl = smb_create_smb4acl(frame);
		assert_non_null(nfs4_acl);

		nfs4_ace = (SMB_ACE4PROP_T) {
			.flags		= 0,
			.who.uid	= 1000,
			.aceType	= ace_dacl_type_mapping[i].nfs4_type,
			.aceFlags	= 0,
			.aceMask	= SMB_ACE4_READ_DATA,
		};
		assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

		assert_true(smbacl4_nfs42win(frame, &params, nfs4_acl,
					     &sids[2], &sids[3], false,
					     &dacl_aces, &good_aces));

		assert_int_equal(good_aces, 1);
		assert_non_null(dacl_aces);

		assert_int_equal(dacl_aces[0].type,
				 ace_dacl_type_mapping[i].dacl_type);
		assert_int_equal(dacl_aces[0].flags, 0);
		assert_int_equal(dacl_aces[0].access_mask, SEC_FILE_READ_DATA);
		assert_true(dom_sid_equal(&dacl_aces[0].trustee, &sids[0]));
	}

	TALLOC_FREE(frame);
}

static void test_acl_type_dacl_to_nfs4(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	int i;

	for (i = 0; i < ARRAY_SIZE(ace_dacl_type_mapping); i++) {
		struct SMB4ACL_T *nfs4_acl;
		struct SMB4ACE_T *nfs4_ace_container;
		SMB_ACE4PROP_T *nfs4_ace;
		struct security_ace dacl_aces[1];
		struct security_acl *dacl;
		struct smbacl4_vfs_params params = {
			.mode = e_simple,
			.do_chown = true,
			.acedup = e_merge,
			.map_full_control = true,
		};

		init_sec_ace(&dacl_aces[0], &sids[0],
			     ace_dacl_type_mapping[i].dacl_type,
			     SEC_FILE_READ_DATA, 0);
		dacl = make_sec_acl(frame, SECURITY_ACL_REVISION_ADS,
				    ARRAY_SIZE(dacl_aces), dacl_aces);
		assert_non_null(dacl);

		nfs4_acl = smbacl4_win2nfs4(frame, false, dacl, &params,
					    101, 102);

		assert_non_null(nfs4_acl);
		assert_int_equal(smbacl4_get_controlflags(nfs4_acl),
				 SEC_DESC_SELF_RELATIVE);
		assert_int_equal(smb_get_naces(nfs4_acl), 1);

		nfs4_ace_container = smb_first_ace4(nfs4_acl);
		assert_non_null(nfs4_ace_container);
		assert_null(smb_next_ace4(nfs4_ace_container));

		nfs4_ace = smb_get_ace4(nfs4_ace_container);
		assert_int_equal(nfs4_ace->flags, 0);
		assert_int_equal(nfs4_ace->who.uid, 1000);
		assert_int_equal(nfs4_ace->aceFlags, 0);
		assert_int_equal(nfs4_ace->aceType,
				 ace_dacl_type_mapping[i].nfs4_type);
		assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);
	}

	TALLOC_FREE(frame);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_cached_id_mappings),
		cmocka_unit_test(test_empty_nfs4_to_dacl),
		cmocka_unit_test(test_empty_dacl_to_nfs4),
		cmocka_unit_test(test_acl_type_nfs4_to_dacl),
		cmocka_unit_test(test_acl_type_dacl_to_nfs4),
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

	return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
