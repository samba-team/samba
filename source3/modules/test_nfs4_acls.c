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

struct ace_flag_mapping_nfs4_to_dacl {
	bool is_directory;
	uint32_t nfs4_flag;
	uint32_t dacl_flag;
} ace_flags_nfs4_to_dacl[] = {
	{ true,  SMB_ACE4_FILE_INHERIT_ACE,
	  SEC_ACE_FLAG_OBJECT_INHERIT },
	{ false, SMB_ACE4_FILE_INHERIT_ACE,
	  0 },
	{ true, SMB_ACE4_DIRECTORY_INHERIT_ACE,
	  SEC_ACE_FLAG_CONTAINER_INHERIT },
	{ false, SMB_ACE4_DIRECTORY_INHERIT_ACE,
	  0 },
	{ true, SMB_ACE4_NO_PROPAGATE_INHERIT_ACE,
	  SEC_ACE_FLAG_NO_PROPAGATE_INHERIT },
	{ false, SMB_ACE4_NO_PROPAGATE_INHERIT_ACE,
	  SEC_ACE_FLAG_NO_PROPAGATE_INHERIT },
	{ true, SMB_ACE4_INHERIT_ONLY_ACE,
	  SEC_ACE_FLAG_INHERIT_ONLY },
	{ false, SMB_ACE4_INHERIT_ONLY_ACE,
	  SEC_ACE_FLAG_INHERIT_ONLY },
	{ true, SMB_ACE4_SUCCESSFUL_ACCESS_ACE_FLAG,
	  0 },
	{ false, SMB_ACE4_SUCCESSFUL_ACCESS_ACE_FLAG,
	  0 },
	{ true, SMB_ACE4_FAILED_ACCESS_ACE_FLAG,
	  0 },
	{ false, SMB_ACE4_FAILED_ACCESS_ACE_FLAG,
	  0 },
	{ true, SMB_ACE4_INHERITED_ACE,
	  SEC_ACE_FLAG_INHERITED_ACE },
	{ false, SMB_ACE4_INHERITED_ACE,
	  SEC_ACE_FLAG_INHERITED_ACE },
};

static void test_ace_flags_nfs4_to_dacl(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	SMB_ACE4PROP_T nfs4_ace;
	int i;

	for (i = 0; i < ARRAY_SIZE(ace_flags_nfs4_to_dacl); i++) {
		struct SMB4ACL_T *nfs4_acl;
		bool is_directory;
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
			.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
			.aceFlags	= ace_flags_nfs4_to_dacl[i].nfs4_flag,
			.aceMask	= SMB_ACE4_READ_DATA,
		};
		assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

		is_directory = ace_flags_nfs4_to_dacl[i].is_directory;

		assert_true(smbacl4_nfs42win(frame, &params, nfs4_acl,
					     &sids[2], &sids[3], is_directory,
					     &dacl_aces, &good_aces));

		assert_int_equal(good_aces, 1);
		assert_non_null(dacl_aces);

		assert_int_equal(dacl_aces[0].type,
				 SEC_ACE_TYPE_ACCESS_ALLOWED);
		assert_int_equal(dacl_aces[0].flags,
				 ace_flags_nfs4_to_dacl[i].dacl_flag);
		assert_int_equal(dacl_aces[0].access_mask, SEC_FILE_READ_DATA);
		assert_true(dom_sid_equal(&dacl_aces[0].trustee, &sids[0]));
	}

	TALLOC_FREE(frame);
}

struct ace_flag_mapping_dacl_to_nfs4 {
	bool is_directory;
	uint32_t dacl_flag;
	uint32_t nfs4_flag;
} ace_flags_dacl_to_nfs4[] = {
	{ true, SEC_ACE_FLAG_OBJECT_INHERIT,
	  SMB_ACE4_FILE_INHERIT_ACE },
	{ false, SEC_ACE_FLAG_OBJECT_INHERIT,
	  0 },
	{ true, SEC_ACE_FLAG_CONTAINER_INHERIT,
	  SMB_ACE4_DIRECTORY_INHERIT_ACE },
	{ false, SEC_ACE_FLAG_CONTAINER_INHERIT,
	  0 },
	{ true, SEC_ACE_FLAG_NO_PROPAGATE_INHERIT,
	  SMB_ACE4_NO_PROPAGATE_INHERIT_ACE },
	{ false, SEC_ACE_FLAG_NO_PROPAGATE_INHERIT,
	  0 },
	{ true, SEC_ACE_FLAG_INHERIT_ONLY,
	  SMB_ACE4_INHERIT_ONLY_ACE },
	{ false, SEC_ACE_FLAG_INHERIT_ONLY,
	  0 },
	{ true, SEC_ACE_FLAG_INHERITED_ACE,
	  SMB_ACE4_INHERITED_ACE },
	{ false, SEC_ACE_FLAG_INHERITED_ACE,
	  SMB_ACE4_INHERITED_ACE },
	{ true, SEC_ACE_FLAG_SUCCESSFUL_ACCESS,
	  0 },
	{ false, SEC_ACE_FLAG_SUCCESSFUL_ACCESS,
	  0 },
	{ true, SEC_ACE_FLAG_FAILED_ACCESS,
	  0 },
	{ false, SEC_ACE_FLAG_FAILED_ACCESS,
	  0 },
};

static void test_ace_flags_dacl_to_nfs4(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	int i;

	for (i = 0; i < ARRAY_SIZE(ace_flags_dacl_to_nfs4); i++) {
		struct SMB4ACL_T *nfs4_acl;
		struct SMB4ACE_T *nfs4_ace_container;
		SMB_ACE4PROP_T *nfs4_ace;
		bool is_directory;
		struct security_ace dacl_aces[1];
		struct security_acl *dacl;
		struct smbacl4_vfs_params params = {
			.mode = e_simple,
			.do_chown = true,
			.acedup = e_merge,
			.map_full_control = true,
		};

		init_sec_ace(&dacl_aces[0], &sids[0],
			     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
			     ace_flags_dacl_to_nfs4[i].dacl_flag);
		dacl = make_sec_acl(frame, SECURITY_ACL_REVISION_ADS,
				    ARRAY_SIZE(dacl_aces), dacl_aces);
		assert_non_null(dacl);

		is_directory = ace_flags_dacl_to_nfs4[i].is_directory;
		nfs4_acl = smbacl4_win2nfs4(frame, is_directory, dacl, &params,
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
		assert_int_equal(nfs4_ace->aceFlags,
				 ace_flags_dacl_to_nfs4[i].nfs4_flag);
		assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);
	}

	TALLOC_FREE(frame);
}

struct ace_perm_mapping {
	uint32_t nfs4_perm;
	uint32_t dacl_perm;
} perm_table_nfs4_to_dacl[] = {
	{ SMB_ACE4_READ_DATA,		SEC_FILE_READ_DATA		},
	{ SMB_ACE4_LIST_DIRECTORY,	SEC_DIR_LIST			},
	{ SMB_ACE4_WRITE_DATA,		SEC_FILE_WRITE_DATA		},
	{ SMB_ACE4_ADD_FILE,		SEC_DIR_ADD_FILE		},
	{ SMB_ACE4_APPEND_DATA,	SEC_FILE_APPEND_DATA		},
	{ SMB_ACE4_ADD_SUBDIRECTORY,	SEC_DIR_ADD_SUBDIR,		},
	{ SMB_ACE4_READ_NAMED_ATTRS,	SEC_FILE_READ_EA		},
	{ SMB_ACE4_READ_NAMED_ATTRS,	SEC_DIR_READ_EA		},
	{ SMB_ACE4_WRITE_NAMED_ATTRS,	SEC_FILE_WRITE_EA		},
	{ SMB_ACE4_WRITE_NAMED_ATTRS,	SEC_DIR_WRITE_EA		},
	{ SMB_ACE4_EXECUTE,		SEC_FILE_EXECUTE		},
	{ SMB_ACE4_EXECUTE,		SEC_DIR_TRAVERSE		},
	{ SMB_ACE4_DELETE_CHILD,	SEC_DIR_DELETE_CHILD		},
	{ SMB_ACE4_READ_ATTRIBUTES,	SEC_FILE_READ_ATTRIBUTE	},
	{ SMB_ACE4_READ_ATTRIBUTES,	SEC_DIR_READ_ATTRIBUTE		},
	{ SMB_ACE4_WRITE_ATTRIBUTES,	SEC_FILE_WRITE_ATTRIBUTE	},
	{ SMB_ACE4_WRITE_ATTRIBUTES,	SEC_DIR_WRITE_ATTRIBUTE	},
	{ SMB_ACE4_DELETE,		SEC_STD_DELETE			},
	{ SMB_ACE4_READ_ACL,		SEC_STD_READ_CONTROL		},
	{ SMB_ACE4_WRITE_ACL,		SEC_STD_WRITE_DAC,		},
	{ SMB_ACE4_WRITE_OWNER,	SEC_STD_WRITE_OWNER		},
	{ SMB_ACE4_SYNCHRONIZE,	SEC_STD_SYNCHRONIZE		},
};

static void test_nfs4_permissions_to_dacl(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	int i;

	for (i = 0; i < ARRAY_SIZE(perm_table_nfs4_to_dacl); i++) {
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
			.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
			.aceFlags	= 0,
			.aceMask	= perm_table_nfs4_to_dacl[i].nfs4_perm,
		};
		assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

		assert_true(smbacl4_nfs42win(frame, &params, nfs4_acl,
					     &sids[0], &sids[1], false,
					     &dacl_aces, &good_aces));

		assert_int_equal(good_aces, 1);
		assert_non_null(dacl_aces);

		assert_int_equal(dacl_aces[0].type,
				 SEC_ACE_TYPE_ACCESS_ALLOWED);
		assert_int_equal(dacl_aces[0].flags, 0);
		assert_int_equal(dacl_aces[0].access_mask,
				 perm_table_nfs4_to_dacl[i].dacl_perm);
		assert_true(dom_sid_equal(&dacl_aces[0].trustee, &sids[0]));
	}

	TALLOC_FREE(frame);
}

struct ace_perm_mapping_dacl_to_nfs4 {
	uint32_t dacl_perm;
	uint32_t nfs4_perm;
} perm_table_dacl_to_nfs4[] = {
	{ SEC_FILE_READ_DATA,		SMB_ACE4_READ_DATA,		},
	{ SEC_DIR_LIST,		SMB_ACE4_LIST_DIRECTORY,	},
	{ SEC_FILE_WRITE_DATA,		SMB_ACE4_WRITE_DATA,		},
	{ SEC_DIR_ADD_FILE,		SMB_ACE4_ADD_FILE,		},
	{ SEC_FILE_APPEND_DATA,	SMB_ACE4_APPEND_DATA,		},
	{ SEC_DIR_ADD_SUBDIR,		SMB_ACE4_ADD_SUBDIRECTORY,	},
	{ SEC_FILE_READ_EA,		SMB_ACE4_READ_NAMED_ATTRS,	},
	{ SEC_DIR_READ_EA,		SMB_ACE4_READ_NAMED_ATTRS,	},
	{ SEC_FILE_WRITE_EA,		SMB_ACE4_WRITE_NAMED_ATTRS,	},
	{ SEC_DIR_WRITE_EA,		SMB_ACE4_WRITE_NAMED_ATTRS,	},
	{ SEC_FILE_EXECUTE,		SMB_ACE4_EXECUTE,		},
	{ SEC_DIR_TRAVERSE,		SMB_ACE4_EXECUTE,		},
	{ SEC_DIR_DELETE_CHILD,	SMB_ACE4_DELETE_CHILD,		},
	{ SEC_FILE_READ_ATTRIBUTE,	SMB_ACE4_READ_ATTRIBUTES,	},
	{ SEC_DIR_READ_ATTRIBUTE,	SMB_ACE4_READ_ATTRIBUTES,	},
	{ SEC_FILE_WRITE_ATTRIBUTE,	SMB_ACE4_WRITE_ATTRIBUTES,	},
	{ SEC_DIR_WRITE_ATTRIBUTE,	SMB_ACE4_WRITE_ATTRIBUTES,	},
	{ SEC_STD_DELETE,		SMB_ACE4_DELETE,		},
	{ SEC_STD_READ_CONTROL,	SMB_ACE4_READ_ACL,		},
	{ SEC_STD_WRITE_DAC,		SMB_ACE4_WRITE_ACL,		},
	{ SEC_STD_WRITE_OWNER,		SMB_ACE4_WRITE_OWNER,		},
	{ SEC_STD_SYNCHRONIZE,		SMB_ACE4_SYNCHRONIZE,		},
	{ SEC_GENERIC_READ,		SMB_ACE4_READ_ACL|
					SMB_ACE4_READ_DATA|
					SMB_ACE4_READ_ATTRIBUTES|
					SMB_ACE4_READ_NAMED_ATTRS|
					SMB_ACE4_SYNCHRONIZE		},
	{ SEC_GENERIC_WRITE,		SMB_ACE4_WRITE_ACL|
					SMB_ACE4_WRITE_DATA|
					SMB_ACE4_WRITE_ATTRIBUTES|
					SMB_ACE4_WRITE_NAMED_ATTRS|
					SMB_ACE4_SYNCHRONIZE		},
	{ SEC_GENERIC_EXECUTE,		SMB_ACE4_READ_ACL|
					SMB_ACE4_READ_ATTRIBUTES|
					SMB_ACE4_EXECUTE|
					SMB_ACE4_SYNCHRONIZE		},
	{ SEC_GENERIC_ALL,		SMB_ACE4_DELETE|
					SMB_ACE4_READ_ACL|
					SMB_ACE4_WRITE_ACL|
					SMB_ACE4_WRITE_OWNER|
					SMB_ACE4_SYNCHRONIZE|
					SMB_ACE4_WRITE_ATTRIBUTES|
					SMB_ACE4_READ_ATTRIBUTES|
					SMB_ACE4_EXECUTE|
					SMB_ACE4_READ_NAMED_ATTRS|
					SMB_ACE4_WRITE_NAMED_ATTRS|
					SMB_ACE4_WRITE_DATA|
					SMB_ACE4_APPEND_DATA|
					SMB_ACE4_READ_DATA|
					SMB_ACE4_DELETE_CHILD		},
};

static void test_dacl_permissions_to_nfs4(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	int i;

	for (i = 0; i < ARRAY_SIZE(perm_table_nfs4_to_dacl); i++) {
		struct SMB4ACL_T *nfs4_acl;
		struct SMB4ACE_T *nfs4_ace_container;
		SMB_ACE4PROP_T *nfs4_ace;
		struct smbacl4_vfs_params params = {
			.mode = e_simple,
			.do_chown = true,
			.acedup = e_merge,
			.map_full_control = true,
		};
		struct security_ace dacl_aces[1];
		struct security_acl *dacl;

		init_sec_ace(&dacl_aces[0], &sids[0],
			     SEC_ACE_TYPE_ACCESS_ALLOWED,
			     perm_table_dacl_to_nfs4[i].dacl_perm, 0);
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
		assert_int_equal(nfs4_ace->aceMask,
				 perm_table_dacl_to_nfs4[i].nfs4_perm);
	}

	TALLOC_FREE(frame);
}

/*
 * Create NFS4 ACL with all possible "special" entries. Verify that
 * the ones that should be mapped to a DACL are mapped and the other
 * ones are ignored.
 */
static void test_special_nfs4_to_dacl(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
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
		.flags		= SMB_ACE4_ID_SPECIAL,
		.who.special_id = SMB_ACE4_WHO_OWNER,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= 0,
		.aceMask	= SMB_ACE4_READ_DATA,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= SMB_ACE4_ID_SPECIAL,
		.who.special_id = SMB_ACE4_WHO_GROUP,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= 0,
		.aceMask	= SMB_ACE4_WRITE_DATA,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= SMB_ACE4_ID_SPECIAL,
		.who.special_id = SMB_ACE4_WHO_EVERYONE,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= 0,
		.aceMask	= SMB_ACE4_APPEND_DATA,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= SMB_ACE4_ID_SPECIAL,
		.who.special_id = SMB_ACE4_WHO_INTERACTIVE,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= 0,
		.aceMask	= SMB_ACE4_READ_NAMED_ATTRS,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= SMB_ACE4_ID_SPECIAL,
		.who.special_id = SMB_ACE4_WHO_NETWORK,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= 0,
		.aceMask	= SMB_ACE4_WRITE_NAMED_ATTRS,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= SMB_ACE4_ID_SPECIAL,
		.who.special_id = SMB_ACE4_WHO_DIALUP,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= 0,
		.aceMask	= SMB_ACE4_EXECUTE,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= SMB_ACE4_ID_SPECIAL,
		.who.special_id = SMB_ACE4_WHO_BATCH,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= 0,
		.aceMask	= SMB_ACE4_READ_ATTRIBUTES,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= SMB_ACE4_ID_SPECIAL,
		.who.special_id = SMB_ACE4_WHO_ANONYMOUS,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= 0,
		.aceMask	= SMB_ACE4_WRITE_ATTRIBUTES,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= SMB_ACE4_ID_SPECIAL,
		.who.special_id = SMB_ACE4_WHO_AUTHENTICATED,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= 0,
		.aceMask	= SMB_ACE4_READ_ACL,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= SMB_ACE4_ID_SPECIAL,
		.who.special_id = SMB_ACE4_WHO_SERVICE,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= 0,
		.aceMask	= SMB_ACE4_WRITE_ACL,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	assert_true(smbacl4_nfs42win(frame, &params, nfs4_acl,
				     &sids[0], &sids[1], false,
				     &dacl_aces, &good_aces));

	assert_int_equal(good_aces, 3);
	assert_non_null(dacl_aces);

	assert_int_equal(dacl_aces[0].type, SEC_ACE_TYPE_ACCESS_ALLOWED);
	assert_int_equal(dacl_aces[0].flags, 0);
	assert_int_equal(dacl_aces[0].access_mask, SEC_FILE_READ_DATA);
	assert_true(dom_sid_equal(&dacl_aces[0].trustee, &sids[0]));

	assert_int_equal(dacl_aces[1].type, SEC_ACE_TYPE_ACCESS_ALLOWED);
	assert_int_equal(dacl_aces[1].flags, 0);
	assert_int_equal(dacl_aces[1].access_mask, SEC_FILE_WRITE_DATA);
	assert_true(dom_sid_equal(&dacl_aces[1].trustee, &sids[1]));

	assert_int_equal(dacl_aces[2].type, SEC_ACE_TYPE_ACCESS_ALLOWED);
	assert_int_equal(dacl_aces[2].flags, 0);
	assert_int_equal(dacl_aces[2].access_mask, SEC_FILE_APPEND_DATA);
	assert_true(dom_sid_equal(&dacl_aces[2].trustee, &global_sid_World));

	TALLOC_FREE(frame);
}

static void test_dacl_to_special_nfs4(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	struct SMB4ACL_T *nfs4_acl;
	struct SMB4ACE_T *nfs4_ace_container;
	SMB_ACE4PROP_T *nfs4_ace;
	struct security_ace dacl_aces[6];
	struct security_acl *dacl;
	struct smbacl4_vfs_params params = {
		.mode = e_simple,
		.do_chown = true,
		.acedup = e_dontcare,
		.map_full_control = true,
	};

	/*
	 * global_Sid_World is mapped to EVERYONE.
	 */
	init_sec_ace(&dacl_aces[0], &global_sid_World,
		     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_WRITE_DATA, 0);
	/*
	 * global_sid_Unix_NFS is ignored.
	 */
	init_sec_ace(&dacl_aces[1], &global_sid_Unix_NFS,
		     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA, 0);
	/*
	 * Anything that maps to owner or owning group with inheritance flags
	 * is NOT mapped to special owner or special group.
	 */
	init_sec_ace(&dacl_aces[2], &sids[0],
		     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
		     SEC_ACE_FLAG_OBJECT_INHERIT);
	init_sec_ace(&dacl_aces[3], &sids[0],
		     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
		     SEC_ACE_FLAG_CONTAINER_INHERIT|SEC_ACE_FLAG_INHERIT_ONLY);
	init_sec_ace(&dacl_aces[4], &sids[1],
		     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
		     SEC_ACE_FLAG_OBJECT_INHERIT);
	init_sec_ace(&dacl_aces[5], &sids[1],
		     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
		     SEC_ACE_FLAG_CONTAINER_INHERIT|SEC_ACE_FLAG_INHERIT_ONLY);
	dacl = make_sec_acl(frame, SECURITY_ACL_REVISION_ADS,
			    ARRAY_SIZE(dacl_aces), dacl_aces);
	assert_non_null(dacl);

	nfs4_acl = smbacl4_win2nfs4(frame, true, dacl, &params, 1000, 1001);

	assert_non_null(nfs4_acl);
	assert_int_equal(smbacl4_get_controlflags(nfs4_acl),
			 SEC_DESC_SELF_RELATIVE);
	assert_int_equal(smb_get_naces(nfs4_acl), 5);

	nfs4_ace_container = smb_first_ace4(nfs4_acl);
	assert_non_null(nfs4_ace_container);

	nfs4_ace = smb_get_ace4(nfs4_ace_container);
	assert_int_equal(nfs4_ace->flags, SMB_ACE4_ID_SPECIAL);
	assert_int_equal(nfs4_ace->who.special_id, SMB_ACE4_WHO_EVERYONE);
	assert_int_equal(nfs4_ace->aceFlags, 0);
	assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_WRITE_DATA);

	nfs4_ace_container = smb_next_ace4(nfs4_ace_container);
	assert_non_null(nfs4_ace_container);

	nfs4_ace = smb_get_ace4(nfs4_ace_container);
	assert_int_equal(nfs4_ace->flags, 0);
	assert_int_equal(nfs4_ace->who.uid, 1000);
	assert_int_equal(nfs4_ace->aceFlags, SMB_ACE4_FILE_INHERIT_ACE);
	assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

	nfs4_ace_container = smb_next_ace4(nfs4_ace_container);
	assert_non_null(nfs4_ace_container);

	nfs4_ace = smb_get_ace4(nfs4_ace_container);
	assert_int_equal(nfs4_ace->flags, 0);
	assert_int_equal(nfs4_ace->who.uid, 1000);
	assert_int_equal(nfs4_ace->aceFlags, SMB_ACE4_DIRECTORY_INHERIT_ACE|
			 SMB_ACE4_INHERIT_ONLY_ACE);
	assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

	nfs4_ace_container = smb_next_ace4(nfs4_ace_container);
	assert_non_null(nfs4_ace_container);

	nfs4_ace = smb_get_ace4(nfs4_ace_container);
	assert_int_equal(nfs4_ace->flags, 0);
	assert_int_equal(nfs4_ace->aceFlags, SMB_ACE4_IDENTIFIER_GROUP|
			 SMB_ACE4_FILE_INHERIT_ACE);
	assert_int_equal(nfs4_ace->who.gid, 1001);
	assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

	nfs4_ace_container = smb_next_ace4(nfs4_ace_container);
	assert_non_null(nfs4_ace_container);

	nfs4_ace = smb_get_ace4(nfs4_ace_container);
	assert_int_equal(nfs4_ace->flags, 0);
	assert_int_equal(nfs4_ace->aceFlags, SMB_ACE4_IDENTIFIER_GROUP|
			 SMB_ACE4_DIRECTORY_INHERIT_ACE|
			 SMB_ACE4_INHERIT_ONLY_ACE);
	assert_int_equal(nfs4_ace->who.gid, 1001);
	assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

	assert_null(smb_next_ace4(nfs4_ace_container));

	TALLOC_FREE(frame);
}

struct creator_ace_flags {
	uint32_t dacl_flags;
	uint32_t nfs4_flags;
} creator_ace_flags[] = {
	{ 0,					0 },

	{ SEC_ACE_FLAG_INHERIT_ONLY,		0 },

	{ SEC_ACE_FLAG_CONTAINER_INHERIT,	SMB_ACE4_DIRECTORY_INHERIT_ACE|
						SMB_ACE4_INHERIT_ONLY_ACE },

	{ SEC_ACE_FLAG_CONTAINER_INHERIT|
	  SEC_ACE_FLAG_INHERIT_ONLY,		SMB_ACE4_DIRECTORY_INHERIT_ACE|
						SMB_ACE4_INHERIT_ONLY_ACE },

	{ SEC_ACE_FLAG_OBJECT_INHERIT,		SMB_ACE4_FILE_INHERIT_ACE|
						SMB_ACE4_INHERIT_ONLY_ACE },
	{ SEC_ACE_FLAG_OBJECT_INHERIT|
	  SEC_ACE_FLAG_INHERIT_ONLY,		SMB_ACE4_FILE_INHERIT_ACE|
						SMB_ACE4_INHERIT_ONLY_ACE },

	{ SEC_ACE_FLAG_CONTAINER_INHERIT|
	  SEC_ACE_FLAG_OBJECT_INHERIT,		SMB_ACE4_DIRECTORY_INHERIT_ACE|
						SMB_ACE4_FILE_INHERIT_ACE|
						SMB_ACE4_INHERIT_ONLY_ACE },

	{ SEC_ACE_FLAG_CONTAINER_INHERIT|
	  SEC_ACE_FLAG_OBJECT_INHERIT|
	  SEC_ACE_FLAG_INHERIT_ONLY,		SMB_ACE4_DIRECTORY_INHERIT_ACE|
						SMB_ACE4_FILE_INHERIT_ACE|
						SMB_ACE4_INHERIT_ONLY_ACE },
};

static void test_dacl_creator_to_nfs4(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int i;

	for (i = 0; i < ARRAY_SIZE(creator_ace_flags); i++) {
		struct SMB4ACL_T *nfs4_acl;
		struct SMB4ACE_T *nfs4_ace_container;
		SMB_ACE4PROP_T *nfs4_ace;
		struct security_ace dacl_aces[2];
		struct security_acl *dacl;
		struct smbacl4_vfs_params params = {
			.mode = e_simple,
			.do_chown = true,
			.acedup = e_merge,
			.map_full_control = true,
		};

		init_sec_ace(&dacl_aces[0], &global_sid_Creator_Owner,
			     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
			     creator_ace_flags[i].dacl_flags);
		init_sec_ace(&dacl_aces[1], &global_sid_Creator_Group,
			     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
			     creator_ace_flags[i].dacl_flags);
		dacl = make_sec_acl(frame, SECURITY_ACL_REVISION_ADS,
				    ARRAY_SIZE(dacl_aces), dacl_aces);
		assert_non_null(dacl);

		nfs4_acl = smbacl4_win2nfs4(frame, true, dacl, &params,
					    101, 102);

		assert_non_null(nfs4_acl);
		assert_int_equal(smbacl4_get_controlflags(nfs4_acl),
				 SEC_DESC_SELF_RELATIVE);

		if (creator_ace_flags[i].nfs4_flags == 0) {
			/*
			 * CREATOR OWNER and CREATOR GROUP not mapped
			 * in thise case.
			 */
			assert_null(smb_first_ace4(nfs4_acl));
		} else {
			assert_int_equal(smb_get_naces(nfs4_acl), 2);

			nfs4_ace_container = smb_first_ace4(nfs4_acl);
			assert_non_null(nfs4_ace_container);

			nfs4_ace = smb_get_ace4(nfs4_ace_container);
			assert_non_null(nfs4_ace);
			assert_int_equal(nfs4_ace->flags, SMB_ACE4_ID_SPECIAL);
			assert_int_equal(nfs4_ace->who.special_id,
					 SMB_ACE4_WHO_OWNER);
			assert_int_equal(nfs4_ace->aceFlags,
					 creator_ace_flags[i].nfs4_flags);
			assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

			nfs4_ace_container = smb_next_ace4(nfs4_ace_container);
			assert_non_null(nfs4_ace_container);
			assert_null(smb_next_ace4(nfs4_ace_container));

			nfs4_ace = smb_get_ace4(nfs4_ace_container);
			assert_non_null(nfs4_ace);
			assert_int_equal(nfs4_ace->flags, SMB_ACE4_ID_SPECIAL);
			assert_int_equal(nfs4_ace->who.special_id,
					 SMB_ACE4_WHO_GROUP);
			assert_int_equal(nfs4_ace->aceFlags,
					 creator_ace_flags[i].nfs4_flags);
			assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);
		}
	}

	TALLOC_FREE(frame);
}

struct creator_owner_nfs4_to_dacl {
	uint32_t special_id;
	uint32_t nfs4_ace_flags;
	uint32_t dacl_ace_flags;
} creator_owner_nfs4_to_dacl[] = {
	{ SMB_ACE4_WHO_OWNER,
	  SMB_ACE4_FILE_INHERIT_ACE,
	  SEC_ACE_FLAG_OBJECT_INHERIT|SEC_ACE_FLAG_INHERIT_ONLY },
	{ SMB_ACE4_WHO_OWNER,
	  SMB_ACE4_DIRECTORY_INHERIT_ACE,
	  SEC_ACE_FLAG_CONTAINER_INHERIT|SEC_ACE_FLAG_INHERIT_ONLY },
	{ SMB_ACE4_WHO_OWNER,
	  SMB_ACE4_FILE_INHERIT_ACE|SMB_ACE4_DIRECTORY_INHERIT_ACE,
	  SEC_ACE_FLAG_OBJECT_INHERIT|SEC_ACE_FLAG_CONTAINER_INHERIT|
	  SEC_ACE_FLAG_INHERIT_ONLY },
	{ SMB_ACE4_WHO_GROUP,
	  SMB_ACE4_FILE_INHERIT_ACE,
	  SEC_ACE_FLAG_OBJECT_INHERIT|SEC_ACE_FLAG_INHERIT_ONLY },
	{ SMB_ACE4_WHO_GROUP,
	  SMB_ACE4_DIRECTORY_INHERIT_ACE,
	  SEC_ACE_FLAG_CONTAINER_INHERIT|SEC_ACE_FLAG_INHERIT_ONLY },
	{ SMB_ACE4_WHO_GROUP,
	  SMB_ACE4_FILE_INHERIT_ACE|SMB_ACE4_DIRECTORY_INHERIT_ACE,
	  SEC_ACE_FLAG_OBJECT_INHERIT|SEC_ACE_FLAG_CONTAINER_INHERIT|
	  SEC_ACE_FLAG_INHERIT_ONLY },
};

static void test_nfs4_to_dacl_creator(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	int i;

	for (i = 0; i < ARRAY_SIZE(creator_owner_nfs4_to_dacl); i++) {
		struct SMB4ACL_T *nfs4_acl;
		SMB_ACE4PROP_T nfs4_ace;
		struct security_ace *dacl_aces, *creator_dacl_ace;
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
			.flags		= SMB_ACE4_ID_SPECIAL,
			.who.special_id
				= creator_owner_nfs4_to_dacl[i].special_id,
			.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
			.aceFlags
				= creator_owner_nfs4_to_dacl[i].nfs4_ace_flags,
			.aceMask	= SMB_ACE4_READ_DATA,
		};
		assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

		assert_true(smbacl4_nfs42win(frame, &params, nfs4_acl,
					     &sids[0], &sids[1], true,
					     &dacl_aces, &good_aces));
		assert_non_null(dacl_aces);

		if (creator_owner_nfs4_to_dacl[i].nfs4_ace_flags &
		    SMB_ACE4_INHERIT_ONLY_ACE) {
			/*
			 * Only one ACE entry for the CREATOR ACE entry.
			 */
			assert_int_equal(good_aces, 1);
			creator_dacl_ace = &dacl_aces[0];
		} else {
			/*
			 * This creates an additional ACE entry for
			 * the permissions on the current object.
			 */
			assert_int_equal(good_aces, 2);

			assert_int_equal(dacl_aces[0].type,
					 SEC_ACE_TYPE_ACCESS_ALLOWED);
			assert_int_equal(dacl_aces[0].flags, 0);
			assert_int_equal(dacl_aces[0].access_mask,
					 SEC_FILE_READ_DATA);

			if (creator_owner_nfs4_to_dacl[i].special_id ==
			    SMB_ACE4_WHO_OWNER) {
				assert_true(dom_sid_equal(&dacl_aces[0].trustee,
							  &sids[0]));
			}

			if (creator_owner_nfs4_to_dacl[i].special_id ==
			    SMB_ACE4_WHO_GROUP) {
				assert_true(dom_sid_equal(&dacl_aces[0].trustee,
							  &sids[1]));
			}

			creator_dacl_ace = &dacl_aces[1];
		}

		assert_int_equal(creator_dacl_ace->type,
				 SEC_ACE_TYPE_ACCESS_ALLOWED);
		assert_int_equal(creator_dacl_ace->flags,
				 creator_owner_nfs4_to_dacl[i].dacl_ace_flags);
		assert_int_equal(creator_dacl_ace->access_mask,
				 SEC_FILE_READ_DATA);
		if (creator_owner_nfs4_to_dacl[i].special_id ==
		    SMB_ACE4_WHO_OWNER) {
			assert_true(dom_sid_equal(&creator_dacl_ace->trustee,
						  &global_sid_Creator_Owner));
		}

		if (creator_owner_nfs4_to_dacl[i].special_id ==
		    SMB_ACE4_WHO_GROUP) {
			assert_true(dom_sid_equal(&creator_dacl_ace->trustee,
						  &global_sid_Creator_Group));
		}
	}

	TALLOC_FREE(frame);
}

struct nfs4_to_dacl_map_full_control{
	bool is_dir;
	bool config;
	bool delete_child_added;
} nfs4_to_dacl_full_control[] = {
	{ true,	true,	false	},
	{ true,	false,	false	},
	{ false,	true,	true	},
	{ false,	false,	false	},
};

static void test_full_control_nfs4_to_dacl(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	int i;

	for (i = 0; i < ARRAY_SIZE(nfs4_to_dacl_full_control); i++) {
		struct SMB4ACL_T *nfs4_acl;
		SMB_ACE4PROP_T nfs4_ace;
		struct security_ace *dacl_aces;
		int good_aces;
		struct smbacl4_vfs_params params = {
			.mode = e_simple,
			.do_chown = true,
			.acedup = e_merge,
			.map_full_control = nfs4_to_dacl_full_control[i].config,
		};
		const uint32_t nfs4_ace_mask_except_deletes =
			SMB_ACE4_READ_DATA|SMB_ACE4_WRITE_DATA|
			SMB_ACE4_APPEND_DATA|SMB_ACE4_READ_NAMED_ATTRS|
			SMB_ACE4_WRITE_NAMED_ATTRS|SMB_ACE4_EXECUTE|
			SMB_ACE4_READ_ATTRIBUTES|SMB_ACE4_WRITE_ATTRIBUTES|
			SMB_ACE4_READ_ACL|SMB_ACE4_WRITE_ACL|
			SMB_ACE4_WRITE_OWNER|SMB_ACE4_SYNCHRONIZE;
		const uint32_t dacl_ace_mask_except_deletes =
			SEC_FILE_READ_DATA|SEC_FILE_WRITE_DATA|
			SEC_FILE_APPEND_DATA|SEC_FILE_READ_EA|
			SEC_FILE_WRITE_EA|SEC_FILE_EXECUTE|
			SEC_FILE_READ_ATTRIBUTE|SEC_FILE_WRITE_ATTRIBUTE|
			SEC_STD_READ_CONTROL|SEC_STD_WRITE_DAC|
			SEC_STD_WRITE_OWNER|SEC_STD_SYNCHRONIZE;

		nfs4_acl = smb_create_smb4acl(frame);
		assert_non_null(nfs4_acl);

		nfs4_ace = (SMB_ACE4PROP_T) {
			.flags		= 0,
			.who.uid	= 1000,
			.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
			.aceFlags	= 0,
			.aceMask	= nfs4_ace_mask_except_deletes,
		};
		assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

		assert_true(
			smbacl4_nfs42win(frame, &params, nfs4_acl,
					 &sids[0], &sids[1],
					 nfs4_to_dacl_full_control[i].is_dir,
					 &dacl_aces, &good_aces));

		assert_int_equal(good_aces, 1);
		assert_non_null(dacl_aces);

		assert_int_equal(dacl_aces[0].type,
				 SEC_ACE_TYPE_ACCESS_ALLOWED);
		assert_int_equal(dacl_aces[0].flags, 0);
		assert_true(dom_sid_equal(&dacl_aces[0].trustee, &sids[0]));
		if (nfs4_to_dacl_full_control[i].delete_child_added) {
			assert_int_equal(dacl_aces[0].access_mask,
					 dacl_ace_mask_except_deletes|
					 SEC_DIR_DELETE_CHILD);
		} else {
			assert_int_equal(dacl_aces[0].access_mask,
					 dacl_ace_mask_except_deletes);
		}
	}

	TALLOC_FREE(frame);
}

struct acedup_settings {
	enum smbacl4_acedup_enum setting;
} acedup_settings[] = {
	{ e_dontcare },
	{ e_reject },
	{ e_ignore },
	{ e_merge },
};

static void test_dacl_to_nfs4_acedup_settings(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	int i;

	for (i = 0; i < ARRAY_SIZE(acedup_settings); i++) {
		struct SMB4ACL_T *nfs4_acl;
		struct SMB4ACE_T *nfs4_ace_container;
		SMB_ACE4PROP_T *nfs4_ace;
		struct security_ace dacl_aces[2];
		struct security_acl *dacl;
		struct smbacl4_vfs_params params = {
			.mode = e_simple,
			.do_chown = true,
			.acedup = acedup_settings[i].setting,
			.map_full_control = true,
		};

		init_sec_ace(&dacl_aces[0], &sids[0],
			     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
			     SEC_ACE_FLAG_OBJECT_INHERIT);
		init_sec_ace(&dacl_aces[1], &sids[0],
			     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_WRITE_DATA,
			     SEC_ACE_FLAG_OBJECT_INHERIT);
		dacl = make_sec_acl(frame, SECURITY_ACL_REVISION_ADS,
				    ARRAY_SIZE(dacl_aces), dacl_aces);
		assert_non_null(dacl);

		nfs4_acl = smbacl4_win2nfs4(frame, true, dacl, &params,
					    101, 102);

		switch(params.acedup) {
		case e_dontcare:
			assert_non_null(nfs4_acl);
			assert_int_equal(smbacl4_get_controlflags(nfs4_acl),
					 SEC_DESC_SELF_RELATIVE);
			assert_int_equal(smb_get_naces(nfs4_acl), 2);

			nfs4_ace_container = smb_first_ace4(nfs4_acl);
			assert_non_null(nfs4_ace_container);

			nfs4_ace = smb_get_ace4(nfs4_ace_container);
			assert_int_equal(nfs4_ace->flags, 0);
			assert_int_equal(nfs4_ace->who.uid, 1000);
			assert_int_equal(nfs4_ace->aceFlags,
					 SMB_ACE4_FILE_INHERIT_ACE);
			assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

			nfs4_ace_container = smb_next_ace4(nfs4_ace_container);
			assert_non_null(nfs4_ace_container);
			assert_null(smb_next_ace4(nfs4_ace_container));

			nfs4_ace = smb_get_ace4(nfs4_ace_container);
			assert_int_equal(nfs4_ace->flags, 0);
			assert_int_equal(nfs4_ace->who.uid, 1000);
			assert_int_equal(nfs4_ace->aceFlags,
					 SMB_ACE4_FILE_INHERIT_ACE);
			assert_int_equal(nfs4_ace->aceMask,
					 SMB_ACE4_WRITE_DATA);
			break;

		case e_reject:
			assert_null(nfs4_acl);
			assert_int_equal(errno, EINVAL);
			break;

		case e_ignore:
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
			assert_int_equal(nfs4_ace->aceFlags,
					 SMB_ACE4_FILE_INHERIT_ACE);
			assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);
			break;

		case e_merge:
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
			assert_int_equal(nfs4_ace->aceFlags,
					 SMB_ACE4_FILE_INHERIT_ACE);
			assert_int_equal(nfs4_ace->aceMask,
					 SMB_ACE4_READ_DATA|
					 SMB_ACE4_WRITE_DATA);
			break;

		default:
			fail_msg("Unexpected value for acedup: %d\n",
				 params.acedup);
		};
	}

	TALLOC_FREE(frame);
}

struct acedup_match {
	int sid_idx1;
	enum security_ace_type type1;
	uint32_t ace_mask1;
	uint8_t flag1;
	int sid_idx2;
	enum security_ace_type type2;
	uint32_t ace_mask2;
	uint8_t flag2;
	bool match;
} acedup_match[] = {
	{ 0, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
	  SEC_ACE_FLAG_OBJECT_INHERIT,
	  0, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
	  SEC_ACE_FLAG_OBJECT_INHERIT,
	  true },
	{ 0, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
	  SEC_ACE_FLAG_OBJECT_INHERIT,
	  1, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
	  SEC_ACE_FLAG_OBJECT_INHERIT,
	  false },
	{ 0, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
	  SEC_ACE_FLAG_OBJECT_INHERIT,
	  0, SEC_ACE_TYPE_ACCESS_DENIED, SEC_FILE_READ_DATA,
	  SEC_ACE_FLAG_OBJECT_INHERIT,
	  false },
	{ 0, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
	  SEC_ACE_FLAG_OBJECT_INHERIT,
	  0, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_WRITE_DATA,
	  SEC_ACE_FLAG_OBJECT_INHERIT,
	  true },
	{ 0, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
	  SEC_ACE_FLAG_OBJECT_INHERIT,
	  0, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
	  SEC_ACE_FLAG_CONTAINER_INHERIT,
	  false },
	{ 0, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
	  SEC_ACE_FLAG_OBJECT_INHERIT,
	  5, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
	  SEC_ACE_FLAG_OBJECT_INHERIT,
	  false },
};

static void test_dacl_to_nfs4_acedup_match(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	int i;

	for (i = 0; i < ARRAY_SIZE(acedup_match); i++) {
		struct SMB4ACL_T *nfs4_acl;
		struct SMB4ACE_T *nfs4_ace_container;
		SMB_ACE4PROP_T *nfs4_ace;
		struct security_ace dacl_aces[2];
		struct security_acl *dacl;
		struct smbacl4_vfs_params params = {
			.mode = e_simple,
			.do_chown = true,
			.acedup = e_ignore,
			.map_full_control = true,
		};

		init_sec_ace(&dacl_aces[0],
			     &sids[acedup_match[i].sid_idx1],
			     acedup_match[i].type1,
			     acedup_match[i].ace_mask1,
			     acedup_match[i].flag1);
		init_sec_ace(&dacl_aces[1],
			     &sids[acedup_match[i].sid_idx2],
			     acedup_match[i].type2,
			     acedup_match[i].ace_mask2,
			     acedup_match[i].flag2);
		dacl = make_sec_acl(frame, SECURITY_ACL_REVISION_ADS,
				    ARRAY_SIZE(dacl_aces), dacl_aces);
		assert_non_null(dacl);

		nfs4_acl = smbacl4_win2nfs4(frame, true, dacl, &params,
					    101, 102);
		assert_non_null(nfs4_acl);
		assert_int_equal(smbacl4_get_controlflags(nfs4_acl),
				 SEC_DESC_SELF_RELATIVE);

		if (acedup_match[i].match) {
			assert_int_equal(smb_get_naces(nfs4_acl), 1);

			nfs4_ace_container = smb_first_ace4(nfs4_acl);
			assert_non_null(nfs4_ace_container);
			assert_null(smb_next_ace4(nfs4_ace_container));

			nfs4_ace = smb_get_ace4(nfs4_ace_container);
			assert_int_equal(nfs4_ace->flags, 0);
			assert_int_equal(nfs4_ace->who.uid, 1000);
			assert_int_equal(nfs4_ace->aceFlags,
					 SMB_ACE4_FILE_INHERIT_ACE);
			assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

		} else {
			assert_int_equal(smb_get_naces(nfs4_acl), 2);

			nfs4_ace_container = smb_first_ace4(nfs4_acl);
			assert_non_null(nfs4_ace_container);

			nfs4_ace = smb_get_ace4(nfs4_ace_container);
			assert_int_equal(nfs4_ace->flags, 0);
			assert_int_equal(nfs4_ace->who.uid, 1000);
			assert_int_equal(nfs4_ace->aceFlags,
					 SMB_ACE4_FILE_INHERIT_ACE);
			assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

			nfs4_ace_container = smb_next_ace4(nfs4_ace_container);
			assert_non_null(nfs4_ace_container);
			assert_null(smb_next_ace4(nfs4_ace_container));

			nfs4_ace = smb_get_ace4(nfs4_ace_container);
			assert_int_equal(nfs4_ace->flags, 0);
		}
	}

	TALLOC_FREE(frame);
}

static void test_dacl_to_nfs4_config_special(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	struct SMB4ACL_T *nfs4_acl;
	struct SMB4ACE_T *nfs4_ace_container;
	SMB_ACE4PROP_T *nfs4_ace;
	struct security_ace dacl_aces[6];
	struct security_acl *dacl;
	struct smbacl4_vfs_params params = {
		.mode = e_special,
		.do_chown = true,
		.acedup = e_dontcare,
		.map_full_control = true,
	};

	/*
	 * global_sid_Creator_Owner or global_sid_Special_Group is NOT mapped
	 * to SMB_ACE4_ID_SPECIAL.
	 */
	init_sec_ace(&dacl_aces[0], &global_sid_Creator_Owner,
		     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
		     SEC_ACE_FLAG_OBJECT_INHERIT);
	init_sec_ace(&dacl_aces[1], &global_sid_Creator_Group,
		     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_WRITE_DATA,
		     SEC_ACE_FLAG_CONTAINER_INHERIT);
	/*
	 * Anything that maps to owner or owning group with inheritance flags
	 * IS mapped to special owner or special group.
	 */
	init_sec_ace(&dacl_aces[2], &sids[0],
		     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
		     SEC_ACE_FLAG_OBJECT_INHERIT);
	init_sec_ace(&dacl_aces[3], &sids[0],
		     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
		     SEC_ACE_FLAG_CONTAINER_INHERIT|SEC_ACE_FLAG_INHERIT_ONLY);
	init_sec_ace(&dacl_aces[4], &sids[1],
		     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
		     SEC_ACE_FLAG_OBJECT_INHERIT);
	init_sec_ace(&dacl_aces[5], &sids[1],
		     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_READ_DATA,
		     SEC_ACE_FLAG_CONTAINER_INHERIT|SEC_ACE_FLAG_INHERIT_ONLY);
	dacl = make_sec_acl(frame, SECURITY_ACL_REVISION_ADS,
			    ARRAY_SIZE(dacl_aces), dacl_aces);
	assert_non_null(dacl);

	nfs4_acl = smbacl4_win2nfs4(frame, true, dacl, &params, 1000, 1001);

	assert_non_null(nfs4_acl);
	assert_int_equal(smbacl4_get_controlflags(nfs4_acl),
			 SEC_DESC_SELF_RELATIVE);
	assert_int_equal(smb_get_naces(nfs4_acl), 6);

	nfs4_ace_container = smb_first_ace4(nfs4_acl);
	assert_non_null(nfs4_ace_container);

	nfs4_ace = smb_get_ace4(nfs4_ace_container);
	assert_int_equal(nfs4_ace->flags, 0);
	assert_int_equal(nfs4_ace->aceFlags, SMB_ACE4_FILE_INHERIT_ACE);
	assert_int_equal(nfs4_ace->who.uid, 1003);
	assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

	nfs4_ace_container = smb_next_ace4(nfs4_ace_container);
	assert_non_null(nfs4_ace_container);

	nfs4_ace = smb_get_ace4(nfs4_ace_container);
	assert_int_equal(nfs4_ace->flags, 0);
	assert_int_equal(nfs4_ace->aceFlags,
			 SMB_ACE4_IDENTIFIER_GROUP|
			 SMB_ACE4_DIRECTORY_INHERIT_ACE);
	assert_int_equal(nfs4_ace->who.gid, 1004);
	assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_WRITE_DATA);

	nfs4_ace_container = smb_next_ace4(nfs4_ace_container);
	assert_non_null(nfs4_ace_container);

	nfs4_ace = smb_get_ace4(nfs4_ace_container);
	assert_int_equal(nfs4_ace->flags, SMB_ACE4_ID_SPECIAL);
	assert_int_equal(nfs4_ace->who.special_id, SMB_ACE4_WHO_OWNER);
	assert_int_equal(nfs4_ace->aceFlags, SMB_ACE4_FILE_INHERIT_ACE);
	assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

	nfs4_ace_container = smb_next_ace4(nfs4_ace_container);
	assert_non_null(nfs4_ace_container);

	nfs4_ace = smb_get_ace4(nfs4_ace_container);
	assert_int_equal(nfs4_ace->flags, SMB_ACE4_ID_SPECIAL);
	assert_int_equal(nfs4_ace->aceFlags, SMB_ACE4_DIRECTORY_INHERIT_ACE|
			 SMB_ACE4_INHERIT_ONLY_ACE);
	assert_int_equal(nfs4_ace->who.special_id, SMB_ACE4_WHO_OWNER);
	assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

	nfs4_ace_container = smb_next_ace4(nfs4_ace_container);
	assert_non_null(nfs4_ace_container);

	nfs4_ace = smb_get_ace4(nfs4_ace_container);
	assert_int_equal(nfs4_ace->flags, SMB_ACE4_ID_SPECIAL);
	assert_int_equal(nfs4_ace->aceFlags, SMB_ACE4_IDENTIFIER_GROUP|
			 SMB_ACE4_FILE_INHERIT_ACE);
	assert_int_equal(nfs4_ace->who.special_id, SMB_ACE4_WHO_GROUP);
	assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

	nfs4_ace_container = smb_next_ace4(nfs4_ace_container);
	assert_non_null(nfs4_ace_container);

	nfs4_ace = smb_get_ace4(nfs4_ace_container);
	assert_int_equal(nfs4_ace->flags, SMB_ACE4_ID_SPECIAL);
	assert_int_equal(nfs4_ace->aceFlags, SMB_ACE4_IDENTIFIER_GROUP|
			 SMB_ACE4_DIRECTORY_INHERIT_ACE|
			 SMB_ACE4_INHERIT_ONLY_ACE);
	assert_int_equal(nfs4_ace->who.special_id, SMB_ACE4_WHO_GROUP);
	assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

	assert_null(smb_next_ace4(nfs4_ace_container));

	TALLOC_FREE(frame);
}

static void test_nfs4_to_dacl_config_special(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	struct SMB4ACL_T *nfs4_acl;
	SMB_ACE4PROP_T nfs4_ace;
	struct security_ace *dacl_aces;
	int good_aces;
	struct smbacl4_vfs_params params = {
		.mode = e_special,
		.do_chown = true,
		.acedup = e_dontcare,
		.map_full_control = true,
	};

	nfs4_acl = smb_create_smb4acl(frame);
	assert_non_null(nfs4_acl);

	/*
	 * In config mode special, this is not mapped to Creator Owner
	 */
	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= SMB_ACE4_ID_SPECIAL,
		.who.special_id = SMB_ACE4_WHO_OWNER,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= SMB_ACE4_FILE_INHERIT_ACE,
		.aceMask	= SMB_ACE4_READ_DATA,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	/*
	 * In config mode special, this is not mapped to Creator Group
	 */
	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= SMB_ACE4_ID_SPECIAL,
		.who.special_id = SMB_ACE4_WHO_GROUP,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= SMB_ACE4_DIRECTORY_INHERIT_ACE,
		.aceMask	= SMB_ACE4_WRITE_DATA,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	assert_true(smbacl4_nfs42win(frame, &params, nfs4_acl,
				     &sids[0], &sids[1], true,
				     &dacl_aces, &good_aces));

	assert_int_equal(good_aces, 2);
	assert_non_null(dacl_aces);

	assert_int_equal(dacl_aces[0].type, SEC_ACE_TYPE_ACCESS_ALLOWED);
	assert_int_equal(dacl_aces[0].flags, SEC_ACE_FLAG_OBJECT_INHERIT);
	assert_int_equal(dacl_aces[0].access_mask, SEC_FILE_READ_DATA);
	assert_true(dom_sid_equal(&dacl_aces[0].trustee, &sids[0]));

	assert_int_equal(dacl_aces[1].type, SEC_ACE_TYPE_ACCESS_ALLOWED);
	assert_int_equal(dacl_aces[1].flags, SEC_ACE_FLAG_CONTAINER_INHERIT);
	assert_int_equal(dacl_aces[1].access_mask, SEC_FILE_WRITE_DATA);
	assert_true(dom_sid_equal(&dacl_aces[1].trustee, &sids[1]));

	TALLOC_FREE(frame);
}

struct nfs_to_dacl_idmap_both {
	uint32_t nfs4_flags;
	uint32_t nfs4_id;
	struct dom_sid *sid;
};

static void test_nfs4_to_dacl_idmap_type_both(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	int i;
	struct nfs_to_dacl_idmap_both nfs_to_dacl_idmap_both[] = {
		{ 0,				1002, &sids[2] },
		{ SMB_ACE4_IDENTIFIER_GROUP,	1002, &sids[2] },
		{ 0,				1005, &sids[6] },
		{ SMB_ACE4_IDENTIFIER_GROUP,	1005, &sids[6] },
	};

	for (i = 0; i < ARRAY_SIZE(nfs_to_dacl_idmap_both); i++) {
		struct SMB4ACL_T *nfs4_acl;
		struct security_ace *dacl_aces;
		SMB_ACE4PROP_T nfs4_ace;
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
			.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
			.aceFlags	= nfs_to_dacl_idmap_both[i].nfs4_flags,
			.aceMask	= SMB_ACE4_READ_DATA,
		};

		if (nfs_to_dacl_idmap_both[i].nfs4_flags &
		    SMB_ACE4_IDENTIFIER_GROUP) {
			nfs4_ace.who.gid = nfs_to_dacl_idmap_both[i].nfs4_id;
		} else {
			nfs4_ace.who.uid = nfs_to_dacl_idmap_both[i].nfs4_id;
		}
		assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

		assert_true(smbacl4_nfs42win(frame, &params, nfs4_acl,
					     &sids[2], &sids[2],
					     false, &dacl_aces, &good_aces));

		assert_int_equal(good_aces, 1);
		assert_non_null(dacl_aces);

		assert_int_equal(dacl_aces[0].type,
				 SEC_ACE_TYPE_ACCESS_ALLOWED);
		assert_int_equal(dacl_aces[0].flags, 0);
		assert_int_equal(dacl_aces[0].access_mask, SEC_FILE_READ_DATA);
		assert_true(dom_sid_equal(&dacl_aces[0].trustee,
					  nfs_to_dacl_idmap_both[i].sid));
	}

	TALLOC_FREE(frame);
}

struct dacl_to_nfs4_idmap_both {
	struct dom_sid *sid;
	uint32_t dacl_flags;
	uint32_t nfs4_flags;
	uint32_t nfs4_ace_flags;
	uint32_t nfs4_id;
	int num_nfs4_aces;
};

/*
 * IDMAP_TYPE_BOTH always creates group entries.
 */
static void test_dacl_to_nfs4_idmap_type_both(void **state)
{
	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	int i;

	struct dacl_to_nfs4_idmap_both dacl_to_nfs4_idmap_both[] = {
	{ &sids[2], 0,
	  SMB_ACE4_ID_SPECIAL, SMB_ACE4_IDENTIFIER_GROUP, SMB_ACE4_WHO_GROUP,
	  2 },
	{ &sids[2], SEC_ACE_FLAG_OBJECT_INHERIT,
	  0, SMB_ACE4_IDENTIFIER_GROUP|SMB_ACE4_FILE_INHERIT_ACE, 1002,
	  1 },
	{ &sids[6], 0,
	  0, SMB_ACE4_IDENTIFIER_GROUP, 1005,
	  1 },
	{ &sids[6], SEC_ACE_FLAG_OBJECT_INHERIT,
	  0, SMB_ACE4_IDENTIFIER_GROUP|SMB_ACE4_FILE_INHERIT_ACE, 1005,
	  1 },
	};

	for (i = 0; i < ARRAY_SIZE(dacl_to_nfs4_idmap_both); i++) {
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

		init_sec_ace(&dacl_aces[0], dacl_to_nfs4_idmap_both[i].sid,
			     SEC_ACE_TYPE_ACCESS_ALLOWED,
			     SEC_FILE_READ_DATA,
			     dacl_to_nfs4_idmap_both[i].dacl_flags);
		dacl = make_sec_acl(frame, SECURITY_ACL_REVISION_ADS,
				    ARRAY_SIZE(dacl_aces), dacl_aces);
		assert_non_null(dacl);

		nfs4_acl = smbacl4_win2nfs4(frame, true, dacl, &params,
					    1002, 1002);

		assert_non_null(nfs4_acl);
		assert_int_equal(smbacl4_get_controlflags(nfs4_acl),
				 SEC_DESC_SELF_RELATIVE);
		assert_int_equal(smb_get_naces(nfs4_acl),
				 dacl_to_nfs4_idmap_both[i].num_nfs4_aces);

		nfs4_ace_container = smb_first_ace4(nfs4_acl);
		assert_non_null(nfs4_ace_container);

		nfs4_ace = smb_get_ace4(nfs4_ace_container);
		assert_int_equal(nfs4_ace->flags,
				 dacl_to_nfs4_idmap_both[i].nfs4_flags);
		assert_int_equal(nfs4_ace->aceFlags,
				 dacl_to_nfs4_idmap_both[i].nfs4_ace_flags);
		if (nfs4_ace->flags & SMB_ACE4_ID_SPECIAL) {
			assert_int_equal(nfs4_ace->who.special_id,
					 dacl_to_nfs4_idmap_both[i].nfs4_id);
		} else if (nfs4_ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) {
			assert_int_equal(nfs4_ace->who.gid,
					 dacl_to_nfs4_idmap_both[i].nfs4_id);
		} else {
			assert_int_equal(nfs4_ace->who.uid,
					 dacl_to_nfs4_idmap_both[i].nfs4_id);
		}
		assert_int_equal(nfs4_ace->aceType,
				 SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE);
		assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);

		if (dacl_to_nfs4_idmap_both[i].num_nfs4_aces == 2) {
			nfs4_ace_container = smb_next_ace4(nfs4_ace_container);
			assert_non_null(nfs4_ace_container);

			nfs4_ace = smb_get_ace4(nfs4_ace_container);
			assert_int_equal(nfs4_ace->flags,
					 dacl_to_nfs4_idmap_both[i].nfs4_flags);
			assert_int_equal(nfs4_ace->aceFlags,
					 dacl_to_nfs4_idmap_both[i].nfs4_ace_flags &
					 ~SMB_ACE4_IDENTIFIER_GROUP);
			if (nfs4_ace->flags & SMB_ACE4_ID_SPECIAL) {
				assert_int_equal(nfs4_ace->who.special_id,
						 SMB_ACE4_WHO_OWNER);
			} else {
				assert_int_equal(nfs4_ace->who.uid,
						 dacl_to_nfs4_idmap_both[i].nfs4_id);
			}
			assert_int_equal(nfs4_ace->aceType,
					 SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE);
			assert_int_equal(nfs4_ace->aceMask, SMB_ACE4_READ_DATA);
		}
	}

	TALLOC_FREE(frame);
}

static void test_nfs4_to_dacl_remove_duplicate(void **state)
{

	struct dom_sid *sids = *state;
	TALLOC_CTX *frame = talloc_stackframe();
	struct SMB4ACL_T *nfs4_acl;
	SMB_ACE4PROP_T nfs4_ace;
	struct security_ace *dacl_aces;
	int good_aces;
	struct smbacl4_vfs_params params = {
		.mode = e_simple,
		.do_chown = true,
		.acedup = e_dontcare,
		.map_full_control = true,
	};

	nfs4_acl = smb_create_smb4acl(frame);
	assert_non_null(nfs4_acl);

	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= 0,
		.who.uid	= 1002,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= SMB_ACE4_INHERITED_ACE,
		.aceMask	= SMB_ACE4_WRITE_DATA,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= 0,
		.who.gid	= 1002,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= SMB_ACE4_IDENTIFIER_GROUP|
				  SMB_ACE4_INHERITED_ACE,
		.aceMask	= SMB_ACE4_WRITE_DATA,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= 0,
		.who.gid	= 1002,
		.aceType	= SMB_ACE4_ACCESS_DENIED_ACE_TYPE,
		.aceFlags	= SMB_ACE4_IDENTIFIER_GROUP|
				  SMB_ACE4_INHERITED_ACE,
		.aceMask	= SMB_ACE4_WRITE_DATA,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	nfs4_ace = (SMB_ACE4PROP_T) {
		.flags		= 0,
		.who.gid	= 1002,
		.aceType	= SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		.aceFlags	= SMB_ACE4_IDENTIFIER_GROUP|
				  SMB_ACE4_INHERITED_ACE,
		.aceMask	= SMB_ACE4_WRITE_DATA,
	};
	assert_non_null(smb_add_ace4(nfs4_acl, &nfs4_ace));

	assert_true(smbacl4_nfs42win(frame, &params, nfs4_acl,
				     &sids[0], &sids[1], true,
				     &dacl_aces, &good_aces));

	assert_int_equal(good_aces, 2);
	assert_non_null(dacl_aces);

	assert_int_equal(dacl_aces[0].type, SEC_ACE_TYPE_ACCESS_ALLOWED);
	assert_int_equal(dacl_aces[0].flags, SEC_ACE_FLAG_INHERITED_ACE);
	assert_int_equal(dacl_aces[0].access_mask, SEC_FILE_WRITE_DATA);
	assert_true(dom_sid_equal(&dacl_aces[0].trustee, &sids[2]));

	assert_int_equal(dacl_aces[1].type, SEC_ACE_TYPE_ACCESS_DENIED);
	assert_int_equal(dacl_aces[1].flags, SEC_ACE_FLAG_INHERITED_ACE);
	assert_int_equal(dacl_aces[1].access_mask, SEC_FILE_WRITE_DATA);
	assert_true(dom_sid_equal(&dacl_aces[1].trustee, &sids[2]));

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
		cmocka_unit_test(test_ace_flags_nfs4_to_dacl),
		cmocka_unit_test(test_ace_flags_dacl_to_nfs4),
		cmocka_unit_test(test_nfs4_permissions_to_dacl),
		cmocka_unit_test(test_dacl_permissions_to_nfs4),
		cmocka_unit_test(test_special_nfs4_to_dacl),
		cmocka_unit_test(test_dacl_to_special_nfs4),
		cmocka_unit_test(test_dacl_creator_to_nfs4),
		cmocka_unit_test(test_nfs4_to_dacl_creator),
		cmocka_unit_test(test_full_control_nfs4_to_dacl),
		cmocka_unit_test(test_dacl_to_nfs4_acedup_settings),
		cmocka_unit_test(test_dacl_to_nfs4_acedup_match),
		cmocka_unit_test(test_dacl_to_nfs4_config_special),
		cmocka_unit_test(test_nfs4_to_dacl_config_special),
		cmocka_unit_test(test_nfs4_to_dacl_idmap_type_both),
		cmocka_unit_test(test_dacl_to_nfs4_idmap_type_both),
		cmocka_unit_test(test_nfs4_to_dacl_remove_duplicate),
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
