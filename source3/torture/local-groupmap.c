/* 
   Unix SMB/CIFS implementation.
   Run some local tests for group mapping
   Copyright (C) Volker Lendecke 2006
   
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

#define CHECK_STATUS(_status, _expected) do { \
	if (!NT_STATUS_EQUAL(_status, _expected)) { \
		printf("(%d) Incorrect status %s - should be %s\n", \
		       __LINE__, nt_errstr(status), nt_errstr(_expected)); \
		goto fail; \
	}} while (0)

static NTSTATUS create_v2_mapping(struct tdb_context *tdb,
				  const char *sid, gid_t gid,
				  enum SID_NAME_USE type,
				  const char *nt_name,
				  const char *comment)
{
	TDB_DATA key, data;
	NTSTATUS status;

	ZERO_STRUCT(data);

	if (asprintf(&key.dptr, "UNIXGROUP/%s", sid) < 0) {
		d_fprintf(stderr, "(%s) asprintf failed\n",
			  __location__);
		return NT_STATUS_NO_MEMORY;
	}
	key.dsize = strlen(key.dptr)+1;
	
	if (!tdb_pack_append(NULL, &data.dptr, &data.dsize, "ddff",
			     (uint32)gid, (uint32)type, nt_name, comment)) {
		d_fprintf(stderr, "(%s) tdb_pack_append failed\n",
			  __location__);
		SAFE_FREE(key.dptr);
		return NT_STATUS_NO_MEMORY;
	}

	if (tdb_store(tdb, key, data, TDB_INSERT) < 0) {
		status = map_ntstatus_from_tdb(tdb);
		d_fprintf(stderr, "(%s) tdb_store failed: %s\n", __location__,
			  nt_errstr(status));
		SAFE_FREE(key.dptr);
		TALLOC_FREE(data.dptr);
		return status;
	}

	SAFE_FREE(key.dptr);
	TALLOC_FREE(data.dptr);
	return NT_STATUS_OK;
}

#define NUM_ENTRIES (50)

static NTSTATUS create_v2_db(BOOL invalid)
{
	struct tdb_context *tdb;
	NTSTATUS status;
	int i;

	tdb = tdb_open_log(lock_path("group_mapping.tdb"), 0, TDB_DEFAULT,
			   O_RDWR|O_CREAT, 0600);
	if (tdb == NULL) {
		d_fprintf(stderr, "(%s) tdb_open_log failed: %s\n",
			  __location__, strerror(errno));
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	/* Empty the database */
	tdb_traverse(tdb, tdb_traverse_delete_fn, NULL);

	if (tdb_store_int32(tdb, "INFO/version", 2) < 0) {
		status = map_ntstatus_from_tdb(tdb);
		d_fprintf(stderr, "(%s) tdb_store_uint32 failed: %s\n",
			  __location__, nt_errstr(status));
		goto fail;
	}

	for (i=1000; i<1000+NUM_ENTRIES; i++) {
		char *sid, *name;
		if (asprintf(&sid, "S-1-5-21-744032650-3806004166-77016029-%d",
			     i) < 0) {
			d_fprintf(stderr, "(%s) asprintf failed\n",
				  __location__);
			goto fail;
		}
		if (asprintf(&name, "Unix group %d", i) < 0) {
			d_fprintf(stderr, "(%s) asprintf failed\n",
				  __location__);
			SAFE_FREE(sid);
			goto fail;
		}
		status = create_v2_mapping(tdb, sid, (gid_t)i,
					   SID_NAME_DOM_GRP, name, name);
		SAFE_FREE(sid);
		SAFE_FREE(name);
		CHECK_STATUS(status, NT_STATUS_OK);
	}
	status = create_v2_mapping(tdb, "S-1-5-32-544", 10000,
				   SID_NAME_ALIAS, "Administrators",
				   "Machine Admins");
	CHECK_STATUS(status, NT_STATUS_OK);
	status = create_v2_mapping(tdb, "S-1-5-32-545", 10001,
				   SID_NAME_ALIAS, "Users", "Machine Users");
	CHECK_STATUS(status, NT_STATUS_OK);

	if (invalid) {
		/* Map 10001 to two different SIDs */
		status = create_v2_mapping(tdb, "S-1-5-32-999", 10001,
					   SID_NAME_ALIAS, "Overlapping",
					   "Invalid mapping");
		CHECK_STATUS(status, NT_STATUS_OK);
	}

	status = create_v2_mapping(tdb, "S-1-5-32-546", -1,
				   SID_NAME_ALIAS, "notthere", "To remove");
	CHECK_STATUS(status, NT_STATUS_OK);

	status = NT_STATUS_OK;
 fail:
	if (tdb != NULL) {
		tdb_close(tdb);
	}
	return status;
}

static BOOL groupmap_diff(const GROUP_MAP *m1, const GROUP_MAP *m2)
{
	return ((sid_compare(&m1->sid, &m2->sid) != 0) ||
		(m1->gid != m2->gid) ||
		(m1->sid_name_use != m2->sid_name_use) ||
		(strcmp(m1->nt_name, m2->nt_name) != 0) ||
		(strcmp(m1->comment, m2->comment) != 0));
}

#undef GROUPDB_V3

BOOL run_local_groupmap(int dummy)
{
	TALLOC_CTX *mem_ctx;
	BOOL ret = False;
	NTSTATUS status;
	GROUP_MAP *maps = NULL;
	size_t num_maps = 0;

	mem_ctx = talloc_init("run_local_groupmap");
	if (mem_ctx == NULL) {
		d_fprintf(stderr, "(%s) talloc_init failed\n",
			  __location__);
		return False;
	}

#ifdef GROUPDB_V3
	status = create_v2_db(True);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	{
		GROUP_MAP map;
		if (pdb_getgrgid(&map, 10001)) {
			d_fprintf(stderr, "(%s) upgrading an invalid group db "
				  "worked\n", __location__);
			goto fail;
		}
	}
#endif

	status = create_v2_db(False);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* This tests upgrading the database, as well as listing */

	if (!NT_STATUS_IS_OK(pdb_enum_group_mapping(NULL, SID_NAME_UNKNOWN,
						    &maps, &num_maps,
						    False))) {
		d_fprintf(stderr, "(%s) pdb_enum_group_mapping failed\n",
			  __location__);
		goto fail;
	}

	if (num_maps != NUM_ENTRIES+2) {
		d_fprintf(stderr, "(%s) expected %d entries, got %d\n",
			  __location__, NUM_ENTRIES+2, num_maps);
		goto fail;
	}

	/* See if getgrsid, getgrgid and getgrnam find the same entry */

	{
		DOM_SID sid;
		GROUP_MAP map, map1;
		string_to_sid(&sid, "S-1-5-32-545");

		ZERO_STRUCT(map);
		status = pdb_getgrsid(&map, &sid);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, "(%s) pdb_getgrsid failed: %s\n",
				  __location__, nt_errstr(status));
			goto fail;
		}

		ZERO_STRUCT(map1);
		status = pdb_getgrgid(&map1, map.gid);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, "(%s) pdb_getgrgid failed: %s\n",
				  __location__, nt_errstr(status));
			goto fail;
		}

		if (groupmap_diff(&map1, &map)) {
			d_fprintf(stderr, "(%s) getgrsid/getgrgid disagree\n",
				  __location__);
			goto fail;
		}
			
		ZERO_STRUCT(map1);
		status = pdb_getgrnam(&map1, map.nt_name);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, "(%s) pdb_getgrnam failed: %s\n",
				  __location__, nt_errstr(status));
			goto fail;
		}

		if (groupmap_diff(&map1, &map)) {
			d_fprintf(stderr, "(%s) getgrsid/getgrnam disagree\n",
				  __location__);
			goto fail;
		}
	}

	/* See if pdb_delete_group_mapping_entry works */

	{
		DOM_SID sid;
		GROUP_MAP map, map1;
		string_to_sid(&sid, "S-1-5-32-545");

		status = pdb_getgrsid(&map, &sid);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, "(%s) did not find S-1-5-32-545: "
				  "%s\n", __location__, nt_errstr(status));
			goto fail;
		}

		status = pdb_delete_group_mapping_entry(sid);
		CHECK_STATUS(status, NT_STATUS_OK);
		status = pdb_delete_group_mapping_entry(sid);
#ifdef GROUPDB_V3
		CHECK_STATUS(status, NT_STATUS_NOT_FOUND);
#else
		CHECK_STATUS(status, NT_STATUS_UNSUCCESSFUL);
#endif

		if (NT_STATUS_IS_OK(pdb_getgrsid(&map1, &sid))) {
			d_fprintf(stderr, "(%s) getgrsid found deleted "
				  "entry\n", __location__);
			goto fail;
		}

		if (NT_STATUS_IS_OK(pdb_getgrgid(&map1, map.gid))) {
			d_fprintf(stderr, "(%s) getgrgid found deleted "
				  "entry\n", __location__);
			goto fail;
		}

		if (NT_STATUS_IS_OK(pdb_getgrnam(&map1, map.nt_name))) {
			d_fprintf(stderr, "(%s) getgrnam found deleted "
				  "entry\n", __location__);
			goto fail;
		}
		
	}

	/* See if pdb_update_group_mapping_entry works */

	{
		DOM_SID sid;
		gid_t oldgid;
		GROUP_MAP map, map1;
		string_to_sid(&sid, "S-1-5-32-544");

		status = pdb_getgrsid(&map, &sid);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, "(%s) did not find S-1-5-32-544: "
				  "%s\n", __location__, nt_errstr(status));
			goto fail;
		}

		oldgid = map.gid;
		map.gid = 4711;

		status = pdb_update_group_mapping_entry(&map);
		CHECK_STATUS(status, NT_STATUS_OK);

		if (NT_STATUS_IS_OK(pdb_getgrgid(&map1, oldgid))) {
			d_fprintf(stderr, "(%s) getgrgid found outdated "
				  "entry\n", __location__);
			goto fail;
		}

		/* Change to an existing entry, see "create_db_v2" */

		map.gid = 1000;
		status = pdb_update_group_mapping_entry(&map);
#ifdef GROUPDB_V3
		CHECK_STATUS(status, NT_STATUS_OBJECTID_EXISTS);
		if (!pdb_getgrgid(&map1, 4711)) {
			d_fprintf(stderr, "(%s) update_group changed entry "
				  "upon failure\n", __location__);
			goto fail;
		}
#else
		CHECK_STATUS(status, NT_STATUS_OK);
#endif
	}

	ret = True;
 fail:
	if (maps != NULL) {
		SAFE_FREE(maps);
	}
	TALLOC_FREE(mem_ctx);
	return ret;
}

