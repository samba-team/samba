/*
   Unix SMB/CIFS implementation.
   IDMAP TDB common code tester

   Copyright (C) Christian Ambach 2012

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

#include "includes.h"
#include "system/filesys.h"
#include "torture/proto.h"
#include "idmap.h"
#include "winbindd/idmap_rw.h"
#include "winbindd/idmap_tdb_common.h"
#include "winbindd/winbindd.h"
#include "winbindd/winbindd_proto.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../libcli/security/dom_sid.h"

#define HWM_GROUP  "GROUP HWM"
#define HWM_USER   "USER HWM"

#define LOW_ID 100
#define HIGH_ID 199

#define DOM_SID1 "S-1-5-21-1234-5678-9012"
#define DOM_SID2 "S-1-5-21-0123-5678-9012"
#define DOM_SID3 "S-1-5-21-0012-5678-9012"
#define DOM_SID4 "S-1-5-21-0001-5678-9012"
#define DOM_SID5 "S-1-5-21-2345-5678-9012"
#define DOM_SID6 "S-1-5-21-3456-5678-9012"

/* overwrite some winbind internal functions */
struct winbindd_domain *find_domain_from_name(const char *domain_name)
{
	return NULL;
}

bool get_global_winbindd_state_offline(void) {
	return false;
}

bool winbindd_use_idmap_cache(void) {
	return false;
}

bool idmap_is_online(void)
{
	return true;
}

NTSTATUS idmap_backends_unixid_to_sid(const char *domname, struct id_map *id)
{
	return NT_STATUS_OK;
}

static bool open_db(struct idmap_tdb_common_context *ctx)
{
	NTSTATUS status;
	char *db_path;

	if(ctx->db) {
		/* already open */
		return true;
	}

	db_path = talloc_asprintf(talloc_tos(), "%s/idmap_test.tdb",
				  lp_private_dir());
	if(!db_path) {
		DEBUG(0, ("Out of memory!\n"));
		return false;
	}

	ctx->db = db_open(ctx, db_path, 0, TDB_DEFAULT,
			  O_RDWR | O_CREAT, 0600,
			  DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);

	if(!ctx->db) {
		DEBUG(0, ("Failed to open database: %s\n", strerror(errno)));
		return false;
	}

	if(dbwrap_transaction_start(ctx->db) != 0) {
		DEBUG(0, ("Failed to start transaction!\n"));
		return false;
	}

	status = dbwrap_store_uint32_bystring(ctx->db, ctx->hwmkey_uid,
					      LOW_ID);
	if(!NT_STATUS_IS_OK(status)) {
		dbwrap_transaction_cancel(ctx->db);
		return false;
	}

	status = dbwrap_store_uint32_bystring(ctx->db, ctx->hwmkey_gid,
					      LOW_ID);
	if(!NT_STATUS_IS_OK(status)) {
		dbwrap_transaction_cancel(ctx->db);
		return false;
	}

	if(dbwrap_transaction_commit(ctx->db) != 0) {
		DEBUG(0, ("Failed to commit transaction!\n"));
		return false;
	}

	return true;
}

static struct idmap_tdb_common_context *createcontext(TALLOC_CTX *memctx)
{
	struct idmap_tdb_common_context *ret;

	ret = talloc_zero(memctx, struct idmap_tdb_common_context);
	ret->rw_ops = talloc_zero(ret, struct idmap_rw_ops);

	ret->max_id = HIGH_ID;
	ret->hwmkey_uid = HWM_USER;
	ret->hwmkey_gid = HWM_GROUP;

	ret->rw_ops->get_new_id = idmap_tdb_common_get_new_id;
	ret->rw_ops->set_mapping = idmap_tdb_common_set_mapping;

	if (!open_db(ret)) {
		return NULL;
	};

	return ret;
}

static struct idmap_domain *createdomain(TALLOC_CTX *memctx)
{
	struct idmap_domain *dom;

	dom = talloc_zero(memctx, struct idmap_domain);
	dom->name = "*";
	dom->low_id = LOW_ID;
	dom->high_id = HIGH_ID;
	dom->read_only = false;
	dom->methods = talloc_zero(dom, struct idmap_methods);
	dom->methods->sids_to_unixids = idmap_tdb_common_sids_to_unixids;
	dom->methods->unixids_to_sids = idmap_tdb_common_unixids_to_sids;
	dom->methods->allocate_id = idmap_tdb_common_get_new_id;

	return dom;
}

static bool test_getnewid1(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status;
	struct unixid id;

	id.type = ID_TYPE_UID;

	status = idmap_tdb_common_get_new_id(dom, &id);

	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_getnewid1: Could not allocate id!\n"));
		return false;
	}

	if(id.id == 0) {
		DEBUG(0, ("test_getnewid1: Allocate returned "
			  "empty id!\n"));
		return false;
	}

	if(id.id > HIGH_ID || id.id < LOW_ID) {
		DEBUG(0, ("test_getnewid1: Allocate returned "
			  "out of range id!\n"));
		return false;
	}

	DEBUG(0, ("test_getnewid1: PASSED!\n"));

	return true;
}

static bool test_getnewid2(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status;
	struct unixid id;
	int i, left;

	id.type = ID_TYPE_UID;

	status = idmap_tdb_common_get_new_id(dom, &id);

	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_getnewid2: Could not allocate id!\n"));
		return false;
	}

	if(id.id == 0) {
		DEBUG(0, ("test_getnewid2: Allocate returned "
			  "empty id!\n"));
		return false;
	}

	if(id.id > HIGH_ID || id.id < LOW_ID) {
		DEBUG(0, ("test_getnewid2: Allocate returned "
			  "out of range id!\n"));
		return false;
	}

	/* how many ids are left? */

	left = HIGH_ID - id.id;

	/* consume them all */
	for(i = 0; i<left; i++) {

		status = idmap_tdb_common_get_new_id(dom, &id);

		if(!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("test_getnewid2: Allocate returned "
				  "error %s\n", nt_errstr(status)));
			return false;
		}

		if(id.id > HIGH_ID) {
			DEBUG(0, ("test_getnewid2: Allocate returned "
				  "out of range id (%d)!\n", id.id));
			return false;
		}
	}

	/* one more must fail */
	status = idmap_tdb_common_get_new_id(dom, &id);

	if(NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_getnewid2: Could allocate id (%d) from "
			  "depleted pool!\n", id.id));
		return false;
	}

	DEBUG(0, ("test_getnewid2: PASSED!\n"));

	return true;
}

static bool test_setmap1(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status;
	struct id_map map;

	ZERO_STRUCT(map);

	/* test for correct return code with invalid data */

	status = idmap_tdb_common_set_mapping(dom, NULL);
	if(!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		DEBUG(0, ("test_setmap1: bad parameter handling!\n"));
		return false;
	}

	status = idmap_tdb_common_set_mapping(dom, &map);
	if(!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		DEBUG(0, ("test_setmap1: bad parameter handling!\n"));
		return false;
	}

	map.sid = dom_sid_parse_talloc(memctx, DOM_SID1 "-100");

	map.xid.type = ID_TYPE_NOT_SPECIFIED;
	map.xid.id = 4711;

	status = idmap_tdb_common_set_mapping(dom, &map);
	if(!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		DEBUG(0, ("test_setmap1: bad parameter handling!\n"));
		return false;
	}

	/* now the good ones */
	map.xid.type = ID_TYPE_UID;
	map.xid.id = 0;

	status = idmap_tdb_common_get_new_id(dom, &(map.xid));
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_setmap1: get_new_uid failed!\n"));
		return false;
	}

	status = idmap_tdb_common_set_mapping(dom, &map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_setmap1: setting UID mapping failed!\n"));
		return false;
	}

	/* try to set the same mapping again as group (must fail) */

	map.xid.type = ID_TYPE_GID;
	status = idmap_tdb_common_set_mapping(dom, &map);
	if(NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_setmap1: could create map for "
			  "group and user!\n"));
		return false;
	}

	/* now a group with a different SID*/
	map.xid.id = 0;

	map.sid = dom_sid_parse_talloc(memctx, DOM_SID1 "-101");

	status = idmap_tdb_common_get_new_id(dom, &(map.xid));
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_setmap1: get_new_gid failed!\n"));
		return false;
	}

	status = idmap_tdb_common_set_mapping(dom, &map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_setmap1: setting GID mapping failed!\n"));
		return false;
	}
	DEBUG(0, ("test_setmap1: PASSED!\n"));

	return true;
}

static bool test_sid2unixid1(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status1, status2, status3;
	struct id_map map;

	/* check for correct dealing with bad parameters */
	status1 = idmap_tdb_common_sid_to_unixid(NULL, &map);
	status2 = idmap_tdb_common_sid_to_unixid(dom, NULL);
	status3 = idmap_tdb_common_sid_to_unixid(NULL, NULL);

	if(!NT_STATUS_EQUAL(NT_STATUS_INVALID_PARAMETER, status1) ||
	    !NT_STATUS_EQUAL(NT_STATUS_INVALID_PARAMETER, status2) ||
	    !NT_STATUS_EQUAL(NT_STATUS_INVALID_PARAMETER, status3)) {
		DEBUG(0, ("test_setmap1: bad parameter handling!\n"));
		return false;
	}

	DEBUG(0, ("test_unixid2sid1: PASSED!\n"));

	return true;
}

static bool test_sid2unixid2(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status;
	struct id_map uid_map, gid_map, test_map;
	bool doagain = true;

	ZERO_STRUCT(uid_map);
	ZERO_STRUCT(gid_map);

	/* create two mappings for a UID and GID */

again:

	uid_map.sid = dom_sid_parse_talloc(memctx, DOM_SID2 "-1000");
	uid_map.xid.type = ID_TYPE_UID;

	gid_map.sid = dom_sid_parse_talloc(memctx, DOM_SID2 "-1001");
	gid_map.xid.type = ID_TYPE_GID;

	status = idmap_tdb_common_new_mapping(dom, &uid_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_sid2unixid1: could not create uid map!\n"));
		return false;
	}

	status = idmap_tdb_common_new_mapping(dom, &gid_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_sid2unixid1: could not create gid map!\n"));
		return false;
	}

	/* now read them back */
	ZERO_STRUCT(test_map);
	test_map.sid = uid_map.sid;

	status = idmap_tdb_common_sid_to_unixid(dom, &test_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_sid2unixid1: sid2unixid failed for uid!\n"));
		return false;
	}

	if(test_map.xid.id!=uid_map.xid.id) {
		DEBUG(0, ("test_sid2unixid1: sid2unixid returned wrong uid!\n"));
		return false;
	}

	test_map.sid = gid_map.sid;

	status = idmap_tdb_common_sid_to_unixid(dom, &test_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_sid2unixid1: sid2unixid failed for gid!\n"));
		return false;
	}

	if(test_map.xid.id!=gid_map.xid.id) {
		DEBUG(0, ("test_sid2unixid1: sid2unixid returned wrong gid!\n"));
		return false;
	}

	/*
	 * Go through the same tests again once to see if trying to recreate
	 * a mapping that was already created will work or not
	 */
	if(doagain) {
		doagain = false;
		goto again;
	}

	DEBUG(0, ("test_sid2unixid1: PASSED!\n"));

	return true;
}

static bool test_sids2unixids1(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status;
	struct id_map uid_map, gid_map, **test_maps;

	ZERO_STRUCT(uid_map);
	ZERO_STRUCT(gid_map);

	/* create two mappings for a UID and GID */

	uid_map.sid = dom_sid_parse_talloc(memctx, DOM_SID4 "-1000");
	uid_map.xid.type = ID_TYPE_UID;

	gid_map.sid = dom_sid_parse_talloc(memctx, DOM_SID4 "-1001");
	gid_map.xid.type = ID_TYPE_GID;

	status = idmap_tdb_common_new_mapping(dom, &uid_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_sids2unixids1: could not create uid map!\n"));
		return false;
	}

	status = idmap_tdb_common_new_mapping(dom, &gid_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_sids2unixids1: could not create gid map!\n"));
		return false;
	}

	/* now read them back  */
	test_maps = talloc_zero_array(memctx, struct id_map*, 3);

	test_maps[0] = talloc(test_maps, struct id_map);
	test_maps[1] = talloc(test_maps, struct id_map);
	test_maps[2] = NULL;

	test_maps[0]->sid = talloc(test_maps, struct dom_sid);
	test_maps[1]->sid = talloc(test_maps, struct dom_sid);
	sid_copy(test_maps[0]->sid, uid_map.sid);
	sid_copy(test_maps[1]->sid, gid_map.sid);

	status = idmap_tdb_common_sids_to_unixids(dom, test_maps);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_sids2sunixids1: sids2unixids failed!\n"));
		talloc_free(test_maps);
		return false;
	}

	if(test_maps[0]->xid.id!=uid_map.xid.id ||
	    test_maps[1]->xid.id!=gid_map.xid.id ) {
		DEBUG(0, ("test_sids2unixids1: sid2unixid returned wrong xid!\n"));
		talloc_free(test_maps);
		return false;
	}

	DEBUG(0, ("test_sids2unixids1: PASSED!\n"));

	talloc_free(test_maps);

	return true;
}

static bool test_sids2unixids2(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status;
	struct id_map **test_maps;
	struct unixid save;

	test_maps = talloc_zero_array(memctx, struct id_map*, 3);

	test_maps[0] = talloc(test_maps, struct id_map);
	test_maps[1] = talloc(test_maps, struct id_map);
	test_maps[2] = NULL;

	/* ask for two new mappings for a UID and GID */
	test_maps[0]->sid = dom_sid_parse_talloc(test_maps, DOM_SID4 "-1003");
	test_maps[0]->xid.type = ID_TYPE_UID;
	test_maps[1]->sid = dom_sid_parse_talloc(test_maps, DOM_SID4 "-1004");
	test_maps[1]->xid.type = ID_TYPE_GID;

	status = idmap_tdb_common_sids_to_unixids(dom, test_maps);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_sids2sunixids2: sids2unixids "
			  "failed (%s)!\n", nt_errstr(status)));
		talloc_free(test_maps);
		return false;
	}

	if(test_maps[0]->xid.id == 0 || test_maps[1]->xid.id == 0) {
		DEBUG(0, ("test_sids2sunixids2: sids2unixids "
			  "returned zero ids!\n"));
		talloc_free(test_maps);
		return false;
	}

	save = test_maps[1]->xid;

	/* ask for a known and a new mapping at the same time */
	talloc_free(test_maps);
	test_maps = talloc_zero_array(memctx, struct id_map*, 3);
	test_maps[0] = talloc(test_maps, struct id_map);
	test_maps[1] = talloc(test_maps, struct id_map);
	test_maps[2] = NULL;

	test_maps[0]->sid = dom_sid_parse_talloc(test_maps, DOM_SID4 "-1004");
	test_maps[0]->xid.type = ID_TYPE_GID;
	test_maps[1]->sid = dom_sid_parse_talloc(test_maps, DOM_SID4 "-1005");
	test_maps[1]->xid.type = ID_TYPE_UID;

	status = idmap_tdb_common_sids_to_unixids(dom, test_maps);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_sids2sunixids2: sids2unixids (2) "
			  "failed (%s)!\n", nt_errstr(status)));
		talloc_free(test_maps);
		return false;
	}

	if(test_maps[0]->xid.type != save.type ||
	    test_maps[0]->xid.id != save.id) {
		DEBUG(0, ("test_sids2sunixids2: second lookup returned "
			  "different value!\n"));
		talloc_free(test_maps);
		return false;
	}

	if(test_maps[1]->xid.id == 0) {
		DEBUG(0, ("test_sids2sunixids2: sids2unixids "
			  "returned zero id for mixed mapping request!\n"));
		talloc_free(test_maps);
		return false;
	}

	DEBUG(0, ("test_sids2unixids2: PASSED!\n"));

	talloc_free(test_maps);

	return true;
}

static bool test_sids2unixids3(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status;
	struct id_map **test_maps;
	bool retval = true;

	/*
	 * check the mapping states:
	 * NONE_MAPPED, SOME_UNMAPPED, OK (all mapped)
	 *
	 * use the ids created by test_sids2unixids1
	 * need to make dom read-only
	 */

	dom->read_only = true;

	test_maps = talloc_zero_array(memctx, struct id_map*, 3);

	test_maps[0] = talloc(test_maps, struct id_map);
	test_maps[1] = talloc(test_maps, struct id_map);
	test_maps[2] = NULL;

	/* NONE_MAPPED first */
	test_maps[0]->sid = talloc(test_maps, struct dom_sid);
	test_maps[1]->sid = talloc(test_maps, struct dom_sid);
	test_maps[0]->sid = dom_sid_parse_talloc(test_maps,
						 "S-1-5-21-1-2-3-4");
	test_maps[0]->xid.type = ID_TYPE_UID;

	test_maps[1]->sid = dom_sid_parse_talloc(test_maps,
						 "S-1-5-21-1-2-3-5");
	test_maps[1]->xid.type = ID_TYPE_GID;

	status = idmap_tdb_common_sids_to_unixids(dom, test_maps);
	if(!NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		DEBUG(0, ("test_sids2unixids3: incorrect status "
			  "(%s), expected NT_STATUS_NONE_MAPPED!\n",
			   nt_errstr(status)));
		retval = false;
		goto out;
	}

	/* SOME_UNMAPPED */
	test_maps[0]->sid = talloc(test_maps, struct dom_sid);
	test_maps[1]->sid = talloc(test_maps, struct dom_sid);
	test_maps[0]->sid = dom_sid_parse_talloc(test_maps,
						 DOM_SID4 "-1000");
	test_maps[0]->xid.type = ID_TYPE_UID;
	test_maps[1]->sid = dom_sid_parse_talloc(test_maps,
						 "S-1-5-21-1-2-3-5");
	test_maps[1]->xid.type = ID_TYPE_GID;

	status = idmap_tdb_common_sids_to_unixids(dom, test_maps);
	if(!NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		DEBUG(0, ("test_sids2unixids3: incorrect status "
			  "(%s), expected STATUS_SOME_UNMAPPED!\n",
			   nt_errstr(status)));
		retval = false;
		goto out;
	}

	/* OK */
	test_maps[0]->sid = talloc(test_maps, struct dom_sid);
	test_maps[1]->sid = talloc(test_maps, struct dom_sid);
	test_maps[0]->sid = dom_sid_parse_talloc(test_maps,
						 DOM_SID4 "-1001");
	test_maps[1]->sid = dom_sid_parse_talloc(test_maps,
						 DOM_SID4 "-1000");

	status = idmap_tdb_common_sids_to_unixids(dom, test_maps);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_sids2unixids3: incorrect status "
			  "(%s), expected NT_STATUS_OK!\n",
			   nt_errstr(status)));
		retval = false;
		goto out;
	}

	DEBUG(0, ("test_sids2unixids3: PASSED!\n"));

out:
	talloc_free(test_maps);
	dom->read_only = false;
	return retval;
}

static bool test_unixid2sid1(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status1, status2, status3;
	struct id_map map;

	/* check for correct dealing with bad parameters */
	status1 = idmap_tdb_common_unixid_to_sid(NULL, &map);
	status2 = idmap_tdb_common_unixid_to_sid(dom, NULL);
	status3 = idmap_tdb_common_unixid_to_sid(NULL, NULL);

	if(!NT_STATUS_EQUAL(NT_STATUS_INVALID_PARAMETER, status1) ||
	    !NT_STATUS_EQUAL(NT_STATUS_INVALID_PARAMETER, status2) ||
	    !NT_STATUS_EQUAL(NT_STATUS_INVALID_PARAMETER, status3)) {
		DEBUG(0, ("test_setmap1: bad parameter handling!\n"));
		return false;
	}

	DEBUG(0, ("test_unixid2sid1: PASSED!\n"));

	return true;
}

static bool test_unixid2sid2(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status;
	struct id_map *map;
	bool retval = true;

	/* ask for mapping that is outside of the range */
	map = talloc(memctx, struct id_map);
	map->sid = talloc(map, struct dom_sid);

	map->xid.type = ID_TYPE_UID;
	map->xid.id = HIGH_ID + 1;

	status = idmap_tdb_common_unixid_to_sid(dom, map);
	if(NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_unixid2sid2: unixid2sid returned "
			  "out-of-range result\n"));
		retval = false;
		goto out;
	}

	DEBUG(0, ("test_unixid2sid2: PASSED!\n"));
out:
	talloc_free(map);
	return retval;

}

static bool test_unixid2sid3(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status;
	struct id_map uid_map, gid_map, test_map;
	struct dom_sid testsid;

	ZERO_STRUCT(uid_map);
	ZERO_STRUCT(gid_map);

	/* create two mappings for a UID and GID */
	uid_map.sid = dom_sid_parse_talloc(memctx, DOM_SID3 "-1000");
	uid_map.xid.type = ID_TYPE_UID;

	gid_map.sid = dom_sid_parse_talloc(memctx, DOM_SID3 "-1001");
	gid_map.xid.type = ID_TYPE_GID;

	status = idmap_tdb_common_new_mapping(dom, &uid_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_unixid2sid3: could not create uid map!\n"));
		return false;
	}

	status = idmap_tdb_common_new_mapping(dom, &gid_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_unixid2sid3: could not create gid map!\n"));
		return false;
	}

	/* now read them back */
	ZERO_STRUCT(test_map);
	test_map.xid.id = uid_map.xid.id;
	test_map.xid.type = ID_TYPE_UID;
	test_map.sid = &testsid;

	status = idmap_tdb_common_unixid_to_sid(dom, &test_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_unixid2sid3: unixid2sid failed for uid!\n"));
		return false;
	}

	if(test_map.xid.type!=uid_map.xid.type) {
		DEBUG(0, ("test_unixid2sid3: unixid2sid returned wrong type!\n"));
		return false;
	}

	if(!dom_sid_equal(test_map.sid, uid_map.sid)) {
		DEBUG(0, ("test_unixid2sid3: unixid2sid returned wrong SID!\n"));
		return false;
	}

	ZERO_STRUCT(test_map);
	test_map.xid.id = gid_map.xid.id;
	test_map.xid.type = ID_TYPE_GID;
	test_map.sid = &testsid;

	status = idmap_tdb_common_unixid_to_sid(dom, &test_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_unixid2sid3: unixid2sid failed for gid!\n"));
		return false;
	}

	if(test_map.xid.type!=gid_map.xid.type) {
		DEBUG(0, ("test_unixid2sid3: unixid2sid returned wrong type!\n"));
		return false;
	}

	if(!dom_sid_equal(test_map.sid,gid_map.sid)) {
		DEBUG(0, ("test_unixid2sid3: unixid2sid returned wrong SID!\n"));
		return false;
	}

	DEBUG(0, ("test_unixid2sid3: PASSED!\n"));

	return true;
}

static bool test_unixids2sids1(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status;
	struct id_map uid_map, gid_map, **test_maps;

	ZERO_STRUCT(uid_map);
	ZERO_STRUCT(gid_map);

	/* create two mappings for a UID and GID */

	uid_map.sid = dom_sid_parse_talloc(memctx, DOM_SID5 "-1000");
	uid_map.xid.type = ID_TYPE_UID;

	gid_map.sid = dom_sid_parse_talloc(memctx, DOM_SID5 "-1001");
	gid_map.xid.type = ID_TYPE_GID;

	status = idmap_tdb_common_new_mapping(dom, &uid_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_unixids2sids1: could not create uid map!\n"));
		return false;
	}

	status = idmap_tdb_common_new_mapping(dom, &gid_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_unixids2sids1: could not create gid map!\n"));
		return false;
	}

	/* now read them back  */
	test_maps = talloc_zero_array(memctx, struct id_map*, 3);

	test_maps[0] = talloc(test_maps, struct id_map);
	test_maps[1] = talloc(test_maps, struct id_map);
	test_maps[2] = NULL;

	test_maps[0]->sid = talloc(test_maps, struct dom_sid);
	test_maps[1]->sid = talloc(test_maps, struct dom_sid);
	test_maps[0]->xid.id = uid_map.xid.id;
	test_maps[0]->xid.type = ID_TYPE_UID;
	test_maps[1]->xid.id = gid_map.xid.id;
	test_maps[1]->xid.type = ID_TYPE_GID;

	status = idmap_tdb_common_unixids_to_sids(dom, test_maps);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_unixids2sids1: unixids2sids failed!\n"));
		talloc_free(test_maps);
		return false;
	}

	if(!dom_sid_equal(test_maps[0]->sid, uid_map.sid) ||
	    !dom_sid_equal(test_maps[1]->sid, gid_map.sid) ) {
		DEBUG(0, ("test_unixids2sids1: unixids2sids returned wrong sid!\n"));
		talloc_free(test_maps);
		return false;
	}

	DEBUG(0, ("test_unixids2sids1: PASSED!\n"));

	talloc_free(test_maps);

	return true;
}

static bool test_unixids2sids2(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status;
	struct id_map **test_maps;
	bool retval = true;

	test_maps = talloc_zero_array(memctx, struct id_map*, 3);

	test_maps[0] = talloc(test_maps, struct id_map);
	test_maps[1] = talloc(test_maps, struct id_map);
	test_maps[2] = NULL;

	/* ask for two unknown mappings for a UID and GID */
	test_maps[0]->sid = talloc(test_maps, struct dom_sid);
	test_maps[1]->sid = talloc(test_maps, struct dom_sid);
	test_maps[0]->xid.id = HIGH_ID - 1;
	test_maps[0]->xid.type = ID_TYPE_UID;
	test_maps[1]->xid.id = HIGH_ID - 1;
	test_maps[1]->xid.type = ID_TYPE_GID;

	status = idmap_tdb_common_unixids_to_sids(dom, test_maps);
	if(NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_unixids2sids2: unixids2sids succeeded "
			  "unexpectedly!\n"));
		retval = false;
		goto out;
	}

	DEBUG(0, ("test_unixids2sids2: PASSED!\n"));

out:
	talloc_free(test_maps);

	return retval;;
}

static bool test_unixids2sids3(TALLOC_CTX *memctx, struct idmap_domain *dom)
{
	NTSTATUS status;
	struct id_map uid_map, gid_map, **test_maps;
	bool retval = true;

	ZERO_STRUCT(uid_map);
	ZERO_STRUCT(gid_map);

	/* create two mappings for a UID and GID */
	uid_map.sid = dom_sid_parse_talloc(memctx, DOM_SID6 "-1000");
	uid_map.xid.type = ID_TYPE_UID;

	gid_map.sid = dom_sid_parse_talloc(memctx, DOM_SID6 "-1001");
	gid_map.xid.type = ID_TYPE_GID;

	status = idmap_tdb_common_new_mapping(dom, &uid_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_unixids2sids3: could not create uid map!\n"));
		return false;
	}

	status = idmap_tdb_common_new_mapping(dom, &gid_map);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_unixids2sids3: could not create gid map!\n"));
		return false;
	}

	/*
	 * check the mapping states:
	 * NONE_MAPPED, SOME_UNMAPPED, OK (all mapped)
	 */
	test_maps = talloc_zero_array(memctx, struct id_map*, 3);

	test_maps[0] = talloc(test_maps, struct id_map);
	test_maps[1] = talloc(test_maps, struct id_map);
	test_maps[2] = NULL;

	/* NONE_MAPPED first */
	test_maps[0]->sid = talloc(test_maps, struct dom_sid);
	test_maps[1]->sid = talloc(test_maps, struct dom_sid);

	test_maps[0]->xid.id = HIGH_ID - 1;
	test_maps[0]->xid.type = ID_TYPE_UID;

	test_maps[1]->xid.id = HIGH_ID - 1;
	test_maps[1]->xid.type = ID_TYPE_GID;

	status = idmap_tdb_common_unixids_to_sids(dom, test_maps);
	if(!NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		DEBUG(0, ("test_unixids2sids3: incorrect status "
			  "(%s), expected NT_STATUS_NONE_MAPPED!\n",
			   nt_errstr(status)));
		retval = false;
		goto out;
	}

	/* SOME_UNMAPPED */
	test_maps[0]->sid = talloc(test_maps, struct dom_sid);
	test_maps[1]->sid = talloc(test_maps, struct dom_sid);
	test_maps[0]->xid = uid_map.xid;
	test_maps[1]->xid.id = HIGH_ID - 1;
	test_maps[1]->xid.type = ID_TYPE_GID;

	status = idmap_tdb_common_unixids_to_sids(dom, test_maps);
	if(!NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		DEBUG(0, ("test_unixids2sids3: incorrect status "
			  "(%s), expected STATUS_SOME_UNMAPPED!\n",
			   nt_errstr(status)));
		retval = false;
		goto out;
	}

	/* OK */
	test_maps[0]->sid = talloc(test_maps, struct dom_sid);
	test_maps[1]->sid = talloc(test_maps, struct dom_sid);
	test_maps[0]->xid = uid_map.xid;
	test_maps[1]->xid = gid_map.xid;

	status = idmap_tdb_common_unixids_to_sids(dom, test_maps);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("test_unixids2sids3: incorrect status "
			  "(%s), expected NT_STATUS_OK!\n",
			   nt_errstr(status)));
		retval = false;
		goto out;
	}

	DEBUG(0, ("test_unixids2sids3: PASSED!\n"));

out:
	talloc_free(test_maps);
	return retval;
}

#define CHECKRESULT(r) if(!r) {return r;}

bool run_idmap_tdb_common_test(int dummy)
{
	bool result;
	struct idmap_tdb_common_context *ctx;
	struct idmap_domain *dom;

	TALLOC_CTX *memctx = talloc_new(NULL);
	TALLOC_CTX *stack = talloc_stackframe();

	ctx = createcontext(memctx);
	if(!ctx) {
		return false;
	}

	dom = createdomain(memctx);

	dom->private_data = ctx;

	/* test a single allocation from pool (no mapping) */
	result = test_getnewid1(memctx, dom);
	CHECKRESULT(result);

	/* test idmap_tdb_common_set_mapping */
	result = test_setmap1(memctx, dom);
	CHECKRESULT(result);

	/* test idmap_tdb_common_sid_to_unixid */
	result = test_sid2unixid1(memctx, dom);
	CHECKRESULT(result);
	result = test_sid2unixid2(memctx, dom);
	CHECKRESULT(result);

	/* test idmap_tdb_common_sids_to_unixids */
	result = test_sids2unixids1(memctx, dom);
	CHECKRESULT(result);
	result = test_sids2unixids2(memctx, dom);
	CHECKRESULT(result);
	result = test_sids2unixids3(memctx, dom);
	CHECKRESULT(result);

	/* test idmap_tdb_common_unixid_to_sid */
	result = test_unixid2sid1(memctx, dom);
	CHECKRESULT(result);
	result = test_unixid2sid2(memctx, dom);
	CHECKRESULT(result);
	result = test_unixid2sid3(memctx, dom);
	CHECKRESULT(result);

	/* test idmap_tdb_common_unixids_to_sids */
	result = test_unixids2sids1(memctx, dom);
	CHECKRESULT(result);
	result = test_unixids2sids2(memctx, dom);
	CHECKRESULT(result);
	result = test_unixids2sids3(memctx, dom);
	CHECKRESULT(result);

	/* test filling up the range */
	result = test_getnewid2(memctx, dom);
	CHECKRESULT(result);

	talloc_free(memctx);
	talloc_free(stack);

	return true;
}
