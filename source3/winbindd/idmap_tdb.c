/* 
   Unix SMB/CIFS implementation.

   idmap TDB backend

   Copyright (C) Tim Potter 2000
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Jeremy Allison 2006
   Copyright (C) Simo Sorce 2003-2006
   Copyright (C) Michael Adam 2009-2010

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
#include "winbindd.h"
#include "idmap.h"
#include "idmap_rw.h"
#include "idmap_tdb_common.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../libcli/security/security.h"
#include "util_tdb.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

/* idmap version determines auto-conversion - this is the database
   structure version specifier. */

#define IDMAP_VERSION 2

/* High water mark keys */
#define HWM_GROUP  "GROUP HWM"
#define HWM_USER   "USER HWM"

struct convert_fn_state {
	struct db_context *db;
	bool failed;
};

/*****************************************************************************
 For idmap conversion: convert one record to new format
 Ancient versions (eg 2.2.3a) of winbindd_idmap.tdb mapped DOMAINNAME/rid
 instead of the SID.
*****************************************************************************/
static int convert_fn(struct db_record *rec, void *private_data)
{
	struct winbindd_domain *domain;
	char *p;
	NTSTATUS status;
	struct dom_sid sid;
	uint32_t rid;
	struct dom_sid_buf keystr;
	fstring dom_name;
	TDB_DATA key;
	TDB_DATA key2;
	TDB_DATA value;
	struct convert_fn_state *s = (struct convert_fn_state *)private_data;

	key = dbwrap_record_get_key(rec);

	DEBUG(10,("Converting %s\n", (const char *)key.dptr));

	p = strchr((const char *)key.dptr, '/');
	if (!p)
		return 0;

	*p = 0;
	fstrcpy(dom_name, (const char *)key.dptr);
	*p++ = '/';

	domain = find_domain_from_name(dom_name);
	if (domain == NULL) {
		/* We must delete the old record. */
		DEBUG(0,("Unable to find domain %s\n", dom_name ));
		DEBUG(0,("deleting record %s\n", (const char *)key.dptr ));

		status = dbwrap_record_delete(rec);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Unable to delete record %s:%s\n",
				(const char *)key.dptr,
				nt_errstr(status)));
			s->failed = true;
			return -1;
		}

		return 0;
	}

	rid = atoi(p);

	sid_compose(&sid, &domain->sid, rid);

	key2 = string_term_tdb_data(dom_sid_str_buf(&sid, &keystr));

	value = dbwrap_record_get_value(rec);

	status = dbwrap_store(s->db, key2, value, TDB_INSERT);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Unable to add record %s:%s\n",
			(const char *)key2.dptr,
			nt_errstr(status)));
		s->failed = true;
		return -1;
	}

	status = dbwrap_store(s->db, value, key2, TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Unable to update record %s:%s\n",
			(const char *)value.dptr,
			nt_errstr(status)));
		s->failed = true;
		return -1;
	}

	status = dbwrap_record_delete(rec);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Unable to delete record %s:%s\n",
			(const char *)key.dptr,
			nt_errstr(status)));
		s->failed = true;
		return -1;
	}

	return 0;
}

/*****************************************************************************
 Convert the idmap database from an older version.
*****************************************************************************/

static bool idmap_tdb_upgrade(struct idmap_domain *dom, struct db_context *db)
{
	int32_t vers;
	struct convert_fn_state s;
	NTSTATUS status;

	status = dbwrap_fetch_int32_bystring(db, "IDMAP_VERSION", &vers);
	if (!NT_STATUS_IS_OK(status)) {
		vers = -1;
	}

	if (IREV(vers) == IDMAP_VERSION) {
		/* Arrggghh ! Bytereversed - make order independent ! */
		/*
		 * high and low records were created on a
		 * big endian machine and will need byte-reversing.
		 */

		int32_t wm;

		status = dbwrap_fetch_int32_bystring(db, HWM_USER, &wm);
		if (!NT_STATUS_IS_OK(status)) {
			wm = -1;
		}

		if (wm != -1) {
			wm = IREV(wm);
		}  else {
			wm = dom->low_id;
		}

		status = dbwrap_store_int32_bystring(db, HWM_USER, wm);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Unable to byteswap user hwm in idmap "
				  "database: %s\n", nt_errstr(status)));
			return False;
		}

		status = dbwrap_fetch_int32_bystring(db, HWM_GROUP, &wm);
		if (!NT_STATUS_IS_OK(status)) {
			wm = -1;
		}

		if (wm != -1) {
			wm = IREV(wm);
		} else {
			wm = dom->low_id;
		}

		status = dbwrap_store_int32_bystring(db, HWM_GROUP, wm);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Unable to byteswap group hwm in idmap "
				  "database: %s\n", nt_errstr(status)));
			return False;
		}
	}

	s.db = db;
	s.failed = false;

	/* the old format stored as DOMAIN/rid - now we store the SID direct */
	status = dbwrap_traverse(db, convert_fn, &s, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Database traverse failed during conversion\n"));
		return false;
	}

	if (s.failed) {
		DEBUG(0, ("Problem during conversion\n"));
		return False;
	}

	status = dbwrap_store_int32_bystring(db, "IDMAP_VERSION",
					     IDMAP_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Unable to store idmap version in database: %s\n",
			  nt_errstr(status)));
		return False;
	}

	return True;
}

static NTSTATUS idmap_tdb_init_hwm(struct idmap_domain *dom)
{
	uint32_t low_uid;
	uint32_t low_gid;
	bool update_uid = false;
	bool update_gid = false;
	struct idmap_tdb_common_context *ctx;
	NTSTATUS status;

	ctx = talloc_get_type(dom->private_data,
			      struct idmap_tdb_common_context);

	status = dbwrap_fetch_uint32_bystring(ctx->db, HWM_USER, &low_uid);
	if (!NT_STATUS_IS_OK(status) || low_uid < dom->low_id) {
		update_uid = true;
	}

	status = dbwrap_fetch_uint32_bystring(ctx->db, HWM_GROUP, &low_gid);
	if (!NT_STATUS_IS_OK(status) || low_gid < dom->low_id) {
		update_gid = true;
	}

	if (!update_uid && !update_gid) {
		return NT_STATUS_OK;
	}

	if (dbwrap_transaction_start(ctx->db) != 0) {
		DEBUG(0, ("Unable to start upgrade transaction!\n"));
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	if (update_uid) {
		status = dbwrap_store_uint32_bystring(ctx->db, HWM_USER,
						      dom->low_id);
		if (!NT_STATUS_IS_OK(status)) {
			dbwrap_transaction_cancel(ctx->db);
			DEBUG(0, ("Unable to initialise user hwm in idmap "
				  "database: %s\n", nt_errstr(status)));
			return NT_STATUS_INTERNAL_DB_ERROR;
		}
	}

	if (update_gid) {
		status = dbwrap_store_uint32_bystring(ctx->db, HWM_GROUP,
						      dom->low_id);
		if (!NT_STATUS_IS_OK(status)) {
			dbwrap_transaction_cancel(ctx->db);
			DEBUG(0, ("Unable to initialise group hwm in idmap "
				  "database: %s\n", nt_errstr(status)));
			return NT_STATUS_INTERNAL_DB_ERROR;
		}
	}

	if (dbwrap_transaction_commit(ctx->db) != 0) {
		DEBUG(0, ("Unable to commit upgrade transaction!\n"));
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	return NT_STATUS_OK;
}

static NTSTATUS idmap_tdb_open_db(struct idmap_domain *dom)
{
	NTSTATUS ret;
	TALLOC_CTX *mem_ctx;
	char *tdbfile = NULL;
	struct db_context *db = NULL;
	int32_t version;
	bool config_error = false;
	struct idmap_tdb_common_context *ctx;

	ctx = talloc_get_type(dom->private_data,
			      struct idmap_tdb_common_context);

	if (ctx->db) {
		/* it is already open */
		return NT_STATUS_OK;
	}

	/* use our own context here */
	mem_ctx = talloc_stackframe();

	/* use the old database if present */
	tdbfile = state_path(talloc_tos(), "winbindd_idmap.tdb");
	if (!tdbfile) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	DEBUG(10,("Opening tdbfile %s\n", tdbfile ));

	/* Open idmap repository */
	db = db_open(mem_ctx, tdbfile, 0, TDB_DEFAULT, O_RDWR | O_CREAT, 0644,
		     DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	if (!db) {
		DEBUG(0, ("Unable to open idmap database\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* check against earlier versions */
	ret = dbwrap_fetch_int32_bystring(db, "IDMAP_VERSION", &version);
	if (!NT_STATUS_IS_OK(ret)) {
		version = -1;
	}

	if (version != IDMAP_VERSION) {
		if (config_error) {
			DEBUG(0,("Upgrade of IDMAP_VERSION from %d to %d is not "
				 "possible with incomplete configuration\n",
				 version, IDMAP_VERSION));
			ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
		if (dbwrap_transaction_start(db) != 0) {
			DEBUG(0, ("Unable to start upgrade transaction!\n"));
			ret = NT_STATUS_INTERNAL_DB_ERROR;
			goto done;
		}

		if (!idmap_tdb_upgrade(dom, db)) {
			dbwrap_transaction_cancel(db);
			DEBUG(0, ("Unable to open idmap database, it's in an old format, and upgrade failed!\n"));
			ret = NT_STATUS_INTERNAL_DB_ERROR;
			goto done;
		}

		if (dbwrap_transaction_commit(db) != 0) {
			DEBUG(0, ("Unable to commit upgrade transaction!\n"));
			ret = NT_STATUS_INTERNAL_DB_ERROR;
			goto done;
		}
	}

	ctx->db = talloc_move(ctx, &db);

	ret = idmap_tdb_init_hwm(dom);

done:
	talloc_free(mem_ctx);
	return ret;
}

/**********************************************************************
 IDMAP MAPPING TDB BACKEND
**********************************************************************/

/*****************************
 Initialise idmap database. 
*****************************/

static NTSTATUS idmap_tdb_db_init(struct idmap_domain *dom)
{
	NTSTATUS ret;
	struct idmap_tdb_common_context *ctx;

	DEBUG(10, ("idmap_tdb_db_init called for domain '%s'\n", dom->name));

	ctx = talloc_zero(dom, struct idmap_tdb_common_context);
	if ( ! ctx) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* load backend specific configuration here: */
#if 0
	if (strequal(dom->name, "*")) {
	} else {
	}
#endif

	ctx->rw_ops = talloc_zero(ctx, struct idmap_rw_ops);
	if (ctx->rw_ops == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	ctx->max_id = dom->high_id;
	ctx->hwmkey_uid = HWM_USER;
	ctx->hwmkey_gid = HWM_GROUP;

	ctx->rw_ops->get_new_id = idmap_tdb_common_get_new_id;
	ctx->rw_ops->set_mapping = idmap_tdb_common_set_mapping;

	dom->private_data = ctx;

	ret = idmap_tdb_open_db(dom);
	if ( ! NT_STATUS_IS_OK(ret)) {
		goto failed;
	}

	return NT_STATUS_OK;

failed:
	talloc_free(ctx);
	return ret;
}

static const struct idmap_methods db_methods = {
	.init = idmap_tdb_db_init,
	.unixids_to_sids = idmap_tdb_common_unixids_to_sids,
	.sids_to_unixids = idmap_tdb_common_sids_to_unixids,
	.allocate_id = idmap_tdb_common_get_new_id,
};

NTSTATUS idmap_tdb_init(TALLOC_CTX *mem_ctx)
{
	DEBUG(10, ("calling idmap_tdb_init\n"));

	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "tdb", &db_methods);
}
