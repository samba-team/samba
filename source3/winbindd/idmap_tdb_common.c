/*
   Unix SMB/CIFS implementation.

   common functions for TDB based idmapping backends

   Copyright (C) Christian Ambach 2012

   These functions were initially copied over from idmap_tdb.c and idmap_tdb2.c
   which are:

   Copyright (C) Tim Potter 2000
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Jeremy Allison 2006
   Copyright (C) Simo Sorce 2003-2006
   Copyright (C) Michael Adam 2009-2010
   Copyright (C) Andrew Tridgell 2007

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
#include "idmap_tdb_common.h"
#include "dbwrap/dbwrap.h"
#include "util_tdb.h"
#include "idmap_rw.h"
#include "../libcli/security/dom_sid.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

struct idmap_tdb_common_allocate_id_context {
	const char *hwmkey;
	const char *hwmtype;
	uint32_t high_hwm;
	uint32_t hwm;
};

static NTSTATUS idmap_tdb_common_allocate_id_action(struct db_context *db,
						    void *private_data)
{
	NTSTATUS ret;
	struct idmap_tdb_common_allocate_id_context *state = private_data;
	uint32_t hwm;

	ret = dbwrap_fetch_uint32_bystring(db, state->hwmkey, &hwm);
	if (!NT_STATUS_IS_OK(ret)) {
		ret = NT_STATUS_INTERNAL_DB_ERROR;
		goto done;
	}

	/* check it is in the range */
	if (hwm > state->high_hwm) {
		DEBUG(1, ("Fatal Error: %s range full!! (max: %lu)\n",
			  state->hwmtype, (unsigned long)state->high_hwm));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* fetch a new id and increment it */
	ret = dbwrap_change_uint32_atomic_bystring(db, state->hwmkey, &hwm, 1);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("Fatal error while fetching a new %s value\n!",
			  state->hwmtype));
		goto done;
	}

	/* recheck it is in the range */
	if (hwm > state->high_hwm) {
		DEBUG(1, ("Fatal Error: %s range full!! (max: %lu)\n",
			  state->hwmtype, (unsigned long)state->high_hwm));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	ret = NT_STATUS_OK;
	state->hwm = hwm;

      done:
	return ret;
}

static NTSTATUS idmap_tdb_common_allocate_id(struct idmap_domain *dom,
					     struct unixid *xid)
{
	const char *hwmkey;
	const char *hwmtype;
	uint32_t hwm = 0;
	NTSTATUS status;
	struct idmap_tdb_common_allocate_id_context state;
	struct idmap_tdb_common_context *ctx;

	ctx =
	    talloc_get_type_abort(dom->private_data,
				  struct idmap_tdb_common_context);

	/* Get current high water mark */
	switch (xid->type) {

	case ID_TYPE_UID:
		hwmkey = ctx->hwmkey_uid;
		hwmtype = "UID";
		break;

	case ID_TYPE_GID:
		hwmkey = ctx->hwmkey_gid;
		hwmtype = "GID";
		break;

	case ID_TYPE_BOTH:
		/*
		 * This is not supported here yet and
		 * already handled in idmap_rw_new_mapping()
		 */
		FALL_THROUGH;
	case ID_TYPE_NOT_SPECIFIED:
		/*
		 * This is handled in idmap_rw_new_mapping()
		 */
		FALL_THROUGH;
	default:
		DEBUG(2, ("Invalid ID type (0x%x)\n", xid->type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	state.hwm = hwm;
	state.high_hwm = ctx->max_id;
	state.hwmtype = hwmtype;
	state.hwmkey = hwmkey;

	status = dbwrap_trans_do(ctx->db, idmap_tdb_common_allocate_id_action,
				 &state);

	if (NT_STATUS_IS_OK(status)) {
		xid->id = state.hwm;
		DEBUG(10, ("New %s = %d\n", hwmtype, state.hwm));
	} else {
		DEBUG(1, ("Error allocating a new %s\n", hwmtype));
	}

	return status;
}

/**
 * Allocate a new unix-ID.
 * For now this is for the default idmap domain only.
 * Should be extended later on.
 */
NTSTATUS idmap_tdb_common_get_new_id(struct idmap_domain * dom,
				     struct unixid * id)
{
	NTSTATUS ret;

	if (!strequal(dom->name, "*")) {
		DEBUG(3, ("idmap_tdb_common_get_new_id: "
			  "Refusing allocation of a new unixid for domain'%s'. "
			  "Currently only supported for the default "
			  "domain \"*\".\n", dom->name));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	ret = idmap_tdb_common_allocate_id(dom, id);

	return ret;
}

/**
 * store a mapping in the database.
 */

struct idmap_tdb_common_set_mapping_context {
	const char *ksidstr;
	const char *kidstr;
};

static NTSTATUS idmap_tdb_common_set_mapping_action(struct db_context *db,
						    void *private_data)
{
	TDB_DATA data;
	NTSTATUS ret;
	struct idmap_tdb_common_set_mapping_context *state = private_data;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	DEBUG(10, ("Storing %s <-> %s map\n", state->ksidstr, state->kidstr));

	/* check whether sid mapping is already present in db */
	ret = dbwrap_fetch_bystring(db, tmp_ctx, state->ksidstr, &data);
	if (NT_STATUS_IS_OK(ret)) {
		ret = NT_STATUS_OBJECT_NAME_COLLISION;
		goto done;
	}

	ret = dbwrap_store_bystring(db, state->ksidstr,
				    string_term_tdb_data(state->kidstr),
				    TDB_INSERT);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0, ("Error storing SID -> ID: %s\n", nt_errstr(ret)));
		goto done;
	}

	ret = dbwrap_store_bystring(db, state->kidstr,
				    string_term_tdb_data(state->ksidstr),
				    TDB_INSERT);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0, ("Error storing ID -> SID: %s\n", nt_errstr(ret)));
		/* try to remove the previous stored SID -> ID map */
		dbwrap_delete_bystring(db, state->ksidstr);
		goto done;
	}

	DEBUG(10, ("Stored %s <-> %s\n", state->ksidstr, state->kidstr));

      done:
	talloc_free(tmp_ctx);
	return ret;
}

NTSTATUS idmap_tdb_common_set_mapping(struct idmap_domain * dom,
				      const struct id_map * map)
{
	struct idmap_tdb_common_context *ctx;
	struct idmap_tdb_common_set_mapping_context state;
	NTSTATUS ret;
	struct dom_sid_buf ksidstr;
	char *kidstr = NULL;

	if (!map || !map->sid) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* TODO: should we filter a set_mapping using low/high filters ? */

	ctx =
	    talloc_get_type_abort(dom->private_data,
				  struct idmap_tdb_common_context);

	switch (map->xid.type) {

	case ID_TYPE_UID:
		kidstr =
		    talloc_asprintf(ctx, "UID %lu", (unsigned long)map->xid.id);
		break;

	case ID_TYPE_GID:
		kidstr =
		    talloc_asprintf(ctx, "GID %lu", (unsigned long)map->xid.id);
		break;

	default:
		DEBUG(2, ("INVALID unix ID type: 0x%02x\n", map->xid.type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (kidstr == NULL) {
		DEBUG(0, ("ERROR: Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	state.ksidstr = dom_sid_str_buf(map->sid, &ksidstr);
	state.kidstr = kidstr;

	ret = dbwrap_trans_do(ctx->db, idmap_tdb_common_set_mapping_action,
			      &state);

      done:
	talloc_free(kidstr);
	return ret;
}

/*
 * Create a new mapping for an unmapped SID, also allocating a new ID.
 * This should be run inside a transaction.
 *
 * TODO:
 *  Properly integrate this with multi domain idmap config:
 *  Currently, the allocator is default-config only.
 */
NTSTATUS idmap_tdb_common_new_mapping(struct idmap_domain * dom,
				      struct id_map * map)
{
	NTSTATUS ret;
	struct idmap_tdb_common_context *ctx;

	ctx =
	    talloc_get_type_abort(dom->private_data,
				  struct idmap_tdb_common_context);

	ret = idmap_rw_new_mapping(dom, ctx->rw_ops, map);

	return ret;
}

/*
  lookup a set of unix ids
*/
NTSTATUS idmap_tdb_common_unixids_to_sids(struct idmap_domain * dom,
					  struct id_map ** ids)
{
	NTSTATUS ret;
	size_t i, num_mapped = 0;
	struct idmap_tdb_common_context *ctx;

	NTSTATUS(*unixid_to_sid_fn) (struct idmap_domain * dom,
				     struct id_map * map);
	ctx =
	    talloc_get_type_abort(dom->private_data,
				  struct idmap_tdb_common_context);

	if (ctx->unixid_to_sid_fn == NULL) {
		unixid_to_sid_fn = idmap_tdb_common_unixid_to_sid;
	} else {
		unixid_to_sid_fn = ctx->unixid_to_sid_fn;
	}

	/* initialize the status to avoid surprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	for (i = 0; ids[i]; i++) {
		ret = unixid_to_sid_fn(dom, ids[i]);
		if (!NT_STATUS_IS_OK(ret)) {

			/* if it is just a failed mapping continue */
			if (NT_STATUS_EQUAL(ret, NT_STATUS_NONE_MAPPED)) {

				/* make sure it is marked as unmapped */
				ids[i]->status = ID_UNMAPPED;
				continue;
			}

			/* some fatal error occurred, return immediately */
			goto done;
		}

		/* all ok, id is mapped */
		ids[i]->status = ID_MAPPED;
		num_mapped += 1;
	}

	ret = NT_STATUS_OK;

done:

	if (NT_STATUS_IS_OK(ret)) {
		if (i == 0 || num_mapped == 0) {
			ret = NT_STATUS_NONE_MAPPED;
		} else if (num_mapped < i) {
			ret = STATUS_SOME_UNMAPPED;
		} else {
			ret = NT_STATUS_OK;
		}
	}

	return ret;
}

/*
  default single id to sid lookup function
*/
NTSTATUS idmap_tdb_common_unixid_to_sid(struct idmap_domain * dom,
					struct id_map * map)
{
	NTSTATUS ret;
	TDB_DATA data;
	char *keystr;
	struct idmap_tdb_common_context *ctx;

	if (!dom || !map) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ctx =
	    talloc_get_type_abort(dom->private_data,
				  struct idmap_tdb_common_context);

	/* apply filters before checking */
	if (!idmap_unix_id_is_in_range(map->xid.id, dom)) {
		DEBUG(5,
		      ("Requested id (%u) out of range (%u - %u). Filtered!\n",
		       map->xid.id, dom->low_id, dom->high_id));
		return NT_STATUS_NONE_MAPPED;
	}

	switch (map->xid.type) {

	case ID_TYPE_UID:
		keystr =
		    talloc_asprintf(ctx, "UID %lu", (unsigned long)map->xid.id);
		break;

	case ID_TYPE_GID:
		keystr =
		    talloc_asprintf(ctx, "GID %lu", (unsigned long)map->xid.id);
		break;

	default:
		DEBUG(2, ("INVALID unix ID type: 0x%02x\n", map->xid.type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (keystr == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	DEBUG(10, ("Fetching record %s\n", keystr));

	/* Check if the mapping exists */
	ret = dbwrap_fetch_bystring(ctx->db, keystr, keystr, &data);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(10, ("Record %s not found\n", keystr));
		ret = NT_STATUS_NONE_MAPPED;
		goto done;
	}

	if ((data.dsize == 0) || (data.dptr[data.dsize-1] != '\0')) {
		DBG_DEBUG("Invalid record length %zu\n", data.dsize);
		ret = NT_STATUS_INTERNAL_DB_ERROR;
		goto done;
	}

	if (!string_to_sid(map->sid, (const char *)data.dptr)) {
		DEBUG(10, ("INVALID SID (%s) in record %s\n",
			   (const char *)data.dptr, keystr));
		ret = NT_STATUS_INTERNAL_DB_ERROR;
		goto done;
	}

	DEBUG(10, ("Found record %s -> %s\n", keystr, (const char *)data.dptr));
	ret = NT_STATUS_OK;

      done:
	talloc_free(keystr);
	return ret;
}

/**********************************
 Single sid to id lookup function.
**********************************/

NTSTATUS idmap_tdb_common_sid_to_unixid(struct idmap_domain * dom,
					struct id_map * map)
{
	NTSTATUS ret;
	TDB_DATA data;
	struct dom_sid_buf keystr;
	unsigned long rec_id = 0;
	struct idmap_tdb_common_context *ctx;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	if (!dom || !map) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	ctx =
	    talloc_get_type_abort(dom->private_data,
				  struct idmap_tdb_common_context);

	dom_sid_str_buf(map->sid, &keystr);

	DEBUG(10, ("Fetching record %s\n", keystr.buf));

	/* Check if sid is present in database */
	ret = dbwrap_fetch_bystring(ctx->db, tmp_ctx, keystr.buf, &data);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(10, ("Record %s not found\n", keystr.buf));
		ret = NT_STATUS_NONE_MAPPED;
		goto done;
	}

	/* What type of record is this ? */
	if (sscanf((const char *)data.dptr, "UID %lu", &rec_id) == 1) {
		/* Try a UID record. */
		map->xid.id = rec_id;
		map->xid.type = ID_TYPE_UID;
		DEBUG(10,
		      ("Found uid record %s -> %s \n", keystr.buf,
		       (const char *)data.dptr));
		ret = NT_STATUS_OK;

	} else if (sscanf((const char *)data.dptr, "GID %lu", &rec_id) == 1) {
		/* Try a GID record. */
		map->xid.id = rec_id;
		map->xid.type = ID_TYPE_GID;
		DEBUG(10,
		      ("Found gid record %s -> %s \n", keystr.buf,
		       (const char *)data.dptr));
		ret = NT_STATUS_OK;

	} else {		/* Unknown record type ! */
		DEBUG(2,
		      ("Found INVALID record %s -> %s\n", keystr.buf,
		       (const char *)data.dptr));
		ret = NT_STATUS_INTERNAL_DB_ERROR;
		goto done;
	}

	/* apply filters before returning result */
	if (!idmap_unix_id_is_in_range(map->xid.id, dom)) {
		DEBUG(5,
		      ("Requested id (%u) out of range (%u - %u). Filtered!\n",
		       map->xid.id, dom->low_id, dom->high_id));
		ret = NT_STATUS_NONE_MAPPED;
	}

      done:
	talloc_free(tmp_ctx);
	return ret;
}

/**********************************
 lookup a set of sids
**********************************/

struct idmap_tdb_common_sids_to_unixids_context {
	struct idmap_domain *dom;
	struct id_map **ids;
	bool allocate_unmapped;
	 NTSTATUS(*sid_to_unixid_fn) (struct idmap_domain * dom,
				      struct id_map * map);
};

static NTSTATUS idmap_tdb_common_sids_to_unixids_action(struct db_context *db,
							void *private_data)
{
	struct idmap_tdb_common_sids_to_unixids_context *state = private_data;
	size_t i, num_mapped = 0, num_required = 0;
	NTSTATUS ret = NT_STATUS_OK;

	DEBUG(10, ("idmap_tdb_common_sids_to_unixids: "
		   " domain: [%s], allocate: %s\n",
		   state->dom->name, state->allocate_unmapped ? "yes" : "no"));

	for (i = 0; state->ids[i]; i++) {
		if ((state->ids[i]->status == ID_UNKNOWN) ||
		    /* retry if we could not map in previous run: */
		    (state->ids[i]->status == ID_UNMAPPED)) {
			NTSTATUS ret2;

			ret2 = state->sid_to_unixid_fn(state->dom,
					state->ids[i]);

			if (!NT_STATUS_IS_OK(ret2)) {

				/* if it is just a failed mapping, continue */
				if (NT_STATUS_EQUAL
				    (ret2, NT_STATUS_NONE_MAPPED)) {

					/* make sure it is marked as unmapped */
					state->ids[i]->status = ID_UNMAPPED;
					ret = STATUS_SOME_UNMAPPED;
				} else {
					/*
					 * some fatal error occurred,
					 * return immediately
					 */
					ret = ret2;
					goto done;
				}
			} else {
				/* all ok, id is mapped */
				state->ids[i]->status = ID_MAPPED;
			}
		}

		if (state->ids[i]->status == ID_MAPPED) {
			num_mapped += 1;
		}

		if ((state->ids[i]->status == ID_UNMAPPED) &&
		    state->allocate_unmapped) {
			ret =
			    idmap_tdb_common_new_mapping(state->dom,
							 state->ids[i]);
			DBG_DEBUG("idmap_tdb_common_new_mapping returned %s\n",
				  nt_errstr(ret));
			if (NT_STATUS_EQUAL(ret, STATUS_SOME_UNMAPPED)) {
				if (state->ids[i]->status == ID_REQUIRE_TYPE) {
					num_required += 1;
					continue;
				}
			}
			if (!NT_STATUS_IS_OK(ret)) {
				ret = STATUS_SOME_UNMAPPED;
				continue;
			}
			num_mapped += 1;
		}
	}

done:

	if (NT_STATUS_IS_OK(ret) ||
	    NT_STATUS_EQUAL(ret, STATUS_SOME_UNMAPPED)) {
		if (i == 0 || num_mapped == 0) {
			ret = NT_STATUS_NONE_MAPPED;
		} else if (num_mapped < i) {
			ret = STATUS_SOME_UNMAPPED;
		} else {
			ret = NT_STATUS_OK;
		}
		if (num_required > 0) {
			ret = STATUS_SOME_UNMAPPED;
		}
	}

	return ret;
}

NTSTATUS idmap_tdb_common_sids_to_unixids(struct idmap_domain * dom,
					  struct id_map ** ids)
{
	NTSTATUS ret;
	int i;
	struct idmap_tdb_common_sids_to_unixids_context state;
	struct idmap_tdb_common_context *ctx;

	ctx =
	    talloc_get_type_abort(dom->private_data,
				  struct idmap_tdb_common_context);

	/* initialize the status to avoid surprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	state.dom = dom;
	state.ids = ids;
	state.allocate_unmapped = false;
	if (ctx->sid_to_unixid_fn == NULL) {
		state.sid_to_unixid_fn = idmap_tdb_common_sid_to_unixid;
	} else {
		state.sid_to_unixid_fn = ctx->sid_to_unixid_fn;
	}

	ret = idmap_tdb_common_sids_to_unixids_action(ctx->db, &state);

	if ( (NT_STATUS_EQUAL(ret, STATUS_SOME_UNMAPPED) ||
	      NT_STATUS_EQUAL(ret, NT_STATUS_NONE_MAPPED)) &&
	     !dom->read_only) {
		state.allocate_unmapped = true;
		ret = dbwrap_trans_do(ctx->db,
				      idmap_tdb_common_sids_to_unixids_action,
				      &state);
	}

	return ret;
}
