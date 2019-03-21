/* 
   Unix SMB/CIFS implementation.

   idmap TDB2 backend, used for clustered Samba setups.

   This uses dbwrap to access tdb files. The location can be set
   using tdb:idmap2.tdb =" in smb.conf

   Copyright (C) Andrew Tridgell 2007

   This is heavily based upon idmap_tdb.c, which is:

   Copyright (C) Tim Potter 2000
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Jeremy Allison 2006
   Copyright (C) Simo Sorce 2003-2006
   Copyright (C) Michael Adam 2009-2010

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
#include "system/filesys.h"
#include "winbindd.h"
#include "idmap.h"
#include "idmap_rw.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../libcli/security/dom_sid.h"
#include "util_tdb.h"
#include "idmap_tdb_common.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

struct idmap_tdb2_context {
	const char *script; /* script to provide idmaps */
};

/* High water mark keys */
#define HWM_GROUP  "GROUP HWM"
#define HWM_USER   "USER HWM"

/*
 * check and initialize high/low water marks in the db
 */
static NTSTATUS idmap_tdb2_init_hwm(struct idmap_domain *dom)
{
	NTSTATUS status;
	uint32_t low_id;
	struct idmap_tdb_common_context *ctx;

	ctx = talloc_get_type(dom->private_data,
			      struct idmap_tdb_common_context);

	/* Create high water marks for group and user id */

	status = dbwrap_fetch_uint32_bystring(ctx->db, HWM_USER, &low_id);
	if (!NT_STATUS_IS_OK(status) || (low_id < dom->low_id)) {
		status = dbwrap_trans_store_uint32_bystring(ctx->db, HWM_USER,
							    dom->low_id);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Unable to initialise user hwm in idmap "
				  "database: %s\n", nt_errstr(status)));
			return NT_STATUS_INTERNAL_DB_ERROR;
		}
	}

	status = dbwrap_fetch_uint32_bystring(ctx->db, HWM_GROUP, &low_id);
	if (!NT_STATUS_IS_OK(status) || (low_id < dom->low_id)) {
		status = dbwrap_trans_store_uint32_bystring(ctx->db, HWM_GROUP,
							    dom->low_id);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Unable to initialise group hwm in idmap "
				  "database: %s\n", nt_errstr(status)));
			return NT_STATUS_INTERNAL_DB_ERROR;
		}
	}

	return NT_STATUS_OK;
}


/*
  open the permanent tdb
 */
static NTSTATUS idmap_tdb2_open_db(struct idmap_domain *dom)
{
	char *db_path;
	struct idmap_tdb_common_context *ctx;

	ctx = talloc_get_type(dom->private_data,
			      struct idmap_tdb_common_context);

	if (ctx->db) {
		/* its already open */
		return NT_STATUS_OK;
	}

	db_path = talloc_asprintf(NULL, "%s/idmap2.tdb", lp_private_dir());
	NT_STATUS_HAVE_NO_MEMORY(db_path);

	/* Open idmap repository */
	ctx->db = db_open(ctx, db_path, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0644,
			  DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	if (ctx->db == NULL) {
		DEBUG(0, ("Unable to open idmap_tdb2 database '%s'\n",
			  db_path));
		TALLOC_FREE(db_path);
		return NT_STATUS_UNSUCCESSFUL;
	}
	TALLOC_FREE(db_path);

	return idmap_tdb2_init_hwm(dom);
}

/**
 * store a mapping in the database.
 */

struct idmap_tdb2_set_mapping_context {
	const char *ksidstr;
	const char *kidstr;
};

static NTSTATUS idmap_tdb2_set_mapping_action(struct db_context *db,
					      void *private_data)
{
	TDB_DATA data;
	NTSTATUS ret;
	struct idmap_tdb2_set_mapping_context *state;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	state = (struct idmap_tdb2_set_mapping_context *)private_data;

	DEBUG(10, ("Storing %s <-> %s map\n", state->ksidstr, state->kidstr));

	/* check wheter sid mapping is already present in db */
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

	DEBUG(10,("Stored %s <-> %s\n", state->ksidstr, state->kidstr));

done:
	talloc_free(tmp_ctx);
	return ret;
}

static NTSTATUS idmap_tdb2_set_mapping(struct idmap_domain *dom, const struct id_map *map)
{
	struct idmap_tdb2_context *ctx;
	NTSTATUS ret;
	char *kidstr;
	struct dom_sid_buf sid_str;
	struct idmap_tdb_common_context *commonctx;
	struct idmap_tdb2_set_mapping_context state;

	if (!map || !map->sid) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	kidstr = NULL;

	/* TODO: should we filter a set_mapping using low/high filters ? */

	commonctx = talloc_get_type(dom->private_data,
				    struct idmap_tdb_common_context);

	ctx = talloc_get_type(commonctx->private_data,
			      struct idmap_tdb2_context);

	switch (map->xid.type) {

	case ID_TYPE_UID:
		kidstr = talloc_asprintf(ctx, "UID %lu", (unsigned long)map->xid.id);
		break;

	case ID_TYPE_GID:
		kidstr = talloc_asprintf(ctx, "GID %lu", (unsigned long)map->xid.id);
		break;

	default:
		DEBUG(2, ("INVALID unix ID type: 0x02%x\n", map->xid.type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (kidstr == NULL) {
		DEBUG(0, ("ERROR: Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	state.ksidstr = dom_sid_str_buf(map->sid, &sid_str);
	state.kidstr = kidstr;

	ret = dbwrap_trans_do(commonctx->db, idmap_tdb2_set_mapping_action,
			      &state);

done:
	talloc_free(kidstr);
	return ret;
}

/*
  run a script to perform a mapping

  The script should the following command lines:

      SIDTOID S-1-xxxx
      IDTOSID UID xxxx
      IDTOSID GID xxxx

  and should return one of the following as a single line of text
     UID:xxxx
     GID:xxxx
     SID:xxxx
     ERR:xxxx
 */
static NTSTATUS idmap_tdb2_script(struct idmap_tdb2_context *ctx,
				  struct id_map *map, const char *fmt, ...)
				  PRINTF_ATTRIBUTE(3,4);

static NTSTATUS idmap_tdb2_script(struct idmap_tdb2_context *ctx, struct id_map *map,
				  const char *fmt, ...)
{
	va_list ap;
	char *cmd;
	FILE *p;
	char line[64];
	unsigned long v;

	cmd = talloc_asprintf(ctx, "%s ", ctx->script);
	NT_STATUS_HAVE_NO_MEMORY(cmd);	

	va_start(ap, fmt);
	cmd = talloc_vasprintf_append(cmd, fmt, ap);
	va_end(ap);
	NT_STATUS_HAVE_NO_MEMORY(cmd);

	p = popen(cmd, "r");
	talloc_free(cmd);
	if (p == NULL) {
		return NT_STATUS_NONE_MAPPED;
	}

	if (fgets(line, sizeof(line)-1, p) == NULL) {
		pclose(p);
		return NT_STATUS_NONE_MAPPED;
	}
	pclose(p);

	DEBUG(10,("idmap script gave: %s\n", line));

	if (sscanf(line, "UID:%lu", &v) == 1) {
		map->xid.id   = v;
		map->xid.type = ID_TYPE_UID;
	} else if (sscanf(line, "GID:%lu", &v) == 1) {
		map->xid.id   = v;
		map->xid.type = ID_TYPE_GID;		
	} else if (strncmp(line, "SID:S-", 6) == 0) {
		if (!string_to_sid(map->sid, &line[4])) {
			DEBUG(0,("Bad SID in '%s' from idmap script %s\n",
				 line, ctx->script));
			return NT_STATUS_NONE_MAPPED;			
		}
	} else {
		DEBUG(0,("Bad reply '%s' from idmap script %s\n",
			 line, ctx->script));
		return NT_STATUS_NONE_MAPPED;
	}

	return NT_STATUS_OK;
}



/*
  Single id to sid lookup function. 
*/
static NTSTATUS idmap_tdb2_id_to_sid(struct idmap_domain *dom, struct id_map *map)
{
	NTSTATUS ret;
	TDB_DATA data;
	char *keystr;
	NTSTATUS status;
	struct idmap_tdb_common_context *commonctx;
	struct idmap_tdb2_context *ctx;


	if (!dom || !map) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = idmap_tdb2_open_db(dom);
	NT_STATUS_NOT_OK_RETURN(status);

	commonctx = talloc_get_type(dom->private_data,
				    struct idmap_tdb_common_context);

	ctx = talloc_get_type(commonctx->private_data,
			      struct idmap_tdb2_context);

	/* apply filters before checking */
	if (!idmap_unix_id_is_in_range(map->xid.id, dom)) {
		DEBUG(5, ("Requested id (%u) out of range (%u - %u). Filtered!\n",
				map->xid.id, dom->low_id, dom->high_id));
		return NT_STATUS_NONE_MAPPED;
	}

	switch (map->xid.type) {

	case ID_TYPE_UID:
		keystr = talloc_asprintf(ctx, "UID %lu", (unsigned long)map->xid.id);
		break;

	case ID_TYPE_GID:
		keystr = talloc_asprintf(ctx, "GID %lu", (unsigned long)map->xid.id);
		break;

	default:
		DEBUG(2, ("INVALID unix ID type: 0x02%x\n", map->xid.type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (keystr == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	DEBUG(10,("Fetching record %s\n", keystr));

	/* Check if the mapping exists */
	status = dbwrap_fetch_bystring(commonctx->db, keystr, keystr, &data);

	if (!NT_STATUS_IS_OK(status)) {
		struct dom_sid_buf sidstr;
		struct idmap_tdb2_set_mapping_context store_state;

		DEBUG(10,("Record %s not found\n", keystr));
		if (ctx->script == NULL) {
			ret = NT_STATUS_NONE_MAPPED;
			goto done;
		}

		ret = idmap_tdb2_script(ctx, map, "IDTOSID %s", keystr);
		if (!NT_STATUS_IS_OK(ret)) {
			goto done;
		}

		store_state.ksidstr = dom_sid_str_buf(map->sid, &sidstr);
		store_state.kidstr = keystr;

		ret = dbwrap_trans_do(commonctx->db,
				      idmap_tdb2_set_mapping_action,
				      &store_state);
		goto done;
	}

	if (!string_to_sid(map->sid, (const char *)data.dptr)) {
		DEBUG(10,("INVALID SID (%s) in record %s\n",
			(const char *)data.dptr, keystr));
		ret = NT_STATUS_INTERNAL_DB_ERROR;
		goto done;
	}

	DEBUG(10,("Found record %s -> %s\n", keystr, (const char *)data.dptr));
	ret = NT_STATUS_OK;

done:
	talloc_free(keystr);
	return ret;
}


/*
 Single sid to id lookup function. 
*/
static NTSTATUS idmap_tdb2_sid_to_id(struct idmap_domain *dom, struct id_map *map)
{
	NTSTATUS ret;
	TDB_DATA data;
	struct dom_sid_buf keystr;
	unsigned long rec_id = 0;
	struct idmap_tdb_common_context *commonctx;
	struct idmap_tdb2_context *ctx;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	ret = idmap_tdb2_open_db(dom);
	NT_STATUS_NOT_OK_RETURN(ret);

	commonctx = talloc_get_type(dom->private_data,
				    struct idmap_tdb_common_context);

	ctx = talloc_get_type(commonctx->private_data,
			      struct idmap_tdb2_context);

	dom_sid_str_buf(map->sid, &keystr);

	DEBUG(10, ("Fetching record %s\n", keystr.buf));

	/* Check if sid is present in database */
	ret = dbwrap_fetch_bystring(commonctx->db, tmp_ctx, keystr.buf, &data);
	if (!NT_STATUS_IS_OK(ret)) {
		char *idstr;
		struct idmap_tdb2_set_mapping_context store_state;

		DBG_DEBUG("Record %s not found\n", keystr.buf);

		if (ctx->script == NULL) {
			ret = NT_STATUS_NONE_MAPPED;
			goto done;
		}

		ret = idmap_tdb2_script(ctx, map, "SIDTOID %s", keystr.buf);
		if (!NT_STATUS_IS_OK(ret)) {
			goto done;
		}

		/* apply filters before returning result */
		if (!idmap_unix_id_is_in_range(map->xid.id, dom)) {
			DEBUG(5, ("Script returned id (%u) out of range "
				  "(%u - %u). Filtered!\n",
				  map->xid.id, dom->low_id, dom->high_id));
			ret = NT_STATUS_NONE_MAPPED;
			goto done;
		}

		idstr = talloc_asprintf(tmp_ctx, "%cID %lu",
					map->xid.type == ID_TYPE_UID?'U':'G',
					(unsigned long)map->xid.id);
		if (idstr == NULL) {
			ret = NT_STATUS_NO_MEMORY;
			goto done;
		}

		store_state.ksidstr = keystr.buf;
		store_state.kidstr = idstr;

		ret = dbwrap_trans_do(commonctx->db,
				      idmap_tdb2_set_mapping_action,
				      &store_state);
		goto done;
	}

	/* What type of record is this ? */
	if (sscanf((const char *)data.dptr, "UID %lu", &rec_id) == 1) { /* Try a UID record. */
		map->xid.id = rec_id;
		map->xid.type = ID_TYPE_UID;
		DBG_DEBUG("Found uid record %s -> %s \n",
			  keystr.buf,
			  (const char *)data.dptr );
		ret = NT_STATUS_OK;

	} else if (sscanf((const char *)data.dptr, "GID %lu", &rec_id) == 1) { /* Try a GID record. */
		map->xid.id = rec_id;
		map->xid.type = ID_TYPE_GID;
		DBG_DEBUG("Found gid record %s -> %s \n",
			  keystr.buf,
			  (const char *)data.dptr );
		ret = NT_STATUS_OK;

	} else { /* Unknown record type ! */
		DBG_WARNING("Found INVALID record %s -> %s\n",
			    keystr.buf,
			    (const char *)data.dptr);
		ret = NT_STATUS_INTERNAL_DB_ERROR;
		goto done;
	}

	/* apply filters before returning result */
	if (!idmap_unix_id_is_in_range(map->xid.id, dom)) {
		DEBUG(5, ("Requested id (%u) out of range (%u - %u). Filtered!\n",
				map->xid.id, dom->low_id, dom->high_id));
		ret = NT_STATUS_NONE_MAPPED;
	}

done:
	talloc_free(tmp_ctx);
	return ret;
}

/*
  Initialise idmap database.
*/
static NTSTATUS idmap_tdb2_db_init(struct idmap_domain *dom)
{
	NTSTATUS ret;
	struct idmap_tdb_common_context *commonctx;
	struct idmap_tdb2_context *ctx;
	const char * idmap_script = NULL;
	const char *ctx_script = NULL;

	commonctx = talloc_zero(dom, struct idmap_tdb_common_context);
	if(!commonctx) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	commonctx->rw_ops = talloc_zero(commonctx, struct idmap_rw_ops);
	if (commonctx->rw_ops == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	ctx = talloc_zero(commonctx, struct idmap_tdb2_context);
	if (!ctx) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	ctx_script = idmap_config_const_string(dom->name, "script", NULL);

	idmap_script = lp_parm_const_string(-1, "idmap", "script", NULL);
	if (idmap_script != NULL) {
		DEBUG(0, ("Warning: 'idmap:script' is deprecated. "
			  " Please use 'idmap config * : script' instead!\n"));
	}

	if (strequal(dom->name, "*") && ctx_script == NULL) {
		/* fall back to idmap:script for backwards compatibility */
		ctx_script = idmap_script;
	}

	if (ctx_script) {
		DEBUG(1, ("using idmap script '%s'\n", ctx_script));
		/*
		 * We must ensure this memory is owned by ctx.
		 * The ctx_script const pointer is a pointer into
		 * the config file data and may become invalid
		 * on config file reload. BUG: 13956
		 */
		ctx->script = talloc_strdup(ctx, ctx_script);
		if (ctx->script == NULL) {
			ret = NT_STATUS_NO_MEMORY;
			goto failed;
		}
	}

	commonctx->max_id = dom->high_id;
	commonctx->hwmkey_uid = HWM_USER;
	commonctx->hwmkey_gid = HWM_GROUP;

	commonctx->sid_to_unixid_fn = idmap_tdb2_sid_to_id;
	commonctx->unixid_to_sid_fn = idmap_tdb2_id_to_sid;

	commonctx->rw_ops->get_new_id = idmap_tdb_common_get_new_id;
	commonctx->rw_ops->set_mapping = idmap_tdb2_set_mapping;

	commonctx->private_data = ctx;
	dom->private_data = commonctx;

	ret = idmap_tdb2_open_db(dom);
	if (!NT_STATUS_IS_OK(ret)) {
		goto failed;
	}

	return NT_STATUS_OK;

failed:
	talloc_free(commonctx);
	return ret;
}


static const struct idmap_methods db_methods = {
	.init            = idmap_tdb2_db_init,
	.unixids_to_sids = idmap_tdb_common_unixids_to_sids,
	.sids_to_unixids = idmap_tdb_common_sids_to_unixids,
	.allocate_id     = idmap_tdb_common_get_new_id
};

static_decl_idmap;
NTSTATUS idmap_tdb2_init(TALLOC_CTX *ctx)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "tdb2", &db_methods);
}
