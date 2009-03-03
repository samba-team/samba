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
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

/* High water mark keys */
#define HWM_GROUP  "GROUP HWM"
#define HWM_USER   "USER HWM"

static struct idmap_tdb2_state {
	/* User and group id pool */
	uid_t low_uid, high_uid;               /* Range of uids to allocate */
	gid_t low_gid, high_gid;               /* Range of gids to allocate */
	const char *idmap_script;
} idmap_tdb2_state;



/* handle to the permanent tdb */
static struct db_context *idmap_tdb2;

static NTSTATUS idmap_tdb2_alloc_load(void);

/*
  open the permanent tdb
 */
static NTSTATUS idmap_tdb2_open_db(void)
{
	char *db_path;
	
	if (idmap_tdb2) {
		/* its already open */
		return NT_STATUS_OK;
	}

	db_path = lp_parm_talloc_string(-1, "tdb", "idmap2.tdb", NULL);
	if (db_path == NULL) {
		/* fall back to the private directory, which, despite
		   its name, is usually on shared storage */
		db_path = talloc_asprintf(NULL, "%s/idmap2.tdb", lp_private_dir());
	}
	NT_STATUS_HAVE_NO_MEMORY(db_path);

	/* Open idmap repository */
	idmap_tdb2 = db_open(NULL, db_path, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0644);
	TALLOC_FREE(db_path);

	if (idmap_tdb2 == NULL) {
		DEBUG(0, ("Unable to open idmap_tdb2 database '%s'\n",
			  db_path));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* load the ranges and high/low water marks */
	return idmap_tdb2_alloc_load();
}


/*
  load the idmap allocation ranges and high/low water marks
*/
static NTSTATUS idmap_tdb2_alloc_load(void)
{
	uid_t low_uid = 0;
	uid_t high_uid = 0;
	gid_t low_gid = 0;
	gid_t high_gid = 0;
	uint32 low_id;

	/* see if a idmap script is configured */
	idmap_tdb2_state.idmap_script = lp_parm_const_string(-1, "idmap",
							     "script", NULL);

	if (idmap_tdb2_state.idmap_script) {
		DEBUG(1, ("using idmap script '%s'\n",
			  idmap_tdb2_state.idmap_script));
	}

	/* load ranges */

	/* Create high water marks for group and user id */
	if (!lp_idmap_uid(&low_uid, &high_uid)
	    || !lp_idmap_gid(&low_gid, &high_gid)) {
		DEBUG(1, ("idmap uid or idmap gid missing\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	idmap_tdb2_state.low_uid = low_uid;
	idmap_tdb2_state.high_uid = high_uid;
	idmap_tdb2_state.low_gid = low_gid;
	idmap_tdb2_state.high_gid = high_gid;

	if (idmap_tdb2_state.high_uid <= idmap_tdb2_state.low_uid) {
		DEBUG(1, ("idmap uid range missing or invalid\n"));
		DEBUGADD(1, ("idmap will be unable to map foreign SIDs\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (((low_id = dbwrap_fetch_int32(idmap_tdb2,
					  HWM_USER)) == -1) ||
	    (low_id < idmap_tdb2_state.low_uid)) {
		if (!NT_STATUS_IS_OK(dbwrap_trans_store_int32(
					     idmap_tdb2, HWM_USER,
					     idmap_tdb2_state.low_uid))) {
			DEBUG(0, ("Unable to initialise user hwm in idmap "
				  "database\n"));
			return NT_STATUS_INTERNAL_DB_ERROR;
		}
	}

	if (idmap_tdb2_state.high_gid <= idmap_tdb2_state.low_gid) {
		DEBUG(1, ("idmap gid range missing or invalid\n"));
		DEBUGADD(1, ("idmap will be unable to map foreign SIDs\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (((low_id = dbwrap_fetch_int32(idmap_tdb2,
					  HWM_GROUP)) == -1) ||
	    (low_id < idmap_tdb2_state.low_gid)) {
		if (!NT_STATUS_IS_OK(dbwrap_trans_store_int32(
					     idmap_tdb2, HWM_GROUP,
					     idmap_tdb2_state.low_gid))) {
			DEBUG(0, ("Unable to initialise group hwm in idmap "
				  "database\n"));
			return NT_STATUS_INTERNAL_DB_ERROR;
		}
	}

	return NT_STATUS_OK;
}


/*
  Initialise idmap alloc database. 
*/
static NTSTATUS idmap_tdb2_alloc_init(const char *params)
{
	/* nothing to do - we want to avoid opening the permanent
	   database if possible. Instead we load the params when we
	   first need it. */
	return NT_STATUS_OK;
}


/*
  Allocate a new id. 
*/
static NTSTATUS idmap_tdb2_allocate_id(struct unixid *xid)
{
	bool ret;
	const char *hwmkey;
	const char *hwmtype;
	uint32_t high_hwm;
	uint32_t hwm;
	int res;
	NTSTATUS status;

	status = idmap_tdb2_open_db();
	NT_STATUS_NOT_OK_RETURN(status);

	/* Get current high water mark */
	switch (xid->type) {

	case ID_TYPE_UID:
		hwmkey = HWM_USER;
		hwmtype = "UID";
		high_hwm = idmap_tdb2_state.high_uid;
		break;

	case ID_TYPE_GID:
		hwmkey = HWM_GROUP;
		hwmtype = "GID";
		high_hwm = idmap_tdb2_state.high_gid;
		break;

	default:
		DEBUG(2, ("Invalid ID type (0x%x)\n", xid->type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	res = idmap_tdb2->transaction_start(idmap_tdb2);
	if (res != 0) {
		DEBUG(1,(__location__ " Failed to start transaction\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if ((hwm = dbwrap_fetch_int32(idmap_tdb2, hwmkey)) == -1) {
		idmap_tdb2->transaction_cancel(idmap_tdb2);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	/* check it is in the range */
	if (hwm > high_hwm) {
		DEBUG(1, ("Fatal Error: %s range full!! (max: %lu)\n", 
			  hwmtype, (unsigned long)high_hwm));
		idmap_tdb2->transaction_cancel(idmap_tdb2);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* fetch a new id and increment it */
	ret = dbwrap_change_uint32_atomic(idmap_tdb2, hwmkey, &hwm, 1);
	if (ret == -1) {
		DEBUG(1, ("Fatal error while fetching a new %s value\n!", hwmtype));
		idmap_tdb2->transaction_cancel(idmap_tdb2);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* recheck it is in the range */
	if (hwm > high_hwm) {
		DEBUG(1, ("Fatal Error: %s range full!! (max: %lu)\n", 
			  hwmtype, (unsigned long)high_hwm));
		idmap_tdb2->transaction_cancel(idmap_tdb2);
		return NT_STATUS_UNSUCCESSFUL;
	}

	res = idmap_tdb2->transaction_commit(idmap_tdb2);
	if (res != 0) {
		DEBUG(1,(__location__ " Failed to commit transaction\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	xid->id = hwm;
	DEBUG(10,("New %s = %d\n", hwmtype, hwm));

	return NT_STATUS_OK;
}

/*
  Get current highest id. 
*/
static NTSTATUS idmap_tdb2_get_hwm(struct unixid *xid)
{
	const char *hwmkey;
	const char *hwmtype;
	uint32_t hwm;
	uint32_t high_hwm;
	NTSTATUS status;

	status = idmap_tdb2_open_db();
	NT_STATUS_NOT_OK_RETURN(status);

	/* Get current high water mark */
	switch (xid->type) {

	case ID_TYPE_UID:
		hwmkey = HWM_USER;
		hwmtype = "UID";
		high_hwm = idmap_tdb2_state.high_uid;
		break;

	case ID_TYPE_GID:
		hwmkey = HWM_GROUP;
		hwmtype = "GID";
		high_hwm = idmap_tdb2_state.high_gid;
		break;

	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	if ((hwm = dbwrap_fetch_int32(idmap_tdb2, hwmkey)) == -1) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	xid->id = hwm;

	/* Warn if it is out of range */
	if (hwm >= high_hwm) {
		DEBUG(0, ("Warning: %s range full!! (max: %lu)\n", 
			  hwmtype, (unsigned long)high_hwm));
	}

	return NT_STATUS_OK;
}

/*
  Set high id. 
*/
static NTSTATUS idmap_tdb2_set_hwm(struct unixid *xid)
{
	/* not supported, or we would invalidate the cache tdb on
	   other nodes */
	DEBUG(0,("idmap_tdb2_set_hwm not supported\n"));
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  Close the alloc tdb 
*/
static NTSTATUS idmap_tdb2_alloc_close(void)
{
	/* don't actually close it */
	return NT_STATUS_OK;
}

/*
  IDMAP MAPPING TDB BACKEND
*/
struct idmap_tdb2_context {
	uint32_t filter_low_id;
	uint32_t filter_high_id;
};

/*
  Initialise idmap database. 
*/
static NTSTATUS idmap_tdb2_db_init(struct idmap_domain *dom,
				   const char *params)
{
	NTSTATUS ret;
	struct idmap_tdb2_context *ctx;
	char *config_option = NULL;
	const char *range;
	NTSTATUS status;

	status = idmap_tdb2_open_db();
	NT_STATUS_NOT_OK_RETURN(status);

	ctx = talloc(dom, struct idmap_tdb2_context);
	if ( ! ctx) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	config_option = talloc_asprintf(ctx, "idmap config %s", dom->name);
	if ( ! config_option) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	range = lp_parm_const_string(-1, config_option, "range", NULL);
	if (( ! range) ||
	    (sscanf(range, "%u - %u", &ctx->filter_low_id, &ctx->filter_high_id) != 2) ||
	    (ctx->filter_low_id > ctx->filter_high_id)) {
		ctx->filter_low_id = 0;
		ctx->filter_high_id = 0;
	}

	dom->private_data = ctx;

	talloc_free(config_option);
	return NT_STATUS_OK;

failed:
	talloc_free(ctx);
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
static NTSTATUS idmap_tdb2_script(struct idmap_tdb2_context *ctx, struct id_map *map,
				  const char *fmt, ...)
{
	va_list ap;
	char *cmd;
	FILE *p;
	char line[64];
	unsigned long v;

	cmd = talloc_asprintf(ctx, "%s ", idmap_tdb2_state.idmap_script);
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
				 line, idmap_tdb2_state.idmap_script));
			return NT_STATUS_NONE_MAPPED;			
		}
	} else {
		DEBUG(0,("Bad reply '%s' from idmap script %s\n",
			 line, idmap_tdb2_state.idmap_script));
		return NT_STATUS_NONE_MAPPED;
	}

	return NT_STATUS_OK;
}



/*
  Single id to sid lookup function. 
*/
static NTSTATUS idmap_tdb2_id_to_sid(struct idmap_tdb2_context *ctx, struct id_map *map)
{
	NTSTATUS ret;
	TDB_DATA data;
	char *keystr;
	NTSTATUS status;

	status = idmap_tdb2_open_db();
	NT_STATUS_NOT_OK_RETURN(status);

	if (!ctx || !map) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* apply filters before checking */
	if ((ctx->filter_low_id && (map->xid.id < ctx->filter_low_id)) ||
	    (ctx->filter_high_id && (map->xid.id > ctx->filter_high_id))) {
		DEBUG(5, ("Requested id (%u) out of range (%u - %u). Filtered!\n",
				map->xid.id, ctx->filter_low_id, ctx->filter_high_id));
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

	/* final SAFE_FREE safe */
	data.dptr = NULL;

	if (keystr == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	DEBUG(10,("Fetching record %s\n", keystr));

	/* Check if the mapping exists */
	data = dbwrap_fetch_bystring(idmap_tdb2, keystr, keystr);

	if (!data.dptr) {
		fstring sidstr;

		DEBUG(10,("Record %s not found\n", keystr));
		if (idmap_tdb2_state.idmap_script == NULL) {
			ret = NT_STATUS_NONE_MAPPED;
			goto done;
		}

		ret = idmap_tdb2_script(ctx, map, "IDTOSID %s", keystr);

		/* store it on shared storage */
		if (!NT_STATUS_IS_OK(ret)) {
			goto done;
		}

		if (sid_to_fstring(sidstr, map->sid)) {
			/* both forward and reverse mappings */
			dbwrap_store_bystring(idmap_tdb2, keystr,
					    string_term_tdb_data(sidstr), 
					    TDB_REPLACE);
			dbwrap_store_bystring(idmap_tdb2, sidstr,
					    string_term_tdb_data(keystr), 
					    TDB_REPLACE);
		}
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
static NTSTATUS idmap_tdb2_sid_to_id(struct idmap_tdb2_context *ctx, struct id_map *map)
{
	NTSTATUS ret;
	TDB_DATA data;
	char *keystr;
	unsigned long rec_id = 0;
	NTSTATUS status;

	status = idmap_tdb2_open_db();
	NT_STATUS_NOT_OK_RETURN(status);

	if ((keystr = sid_string_talloc(ctx, map->sid)) == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	DEBUG(10,("Fetching record %s\n", keystr));

	/* Check if sid is present in database */
	data = dbwrap_fetch_bystring(idmap_tdb2, keystr, keystr);
	if (!data.dptr) {
		fstring idstr;

		DEBUG(10,(__location__ " Record %s not found\n", keystr));

		if (idmap_tdb2_state.idmap_script == NULL) {
			ret = NT_STATUS_NONE_MAPPED;
			goto done;
		}
			
		ret = idmap_tdb2_script(ctx, map, "SIDTOID %s", keystr);
		/* store it on shared storage */
		if (!NT_STATUS_IS_OK(ret)) {
			goto done;
		}

		snprintf(idstr, sizeof(idstr), "%cID %lu", 
			 map->xid.type == ID_TYPE_UID?'U':'G',
			 (unsigned long)map->xid.id);
		/* store both forward and reverse mappings */
		dbwrap_store_bystring(idmap_tdb2, keystr, string_term_tdb_data(idstr),
				    TDB_REPLACE);
		dbwrap_store_bystring(idmap_tdb2, idstr, string_term_tdb_data(keystr),
				    TDB_REPLACE);
		goto done;
	}

	/* What type of record is this ? */
	if (sscanf((const char *)data.dptr, "UID %lu", &rec_id) == 1) { /* Try a UID record. */
		map->xid.id = rec_id;
		map->xid.type = ID_TYPE_UID;
		DEBUG(10,("Found uid record %s -> %s \n", keystr, (const char *)data.dptr ));
		ret = NT_STATUS_OK;

	} else if (sscanf((const char *)data.dptr, "GID %lu", &rec_id) == 1) { /* Try a GID record. */
		map->xid.id = rec_id;
		map->xid.type = ID_TYPE_GID;
		DEBUG(10,("Found gid record %s -> %s \n", keystr, (const char *)data.dptr ));
		ret = NT_STATUS_OK;

	} else { /* Unknown record type ! */
		DEBUG(2, ("Found INVALID record %s -> %s\n", keystr, (const char *)data.dptr));
		ret = NT_STATUS_INTERNAL_DB_ERROR;
	}
	
	/* apply filters before returning result */
	if ((ctx->filter_low_id && (map->xid.id < ctx->filter_low_id)) ||
	    (ctx->filter_high_id && (map->xid.id > ctx->filter_high_id))) {
		DEBUG(5, ("Requested id (%u) out of range (%u - %u). Filtered!\n",
				map->xid.id, ctx->filter_low_id, ctx->filter_high_id));
		ret = NT_STATUS_NONE_MAPPED;
	}

done:
	talloc_free(keystr);
	return ret;
}

/*
  lookup a set of unix ids. 
*/
static NTSTATUS idmap_tdb2_unixids_to_sids(struct idmap_domain *dom, struct id_map **ids)
{
	struct idmap_tdb2_context *ctx;
	NTSTATUS ret;
	int i;

	/* initialize the status to avoid suprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}
	
	ctx = talloc_get_type(dom->private_data, struct idmap_tdb2_context);

	for (i = 0; ids[i]; i++) {
		ret = idmap_tdb2_id_to_sid(ctx, ids[i]);
		if ( ! NT_STATUS_IS_OK(ret)) {

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
	}

	ret = NT_STATUS_OK;

done:
	return ret;
}

/*
  lookup a set of sids. 
*/
static NTSTATUS idmap_tdb2_sids_to_unixids(struct idmap_domain *dom, struct id_map **ids)
{
	struct idmap_tdb2_context *ctx;
	NTSTATUS ret;
	int i;

	/* initialize the status to avoid suprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}
	
	ctx = talloc_get_type(dom->private_data, struct idmap_tdb2_context);

	for (i = 0; ids[i]; i++) {
		ret = idmap_tdb2_sid_to_id(ctx, ids[i]);
		if ( ! NT_STATUS_IS_OK(ret)) {

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
	}

	ret = NT_STATUS_OK;

done:
	return ret;
}


/*
  set a mapping. 
*/
static NTSTATUS idmap_tdb2_set_mapping(struct idmap_domain *dom, const struct id_map *map)
{
	struct idmap_tdb2_context *ctx;
	NTSTATUS ret;
	TDB_DATA data;
	char *ksidstr, *kidstr;
	int res;
	bool started_transaction = false;

	if (!map || !map->sid) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ksidstr = kidstr = NULL;

	/* TODO: should we filter a set_mapping using low/high filters ? */
	
	ctx = talloc_get_type(dom->private_data, struct idmap_tdb2_context);

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

	if (!(ksidstr = sid_string_talloc(ctx, map->sid))) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	DEBUG(10, ("Storing %s <-> %s map\n", ksidstr, kidstr));

	res = idmap_tdb2->transaction_start(idmap_tdb2);
	if (res != 0) {
		DEBUG(1,(__location__ " Failed to start transaction\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	started_transaction = true;
	
	/* check wheter sid mapping is already present in db */
	data = dbwrap_fetch_bystring(idmap_tdb2, ksidstr, ksidstr);
	if (data.dptr) {
		ret = NT_STATUS_OBJECT_NAME_COLLISION;
		goto done;
	}

	ret = dbwrap_store_bystring(idmap_tdb2, ksidstr, string_term_tdb_data(kidstr),
				  TDB_INSERT);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0, ("Error storing SID -> ID: %s\n", nt_errstr(ret)));
		goto done;
	}
	ret = dbwrap_store_bystring(idmap_tdb2, kidstr, string_term_tdb_data(ksidstr),
				  TDB_INSERT);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0, ("Error storing ID -> SID: %s\n", nt_errstr(ret)));
		/* try to remove the previous stored SID -> ID map */
		dbwrap_delete_bystring(idmap_tdb2, ksidstr);
		goto done;
	}

	started_transaction = false;

	res = idmap_tdb2->transaction_commit(idmap_tdb2);
	if (res != 0) {
		DEBUG(1,(__location__ " Failed to commit transaction\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	DEBUG(10,("Stored %s <-> %s\n", ksidstr, kidstr));
	ret = NT_STATUS_OK;

done:
	if (started_transaction) {
		idmap_tdb2->transaction_cancel(idmap_tdb2);
	}
	talloc_free(ksidstr);
	talloc_free(kidstr);
	return ret;
}

/*
  remove a mapping. 
*/
static NTSTATUS idmap_tdb2_remove_mapping(struct idmap_domain *dom, const struct id_map *map)
{
	/* not supported as it would invalidate the cache tdb on other
	   nodes */
	DEBUG(0,("idmap_tdb2_remove_mapping not supported\n"));
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  Close the idmap tdb instance
*/
static NTSTATUS idmap_tdb2_close(struct idmap_domain *dom)
{
	/* don't do anything */
	return NT_STATUS_OK;
}


/*
  Dump all mappings out
*/
static NTSTATUS idmap_tdb2_dump_data(struct idmap_domain *dom, struct id_map **maps, int *num_maps)
{
	DEBUG(0,("idmap_tdb2_dump_data not supported\n"));
	return NT_STATUS_NOT_SUPPORTED;
}

static struct idmap_methods db_methods = {
	.init            = idmap_tdb2_db_init,
	.unixids_to_sids = idmap_tdb2_unixids_to_sids,
	.sids_to_unixids = idmap_tdb2_sids_to_unixids,
	.set_mapping     = idmap_tdb2_set_mapping,
	.remove_mapping  = idmap_tdb2_remove_mapping,
	.dump_data       = idmap_tdb2_dump_data,
	.close_fn        = idmap_tdb2_close
};

static struct idmap_alloc_methods db_alloc_methods = {
	.init        = idmap_tdb2_alloc_init,
	.allocate_id = idmap_tdb2_allocate_id,
	.get_id_hwm  = idmap_tdb2_get_hwm,
	.set_id_hwm  = idmap_tdb2_set_hwm,
	.close_fn    = idmap_tdb2_alloc_close
};

NTSTATUS idmap_tdb2_init(void)
{
	NTSTATUS ret;

	/* register both backends */
	ret = smb_register_idmap_alloc(SMB_IDMAP_INTERFACE_VERSION, "tdb2", &db_alloc_methods);
	if (! NT_STATUS_IS_OK(ret)) {
		DEBUG(0, ("Unable to register idmap alloc tdb2 module: %s\n", get_friendly_nt_error_msg(ret)));
		return ret;
	}

	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "tdb2", &db_methods);
}
