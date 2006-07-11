/* 
   Unix SMB/CIFS implementation.

   idmap TDB backend

   Copyright (C) Tim Potter 2000
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Simo Sorce 2003
   Copyright (C) Jeremy Allison 2006
   
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

/* High water mark keys */
#define HWM_GROUP  "GROUP HWM"
#define HWM_USER   "USER HWM"

/* Globals */
static TDB_CONTEXT *idmap_tdb;

static struct idmap_state {

	/* User and group id pool */

	uid_t uid_low, uid_high;               /* Range of uids to allocate */
	gid_t gid_low, gid_high;               /* Range of gids to allocate */
} idmap_state;

/**********************************************************************
 Allocate either a user or group id from the pool 
**********************************************************************/
 
static NTSTATUS db_allocate_id(unid_t *id, enum idmap_type id_type)
{
	BOOL ret;
	int hwm;

	/* Get current high water mark */
	switch (id_type) {
		case ID_USERID:

			if ((hwm = tdb_fetch_int32(idmap_tdb, HWM_USER)) == -1) {
				return NT_STATUS_INTERNAL_DB_ERROR;
			}

			/* check it is in the range */
			if (hwm > idmap_state.uid_high) {
				DEBUG(0, ("idmap Fatal Error: UID range full!! (max: %lu)\n", 
					  (unsigned long)idmap_state.uid_high));
				return NT_STATUS_UNSUCCESSFUL;
			}

			/* fetch a new id and increment it */
			ret = tdb_change_uint32_atomic(idmap_tdb, HWM_USER, (unsigned int *)&hwm, 1);
			if (!ret) {
				DEBUG(0, ("idmap_tdb: Fatal error while fetching a new id\n!"));
				return NT_STATUS_UNSUCCESSFUL;
			}

			/* recheck it is in the range */
			if (hwm > idmap_state.uid_high) {
				DEBUG(0, ("idmap Fatal Error: UID range full!! (max: %lu)\n", 
					  (unsigned long)idmap_state.uid_high));
				return NT_STATUS_UNSUCCESSFUL;
			}
			
			(*id).uid = hwm;
			DEBUG(10,("db_allocate_id: ID_USERID (*id).uid = %d\n", (unsigned int)hwm));

			break;
		case ID_GROUPID:
			if ((hwm = tdb_fetch_int32(idmap_tdb, HWM_GROUP)) == -1) {
				return NT_STATUS_INTERNAL_DB_ERROR;
			}

			/* check it is in the range */
			if (hwm > idmap_state.gid_high) {
				DEBUG(0, ("idmap Fatal Error: GID range full!! (max: %lu)\n", 
					  (unsigned long)idmap_state.gid_high));
				return NT_STATUS_UNSUCCESSFUL;
			}

			/* fetch a new id and increment it */
			ret = tdb_change_uint32_atomic(idmap_tdb, HWM_GROUP, (unsigned int *)&hwm, 1);

			if (!ret) {
				DEBUG(0, ("idmap_tdb: Fatal error while fetching a new id\n!"));
				return NT_STATUS_UNSUCCESSFUL;
			}

			/* recheck it is in the range */
			if (hwm > idmap_state.gid_high) {
				DEBUG(0, ("idmap Fatal Error: GID range full!! (max: %lu)\n", 
					  (unsigned long)idmap_state.gid_high));
				return NT_STATUS_UNSUCCESSFUL;
			}
			
			(*id).gid = hwm;
			DEBUG(10,("db_allocate_id: ID_GROUPID (*id).gid = %d\n", (unsigned int)hwm));
			
			break;
		default:
			return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

/* Get a sid from an id - internal non-reverse map checking function. */

static NTSTATUS db_internal_get_sid_from_id(DOM_SID *sid, unid_t id, enum idmap_type id_type)
{
	TDB_DATA key, data;
	TALLOC_CTX *memctx;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((memctx = talloc_new(NULL)) == NULL) {
		DEBUG(0, ("ERROR: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	switch (id_type) {
		case ID_USERID:
			key.dptr = talloc_asprintf(memctx, "UID %lu", (unsigned long)id.uid);
			break;
		case ID_GROUPID:
			key.dptr = talloc_asprintf(memctx, "GID %lu", (unsigned long)id.gid);
			break;
		default:
			ret = NT_STATUS_INVALID_PARAMETER;
			goto done;
	}

	if (key.dptr == NULL) {
		DEBUG(0, ("ERROR: Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	key.dsize = strlen(key.dptr) + 1;

	DEBUG(10,("db_internal_get_sid_from_id: fetching record %s\n", key.dptr));

	data = tdb_fetch(idmap_tdb, key);

	if (data.dptr) {
		if (string_to_sid(sid, data.dptr)) {
			DEBUG(10,("db_internal_get_sid_from_id: fetching record %s -> %s\n", key.dptr, data.dptr ));
			ret = NT_STATUS_OK;
		}
		SAFE_FREE(data.dptr);
	}

done:
	talloc_free(memctx);
	return ret;
}

/* Get an id from a sid - internal non-reverse map checking function. */

static NTSTATUS db_internal_get_id_from_sid(unid_t *id, enum idmap_type *id_type, const DOM_SID *sid)
{
	NTSTATUS ret;
	TDB_DATA key, data;
	TALLOC_CTX *memctx;
	unsigned long rec_id;

	if ((memctx = talloc_new(NULL)) == NULL) {
		DEBUG(0, ("ERROR: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Check if sid is present in database */
	if ((key.dptr = talloc_asprintf(memctx, "%s", sid_string_static(sid))) == NULL) {
		DEBUG(0, ("ERROR: Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	key.dsize = strlen(key.dptr) + 1;

	DEBUG(10,("db_internal_get_id_from_sid: fetching record %s\n", key.dptr));

	data = tdb_fetch(idmap_tdb, key);
	if (!data.dptr) {
		DEBUG(10,("db_internal_get_id_from_sid: record %s not found\n", key.dptr));
		ret = NT_STATUS_NO_SUCH_USER;
		goto done;
	} else {
		DEBUG(10,("db_internal_get_id_from_sid: record %s -> %s\n", key.dptr, data.dptr));
	}

	/* What type of record is this ? */

	/* Try and parse and return a uid */
	if (sscanf(data.dptr, "UID %lu", &rec_id) == 1) {
		id->uid = (uid_t)rec_id;
		*id_type = ID_USERID;
		DEBUG(10,("db_internal_get_id_from_sid: fetching uid record %s -> %s \n",
						key.dptr, data.dptr ));
		ret = NT_STATUS_OK;
	} else if (sscanf(data.dptr, "GID %lu", &rec_id) == 1) { /* Try a GID record. */
		id->gid = (uid_t)rec_id;
		*id_type = ID_GROUPID;
		DEBUG(10,("db_internal_get_id_from_sid: fetching gid record %s -> %s \n",
						key.dptr, data.dptr ));
		ret = NT_STATUS_OK;
	} else {
		/* Unknown record type ! */
		ret = NT_STATUS_INTERNAL_DB_ERROR;
	}
	
	SAFE_FREE(data.dptr);

done:
	talloc_free(memctx);
	return ret;
}

/* Get a sid from an id - internal non-reverse map checking function. */

static NTSTATUS db_get_sid_from_id(DOM_SID *sid, unid_t id, enum idmap_type id_type, int flags)
{
	NTSTATUS ret;
	unid_t tmp_id;
	enum idmap_type tmp_id_type;

	ret = db_internal_get_sid_from_id(sid, id, id_type);

	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	/* Ensure the reverse mapping exists. */

	ret = db_internal_get_id_from_sid(&tmp_id, &tmp_id_type, sid);
	if (NT_STATUS_IS_OK(ret)) {
		/* Check the reverse mapping is the same. */
		if (tmp_id.uid != id.uid || tmp_id_type != id_type) {
			DEBUG(10,("db_get_sid_from_id: reverse mapping mismatch "
				"tmp_id = %u, id = %u, tmp_id_type = %u, id_type = %u\n",
					(unsigned int)tmp_id.uid, (unsigned int)id.uid,
					(unsigned int)tmp_id_type, (unsigned int)id_type ));
			return NT_STATUS_NO_SUCH_USER;
		}
	}

	return ret;
}

/***********************************************************************
 Why is this function internal and not part of the interface ?????
 This *sucks* and is bad design and needs fixing. JRA.
***********************************************************************/

static NTSTATUS db_internal_allocate_new_id_for_sid(unid_t *id, enum idmap_type *id_type, const DOM_SID *sid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	TDB_DATA sid_data;
	TDB_DATA ugid_data;
	TALLOC_CTX *memctx;

	if ((memctx = talloc_new(NULL)) == NULL) {
		DEBUG(0, ("ERROR: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if ((sid_data.dptr = talloc_asprintf(memctx, "%s", sid_string_static(sid))) == NULL) {
		DEBUG(0, ("ERROR: Out of memory!\n"));
		talloc_free(memctx);
		return NT_STATUS_NO_MEMORY;
	}

	sid_data.dsize = strlen(sid_data.dptr) + 1;

	/* Lock the record for this SID. */
	if (tdb_chainlock(idmap_tdb, sid_data) != 0) {
		DEBUG(10,("db_internal_allocate_new_id_for_sid: failed to lock record %s. Error %s\n",
				sid_data.dptr, tdb_errorstr(idmap_tdb) ));
		talloc_free(memctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	do {
		/* Allocate a new id for this sid */
		ret = db_allocate_id(id, *id_type);
		if (!NT_STATUS_IS_OK(ret)) {
			goto done;
		}
			
		/* Store the UID side */
		/* Store new id */
		if (*id_type == ID_USERID) {
			ugid_data.dptr = talloc_asprintf(memctx, "UID %lu",
							(unsigned long)((*id).uid));
		} else {
			ugid_data.dptr = talloc_asprintf(memctx, "GID %lu",
							(unsigned long)((*id).gid));
		}

		if (ugid_data.dptr == NULL) {
			DEBUG(0, ("ERROR: Out of memory!\n"));
			ret = NT_STATUS_NO_MEMORY;
			goto done;
		}

		ugid_data.dsize = strlen(ugid_data.dptr) + 1;
			
		DEBUG(10,("db_internal_allocate_new_id_for_sid: storing %s -> %s\n",
				ugid_data.dptr, sid_data.dptr ));

		if (tdb_store(idmap_tdb, ugid_data, sid_data, TDB_INSERT) != -1) {
			ret = NT_STATUS_OK;
			break;
		}
		if (tdb_error(idmap_tdb) != TDB_ERR_EXISTS) {
			DEBUG(10,("db_internal_allocate_new_id_for_sid: error %s\n", tdb_errorstr(idmap_tdb)));
		}
				
		ret = NT_STATUS_INTERNAL_DB_ERROR;

	} while (tdb_error(idmap_tdb) == TDB_ERR_EXISTS);

	if (NT_STATUS_IS_OK(ret)) {
		DEBUG(10,("db_internal_allocate_new_id_for_sid: storing %s -> %s\n",
			sid_data.dptr, ugid_data.dptr ));

		if (tdb_store(idmap_tdb, sid_data, ugid_data, TDB_REPLACE) == -1) {
			DEBUG(10,("db_internal_allocate_new_id_for_sid: error %s\n", tdb_errorstr(idmap_tdb) ));
			ret = NT_STATUS_INTERNAL_DB_ERROR;
		}
	}

  done:

	tdb_chainunlock(idmap_tdb, sid_data);
	talloc_free(memctx);

	return ret;
}

/***********************************************************************
 Get an id from a sid - urg. This is assuming the *output* parameter id_type
 has been initialized with the correct needed type - ID_USERID or ID_GROUPID.
 This function also allocates new mappings ! WTF ??????
 This *sucks* and is bad design and needs fixing. JRA.
***********************************************************************/

static NTSTATUS db_get_id_from_sid(unid_t *id, enum idmap_type *id_type, const DOM_SID *sid, int flags)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	enum idmap_type tmp_id_type = *id_type;

	DEBUG(10,("db_get_id_from_sid %s\n", sid_string_static(sid)));

	ret = db_internal_get_id_from_sid(id, &tmp_id_type, sid);

	if (NT_STATUS_IS_OK(ret)) {
		DOM_SID sid_tmp;

		/* Check the reverse mapping is the same. Remember *id_type was set as a parameter
		   to this call... */
		if (tmp_id_type != *id_type) {
			DEBUG(10,("db_get_sid_from_id: sid %s reverse mapping mismatch "
				"tmp_id_type = %u, id_type = %u\n",
					sid_string_static(sid),
					(unsigned int)tmp_id_type, (unsigned int)(*id_type) ));
			return NT_STATUS_NO_SUCH_USER;
		}

		ret = db_internal_get_sid_from_id(&sid_tmp, *id, *id_type);
		if (NT_STATUS_IS_OK(ret)) {
			if (!sid_equal(&sid_tmp, sid)) {
				DEBUG(10,("db_get_sid_from_id: sid %s reverse mapping SID mismatch"
					"id = %u, id_type = %u\n",
						sid_string_static(sid),
						(unsigned int)id->uid, (unsigned int)(*id_type) ));
				return NT_STATUS_NO_SUCH_USER;
			}
		}
		return ret;
	}

	if (flags & IDMAP_FLAG_QUERY_ONLY) {
		return ret;
	}

	/* We're in to bad design territory.... This call is now
	   *allocating* and storing a new mapping for sid -> id. This SHOULD
	   NOT BE DONE HERE ! There needs to be a separate upper
	   level call for this... I think the reason this was badly
	   designed this way was the desire to reuse cache code with
	   a tdb idmap implementation. They MUST be separated ! JRA */

	return db_internal_allocate_new_id_for_sid(id, id_type, sid);
}

static NTSTATUS db_set_mapping(const DOM_SID *sid, unid_t id, enum idmap_type id_type)
{
	NTSTATUS ret;
	TDB_DATA ksid, kid, data;
	TALLOC_CTX *memctx;

	DEBUG(10,("db_set_mapping: id_type = 0x%x\n", (unsigned int)id_type));

	if ((memctx = talloc_new(NULL)) == NULL) {
		DEBUG(0, ("ERROR: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if ((ksid.dptr = talloc_asprintf(memctx, "%s", sid_string_static(sid))) == NULL) {
		DEBUG(0, ("ERROR: Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}
	ksid.dsize = strlen(ksid.dptr) + 1;

	if (id_type == ID_USERID) {
		kid.dptr = talloc_asprintf(memctx, "UID %lu", (unsigned long)id.uid);
	} else {
		kid.dptr = talloc_asprintf(memctx, "GID %lu", (unsigned long)id.gid);
	}

	if (kid.dptr == NULL) {
		DEBUG(0, ("ERROR: Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}
	kid.dsize = strlen(kid.dptr) + 1;

	/* *DELETE* prevoius mappings if any.
	 * This is done both SID and [U|G]ID passed in */
	
	/* Lock the record for this SID. */
	if (tdb_chainlock(idmap_tdb, ksid) != 0) {
		DEBUG(10,("db_set_mapping: failed to lock record %s. Error %s\n",
				ksid.dptr, tdb_errorstr(idmap_tdb) ));
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(10,("db_set_mapping: fetching %s\n", ksid.dptr));

	data = tdb_fetch(idmap_tdb, ksid);
	if (data.dptr) {
		DEBUG(10,("db_set_mapping: deleting %s and %s\n", data.dptr, ksid.dptr ));
		tdb_delete(idmap_tdb, data);
		tdb_delete(idmap_tdb, ksid);
		SAFE_FREE(data.dptr);
	}
	data = tdb_fetch(idmap_tdb, kid);
	if (data.dptr) {
		DEBUG(10,("db_set_mapping: deleting %s and %s\n", data.dptr, kid.dptr ));
		tdb_delete(idmap_tdb, data);
		tdb_delete(idmap_tdb, kid);
		SAFE_FREE(data.dptr);
	}

	if (tdb_store(idmap_tdb, ksid, kid, TDB_INSERT) == -1) {
		DEBUG(0, ("idb_set_mapping: tdb_store 1 error: %s\n", tdb_errorstr(idmap_tdb)));
		tdb_chainunlock(idmap_tdb, ksid);
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	if (tdb_store(idmap_tdb, kid, ksid, TDB_INSERT) == -1) {
		DEBUG(0, ("idb_set_mapping: tdb_store 2 error: %s\n", tdb_errorstr(idmap_tdb)));
		tdb_chainunlock(idmap_tdb, ksid);
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	tdb_chainunlock(idmap_tdb, ksid);
	DEBUG(10,("db_set_mapping: stored %s -> %s and %s -> %s\n", ksid.dptr, kid.dptr, kid.dptr, ksid.dptr ));
	ret = NT_STATUS_OK;
done:
	talloc_free(memctx);
	return ret;
}

/*****************************************************************************
 Initialise idmap database. 
*****************************************************************************/

static NTSTATUS db_idmap_init( const char *params )
{
	SMB_STRUCT_STAT stbuf;
	char *tdbfile = NULL;
	int32 version;
	BOOL tdb_is_new = False;

	/* use the old database if present */
	tdbfile = SMB_STRDUP(lock_path("winbindd_idmap.tdb"));
	if (!tdbfile) {
		DEBUG(0, ("idmap_init: out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (!file_exist(tdbfile, &stbuf)) {
		tdb_is_new = True;
	}

	DEBUG(10,("db_idmap_init: Opening tdbfile %s\n", tdbfile ));

	/* Open idmap repository */
	if (!(idmap_tdb = tdb_open_log(tdbfile, 0,
				       TDB_DEFAULT, O_RDWR | O_CREAT,
				       0644))) {
		DEBUG(0, ("idmap_init: Unable to open idmap database\n"));
		SAFE_FREE(tdbfile);
		return NT_STATUS_UNSUCCESSFUL;
	}

	SAFE_FREE(tdbfile);

	if (tdb_is_new) {
		/* the file didn't existed before opening it, let's
		 * store idmap version as nobody else yet opened and
		 * stored it. I do not like this method but didn't
		 * found a way to understand if an opened tdb have
		 * been just created or not --- SSS */
		tdb_store_int32(idmap_tdb, "IDMAP_VERSION", IDMAP_VERSION);
	}

	/* check against earlier versions */
	version = tdb_fetch_int32(idmap_tdb, "IDMAP_VERSION");
	if (version != IDMAP_VERSION) {
		DEBUG(0, ("idmap_init: Unable to open idmap database, it's in an old format!\n"));
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	/* Create high water marks for group and user id */
	if (!lp_idmap_uid(&idmap_state.uid_low, &idmap_state.uid_high)) {
		DEBUG(1, ("idmap uid range missing or invalid\n"));
		DEBUGADD(1, ("idmap will be unable to map foreign SIDs\n"));
	} else {
		if (tdb_fetch_int32(idmap_tdb, HWM_USER) == -1) {
			if (tdb_store_int32(idmap_tdb, HWM_USER, idmap_state.uid_low) == -1) {
				DEBUG(0, ("idmap_init: Unable to initialise user hwm in idmap database\n"));
				return NT_STATUS_INTERNAL_DB_ERROR;
			}
		}
	}

	if (!lp_idmap_gid(&idmap_state.gid_low, &idmap_state.gid_high)) {
		DEBUG(1, ("idmap gid range missing or invalid\n"));
		DEBUGADD(1, ("idmap will be unable to map foreign SIDs\n"));
	} else {
		if (tdb_fetch_int32(idmap_tdb, HWM_GROUP) == -1) {
			if (tdb_store_int32(idmap_tdb, HWM_GROUP, idmap_state.gid_low) == -1) {
				DEBUG(0, ("idmap_init: Unable to initialise group hwm in idmap database\n"));
				return NT_STATUS_INTERNAL_DB_ERROR;
			}
		}
	}

	return NT_STATUS_OK;
}

/* Close the tdb */
static NTSTATUS db_idmap_close(void)
{
	if (idmap_tdb) {
		if (tdb_close(idmap_tdb) == 0) {
			return NT_STATUS_OK;
		} else {
			return NT_STATUS_UNSUCCESSFUL;
		}
	}
	return NT_STATUS_OK;
}


/* Dump status information to log file.  Display different stuff based on
   the debug level:

   Debug Level        Information Displayed
   =================================================================
   0                  Percentage of [ug]id range allocated
   0                  High water marks (next allocated ids)
*/

#define DUMP_INFO 0

static void db_idmap_status(void)
{
	int user_hwm, group_hwm;

	DEBUG(0, ("winbindd idmap status:\n"));

	/* Get current high water marks */

	if ((user_hwm = tdb_fetch_int32(idmap_tdb, HWM_USER)) == -1) {
		DEBUG(DUMP_INFO,
		      ("\tCould not get userid high water mark!\n"));
	}

	if ((group_hwm = tdb_fetch_int32(idmap_tdb, HWM_GROUP)) == -1) {
		DEBUG(DUMP_INFO,
		      ("\tCould not get groupid high water mark!\n"));
	}

	/* Display next ids to allocate */

	if (user_hwm != -1) {
		DEBUG(DUMP_INFO,
		      ("\tNext userid to allocate is %d\n", user_hwm));
	}

	if (group_hwm != -1) {
		DEBUG(DUMP_INFO,
		      ("\tNext groupid to allocate is %d\n", group_hwm));
	}

	/* Display percentage of id range already allocated. */

	if (user_hwm != -1) {
		int num_users = user_hwm - idmap_state.uid_low;
		int total_users =
		    idmap_state.uid_high - idmap_state.uid_low;

		DEBUG(DUMP_INFO,
		      ("\tUser id range is %d%% full (%d of %d)\n",
		       num_users * 100 / total_users, num_users,
		       total_users));
	}

	if (group_hwm != -1) {
		int num_groups = group_hwm - idmap_state.gid_low;
		int total_groups =
		    idmap_state.gid_high - idmap_state.gid_low;

		DEBUG(DUMP_INFO,
		      ("\tGroup id range is %d%% full (%d of %d)\n",
		       num_groups * 100 / total_groups, num_groups,
		       total_groups));
	}

	/* Display complete mapping of users and groups to rids */
}

/**********************************************************************
 Return the TDB_CONTEXT* for winbindd_idmap.  I **really** feel
 dirty doing this, but not so dirty that I want to create another 
 tdb
***********************************************************************/

TDB_CONTEXT *idmap_tdb_handle( void )
{
	if ( idmap_tdb )
		return idmap_tdb;
		
	/* go ahead an open it;  db_idmap_init() doesn't use any params 
	   right now */
	   
	db_idmap_init( NULL );
	if ( idmap_tdb )
		return idmap_tdb;
		
	return NULL;
}

static struct idmap_methods db_methods = {

	db_idmap_init,
	db_allocate_id,
	db_get_sid_from_id,
	db_get_id_from_sid,
	db_set_mapping,
	db_idmap_close,
	db_idmap_status

};

NTSTATUS idmap_tdb_init(void)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "tdb", &db_methods);
}
