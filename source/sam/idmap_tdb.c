/* 
   Unix SMB/CIFS implementation.

   idmap TDB backend

   Copyright (C) Tim Potter 2000
   Copyright (C) Anthony Liguori 2003
   Copyright (C) Simo Sorce 2003
   
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

/* idmap version determines auto-conversion */
#define IDMAP_VERSION 2

/* Globals */
static TDB_CONTEXT *idmap_tdb;

static struct idmap_state {

	/* User and group id pool */

	uid_t uid_low, uid_high;               /* Range of uids to allocate */
	gid_t gid_low, gid_high;               /* Range of gids to allocate */
} idmap_state;

/* Allocate either a user or group id from the pool */
static NTSTATUS db_allocate_id(unid_t *id, int id_type)
{
	BOOL ret;
	int hwm;

	if (!id) return NT_STATUS_INVALID_PARAMETER;

	/* Get current high water mark */
	switch (id_type & ID_TYPEMASK) {
		case ID_USERID:
			if ((hwm = tdb_fetch_int32(idmap_tdb, HWM_USER)) == -1) {
				return NT_STATUS_INTERNAL_DB_ERROR;
			}

			/* check it is in the range */
			if (hwm > idmap_state.uid_high) {
				DEBUG(0, ("idmap Fatal Error: UID range full!! (max: %u)\n", idmap_state.uid_high));
				return NT_STATUS_UNSUCCESSFUL;
			}

			/* fetch a new id and increment it */
			ret = tdb_change_uint32_atomic(idmap_tdb, HWM_USER, &hwm, 1);
			if (!ret) {
				DEBUG(0, ("idmap_tdb: Fatal error while fetching a new id\n!"));
				return NT_STATUS_UNSUCCESSFUL;
			}

			/* recheck it is in the range */
			if (hwm > idmap_state.uid_high) {
				DEBUG(0, ("idmap Fatal Error: UID range full!! (max: %u)\n", idmap_state.uid_high));
				return NT_STATUS_UNSUCCESSFUL;
			}
			
			(*id).uid = hwm;

			break;
		case ID_GROUPID:
			if ((hwm = tdb_fetch_int32(idmap_tdb, HWM_GROUP)) == -1) {
				return NT_STATUS_INTERNAL_DB_ERROR;
			}

			/* check it is in the range */
			if (hwm > idmap_state.gid_high) {
				DEBUG(0, ("idmap Fatal Error: GID range full!! (max: %u)\n", idmap_state.gid_high));
				return NT_STATUS_UNSUCCESSFUL;
			}

			/* fetch a new id and increment it */
			ret = tdb_change_uint32_atomic(idmap_tdb, HWM_GROUP, &hwm, 1);

			if (!ret) {
				DEBUG(0, ("idmap_tdb: Fatal error while fetching a new id\n!"));
				return NT_STATUS_UNSUCCESSFUL;
			}

			/* recheck it is in the range */
			if (hwm > idmap_state.gid_high) {
				DEBUG(0, ("idmap Fatal Error: GID range full!! (max: %u)\n", idmap_state.gid_high));
				return NT_STATUS_UNSUCCESSFUL;
			}
			
			(*id).gid = hwm;
			
			break;
		default:
			return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

/* Set the HWM if necessary */
/* This is not transaction safe, but the tdb should be locked
   in db_set_mapping anyway. */
static NTSTATUS db_adjust_hwm(unid_t id, int id_type)
{
	int32 hwm;

	switch (id_type & ID_TYPEMASK) {
	case ID_USERID:
		hwm = tdb_fetch_int32(idmap_tdb, HWM_USER);
		if (hwm == -1)
			return NT_STATUS_INTERNAL_DB_ERROR;

		if ((id.uid < hwm) || (id.uid > idmap_state.uid_high))
			return NT_STATUS_OK;

		if (tdb_store_int32(idmap_tdb, HWM_USER, id.uid+1) != 0)
			return NT_STATUS_UNSUCCESSFUL;

		break;

	case ID_GROUPID:
		hwm = tdb_fetch_int32(idmap_tdb, HWM_GROUP);
		if (hwm == -1)
			return NT_STATUS_INTERNAL_DB_ERROR;

		if ((id.gid < hwm) || (id.gid > idmap_state.gid_high))
			return NT_STATUS_OK;

		if (tdb_store_int32(idmap_tdb, HWM_GROUP, id.gid+1) != 0)
			return NT_STATUS_UNSUCCESSFUL;

		break;

	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

/* Get a sid from an id */
static NTSTATUS db_get_sid_from_id(DOM_SID *sid, unid_t id, int id_type)
{
	TDB_DATA key, data;
	fstring keystr;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if (!sid) return NT_STATUS_INVALID_PARAMETER;

	switch (id_type & ID_TYPEMASK) {
		case ID_USERID:
			slprintf(keystr, sizeof(keystr), "UID %d", id.uid);
			break;
		case ID_GROUPID:
			slprintf(keystr, sizeof(keystr), "GID %d", id.gid);
			break;
		default:
			return NT_STATUS_UNSUCCESSFUL;
	}

	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data = tdb_fetch(idmap_tdb, key);

	if (data.dptr) {
		if (string_to_sid(sid, data.dptr)) {
			ret = NT_STATUS_OK;
		}
		SAFE_FREE(data.dptr);
	}

	return ret;
}

/* Get an id from a sid */
static NTSTATUS db_get_id_from_sid(unid_t *id, int *id_type, const DOM_SID *sid)
{
	TDB_DATA data, key;
	fstring keystr;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if (!sid || !id || !id_type) return NT_STATUS_INVALID_PARAMETER;

	/* Check if sid is present in database */
	sid_to_string(keystr, sid);

	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data = tdb_fetch(idmap_tdb, key);

	if (data.dptr) {
		int type = *id_type & ID_TYPEMASK;
		fstring scanstr;

		if (type == ID_EMPTY || type == ID_USERID) {
			/* Parse and return existing uid */
			fstrcpy(scanstr, "UID %d");

			if (sscanf(data.dptr, scanstr, &((*id).uid)) == 1) {
				/* uid ok? */
				if (type == ID_EMPTY) {
					*id_type = ID_USERID;
				}
				ret = NT_STATUS_OK;
				goto idok;
			}
		}

		if (type == ID_EMPTY || type == ID_GROUPID) {
			/* Parse and return existing gid */
			fstrcpy(scanstr, "GID %d");

			if (sscanf(data.dptr, scanstr, &((*id).gid)) == 1) {
				/* gid ok? */
				if (type == ID_EMPTY) {
					*id_type = ID_GROUPID;
				}
				ret = NT_STATUS_OK;
			}
		}
idok:
		SAFE_FREE(data.dptr);

	} else if (!(*id_type & ID_NOMAP) &&
		   (((*id_type & ID_TYPEMASK) == ID_USERID)
		    || (*id_type & ID_TYPEMASK) == ID_GROUPID)) {

		/* Allocate a new id for this sid */
		ret = db_allocate_id(id, *id_type);
		if (NT_STATUS_IS_OK(ret)) {
			fstring keystr2;

			/* Store new id */
			if (*id_type & ID_USERID) {
				slprintf(keystr2, sizeof(keystr2), "UID %d", (*id).uid);
			} else {
				slprintf(keystr2, sizeof(keystr2), "GID %d", (*id).gid);
			}

			data.dptr = keystr2;
			data.dsize = strlen(keystr2) + 1;

			if (tdb_store(idmap_tdb, key, data, TDB_REPLACE) == -1) {
				/* TODO: print tdb error !! */
				return NT_STATUS_UNSUCCESSFUL;
			}
			if (tdb_store(idmap_tdb, data, key, TDB_REPLACE) == -1) {
				/* TODO: print tdb error !! */
				return NT_STATUS_UNSUCCESSFUL;
			}

			ret = NT_STATUS_OK;
		}
	}
	
	return ret;
}

static NTSTATUS db_set_mapping(const DOM_SID *sid, unid_t id, int id_type)
{
	TDB_DATA ksid, kid, data;
	fstring ksidstr;
	fstring kidstr;

	if (!sid) return NT_STATUS_INVALID_PARAMETER;

	sid_to_string(ksidstr, sid);

	ksid.dptr = ksidstr;
	ksid.dsize = strlen(ksidstr) + 1;

	if (id_type & ID_USERID) {
		slprintf(kidstr, sizeof(kidstr), "UID %d", id.uid);
	} else if (id_type & ID_GROUPID) {
		slprintf(kidstr, sizeof(kidstr), "GID %d", id.gid);
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}

	kid.dptr = kidstr;
	kid.dsize = strlen(kidstr) + 1;

	/* *DELETE* prevoius mappings if any.
	 * This is done both SID and [U|G]ID passed in */
	
	data = tdb_fetch(idmap_tdb, ksid);
	if (data.dptr) {
		tdb_delete(idmap_tdb, data);
		tdb_delete(idmap_tdb, ksid);
	}
	data = tdb_fetch(idmap_tdb, kid);
	if (data.dptr) {
		tdb_delete(idmap_tdb, data);
		tdb_delete(idmap_tdb, kid);
	}

	if (tdb_store(idmap_tdb, ksid, kid, TDB_INSERT) == -1) {
		DEBUG(0, ("idb_set_mapping: tdb_store 1 error: %s\n", tdb_errorstr(idmap_tdb)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	if (tdb_store(idmap_tdb, kid, ksid, TDB_INSERT) == -1) {
		DEBUG(0, ("idb_set_mapping: tdb_store 2 error: %s\n", tdb_errorstr(idmap_tdb)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	return db_adjust_hwm(id, id_type);
}

/*****************************************************************************
 Initialise idmap database. 
*****************************************************************************/
static NTSTATUS db_idmap_init( char *params )
{
	SMB_STRUCT_STAT stbuf;
	char *tdbfile = NULL;
	int32 version;
	BOOL tdb_is_new = False;

	/* use the old database if present */
	if (!file_exist(lock_path("idmap.tdb"), &stbuf)) {
		if (file_exist(lock_path("winbindd_idmap.tdb"), &stbuf)) {
			DEBUG(0, ("idmap_init: using winbindd_idmap.tdb file!\n"));
			tdbfile = strdup(lock_path("winbindd_idmap.tdb"));
			if (!tdbfile) {
				DEBUG(0, ("idmap_init: out of memory!\n"));
				return NT_STATUS_NO_MEMORY;
			}
		} else {
			tdb_is_new = True;
		}
	}
	if (!tdbfile) {
		tdbfile = strdup(lock_path("idmap.tdb"));
		if (!tdbfile) {
			DEBUG(0, ("idmap_init: out of memory!\n"));
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* Open tdb cache */
	if (!(idmap_tdb = tdb_open_log(tdbfile, 0,
				       TDB_DEFAULT, O_RDWR | O_CREAT,
				       0600))) {
		DEBUG(0, ("idmap_init: Unable to open idmap database\n"));
		SAFE_FREE(tdbfile);
		return NT_STATUS_UNSUCCESSFUL;
	}

	SAFE_FREE(tdbfile);

	/* check against earlier versions */
	if (tdb_is_new) {
		/* TODO: delete the file if this fail */
		tdb_store_int32(idmap_tdb, "IDMAP_VERSION", IDMAP_VERSION);
	} else {
		version = tdb_fetch_int32(idmap_tdb, "IDMAP_VERSION");
		if (version != IDMAP_VERSION) {
			DEBUG(0, ("idmap_init: Unable to open idmap database, it's in an old format!\n"));
			return NT_STATUS_INTERNAL_DB_ERROR;
		}
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

static struct idmap_methods db_methods = {

	db_idmap_init,
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
