/*
 * Unix SMB/CIFS implementation. 
 * SMB parameters and setup
 * Copyright (C) Andrew Tridgell   1992-1998
 * Copyright (C) Simo Sorce        2000-2003
 * Copyright (C) Gerald Carter     2000
 * Copyright (C) Jeremy Allison    2001
 * Copyright (C) Andrew Bartlett   2002
 * Copyright (C) Rafal Szczesniak  2004
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

#if 0 /* when made a module use this */

static int tdbsam_debug_level = DBGC_ALL;
#undef DBGC_CLASS
#define DBGC_CLASS tdbsam_debug_level

#else

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

#endif

#define TDBSAM_VERSION	2	/* Most recent TDBSAM version */
#define TDBSAM_VERSION_STRING	"INFO/version"
#define PASSDB_FILE_NAME	"passdb.tdb"
#define USERPREFIX		"USER_"
#define RIDPREFIX		"RID_"
#define PRIVPREFIX		"PRIV_"
#define TRUSTPW_PREFIX		"TRUSTPW_"
#define tdbsamver_t 	int32

struct tdbsam_privates {
	TDB_CONTEXT 	*passwd_tdb;
	TDB_LIST_NODE   *tp_key_list;

	/* retrive-once info */
	const char *tdbsam_location;
};

struct pwent_list {
	struct pwent_list *prev, *next;
	TDB_DATA key;
};
static struct pwent_list *tdbsam_pwent_list;


/**
 * Convert old TDBSAM to the latest version.
 * @param pdb_tdb A pointer to the opened TDBSAM file which must be converted. 
 *                This file must be opened with read/write access.
 * @param from Current version of the TDBSAM file.
 * @return True if the conversion has been successful, false otherwise. 
 **/

static BOOL tdbsam_convert(TDB_CONTEXT *pdb_tdb, tdbsamver_t from) 
{
	const char * vstring = TDBSAM_VERSION_STRING;
	SAM_ACCOUNT *user = NULL;
	const char *prefix = USERPREFIX;
	TDB_DATA 	data, key, old_key;
	uint8		*buf = NULL;
	BOOL 		ret;

	if (pdb_tdb == NULL) {
		DEBUG(0,("tdbsam_convert: Bad TDB Context pointer.\n"));
		return False;
	}

	/* handle a Samba upgrade */
	tdb_lock_bystring(pdb_tdb, vstring, 0);
	
	if (!NT_STATUS_IS_OK(pdb_init_sam(&user))) {
		DEBUG(0,("tdbsam_convert: cannot initialized a SAM_ACCOUNT.\n"));
		return False;
	}

	/* Enumerate all records and convert them */
	key = tdb_firstkey(pdb_tdb);

	while (key.dptr) {
	
		/* skip all non-USER entries (eg. RIDs) */
		while ((key.dsize != 0) && (strncmp(key.dptr, prefix, strlen (prefix)))) {
			old_key = key;
			/* increment to next in line */
			key = tdb_nextkey(pdb_tdb, key);
			SAFE_FREE(old_key.dptr);
		}
	
		if (key.dptr) {
			
			/* read from tdbsam */
			data = tdb_fetch(pdb_tdb, key);
			if (!data.dptr) {
				DEBUG(0,("tdbsam_convert: database entry not found: %s.\n",key.dptr));
				return False;
			}
	
			if (!NT_STATUS_IS_OK(pdb_reset_sam(user))) {
				DEBUG(0,("tdbsam_convert: cannot reset SAM_ACCOUNT.\n"));
				SAFE_FREE(data.dptr);
				return False;
			}
			
			/* unpack the buffer from the former format */
			DEBUG(10,("tdbsam_convert: Try unpacking a record with (key:%s) (version:%d)\n", key.dptr, from));
			switch (from) {
				case 0:
					ret = init_sam_from_buffer_v0(user, (uint8 *)data.dptr, data.dsize);
					break;
				case 1:
					ret = init_sam_from_buffer_v1(user, (uint8 *)data.dptr, data.dsize);
					break;
				case 2:
					ret = init_sam_from_buffer_v2(user, (uint8 *)data.dptr, data.dsize);
					break;
				default:
					/* unknown tdbsam version */
					ret = False;
			}
			if (!ret) {
				DEBUG(0,("tdbsam_convert: Bad SAM_ACCOUNT entry returned from TDB (key:%s) (version:%d)\n", key.dptr, from));
				SAFE_FREE(data.dptr);
				return False;
			}
	
			/* We're finished with the old data. */
			SAFE_FREE(data.dptr);

			/* pack from the buffer into the new format */
			DEBUG(10,("tdbsam_convert: Try packing a record (key:%s) (version:%d)\n", key.dptr, from));
			if ((data.dsize=init_buffer_from_sam (&buf, user, False)) == -1) {
				DEBUG(0,("tdbsam_convert: cannot pack the SAM_ACCOUNT into the new format\n"));
				SAFE_FREE(data.dptr);
				return False;
			}
			data.dptr = (char *)buf;
			
			/* Store the buffer inside the TDBSAM */
			if (tdb_store(pdb_tdb, key, data, TDB_MODIFY) != TDB_SUCCESS) {
				DEBUG(0,("tdbsam_convert: cannot store the SAM_ACCOUNT (key:%s) in new format\n",key.dptr));
				SAFE_FREE(data.dptr);
				return False;
			}
			
			SAFE_FREE(data.dptr);
			
			/* increment to next in line */
			old_key = key;
			key = tdb_nextkey(pdb_tdb, key);
			SAFE_FREE(old_key.dptr);
		}
		
	}

	pdb_free_sam(&user);
	
	/* upgrade finished */
	tdb_store_int32(pdb_tdb, vstring, TDBSAM_VERSION);
	tdb_unlock_bystring(pdb_tdb, vstring);

	return(True);	
}

/**
 * Open the TDB passwd database, check version and convert it if needed.
 * @param name filename of the tdbsam file.
 * @param open_flags file access mode.
 * @return a TDB_CONTEXT handle on the tdbsam file.
 **/

static TDB_CONTEXT * tdbsam_tdbopen (const char *name, int open_flags)
{
	TDB_CONTEXT 	*pdb_tdb;
	tdbsamver_t	version;
	
	/* Try to open tdb passwd */
	if (!(pdb_tdb = tdb_open_log(name, 0, TDB_DEFAULT, 
				     open_flags, 0600))) {
		DEBUG(0, ("Unable to open/create TDB passwd\n"));
		return NULL;
	}

	/* Check the version */
	version = (tdbsamver_t) tdb_fetch_int32(pdb_tdb, 
						TDBSAM_VERSION_STRING);
	if (version == -1)
		version = 0;	/* Version not found, assume version 0 */
	
	/* Compare the version */
	if (version > TDBSAM_VERSION) {
		/* Version more recent than the latest known */ 
		DEBUG(0, ("TDBSAM version unknown: %d\n", version));
		tdb_close(pdb_tdb);
		pdb_tdb = NULL;
	} 
	else if (version < TDBSAM_VERSION) {
		/* Older version, must be converted */
		DEBUG(1, ("TDBSAM version too old (%d), trying to convert it.\n", version));
		
		/* Reopen the pdb file with read-write access if needed */
		if (!(open_flags & O_RDWR)) {
			DEBUG(10, ("tdbsam_tdbopen: TDB file opened with read only access, reopen it with read-write access.\n"));
			tdb_close(pdb_tdb);
			pdb_tdb = tdb_open_log(name, 0, TDB_DEFAULT, (open_flags & 07777770) | O_RDWR, 0600);
		}
		
		/* Convert */
		if (!tdbsam_convert(pdb_tdb, version)){
			DEBUG(0, ("tdbsam_tdbopen: Error when trying to convert tdbsam: %s\n",name));
			tdb_close(pdb_tdb);
			pdb_tdb = NULL;
		} else {
			DEBUG(1, ("TDBSAM converted successfully.\n"));
		}

		/* Reopen the pdb file as it must be */
		if (!(open_flags & O_RDWR)) {
			tdb_close(pdb_tdb);
			pdb_tdb = tdb_open_log(name, 0, TDB_DEFAULT, open_flags, 0600);
		}
	}
	
	return pdb_tdb;
}

/*****************************************************************************
 Utility functions to close the tdb sam database
 ****************************************************************************/

static void tdbsam_tdbclose ( struct tdbsam_privates *state )
{
	if ( !state )
		return;
		
	if ( state->passwd_tdb ) {
		tdb_close( state->passwd_tdb );
		state->passwd_tdb = NULL;
	}
	
	return;
		
}

/****************************************************************************
 creates a list of user keys
****************************************************************************/

static int tdbsam_traverse_setpwent(TDB_CONTEXT *t, TDB_DATA key, TDB_DATA data, void *state)
{
	const char *prefix = USERPREFIX;
	int  prefixlen = strlen (prefix);
	struct pwent_list *ptr;
	
	if ( strncmp(key.dptr, prefix, prefixlen) == 0 ) {
		if ( !(ptr=(struct pwent_list*)malloc(sizeof(struct pwent_list))) ) {
			DEBUG(0,("tdbsam_traverse_setpwent: Failed to malloc new entry for list\n"));
			
			/* just return 0 and let the traversal continue */
			return 0;
		}
		ZERO_STRUCTP(ptr);
		
		/* save a copy of the key */
		
		ptr->key.dptr = memdup( key.dptr, key.dsize );
		ptr->key.dsize = key.dsize;
		
		DLIST_ADD( tdbsam_pwent_list, ptr );
	
	}
	
	
	return 0;
}

/***************************************************************
 Open the TDB passwd database for SAM account enumeration.
 Save a list of user keys for iteration.
****************************************************************/

static NTSTATUS tdbsam_setsampwent(struct pdb_methods *my_methods, BOOL update)
{
	uint32 flags = update ? (O_RDWR|O_CREAT) : O_RDONLY;
	
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	
	if ( !(tdb_state->passwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, flags )) ) 
		return NT_STATUS_UNSUCCESSFUL;

	tdb_traverse( tdb_state->passwd_tdb, tdbsam_traverse_setpwent, NULL );
	
	return NT_STATUS_OK;
}


/***************************************************************
 End enumeration of the TDB passwd list.
****************************************************************/

static void tdbsam_endsampwent(struct pdb_methods *my_methods)
{
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	struct pwent_list *ptr, *ptr_next;
	
	tdbsam_tdbclose( tdb_state );
	
	/* clear out any remaining entries in the list */
	
	for ( ptr=tdbsam_pwent_list; ptr; ptr = ptr_next ) {
		ptr_next = ptr->next;
		DLIST_REMOVE( tdbsam_pwent_list, ptr );
		SAFE_FREE( ptr->key.dptr);
		SAFE_FREE( ptr );
	}
	
	DEBUG(7, ("endtdbpwent: closed sam database.\n"));
}

/*****************************************************************
 Get one SAM_ACCOUNT from the TDB (next in line)
*****************************************************************/

static NTSTATUS tdbsam_getsampwent(struct pdb_methods *my_methods, SAM_ACCOUNT *user)
{
	NTSTATUS 		nt_status = NT_STATUS_UNSUCCESSFUL;
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_DATA 		data;
	struct pwent_list	*pkey;
	
	if ( !user ) {
		DEBUG(0,("tdbsam_getsampwent: SAM_ACCOUNT is NULL.\n"));
		return nt_status;
	}

	if ( !tdbsam_pwent_list ) {
		DEBUG(4,("tdbsam_getsampwent: end of list\n"));
		tdbsam_tdbclose( tdb_state );
		return nt_status;
	}
	
	if ( !tdb_state->passwd_tdb ) {
		if ( !(tdb_state->passwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, O_RDONLY)) )
			return nt_status;
	}

	/* pull the next entry */
		
	pkey = tdbsam_pwent_list;
	DLIST_REMOVE( tdbsam_pwent_list, pkey );
	
	data = tdb_fetch(tdb_state->passwd_tdb, pkey->key);

	SAFE_FREE( pkey->key.dptr);
	SAFE_FREE( pkey);
	
	if (!data.dptr) {
		DEBUG(5,("pdb_getsampwent: database entry not found.  Was the user deleted?\n"));
		return nt_status;
	}
  
	if (!init_sam_from_buffer(user, (unsigned char *)data.dptr, data.dsize)) {
		DEBUG(0,("pdb_getsampwent: Bad SAM_ACCOUNT entry returned from TDB!\n"));
	}
	
	SAFE_FREE( data.dptr );
	

	return NT_STATUS_OK;
}

/******************************************************************
 Lookup a name in the SAM TDB
******************************************************************/

static NTSTATUS tdbsam_getsampwnam (struct pdb_methods *my_methods, SAM_ACCOUNT *user, const char *sname)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_CONTEXT 	*pwd_tdb;
	TDB_DATA 	data, key;
	fstring 	keystr;
	fstring		name;

	if ( !user ) {
		DEBUG(0,("pdb_getsampwnam: SAM_ACCOUNT is NULL.\n"));
		return nt_status;
	}

	/* Data is stored in all lower-case */
	fstrcpy(name, sname);
	strlower_m(name);

	/* set search key */
	slprintf(keystr, sizeof(keystr)-1, "%s%s", USERPREFIX, name);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	/* open the accounts TDB */
	if (!(pwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, O_RDONLY))) {
	
		if (errno == ENOENT) {
			/*
			 * TDB file doesn't exist, so try to create new one. This is useful to avoid
			 * confusing error msg when adding user account first time
			 */
			if (!(pwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, O_CREAT ))) {
				DEBUG(0, ("pdb_getsampwnam: TDB passwd (%s) did not exist. File successfully created.\n",
				          tdb_state->tdbsam_location));
			} else {
				DEBUG(0, ("pdb_getsampwnam: TDB passwd (%s) does not exist. Couldn't create new one. Error was: %s\n",
				          tdb_state->tdbsam_location, strerror(errno)));
			}
			
			/* requested user isn't there anyway */
			nt_status = NT_STATUS_NO_SUCH_USER;
			return nt_status;
		}
		DEBUG(0, ("pdb_getsampwnam: Unable to open TDB passwd (%s)!\n", tdb_state->tdbsam_location));
		return nt_status;
	}

	/* get the record */
	data = tdb_fetch(pwd_tdb, key);
	if (!data.dptr) {
		DEBUG(5,("pdb_getsampwnam (TDB): error fetching database.\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		tdb_close(pwd_tdb);
		return nt_status;
	}
  
  	/* unpack the buffer */
	if (!init_sam_from_buffer(user, (unsigned char *)data.dptr, data.dsize)) {
		DEBUG(0,("pdb_getsampwent: Bad SAM_ACCOUNT entry returned from TDB!\n"));
		SAFE_FREE(data.dptr);
		tdb_close(pwd_tdb);
		return nt_status;
	}
	SAFE_FREE(data.dptr);

	/* no further use for database, close it now */
	tdb_close(pwd_tdb);
	
	return NT_STATUS_OK;
}

/***************************************************************************
 Search by rid
 **************************************************************************/

static NTSTATUS tdbsam_getsampwrid (struct pdb_methods *my_methods, SAM_ACCOUNT *user, uint32 rid)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_CONTEXT 		*pwd_tdb;
	TDB_DATA 		data, key;
	fstring 		keystr;
	fstring			name;
	
	if (user==NULL) {
		DEBUG(0,("pdb_getsampwrid: SAM_ACCOUNT is NULL.\n"));
		return nt_status;
	}

	/* set search key */
	slprintf(keystr, sizeof(keystr)-1, "%s%.8x", RIDPREFIX, rid);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;

	/* open the accounts TDB */
	if (!(pwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, O_RDONLY))) {
		DEBUG(0, ("pdb_getsampwrid: Unable to open TDB rid database!\n"));
		return nt_status;
	}

	/* get the record */
	data = tdb_fetch (pwd_tdb, key);
	if (!data.dptr) {
		DEBUG(5,("pdb_getsampwrid (TDB): error looking up RID %d by key %s.\n", rid, keystr));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close (pwd_tdb);
		return nt_status;
	}


	fstrcpy(name, data.dptr);
	SAFE_FREE(data.dptr);
	
	tdb_close (pwd_tdb);
	
	return tdbsam_getsampwnam (my_methods, user, name);
}

static NTSTATUS tdbsam_getsampwsid(struct pdb_methods *my_methods, SAM_ACCOUNT * user, const DOM_SID *sid)
{
	uint32 rid;
	if (!sid_peek_check_rid(get_global_sam_sid(), sid, &rid))
		return NT_STATUS_UNSUCCESSFUL;
	return tdbsam_getsampwrid(my_methods, user, rid);
}

/***************************************************************************
 Delete a SAM_ACCOUNT
****************************************************************************/

static NTSTATUS tdbsam_delete_sam_account(struct pdb_methods *my_methods, SAM_ACCOUNT *sam_pass)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_CONTEXT 	*pwd_tdb;
	TDB_DATA 	key;
	fstring 	keystr;
	uint32		rid;
	fstring		name;
	
	fstrcpy(name, pdb_get_username(sam_pass));
	strlower_m(name);
	
	/* open the TDB */
	if (!(pwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, O_RDWR))) {
		DEBUG(0, ("Unable to open TDB passwd!"));
		return nt_status;
	}
  
  	/* set the search key */
	slprintf(keystr, sizeof(keystr)-1, "%s%s", USERPREFIX, name);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;
	
	rid = pdb_get_user_rid(sam_pass);

	/* it's outaa here!  8^) */
	if (tdb_delete(pwd_tdb, key) != TDB_SUCCESS) {
		DEBUG(5, ("Error deleting entry from tdb passwd database!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close(pwd_tdb); 
		return nt_status;
	}	

	/* delete also the RID key */

  	/* set the search key */
	slprintf(keystr, sizeof(keystr)-1, "%s%.8x", RIDPREFIX, rid);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;

	/* it's outaa here!  8^) */
	if (tdb_delete(pwd_tdb, key) != TDB_SUCCESS) {
		DEBUG(5, ("Error deleting entry from tdb rid database!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close(pwd_tdb); 
		return nt_status;
	}
	
	tdb_close(pwd_tdb);
	
	return NT_STATUS_OK;
}

/***************************************************************************
 Update the TDB SAM
****************************************************************************/

static BOOL tdb_update_sam(struct pdb_methods *my_methods, SAM_ACCOUNT* newpwd, int flag)
{
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_CONTEXT 	*pwd_tdb = NULL;
	TDB_DATA 	key, data;
	uint8		*buf = NULL;
	fstring 	keystr;
	fstring		name;
	BOOL		ret = True;
	uint32		user_rid;

	/* invalidate the existing TDB iterator if it is open */
	
	if (tdb_state->passwd_tdb) {
		tdb_close(tdb_state->passwd_tdb);
		tdb_state->passwd_tdb = NULL;
	}

 	/* open the account TDB passwd*/
	
	pwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, O_RDWR | O_CREAT);
	
  	if (!pwd_tdb) {
		DEBUG(0, ("tdb_update_sam: Unable to open TDB passwd (%s)!\n", 
			tdb_state->tdbsam_location));
		return False;
	}

	if (!pdb_get_group_rid(newpwd)) {
		DEBUG (0,("tdb_update_sam: Failing to store a SAM_ACCOUNT for [%s] without a primary group RID\n",
			pdb_get_username(newpwd)));
		ret = False;
		goto done;
	}

	if ( !(user_rid = pdb_get_user_rid(newpwd)) ) {
		DEBUG(0,("tdb_update_sam: SAM_ACCOUNT (%s) with no RID!\n", pdb_get_username(newpwd)));
		ret = False;
		goto done;
	}

	/* copy the SAM_ACCOUNT struct into a BYTE buffer for storage */
	if ((data.dsize=init_buffer_from_sam (&buf, newpwd, False)) == -1) {
		DEBUG(0,("tdb_update_sam: ERROR - Unable to copy SAM_ACCOUNT info BYTE buffer!\n"));
		ret = False;
		goto done;
	}
	data.dptr = (char *)buf;

	fstrcpy(name, pdb_get_username(newpwd));
	strlower_m(name);
	
	DEBUG(5, ("Storing %saccount %s with RID %d\n", flag == TDB_INSERT ? "(new) " : "", name, user_rid));

  	/* setup the USER index key */
	slprintf(keystr, sizeof(keystr)-1, "%s%s", USERPREFIX, name);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	/* add the account */
	if (tdb_store(pwd_tdb, key, data, flag) != TDB_SUCCESS) {
		DEBUG(0, ("Unable to modify passwd TDB!"));
		DEBUGADD(0, (" Error: %s", tdb_errorstr(pwd_tdb)));
		DEBUGADD(0, (" occured while storing the main record (%s)\n", keystr));
		ret = False;
		goto done;
	}
	
	/* setup RID data */
	data.dsize = strlen(name) + 1;
	data.dptr = name;

	/* setup the RID index key */
	slprintf(keystr, sizeof(keystr)-1, "%s%.8x", RIDPREFIX, user_rid);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;
	
	/* add the reference */
	if (tdb_store(pwd_tdb, key, data, flag) != TDB_SUCCESS) {
		DEBUG(0, ("Unable to modify TDB passwd !"));
		DEBUGADD(0, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		DEBUGADD(0, (" occured while storing the RID index (%s)\n", keystr));
		ret = False;
		goto done;
	}

done:	
	/* cleanup */
	tdb_close (pwd_tdb);
	SAFE_FREE(buf);
	
	return (ret);	
}

/***************************************************************************
 Modifies an existing SAM_ACCOUNT
****************************************************************************/

static NTSTATUS tdbsam_update_sam_account (struct pdb_methods *my_methods, SAM_ACCOUNT *newpwd)
{
	if (tdb_update_sam(my_methods, newpwd, TDB_MODIFY))
		return NT_STATUS_OK;
	else
		return NT_STATUS_UNSUCCESSFUL;
}

/***************************************************************************
 Adds an existing SAM_ACCOUNT
****************************************************************************/

static NTSTATUS tdbsam_add_sam_account (struct pdb_methods *my_methods, SAM_ACCOUNT *newpwd)
{
	if (tdb_update_sam(my_methods, newpwd, TDB_INSERT))
		return NT_STATUS_OK;
	else
		return NT_STATUS_UNSUCCESSFUL;
}

static void free_private_data(void **vp) 
{
	struct tdbsam_privates **tdb_state = (struct tdbsam_privates **)vp;
	tdbsam_tdbclose(*tdb_state);
	*tdb_state = NULL;

	/* No need to free any further, as it is talloc()ed */
}


/**
 * Start trust passwords enumeration. 
 * Function performs a search for properly prefixed objects.
 *
 * @param methods methods belonging in pdb context (module)
 * @return nt status of performed operation
 **/

static NTSTATUS tdbsam_settrustpwent(struct pdb_methods *methods)
{
	TDB_CONTEXT *secrets_tdb = secrets_open();
	char* trustpw_pattern;
	struct tdbsam_privates *priv;
	
	if (!methods)
		return NT_STATUS_UNSUCCESSFUL;
	
	if (!secrets_tdb) {
		DEBUG(1, ("pdb_settrustpwent: couldn't open secrets.tdb file.\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	priv = (struct tdbsam_privates*) methods->private_data;
	
	DEBUG(7, ("pdb_settrustpwent: opening trust passwords database.\n"));
	asprintf(&trustpw_pattern, "%s*", TRUSTPW_PREFIX);
	priv->tp_key_list = tdb_search_keys(secrets_tdb, trustpw_pattern);
	
	SAFE_FREE(trustpw_pattern);
	return NT_STATUS_OK;
}


static void tdbsam_endtrustpwent(struct pdb_methods *methods)
{
	struct tdbsam_privates *priv;
	
	if (!methods) return;
	
	priv = (struct tdbsam_privates*) methods->private_data;
	tdb_search_list_free(priv->tp_key_list);
	priv->tp_key_list = NULL;
	DEBUG(7, ("pdb_endtrustpwent: closing trust passwords database.\n"));
}


/**
 * Enumerate across trust passwords (machine and interdomain nt/ads)
 *
 * @param methods methods belonging in pdb context (module)
 * @param trust trust password structure
 *
 * @return nt status of performed operation
 **/

static NTSTATUS tdbsam_gettrustpwent(struct pdb_methods *methods, SAM_TRUST_PASSWD *trust)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct tdbsam_privates *priv;
	TDB_LIST_NODE *tp_key;
	TDB_DATA tp_data;
	TDB_CONTEXT *secrets_tdb = secrets_open();

	if (!methods)
		return NT_STATUS_UNSUCCESSFUL;

	if (!secrets_tdb) {
		DEBUG(0, ("pdb_gettrustpwent: couldn't open secrets.tdb file!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	priv = (struct tdbsam_privates*) methods->private_data;

	tp_key = priv->tp_key_list;
	if (!tp_key || !tp_key->node_key.dptr) {
		DEBUG(7, ("pdb_gettrustpwent: end of search keys list.\n"));
		return NT_STATUS_NO_MORE_ENTRIES;
	}

	DLIST_REMOVE(priv->tp_key_list, tp_key);

	tp_data = tdb_fetch(secrets_tdb, tp_key->node_key);
	SAFE_FREE(tp_key->node_key.dptr);
	SAFE_FREE(tp_key);

	if (!tp_data.dptr) {
		DEBUG(5, ("pdb_gettrustpwent: no database entry found. Deleted password ?\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!pdb_init_trustpw_from_buffer(trust, (const char**)&tp_data.dptr,
	                                  tp_data.dsize)) {
		DEBUG(0, ("pdb_gettrustpwent: Bad SAM_TRUST_PASSWD entry returned from TDB!\n"));
	}

	nt_status = STATUS_MORE_ENTRIES;
	SAFE_FREE(tp_data.dptr);
	return nt_status;
}


/**
 * Get trust password by trusted party name
 *
 * @param methods methods belonging to pdb context (module)
 * @param trust trust password structure
 * @param sid trusted party name
 *
 * @return nt status of performed operation
 **/

static NTSTATUS tdbsam_gettrustpwnam(struct pdb_methods *methods, SAM_TRUST_PASSWD *trust,
                                     const char *name)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	char domain_name[32];
	size_t domain_name_len = sizeof(domain_name);
	size_t uni_name_len;
	
	if (!methods) return nt_status;

	if (!trust) {
		DEBUG(0, ("pdb_gettrustpwnam: SAM_TRUST_PASSWD is NULL\n"));
		return nt_status;
	}

	if (!name) {
		DEBUG(0, ("pdb_gettrustpwnam: char *name is NULL\n"));
		return nt_status;
	}

	nt_status = methods->settrustpwent(methods);
	if (!NT_STATUS_IS_OK(nt_status))
		return nt_status;

	DEBUG(7, ("pdb_gettrustpwnam: Searching for trust password %s", name));
	do {
		/* get trust password (next in turn) */
		nt_status = methods->gettrustpwent(methods, trust);
		
		/* convert unicode name and do case insensitive compare source
		   string length is given as byte length, even though it not
		   necessarily corresponds to the actual unicode string length */
		pull_ucs2(NULL, domain_name, trust->private.uni_name, domain_name_len,
		          sizeof(trust->private.uni_name), 0);
		uni_name_len = trust->private.uni_name_len;
		domain_name[uni_name_len > 32 ? 32 : uni_name_len] = 0;

		DEBUG(10, ("Trust password: %s\n", domain_name));
		if (!StrnCaseCmp(domain_name, name, sizeof(domain_name))) {
			DEBUG(7, ("pdb_gettrustpwnam: Trust password %s found!\n", domain_name));
			return NT_STATUS_OK;
		}

	} while (NT_STATUS_EQUAL(nt_status, STATUS_MORE_ENTRIES));

	DEBUG(7, ("pdb_gettrustpwnam: Trust password not found"));	
	methods->endtrustpwent(methods);
	return nt_status;
}


/**
 * Get trust password by trusted party sid
 *
 * @param methods methods belonging to pdb context (module)
 * @param trust trust password structure
 * @param sid trusted party sid
 *
 * @return nt status of performed operation
 **/
 
static NTSTATUS tdbsam_gettrustpwsid(struct pdb_methods *methods, SAM_TRUST_PASSWD *trust,
                                     const DOM_SID *sid)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;	
	
	if (!methods) return nt_status;

	if (!trust) {
		DEBUG(0, ("pdb_gettrustpwsid: SAM_TRUST_PASSWD is NULL\n"));
		return nt_status;
	}

	if (!sid) {
		DEBUG(0, ("pdb_gettrustpwsid: DOM_SID is NULL\n"));
		return nt_status;
	}

	nt_status = methods->settrustpwent(methods);
	if (!NT_STATUS_IS_OK(nt_status))
		return nt_status;

	DEBUG(7, ("pdb_gettrustpwsid: Searching for trust password %s\n", sid_string_static(sid)));
	do {
		nt_status = tdbsam_gettrustpwent(methods, trust);

		DEBUG(10, ("Trust password: %s\n", sid_string_static(&trust->private.domain_sid)));
		if (sid_equal(&trust->private.domain_sid, sid)) {
			DEBUG(7, ("pdb_gettrustpwsid: Trust password %s found!\n",
			          sid_string_static(&trust->private.domain_sid)));
			return NT_STATUS_OK;
		}
	
	} while (NT_STATUS_EQUAL(nt_status, STATUS_MORE_ENTRIES));

	DEBUG(7, ("pdb_gettrustpwsid: Trust password not found"));
	methods->endtrustpwent(methods);
	return nt_status;
}


static NTSTATUS tdb_update_trustpw(const SAM_TRUST_PASSWD *pass, int tdb_flag)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *mem_ctx;
	TDB_CONTEXT *secrets_tdb;
	TDB_DATA key, data;
	
	char* domain = NULL, *tp_key = NULL;
	char* buffer;
	size_t buffer_len;

	secrets_tdb = secrets_open();
	if (!secrets_tdb) {
		DEBUG(1, ("tdb_update_trustpw: couldn't open secrets.tdb file!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	mem_ctx = talloc_init("tdbsam_add_trust_passwd: storing new trust password");
	if (!mem_ctx) {
		DEBUG(0, ("tdb_update_trustpw: couldn't create talloc context. Out of memory ?\n"));
		return NT_STATUS_NO_MEMORY;
	}
		
	/* convert unicode name to char* and create the key for tdb record */
	pull_ucs2_talloc(mem_ctx, &domain, pass->private.uni_name);
	if (!domain) {
		DEBUG(0, ("tdb_update_trustpw: couldn't allocate talloc memory. Out of memory?\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	tp_key = talloc_asprintf(mem_ctx, "%s%s", TRUSTPW_PREFIX, domain);
	if (!tp_key) {
		DEBUG(0, ("tdb_update_trustpw: couldn't allocate talloc memory. Out of memory?\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* prepare storage record */
	buffer_len = pdb_init_buffer_from_trustpw(mem_ctx, &buffer, pass);

	key.dptr   = tp_key;
	key.dsize  = strlen(tp_key);
	data.dptr  = buffer;
	data.dsize = buffer_len;

	/* write the packed structure in secrets.tdb */
	if (tdb_store(secrets_tdb, key, data, tdb_flag) != TDB_SUCCESS) {
		DEBUG(1, ("tdb_update_trustpw: couldn't write SAM_TRUST_PASSWD structure in secrets.tdb!\n"));
		talloc_destroy(mem_ctx);
		return nt_status;
	}

	DEBUG(7, ("tdb_update_trustpw: SAM_TRUST_PASSWD structure stored successfully.\n"));
	nt_status = NT_STATUS_OK;
	talloc_destroy(mem_ctx);
	return nt_status;
}


/**
 * Add new trust password.
 *
 * @param methods methods belonging in pdb context (module)
 * @param trust trust password structure
 *
 * @return nt status of performed operation
 **/

static NTSTATUS tdbsam_add_trust_passwd(struct pdb_methods *methods, const SAM_TRUST_PASSWD *trust)
{
	DEBUG(7, ("pdb_add_trust_passwd: adding new trust password\n"));
	return tdb_update_trustpw(trust, TDB_INSERT);
}


/**
 * Update trust password.
 *
 * @param methods methods belonging in pdb context (module)
 * @param trust trust password structure
 *
 * @return nt status of performed operation
 **/

static NTSTATUS tdbsam_update_trust_passwd(struct pdb_methods *methods, const SAM_TRUST_PASSWD* trust)
{
	DEBUG(7, ("pdb_update_trust_passwd: updating trust password\n"));
	return tdb_update_trustpw(trust, TDB_MODIFY);
}


/**
 * Delete trust password.
 *
 * @param methods methods belonging in pdb context (module)
 * @param trust trust password structure
 *
 * @return nt status of performed operation
 **/

static NTSTATUS tdbsam_delete_trust_passwd(struct pdb_methods *methods, const SAM_TRUST_PASSWD* trust)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	int status;
	TALLOC_CTX *mem_ctx = NULL;
	TDB_CONTEXT *secrets_tdb = NULL;
	TDB_DATA domain_key;
	char *domain = NULL;
	struct trust_passwd_data t;
	
	if (!methods) return nt_status;

	if (!trust) {
		DEBUG(0, ("pdb_delete_trust_passwd: SAM_TRUST_PASSWD is NULL\n"));
		return nt_status;
	}
	t = trust->private;

	secrets_tdb = secrets_open();
	if (!secrets_tdb) {
		DEBUG(1, ("pdb_delete_trust_passwd: couldn't open secrets.tdb file!\n"));
		return nt_status;
	}
	
	mem_ctx = talloc_init("tdbsam_delete_trust_passwd: deleting trust password");
	if (!mem_ctx) {
		DEBUG(0, ("pdb_delete_trust_passwd: couln't create talloc context. Out of memory ?\n"));
		return nt_status;
	}
	
	/* convert unicode name to char* and make sure it's null-terminated */
	pull_ucs2_talloc(mem_ctx, &domain, t.uni_name);
	if (!domain) {
		DEBUG(0, ("pdb_delete_trust_passwd: couldn't allocate talloc memory. Out of memory?\n"));
		return NT_STATUS_NO_MEMORY;
	}

	domain_key.dptr  = talloc_asprintf(mem_ctx, "%s%s", TRUSTPW_PREFIX, domain);
	domain_key.dsize = strlen(TRUSTPW_PREFIX) + t.uni_name_len;
	if (!domain_key.dptr) {
		DEBUG(0, ("pdb_delete_trust_passwd: couldn't allocate talloc memory. Out of memory?\n"));
		return NT_STATUS_NO_MEMORY;
	}

	status = tdb_delete(secrets_tdb, domain_key);
	if (status) {
		DEBUG(0, ("pdb_delete_trust_passwd: couldn't delete %s record from secrets.tdb!\n",
		           domain_key.dptr));
	} else {
		DEBUG(0, ("pdb_delete_trust_passwd: trust password %s successfully deleted\n",
		          domain));
	}

	talloc_destroy(mem_ctx);
	return status ? NT_STATUS_UNSUCCESSFUL : NT_STATUS_OK;
}


static NTSTATUS tdbsam_lsa_create_account(struct pdb_methods *my_methods, const DOM_SID *sid)
{
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_CONTEXT 	*pwd_tdb = NULL;
	TDB_DATA 	key, data;
	fstring 	keystr;
	NTSTATUS	ret = NT_STATUS_UNSUCCESSFUL;
	fstring		sid_str;

	/* invalidate the existing TDB iterator if it is open */
	
	if (tdb_state->passwd_tdb) {
		tdb_close(tdb_state->passwd_tdb);
		tdb_state->passwd_tdb = NULL;
	}

 	/* open the account TDB passwd*/
	
	pwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, O_RDWR | O_CREAT);
	
  	if (!pwd_tdb) {
		DEBUG(0, ("tdb_lsa_create_account: Unable to open TDB passwd (%s)!\n", 
			tdb_state->tdbsam_location));
		return NT_STATUS_UNSUCCESSFUL;
	}

  	/* setup the PRIV index key */
	sid_to_string(sid_str, sid);

	slprintf(keystr, sizeof(keystr)-1, "%s%s", PRIVPREFIX, sid_str);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	/* get the record */
	data = tdb_fetch (pwd_tdb, key);

	/* check if the privilege already exist in the database */
	if (data.dptr != NULL) {
		ret = NT_STATUS_OK;
		goto done;
	}

	data.dptr = strdup("");
	data.dsize = 1;

	/* add the account */
	if (tdb_store(pwd_tdb, key, data, TDB_INSERT) != TDB_SUCCESS) {
		DEBUG(0, ("Unable to modify passwd TDB!"));
		DEBUGADD(0, (" Error: %s", tdb_errorstr(pwd_tdb)));
		DEBUGADD(0, (" occured while storing the main record (%s)\n", keystr));
		goto done;
	}

	ret = NT_STATUS_OK;
	
done:	
	/* cleanup */
	tdb_close (pwd_tdb);
	
	return (ret);	
}

/***************************************************************************
 Add privilege to sid
****************************************************************************/

static NTSTATUS tdbsam_add_privilege_to_sid(struct pdb_methods *my_methods, const char *priv_name, const DOM_SID *sid)
{
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_CONTEXT 	*pwd_tdb = NULL;
	TDB_DATA 	key, data;
	fstring 	keystr;
	NTSTATUS	ret = NT_STATUS_UNSUCCESSFUL;
	fstring		sid_str;
	char		*priv_list = NULL, *s = NULL;
	size_t		str_size;
	int		priv_name_len = strlen(priv_name);
	int		flag;

	/* invalidate the existing TDB iterator if it is open */
	
	if (tdb_state->passwd_tdb) {
		tdb_close(tdb_state->passwd_tdb);
		tdb_state->passwd_tdb = NULL;
	}

 	/* open the account TDB passwd*/
	
	pwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, O_RDWR | O_CREAT);
	
  	if (!pwd_tdb) {
		DEBUG(0, ("tdb_add_privilege_to_sid: Unable to open TDB passwd (%s)!\n", 
			tdb_state->tdbsam_location));
		return NT_STATUS_UNSUCCESSFUL;
	}

  	/* setup the PRIV index key */
	sid_to_string(sid_str, sid);

	slprintf(keystr, sizeof(keystr)-1, "%s%s", PRIVPREFIX, sid_str);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	/* check if the privilege already exist in the database */

	/* get the record */
	data = tdb_fetch (pwd_tdb, key);

	if (data.dptr) {
		char *p;

		/* check the list is not empty */
		if (*(data.dptr)) {
			priv_list = strdup(data.dptr);
			if (!priv_list) {
				DEBUG(0, ("tdbsam_add_privilege_to_sid: Out of Memory!\n"));
				goto done;
			}
		}

		/* check the privilege is not yet there */
		p = data.dptr;

		do {
			p += (p == data.dptr)?0:1;
			if ((StrnCaseCmp(p, priv_name, priv_name_len)) == 0)	{
				ret = NT_STATUS_OK;
				SAFE_FREE(priv_list);
				SAFE_FREE(data.dptr);
				goto done;
			}

		} while ((p = strchr(p, ',')) != NULL);
 
		SAFE_FREE(data.dptr);

		flag = TDB_MODIFY;
	} else {
		/* if sid does not exist create one */
		flag = TDB_INSERT;
	}

	/* add the given privilege */
	if (priv_list) {
		int priv_list_len = strlen(priv_list);
		str_size = priv_list_len + priv_name_len + 2;
		s = realloc(priv_list, str_size);
		if (!s) {
			DEBUG(0, ("tdbsam_add_privilege_to_sid: Out of Memory!\n"));
			ret = NT_STATUS_NO_MEMORY;
			goto done;
		}
		priv_list = s;
		s = &priv_list[priv_list_len];
		snprintf(s, priv_name_len + 2, ",%s", priv_name);

	} else {
		priv_list = strdup(priv_name);
		if (!priv_list) {
			DEBUG(0, ("tdbsam_add_sid_to_privilege: Out of Memory!\n"));
			ret = NT_STATUS_NO_MEMORY;
			goto done;
		}

	}

	/* copy the PRIVILEGE struct into a BYTE buffer for storage */
	data.dsize = strlen(priv_list) + 1;
	data.dptr = priv_list;

	/* add the account */
	if (tdb_store(pwd_tdb, key, data, flag) != TDB_SUCCESS) {
		DEBUG(0, ("Unable to modify passwd TDB!"));
		DEBUGADD(0, (" Error: %s", tdb_errorstr(pwd_tdb)));
		DEBUGADD(0, (" occured while storing the main record (%s)\n", keystr));
		goto done;
	}

	ret = NT_STATUS_OK;
	
done:	
	/* cleanup */
	tdb_close (pwd_tdb);
	SAFE_FREE(priv_list);
	
	return (ret);	
}

/***************************************************************************
 Reomve privilege from sid
****************************************************************************/

static NTSTATUS tdbsam_remove_privilege_from_sid(struct pdb_methods *my_methods, const char *priv_name, const DOM_SID *sid)
{
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_CONTEXT 	*pwd_tdb = NULL;
	TDB_DATA 	key, data;
	fstring 	keystr;
	fstring		name;
	NTSTATUS	ret = NT_STATUS_UNSUCCESSFUL;
	fstring		sid_str;
	char		*priv_list = NULL, *p = NULL;
	int		priv_name_len = strlen(priv_name);

	/* invalidate the existing TDB iterator if it is open */
	
	if (tdb_state->passwd_tdb) {
		tdb_close(tdb_state->passwd_tdb);
		tdb_state->passwd_tdb = NULL;
	}

 	/* open the account TDB passwd*/
	
	pwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, O_RDWR | O_CREAT);
	
  	if (!pwd_tdb) {
		DEBUG(0, ("tdbsam_remove_sid_from_privilege: Unable to open TDB passwd (%s)!\n", 
			tdb_state->tdbsam_location));
		return NT_STATUS_UNSUCCESSFUL;
	}

  	/* setup the PRIV index key */
	sid_to_string(sid_str, sid);

	fstrcpy(name, priv_name);
	strlower_m(name);
	
	slprintf(keystr, sizeof(keystr)-1, "%s%s", PRIVPREFIX, sid_str);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	/* check if the privilege already exist in the database */

	/* get the record */
	data = tdb_fetch (pwd_tdb, key);

	/* if privilege does not exist, just leave */
	if (!data.dptr) {
		ret = NT_STATUS_OK;
		goto done;
	}

	priv_list = strdup(data.dptr);
	SAFE_FREE(data.dptr);
	if (!priv_list) {
		DEBUG(0, ("tdbsam_remove_sid_from_privilege: Out of Memory!\n"));
		goto done;
	}

	/* remove the given privilege */
	p = priv_list;

	do {
		p += (p == priv_list)?0:1;
		if ((StrnCaseCmp(p, priv_name, priv_name_len)) == 0)	{
			break;
		}

	} while ((p = strchr(p, ',')) != NULL);
 
	if (p) {
		char *s;
		s = strchr(p, ',');
		if (s) {
			size_t l = strlen(priv_list) + 1 - (p - priv_list);
			memmove(p, ++s, l);
		} else {
			if (p != priv_list)
				p--;
			*p = '\0';
		}
	} else {
		/* sid not found */
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* copy the PRIVILEGE struct into a BYTE buffer for storage */
	data.dsize = strlen(priv_list) + 1;
	data.dptr = priv_list;

	/* add the account */
	if (tdb_store(pwd_tdb, key, data, TDB_MODIFY) != TDB_SUCCESS) {
		DEBUG(0, ("Unable to modify passwd TDB!"));
		DEBUGADD(0, (" Error: %s", tdb_errorstr(pwd_tdb)));
		DEBUGADD(0, (" occured while storing the main record (%s)\n", keystr));
		goto done;
	}

	ret = NT_STATUS_OK;
	
done:	
	/* cleanup */
	tdb_close (pwd_tdb);
	SAFE_FREE(priv_list);
	
	return (ret);	
}

/***************************************************************************
 get the privilege list for the given list of sids
****************************************************************************/

struct priv_traverse_1 {
	char **sid_list;
	PRIVILEGE_SET *privset;
};

static int tdbsam_traverse_sids(TDB_CONTEXT *t, TDB_DATA key, TDB_DATA data, void *state)
{
	struct priv_traverse_1 *pt = (struct priv_traverse_1 *)state;
	int  prefixlen = strlen(PRIVPREFIX);

	/* check we have a PRIV_+SID entry */
	if (strncmp(key.dptr, PRIVPREFIX, prefixlen) == 0) {

		fstring sid_str;
		int i;
		/* add to privilege_set if any of the sid in the token
		 * contain the privilege */

		fstrcpy(sid_str, &key.dptr[strlen(PRIVPREFIX)]);

		for (i = 0; pt->sid_list[i] != NULL; i++) {
			int len;

			len = MAX(strlen(sid_str), strlen(pt->sid_list[i]));
			if (strncmp(sid_str, pt->sid_list[i], len) == 0) {
				char *c, *s;

				s = data.dptr;
				if (*s != '\0') {

					DEBUG(10, ("sid [%s] found in users sid list\n", pt->sid_list[i]));
					DEBUG(10, ("adding privileges [%s] to the users privilege list\n", data.dptr));

					while ((c = strchr(s, ',')) != NULL) {
						*c = '\0';
					
						add_privilege_by_name(pt->privset, s);
						s = c + 1;
					}
					add_privilege_by_name(pt->privset, s);
				}
			}
		}
	}

	return 0;
}

/***************************************************************************
 get the privilege list for the given list of sids
****************************************************************************/

struct priv_traverse_2 {
	const char *privname;
	DOM_SID **sid_list;
	int *sid_count;
	NTSTATUS status;
};

static int tdbsam_traverse_single_privilege(TDB_CONTEXT *t, TDB_DATA key, TDB_DATA data, void *state)
{
	struct priv_traverse_2 *pt = (struct priv_traverse_2 *)state;
	int  prefixlen = strlen(PRIVPREFIX);
	int privname_len = strlen(pt->privname);

	if (*(data.dptr) == 0) return 0;

	/* check we have a PRIV_+SID entry */
	if (strncmp(key.dptr, PRIVPREFIX, prefixlen) == 0) {

		fstring sid_str;
		char *p;
		BOOL found = False;
		/* add to privilege_set if any of the sid in the token
		 * contain the privilege */

		fstrcpy(sid_str, &key.dptr[strlen(PRIVPREFIX)]);

		p = data.dptr;

		do {
			p += (p == data.dptr)?0:1;
			if ((StrnCaseCmp(p, pt->privname, privname_len)) == 0)	{
				found = True;
				break;
			}

		} while ((p = strchr(p, ',')) != NULL);
 
		if (found) {
			/* add the discovered sid */
			DOM_SID tmpsid;

			if (!string_to_sid(&tmpsid, sid_str)) {
				DEBUG(3, ("Could not convert SID\n"));
				return 0;
			}

			add_sid_to_array(&tmpsid, pt->sid_list, pt->sid_count);

			if (pt->sid_list == NULL) {
				pt->status = NT_STATUS_NO_MEMORY;
				return 1;
			}

			pt->status = NT_STATUS_OK;
		}
	}

	return 0;
}

static int tdbsam_traverse_accounts(TDB_CONTEXT *t, TDB_DATA key, TDB_DATA data, void *state)
{
	struct priv_traverse_2 *pt = (struct priv_traverse_2 *)state;
	int  prefixlen = strlen(PRIVPREFIX);

	if (*(data.dptr) == 0) return 0;

	/* check we have a PRIV_+SID entry */
	if (strncmp(key.dptr, PRIVPREFIX, prefixlen) == 0) {
		/* add the discovered sid */
		DOM_SID tmpsid;

		fstring sid_str;
		/* add to privilege_set if any of the sid in the token
		 * contain the privilege */

		fstrcpy(sid_str, &key.dptr[strlen(PRIVPREFIX)]);

		if (!string_to_sid(&tmpsid, sid_str)) {
			DEBUG(3, ("Could not convert SID\n"));
			return 0;
		}

		add_sid_to_array(&tmpsid, pt->sid_list, pt->sid_count);

		if (pt->sid_list == NULL) {
			pt->status = NT_STATUS_NO_MEMORY;
			return 1;
		}

		pt->status = NT_STATUS_OK;
	}

	return 0;
}

static NTSTATUS tdbsam_get_privilege_set(struct pdb_methods *my_methods, DOM_SID *user_sids, int num_sids, PRIVILEGE_SET *privset)
{
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	TDB_CONTEXT 	*pwd_tdb = NULL;
	struct priv_traverse_1 pt;
	fstring sid_str;
	char **sid_list;
	int i;

	if (!(pwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, O_RDONLY ))) 
		return NT_STATUS_UNSUCCESSFUL;

	sid_list = (char **)malloc(sizeof(char *) * (num_sids + 1));
	for (i = 0; i < num_sids; i++) {
		sid_to_string(sid_str, &user_sids[i]);
		sid_list[i] = strdup(sid_str);
		if ( ! sid_list[i]) {
			ret = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}
	sid_list[i] = NULL;

	pt.sid_list = sid_list;
	pt.privset = privset;
	tdb_traverse(pwd_tdb, tdbsam_traverse_sids, &pt);

	ret = NT_STATUS_OK;

done:
	i = 0;
	while (sid_list[i]) {
		free(sid_list[i]);
		i++;
	}
	free(sid_list);

	tdb_close(pwd_tdb);

	return ret;
}	

static NTSTATUS tdbsam_get_privilege_entry(struct pdb_methods *my_methods, const char *privname, DOM_SID **sid_list, int *sid_count)
{
	TDB_CONTEXT *pwd_tdb = NULL;
	struct priv_traverse_2 pt;
	
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;

	if (!(pwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, O_RDONLY)))
		return NT_STATUS_UNSUCCESSFUL;

	pt.status = NT_STATUS_UNSUCCESSFUL;
	pt.sid_list = sid_list;
	pt.sid_count = sid_count;
	pt.privname = privname;

	tdb_traverse(pwd_tdb, tdbsam_traverse_single_privilege, &pt);

	if (!NT_STATUS_IS_OK(pt.status)) {
		SAFE_FREE(*sid_list);
		*sid_list = NULL;
		*sid_count = 0;
	}

	tdb_close(pwd_tdb);
	return pt.status;
}	

static NTSTATUS tdbsam_lsa_enumerate_accounts(struct pdb_methods *my_methods, DOM_SID **sid_list, int *sid_count)
{
	TDB_CONTEXT *pwd_tdb = NULL;
	struct priv_traverse_2 pt;
	
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;

	if (!(pwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, O_RDONLY)))
		return NT_STATUS_UNSUCCESSFUL;
	pt.status = NT_STATUS_NO_MORE_ENTRIES;
	pt.sid_list = sid_list;
	pt.sid_count = sid_count;
	pt.privname = NULL;

	tdb_traverse(pwd_tdb, tdbsam_traverse_accounts, &pt);

	if (!NT_STATUS_IS_OK(pt.status)) {
		SAFE_FREE(*sid_list);
		*sid_list = NULL;
		*sid_count = 0;
	}

	tdb_close(pwd_tdb);
	return pt.status;
}


/**
 * Init tdbsam backend
 *
 * @param pdb_context initialised passdb context
 * @param pdb_method backend methods structure to be filled with function pointers
 * @param location the backend tdb file location
 *
 * @return nt_status code
 **/

static NTSTATUS pdb_init_tdbsam(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	NTSTATUS nt_status;
	struct tdbsam_privates *tdb_state;

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_methods(pdb_context->mem_ctx, pdb_method))) {
		return nt_status;
	}

	(*pdb_method)->name = "tdbsam";

	(*pdb_method)->setsampwent = tdbsam_setsampwent;
	(*pdb_method)->endsampwent = tdbsam_endsampwent;
	(*pdb_method)->getsampwent = tdbsam_getsampwent;
	(*pdb_method)->getsampwnam = tdbsam_getsampwnam;
	(*pdb_method)->getsampwsid = tdbsam_getsampwsid;
	(*pdb_method)->add_sam_account = tdbsam_add_sam_account;
	(*pdb_method)->update_sam_account = tdbsam_update_sam_account;
	(*pdb_method)->delete_sam_account = tdbsam_delete_sam_account;
	(*pdb_method)->settrustpwent = tdbsam_settrustpwent;
	(*pdb_method)->endtrustpwent = tdbsam_endtrustpwent;
	(*pdb_method)->gettrustpwent = tdbsam_gettrustpwent;
	(*pdb_method)->gettrustpwnam = tdbsam_gettrustpwnam;
	(*pdb_method)->gettrustpwsid = tdbsam_gettrustpwsid;
	(*pdb_method)->add_trust_passwd = tdbsam_add_trust_passwd;
	(*pdb_method)->update_trust_passwd = tdbsam_update_trust_passwd;
	(*pdb_method)->delete_trust_passwd = tdbsam_delete_trust_passwd;
	(*pdb_method)->lsa_create_account = tdbsam_lsa_create_account;
	(*pdb_method)->lsa_enumerate_accounts = tdbsam_lsa_enumerate_accounts;
	(*pdb_method)->add_privilege_to_sid = tdbsam_add_privilege_to_sid;
	(*pdb_method)->remove_privilege_from_sid = tdbsam_remove_privilege_from_sid;
	(*pdb_method)->get_privilege_set = tdbsam_get_privilege_set;
	(*pdb_method)->get_privilege_entry = tdbsam_get_privilege_entry;

	tdb_state = talloc_zero(pdb_context->mem_ctx, sizeof(struct tdbsam_privates));

	if (!tdb_state) {
		DEBUG(0, ("talloc() failed for tdbsam private_data!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (location) {
		tdb_state->tdbsam_location = talloc_strdup(pdb_context->mem_ctx, location);
	} else {
		pstring tdbfile;
		get_private_directory(tdbfile);
		pstrcat(tdbfile, "/");
		pstrcat(tdbfile, PASSDB_FILE_NAME);
		tdb_state->tdbsam_location = talloc_strdup(pdb_context->mem_ctx, tdbfile);
	}

	(*pdb_method)->private_data = tdb_state;

	(*pdb_method)->free_private_data = free_private_data;

	return NT_STATUS_OK;
}

NTSTATUS pdb_tdbsam_init(void)
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "tdbsam", pdb_init_tdbsam);
}
