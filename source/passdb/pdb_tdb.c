/*
 * Unix SMB/CIFS implementation. 
 * SMB parameters and setup
 * Copyright (C) Andrew Tridgell   1992-1998
 * Copyright (C) Simo Sorce        2000-2003
 * Copyright (C) Gerald Carter     2000-2006
 * Copyright (C) Jeremy Allison    2001
 * Copyright (C) Andrew Bartlett   2002
 * Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2005
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

struct pwent_list {
	struct pwent_list *prev, *next;
	TDB_DATA key;
};
static struct pwent_list *tdbsam_pwent_list;

/* GLOBAL TDB SAM CONTEXT */

static TDB_CONTEXT *tdbsam;
static int ref_count = 0;
static pstring tdbsam_filename;

/**
 * Convert old TDBSAM to the latest version.
 * @param pdb_tdb A pointer to the opened TDBSAM file which must be converted. 
 *                This file must be opened with read/write access.
 * @param from Current version of the TDBSAM file.
 * @return True if the conversion has been successful, false otherwise. 
 **/

static BOOL tdbsam_convert(int32 from) 
{
	const char      *vstring = TDBSAM_VERSION_STRING;
	const char      *prefix = USERPREFIX;
	TDB_DATA 	data, key, old_key;
	uint8		*buf = NULL;
	BOOL 		ret;

	/* handle a Samba upgrade */
	tdb_lock_bystring(tdbsam, vstring, 0);
	
	/* Enumerate all records and convert them */
	key = tdb_firstkey(tdbsam);

	while (key.dptr) {
	
		/* skip all non-USER entries (eg. RIDs) */
		while ((key.dsize != 0) && (strncmp(key.dptr, prefix, strlen (prefix)))) {
			old_key = key;
			/* increment to next in line */
			key = tdb_nextkey(tdbsam, key);
			SAFE_FREE(old_key.dptr);
		}
	
		if (key.dptr) {
			struct samu *user = NULL;

			/* read from tdbsam */
			data = tdb_fetch(tdbsam, key);
			if (!data.dptr) {
				DEBUG(0,("tdbsam_convert: database entry not found: %s.\n",key.dptr));
				return False;
			}
	
			/* unpack the buffer from the former format */
			pdb_init_sam( &user );
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
				DEBUG(0,("tdbsam_convert: Bad struct samu entry returned from TDB (key:%s) (version:%d)\n", key.dptr, from));
				SAFE_FREE(data.dptr);
				TALLOC_FREE(user );
				return False;
			}
	
			/* We're finished with the old data. */
			SAFE_FREE(data.dptr);

			/* pack from the buffer into the new format */
			
			DEBUG(10,("tdbsam_convert: Try packing a record (key:%s) (version:%d)\n", key.dptr, from));
			data.dsize = init_buffer_from_sam (&buf, user, False);
			TALLOC_FREE(user );
			
			if ( data.dsize == -1 ) {
				DEBUG(0,("tdbsam_convert: cannot pack the struct samu into the new format\n"));
				return False;
			}
			data.dptr = (char *)buf;
			
			/* Store the buffer inside the TDBSAM */
			if (tdb_store(tdbsam, key, data, TDB_MODIFY) != TDB_SUCCESS) {
				DEBUG(0,("tdbsam_convert: cannot store the struct samu (key:%s) in new format\n",key.dptr));
				SAFE_FREE(data.dptr);
				return False;
			}
			
			SAFE_FREE(data.dptr);
			
			/* increment to next in line */
			old_key = key;
			key = tdb_nextkey(tdbsam, key);
			SAFE_FREE(old_key.dptr);
		}
		
	}

	
	/* upgrade finished */
	tdb_store_int32(tdbsam, vstring, TDBSAM_VERSION);
	tdb_unlock_bystring(tdbsam, vstring);

	return(True);	
}

/*********************************************************************
 Open the tdbsam file based on the absolute path specified.
 Uses a reference count to allow multiple open calls.
*********************************************************************/

static BOOL tdbsam_open( const char *name )
{
	int32	version;
	
	/* check if we are already open */
	
	if ( tdbsam ) {
		ref_count++;
		DEBUG(8,("tdbsam_open: Incrementing open reference count.  Ref count is now %d\n", 
			ref_count));
		return True;
	}
	
	SMB_ASSERT( ref_count == 0 );
	
	/* Try to open tdb passwd.  Create a new one if necessary */
	
	if (!(tdbsam = tdb_open_log(name, 0, TDB_DEFAULT, O_CREAT|O_RDWR, 0600))) {
		DEBUG(0, ("tdbsam_open: Failed to open/create TDB passwd [%s]\n", name));
		return False;
	}

	/* Check the version */
	version = tdb_fetch_int32( tdbsam, TDBSAM_VERSION_STRING );
	
	if (version == -1)
		version = 0;	/* Version not found, assume version 0 */
	
	/* Compare the version */
	if (version > TDBSAM_VERSION) {
		/* Version more recent than the latest known */ 
		DEBUG(0, ("tdbsam_open: unknown version => %d\n", version));
		tdb_close( tdbsam );
		return False;
	} 
	
	
	if ( version < TDBSAM_VERSION ) {	
		DEBUG(1, ("tdbsam_open: Converting version %d database to version %d.\n", 
			version, TDBSAM_VERSION));
		
		if ( !tdbsam_convert(version) ) {
			DEBUG(0, ("tdbsam_open: Error when trying to convert tdbsam [%s]\n",name));
			tdb_close(tdbsam);
			return False;
		}
			
		DEBUG(3, ("TDBSAM converted successfully.\n"));
	}
	
	/* set the initial reference count */

	ref_count = 1;

	DEBUG(4,("tdbsam_open: successfully opened %s\n", name ));	
	
	return True;
}

/****************************************************************************
 wrapper atound tdb_close() to handle the reference count
****************************************************************************/

void tdbsam_close( void )
{
	ref_count--;
	
	DEBUG(8,("tdbsam_close: Reference count is now %d.\n", ref_count));

	SMB_ASSERT(ref_count >= 0 );
	
	if ( ref_count == 0 ) {
		tdb_close( tdbsam );
		tdbsam = NULL;
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
		if ( !(ptr=SMB_MALLOC_P(struct pwent_list)) ) {
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

static NTSTATUS tdbsam_setsampwent(struct pdb_methods *my_methods, BOOL update, uint16 acb_mask)
{
	if ( !tdbsam_open( tdbsam_filename ) ) {
		DEBUG(0,("tdbsam_getsampwnam: failed to open %s!\n", tdbsam_filename));
		return NT_STATUS_ACCESS_DENIED;
	}

	tdb_traverse( tdbsam, tdbsam_traverse_setpwent, NULL );

	return NT_STATUS_OK;
}


/***************************************************************
 End enumeration of the TDB passwd list.
****************************************************************/

static void tdbsam_endsampwent(struct pdb_methods *my_methods)
{
	struct pwent_list *ptr, *ptr_next;
	
	/* clear out any remaining entries in the list */
	
	for ( ptr=tdbsam_pwent_list; ptr; ptr = ptr_next ) {
		ptr_next = ptr->next;
		DLIST_REMOVE( tdbsam_pwent_list, ptr );
		SAFE_FREE( ptr->key.dptr);
		SAFE_FREE( ptr );
	}
	
	DEBUG(7, ("endtdbpwent: closed sam database.\n"));

	tdbsam_close();
}

/*****************************************************************
 Get one struct samu from the TDB (next in line)
*****************************************************************/

static NTSTATUS tdbsam_getsampwent(struct pdb_methods *my_methods, struct samu *user)
{
	NTSTATUS 		nt_status = NT_STATUS_UNSUCCESSFUL;
	TDB_DATA 		data;
	struct pwent_list	*pkey;

	if ( !user ) {
		DEBUG(0,("tdbsam_getsampwent: struct samu is NULL.\n"));
		return nt_status;
	}

	if ( !tdbsam_pwent_list ) {
		DEBUG(4,("tdbsam_getsampwent: end of list\n"));
		return nt_status;
	}
	
	/* pull the next entry */
		
	pkey = tdbsam_pwent_list;
	DLIST_REMOVE( tdbsam_pwent_list, pkey );
	
	data = tdb_fetch(tdbsam, pkey->key);

	SAFE_FREE( pkey->key.dptr);
	SAFE_FREE( pkey);
	
	if ( !data.dptr ) {
		DEBUG(5,("pdb_getsampwent: database entry not found.  Was the user deleted?\n"));
		return nt_status;
	}
  
	if ( !init_sam_from_buffer(user, (unsigned char *)data.dptr, data.dsize) ) {
		DEBUG(0,("pdb_getsampwent: Bad struct samu entry returned from TDB!\n"));
	}
	
	SAFE_FREE( data.dptr );

	return NT_STATUS_OK;
}

/******************************************************************
 Lookup a name in the SAM TDB
******************************************************************/

static NTSTATUS tdbsam_getsampwnam (struct pdb_methods *my_methods, struct samu *user, const char *sname)
{
	NTSTATUS	result;
	TDB_DATA 	data, key;
	fstring 	keystr;
	fstring		name;

	if ( !user ) {
		DEBUG(0,("pdb_getsampwnam: struct samu is NULL.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Data is stored in all lower-case */
	fstrcpy(name, sname);
	strlower_m(name);

	/* set search key */
	slprintf(keystr, sizeof(keystr)-1, "%s%s", USERPREFIX, name);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	/* open the database */
		
	if ( !tdbsam_open( tdbsam_filename ) ) {
		DEBUG(0,("tdbsam_getsampwnam: failed to open %s!\n", tdbsam_filename));
		return NT_STATUS_ACCESS_DENIED;
	}
	
	/* get the record */
	
	data = tdb_fetch(tdbsam, key);
	if (!data.dptr) {
		DEBUG(5,("pdb_getsampwnam (TDB): error fetching database.\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		result = NT_STATUS_NO_SUCH_USER;
		goto done;
	}
  
  	/* unpack the buffer */
	
	if (!init_sam_from_buffer(user, (unsigned char *)data.dptr, data.dsize)) {
		DEBUG(0,("pdb_getsampwent: Bad struct samu entry returned from TDB!\n"));
		SAFE_FREE(data.dptr);
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}
	
	result = NT_STATUS_OK;
	
 done:
	SAFE_FREE(data.dptr);
	tdbsam_close();
	
	return result;
}

/***************************************************************************
 Search by rid
 **************************************************************************/

static NTSTATUS tdbsam_getsampwrid (struct pdb_methods *my_methods, struct samu *user, uint32 rid)
{
	NTSTATUS                nt_status = NT_STATUS_UNSUCCESSFUL;
	TDB_DATA 		data, key;
	fstring 		keystr;
	fstring			name;

	if ( !user ) {
		DEBUG(0,("pdb_getsampwrid: struct samu is NULL.\n"));
		return nt_status;
	}
	
	/* set search key */
	
	slprintf(keystr, sizeof(keystr)-1, "%s%.8x", RIDPREFIX, rid);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;

	/* open the database */
		
	if ( !tdbsam_open( tdbsam_filename ) ) {
		DEBUG(0,("tdbsam_getsampwnam: failed to open %s!\n", tdbsam_filename));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* get the record */
	
	data = tdb_fetch (tdbsam, key);
	if (!data.dptr) {
		DEBUG(5,("pdb_getsampwrid (TDB): error looking up RID %d by key %s.\n", rid, keystr));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam)));
		nt_status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	fstrcpy(name, data.dptr);
	SAFE_FREE(data.dptr);
	
	nt_status = tdbsam_getsampwnam (my_methods, user, name);

 done:
	/* cleanup */
	
	tdbsam_close();
		
	return nt_status;
}

static NTSTATUS tdbsam_getsampwsid(struct pdb_methods *my_methods, struct samu * user, const DOM_SID *sid)
{
	uint32 rid;
	
	if ( !sid_peek_check_rid(get_global_sam_sid(), sid, &rid) )
		return NT_STATUS_UNSUCCESSFUL;

	return tdbsam_getsampwrid(my_methods, user, rid);
}

static BOOL tdb_delete_samacct_only( struct samu *sam_pass )
{
	TDB_DATA 	key;
	fstring 	keystr;
	fstring		name;

	fstrcpy(name, pdb_get_username(sam_pass));
	strlower_m(name);
	
  	/* set the search key */
	
	slprintf(keystr, sizeof(keystr)-1, "%s%s", USERPREFIX, name);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;
	
	/* it's outaa here!  8^) */
	
	if (tdb_delete(tdbsam, key) != TDB_SUCCESS) {
		DEBUG(5, ("Error deleting entry from tdb passwd database!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam)));
		return False;
	}
	
	return True;
}

/***************************************************************************
 Delete a struct samu records for the username and RID key
****************************************************************************/

static NTSTATUS tdbsam_delete_sam_account(struct pdb_methods *my_methods, struct samu *sam_pass)
{
	NTSTATUS        nt_status = NT_STATUS_UNSUCCESSFUL;
	TDB_DATA 	key;
	fstring 	keystr;
	uint32		rid;
	fstring		name;
	
	/* make sure we have an open handle to the tdb.  Should have happened 
	   at module  initialization time */
	   
	if ( !tdbsam ) {
		DEBUG(0,("tdbsam_getsampwrid: tdbsam not open!\n"));
		return NT_STATUS_NO_SUCH_USER;
	}

	fstrcpy(name, pdb_get_username(sam_pass));
	strlower_m(name);
	
  	/* set the search key */

	slprintf(keystr, sizeof(keystr)-1, "%s%s", USERPREFIX, name);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;
	
	rid = pdb_get_user_rid(sam_pass);

	/* open the database */
		
	if ( !tdbsam_open( tdbsam_filename ) ) {
		DEBUG(0,("tdbsam_getsampwnam: failed to open %s!\n", tdbsam_filename));
		return NT_STATUS_ACCESS_DENIED;
	}
	
	/* it's outaa here!  8^) */

	if ( tdb_delete(tdbsam, key) != TDB_SUCCESS ) {
		DEBUG(5, ("Error deleting entry from tdb passwd database!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam)));
		nt_status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

  	/* set the search key */
	
	slprintf(keystr, sizeof(keystr)-1, "%s%.8x", RIDPREFIX, rid);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;

	/* it's outaa here!  8^) */
	
	if ( tdb_delete(tdbsam, key) != TDB_SUCCESS ) {
		DEBUG(5, ("Error deleting entry from tdb rid database!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam)));
		nt_status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	nt_status = NT_STATUS_OK;
	
 done:
	tdbsam_close();
	
	return nt_status;
}


/***************************************************************************
 Update the TDB SAM account record only
 Assumes that the tdbsam is already open 
****************************************************************************/
static BOOL tdb_update_samacct_only( struct samu* newpwd, int flag )
{
	TDB_DATA 	key, data;
	uint8		*buf = NULL;
	fstring 	keystr;
	fstring		name;
	BOOL		ret = True;

	/* copy the struct samu struct into a BYTE buffer for storage */
	
	if ( (data.dsize=init_buffer_from_sam (&buf, newpwd, False)) == -1 ) {
		DEBUG(0,("tdb_update_sam: ERROR - Unable to copy struct samu info BYTE buffer!\n"));
		ret = False;
		goto done;
	}
	data.dptr = (char *)buf;

	fstrcpy(name, pdb_get_username(newpwd));
	strlower_m(name);
	
	DEBUG(5, ("Storing %saccount %s with RID %d\n", 
		  flag == TDB_INSERT ? "(new) " : "", name, 
		  pdb_get_user_rid(newpwd)));

  	/* setup the USER index key */
	slprintf(keystr, sizeof(keystr)-1, "%s%s", USERPREFIX, name);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	/* add the account */
	
	if ( tdb_store(tdbsam, key, data, flag) != TDB_SUCCESS ) {
		DEBUG(0, ("Unable to modify passwd TDB!"));
		DEBUGADD(0, (" Error: %s", tdb_errorstr(tdbsam)));
		DEBUGADD(0, (" occured while storing the main record (%s)\n",
			     keystr));
		ret = False;
		goto done;
	}

done:	
	/* cleanup */
	SAFE_FREE(buf);
	
	return ret;
}

/***************************************************************************
 Update the TDB SAM RID record only
 Assumes that the tdbsam is already open 
****************************************************************************/
static BOOL tdb_update_ridrec_only( struct samu* newpwd, int flag )
{
	TDB_DATA 	key, data;
	fstring 	keystr;
	fstring		name;

	fstrcpy(name, pdb_get_username(newpwd));
	strlower_m(name);

	/* setup RID data */
	data.dsize = strlen(name) + 1;
	data.dptr = name;

	/* setup the RID index key */
	slprintf(keystr, sizeof(keystr)-1, "%s%.8x", RIDPREFIX,  pdb_get_user_rid(newpwd));
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;
	
	/* add the reference */
	if (tdb_store(tdbsam, key, data, flag) != TDB_SUCCESS) {
		DEBUG(0, ("Unable to modify TDB passwd !"));
		DEBUGADD(0, (" Error: %s\n", tdb_errorstr(tdbsam)));
		DEBUGADD(0, (" occured while storing the RID index (%s)\n", keystr));
		return False;
	}

	return True;

}

/***************************************************************************
 Update the TDB SAM
****************************************************************************/

static BOOL tdb_update_sam(struct pdb_methods *my_methods, struct samu* newpwd, int flag)
{
	uint32		user_rid;
	BOOL            result = True;

	/* invalidate the existing TDB iterator if it is open */
	
	tdbsam_endsampwent( my_methods );
	
	if ( !pdb_get_group_rid(newpwd) ) {
		DEBUG (0,("tdb_update_sam: Failing to store a struct samu for [%s] "
			"without a primary group RID\n", pdb_get_username(newpwd)));
		return False;
	}

	if ( !(user_rid = pdb_get_user_rid(newpwd)) ) {
		DEBUG(0,("tdb_update_sam: struct samu (%s) with no RID!\n", pdb_get_username(newpwd)));
		return False;
	}

	/* open the database */
		
	if ( !tdbsam_open( tdbsam_filename ) ) {
		DEBUG(0,("tdbsam_getsampwnam: failed to open %s!\n", tdbsam_filename));
		return False;
	}
	
	if ( !tdb_update_samacct_only(newpwd, flag) || !tdb_update_ridrec_only(newpwd, flag)) {
		result = False;
	}

	/* cleanup */

	tdbsam_close();
	
	return result;	
}

/***************************************************************************
 Modifies an existing struct samu
****************************************************************************/

static NTSTATUS tdbsam_update_sam_account (struct pdb_methods *my_methods, struct samu *newpwd)
{
	if ( !tdb_update_sam(my_methods, newpwd, TDB_MODIFY) )
		return NT_STATUS_UNSUCCESSFUL;
	
	return NT_STATUS_OK;
}

/***************************************************************************
 Adds an existing struct samu
****************************************************************************/

static NTSTATUS tdbsam_add_sam_account (struct pdb_methods *my_methods, struct samu *newpwd)
{
	if ( !tdb_update_sam(my_methods, newpwd, TDB_INSERT) )
		return NT_STATUS_UNSUCCESSFUL;
		
	return NT_STATUS_OK;
}

/***************************************************************************
 Renames a struct samu
 - check for the posix user/rename user script
 - Add and lock the new user record
 - rename the posix user
 - rewrite the rid->username record
 - delete the old user
 - unlock the new user record
***************************************************************************/
static NTSTATUS tdbsam_rename_sam_account(struct pdb_methods *my_methods,
					  struct samu *old_acct, 
					  const char *newname)
{
	struct samu      *new_acct = NULL;
	pstring          rename_script;
	BOOL             interim_account = False;
	int              rename_ret;

	/* make sure we have an open handle to the tdb.  Should have happened 
	   at module  initialization time */
	   
	if ( !tdbsam ) {
		DEBUG(0,("tdbsam_getsampwrid: tdbsam not open!\n"));
		return NT_STATUS_NO_SUCH_USER;
	}
	
	/* can't do anything without an external script */
	
	pstrcpy(rename_script, lp_renameuser_script() );
	if ( ! *rename_script )
		return NT_STATUS_ACCESS_DENIED;

	/* invalidate the existing TDB iterator if it is open */
	
	tdbsam_endsampwent( my_methods );

	if ( !pdb_copy_sam_account(old_acct, &new_acct) 
		|| !pdb_set_username(new_acct, newname, PDB_CHANGED)) 
	{
		TALLOC_FREE(new_acct );
		return NT_STATUS_NO_MEMORY;
	}

	/* open the database */
		
	if ( !tdbsam_open( tdbsam_filename ) ) {
		DEBUG(0,("tdbsam_getsampwnam: failed to open %s!\n", tdbsam_filename));
		TALLOC_FREE(new_acct );
		return NT_STATUS_ACCESS_DENIED;
	}

	/* add the new account and lock it */
	
	if ( !tdb_update_samacct_only(new_acct, TDB_INSERT) ) 
	{
		goto done;
	}
	
	interim_account = True;

	if ( tdb_lock_bystring(tdbsam, newname, 30) == -1 ) {
		goto done;
	}

	/* rename the posix user */
	
	pstring_sub(rename_script, "%unew", newname);
	pstring_sub(rename_script, "%uold", pdb_get_username(old_acct));
	rename_ret = smbrun(rename_script, NULL);

	DEBUG(rename_ret ? 0 : 3,("Running the command `%s' gave %d\n", rename_script, rename_ret));

	if (rename_ret) 
		goto done; 

	/* rewrite the rid->username record */
	
	if ( !tdb_update_ridrec_only( new_acct, TDB_MODIFY) )
		goto done;
	interim_account = False;
	tdb_unlock_bystring( tdbsam, newname );

	tdb_delete_samacct_only( old_acct );
	
	tdbsam_close();
	
	TALLOC_FREE(new_acct );
	return NT_STATUS_OK;

done:	
	/* cleanup */
	if (interim_account) {
		tdb_unlock_bystring(tdbsam, newname);
		tdb_delete_samacct_only(new_acct);
	}
	
	tdbsam_close();
	
	if (new_acct)
		TALLOC_FREE(new_acct);
	
	return NT_STATUS_ACCESS_DENIED;	
}

static BOOL tdbsam_rid_algorithm(struct pdb_methods *methods)
{
	return False;
}

/*
 * Historically, winbind was responsible for allocating RIDs, so the next RID
 * value was stored in winbindd_idmap.tdb. It has been moved to passdb now,
 * but for compatibility reasons we still keep the the next RID counter in
 * winbindd_idmap.tdb.
 */

/*****************************************************************************
 Initialise idmap database. For now (Dec 2005) this is a copy of the code in
 sam/idmap_tdb.c. Maybe at a later stage we can remove that capability from
 winbind completely and store the RID counter in passdb.tdb.

 Dont' fully initialize with the HWM values, if it's new, we're only
 interested in the RID counter.
*****************************************************************************/

static BOOL init_idmap_tdb(TDB_CONTEXT *tdb)
{
	int32 version;

	if (tdb_lock_bystring(tdb, "IDMAP_VERSION", 0) != 0) {
		DEBUG(0, ("Could not lock IDMAP_VERSION\n"));
		return False;
	}

	version = tdb_fetch_int32(tdb, "IDMAP_VERSION");

	if (version == -1) {
		/* No key found, must be a new db */
		if (tdb_store_int32(tdb, "IDMAP_VERSION",
				    IDMAP_VERSION) != 0) {
			DEBUG(0, ("Could not store IDMAP_VERSION\n"));
			tdb_unlock_bystring(tdb, "IDMAP_VERSION");
			return False;
		}
		version = IDMAP_VERSION;
	}

	if (version != IDMAP_VERSION) {
		DEBUG(0, ("Expected IDMAP_VERSION=%d, found %d. Please "
			  "start winbind once\n", IDMAP_VERSION, version));
		tdb_unlock_bystring(tdb, "IDMAP_VERSION");
		return False;
	}

	tdb_unlock_bystring(tdb, "IDMAP_VERSION");
	return True;
}

static BOOL tdbsam_new_rid(struct pdb_methods *methods, uint32 *prid)
{
	TDB_CONTEXT *tdb;
	uint32 rid;
	BOOL ret = False;

	tdb = tdb_open_log(lock_path("winbindd_idmap.tdb"), 0,
			   TDB_DEFAULT, O_RDWR | O_CREAT, 0644);

	if (tdb == NULL) {
		DEBUG(1, ("Could not open idmap: %s\n", strerror(errno)));
		goto done;
	}

	if (!init_idmap_tdb(tdb)) {
		DEBUG(1, ("Could not init idmap\n"));
		goto done;
	}

	rid = BASE_RID;		/* Default if not set */

	if (!tdb_change_uint32_atomic(tdb, "RID_COUNTER", &rid, 1)) {
		DEBUG(3, ("tdbsam_new_rid: Failed to increase RID_COUNTER\n"));
		goto done;
	}

	*prid = rid;
	ret = True;

 done:
	if ((tdb != NULL) && (tdb_close(tdb) != 0)) {
		smb_panic("tdb_close(idmap_tdb) failed\n");
	}

	return ret;
}

/*********************************************************************
 Initialize the tdb sam backend.  Setup the dispath table of methods,
 open the tdb, etc...
*********************************************************************/

static NTSTATUS pdb_init_tdbsam(struct pdb_methods **pdb_method, const char *location)
{
	NTSTATUS nt_status;
	pstring tdbfile;
	const char *pfile = location;

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_method( pdb_method ))) {
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
	(*pdb_method)->rename_sam_account = tdbsam_rename_sam_account;

	(*pdb_method)->rid_algorithm = tdbsam_rid_algorithm;
	(*pdb_method)->new_rid = tdbsam_new_rid;

	/* save the path for later */
			   
	if ( !location ) {
		pstr_sprintf( tdbfile, "%s/%s", lp_private_dir(), PASSDB_FILE_NAME );
		pfile = tdbfile;
	}
	pstrcpy( tdbsam_filename, pfile );

	/* no private data */
	
	(*pdb_method)->private_data      = NULL;
	(*pdb_method)->free_private_data = NULL;

	return NT_STATUS_OK;
}

NTSTATUS pdb_tdbsam_init(void)
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "tdbsam", pdb_init_tdbsam);
}
