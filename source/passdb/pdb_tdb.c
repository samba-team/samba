/*
 * Unix SMB/CIFS implementation. 
 * SMB parameters and setup
 * Copyright (C) Andrew Tridgell   1992-1998
 * Copyright (C) Simo Sorce        2000-2002
 * Copyright (C) Gerald Carter     2000
 * Copyright (C) Jeremy Allison    2001
 * Copyright (C) Andrew Bartlett   2002
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

#define PDB_VERSION		"20010830"
#define PASSDB_FILE_NAME	"passdb.tdb"
#define USERPREFIX		"USER_"
#define RIDPREFIX		"RID_"

struct tdbsam_privates {
	TDB_CONTEXT 	*passwd_tdb;
	TDB_DATA 	key;

	/* retrive-once info */
	const char *tdbsam_location;
};

/***************************************************************
 Open the TDB passwd database for SAM account enumeration.
****************************************************************/

static NTSTATUS tdbsam_setsampwent(struct pdb_methods *my_methods, BOOL update)
{
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	
	/* Open tdb passwd */
	if (!(tdb_state->passwd_tdb = tdb_open_log(tdb_state->tdbsam_location, 0, TDB_DEFAULT, update?(O_RDWR|O_CREAT):O_RDONLY, 0600)))
	{
		DEBUG(0, ("Unable to open/create TDB passwd\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	tdb_state->key = tdb_firstkey(tdb_state->passwd_tdb);

	return NT_STATUS_OK;
}

static void close_tdb(struct tdbsam_privates *tdb_state) 
{
	if (tdb_state->passwd_tdb) {
		tdb_close(tdb_state->passwd_tdb);
		tdb_state->passwd_tdb = NULL;
	}
}

/***************************************************************
 End enumeration of the TDB passwd list.
****************************************************************/

static void tdbsam_endsampwent(struct pdb_methods *my_methods)
{
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	SAFE_FREE(tdb_state->key.dptr);
	close_tdb(tdb_state);
	
	DEBUG(7, ("endtdbpwent: closed sam database.\n"));
}

/*****************************************************************
 Get one SAM_ACCOUNT from the TDB (next in line)
*****************************************************************/

static NTSTATUS tdbsam_getsampwent(struct pdb_methods *my_methods, SAM_ACCOUNT *user)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_DATA 	data, old_key;
	const char *prefix = USERPREFIX;
	int  prefixlen = strlen (prefix);


	if (user==NULL) {
		DEBUG(0,("pdb_get_sampwent: SAM_ACCOUNT is NULL.\n"));
		return nt_status;
	}

	/* skip all non-USER entries (eg. RIDs) */
	while ((tdb_state->key.dsize != 0) && (strncmp(tdb_state->key.dptr, prefix, prefixlen))) {

		old_key = tdb_state->key;

		/* increment to next in line */
		tdb_state->key = tdb_nextkey(tdb_state->passwd_tdb, tdb_state->key);

		SAFE_FREE(old_key.dptr);
	}

	/* do we have an valid iteration pointer? */
	if(tdb_state->passwd_tdb == NULL) {
		DEBUG(0,("pdb_get_sampwent: Bad TDB Context pointer.\n"));
		return nt_status;
	}

	data = tdb_fetch(tdb_state->passwd_tdb, tdb_state->key);
	if (!data.dptr) {
		DEBUG(5,("pdb_getsampwent: database entry not found.\n"));
		return nt_status;
	}
  
  	/* unpack the buffer */
	if (!init_sam_from_buffer(user, (unsigned char *)data.dptr, data.dsize)) {
		DEBUG(0,("pdb_getsampwent: Bad SAM_ACCOUNT entry returned from TDB!\n"));
		SAFE_FREE(data.dptr);
		return nt_status;
	}
	SAFE_FREE(data.dptr);
	
	old_key = tdb_state->key;
	
	/* increment to next in line */
	tdb_state->key = tdb_nextkey(tdb_state->passwd_tdb, tdb_state->key);

	SAFE_FREE(old_key.dptr);

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

	if (user==NULL) {
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
	if (!(pwd_tdb = tdb_open_log(tdb_state->tdbsam_location, 0, TDB_DEFAULT, O_RDONLY, 0600))) {
	
		if (errno == ENOENT) {
			/*
			 * TDB file doesn't exist, so try to create new one. This is useful to avoid
			 * confusing error msg when adding user account first time
			 */
			if (!(pwd_tdb = tdb_open_log(tdb_state->tdbsam_location, 0, TDB_DEFAULT, O_CREAT, 0600))) {
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
	if (!(pwd_tdb = tdb_open_log(tdb_state->tdbsam_location, 0, TDB_DEFAULT, O_RDONLY, 0600))) {
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
	if (!(pwd_tdb = tdb_open_log(tdb_state->tdbsam_location, 0, TDB_DEFAULT, O_RDWR, 0600))) {
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
	
	pwd_tdb = tdb_open_log(tdb_state->tdbsam_location, 0, TDB_DEFAULT, O_RDWR | O_CREAT, 0600);
	
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
	close_tdb(*tdb_state);
	*tdb_state = NULL;

	/* No need to free any further, as it is talloc()ed */
}


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

