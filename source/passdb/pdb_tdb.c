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

#define TDBSAM_VERSION	1			/* Most recent TDBSAM version */
#define PDB_VERSION		"20010830"
#define PASSDB_FILE_NAME	"passdb.tdb"
#define USERPREFIX		"USER_"
#define RIDPREFIX		"RID_"
#define tdbsamver_t 	int32

struct tdbsam_privates {
	TDB_CONTEXT 	*passwd_tdb;
	TDB_DATA 	key;

	/* retrive-once info */
	const char *tdbsam_location;
};

/**
 * Convert old TDBSAM to the latest version.
 * @param pdb_tdb A pointer to the opened TDBSAM file which must be converted. 
 *                This file must be opened with read/write access.
 * @param from Current version of the TDBSAM file.
 * @return True if the conversion has been successful, false otherwise. 
 **/

static BOOL tdbsam_convert(TDB_CONTEXT *pdb_tdb, tdbsamver_t from) 
{
	const char * vstring = "INFO/version";
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
				default:
					/* unknown tdbsam version */
					ret = False;
			}
			if (!ret) {
				DEBUG(0,("tdbsam_convert: Bad SAM_ACCOUNT entry returned from TDB (key:%s) (version:%d)\n", key.dptr, from));
				SAFE_FREE(data.dptr);
				return False;
			}
	
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
	if (!(pdb_tdb = tdb_open_log(name, 0, TDB_DEFAULT, open_flags, 0600)))
		return NULL;

	/* Check the version */
	version = (tdbsamver_t) tdb_fetch_int32(pdb_tdb, "INFO/version");
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

/***************************************************************
 Open the TDB passwd database for SAM account enumeration.
****************************************************************/

static NTSTATUS tdbsam_setsampwent(struct pdb_methods *my_methods, BOOL update)
{
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	
	/* Open tdb passwd */
	if (!(tdb_state->passwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, update?(O_RDWR|O_CREAT):O_RDONLY)))
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
	if (!(pwd_tdb = tdbsam_tdbopen(tdb_state->tdbsam_location, O_RDONLY))) {
	
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
	close_tdb(*tdb_state);
	*tdb_state = NULL;

	/* No need to free any further, as it is talloc()ed */
}

/**
 * Start enumerating through trust passwords (machine and
 * interdomain nt/ads)
 *
 * @param methods methods belonging in pdb context (module)
 * @param trust trust password structure
 *
 * @return nt status of performed operation
 **/

static NTSTATUS tdbsam_gettrustpwent(struct pdb_methods *methods, SAM_TRUST_PASSWD *trust)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct trust_passwd_data t;
	TALLOC_CTX *mem_ctx;
	
	TRUSTDOM **trustdom;
	static int enum_ctx;
	int num_domains = 0;
	unsigned int max_domains = 1;
	char *dom_name, *dom_pass;
	
	smb_ucs2_t *uni_dom_name;
	uint8 mach_pass[16];
	uint32 sec_chan;
	
	if (!methods) return NT_STATUS_UNSUCCESSFUL;
	
	/*
	 * NT domain trust passwords
	 */
	
	/* rewind enumeration when passed NULL pointer as a trust */
	if (!trust) {
		enum_ctx = 0;
		return NT_STATUS_OK;
	}
	
	mem_ctx = talloc_init("tdbsam_gettrustpwent: trust password enumeration");

	/* fetch next trusted domain (one at a time) and its full information */
	nt_status = secrets_get_trusted_domains(mem_ctx, &enum_ctx, max_domains, &num_domains,
	                                        &trustdom);
	if (num_domains) {
		pull_ucs2_talloc(mem_ctx, &dom_name, trustdom[0]->name);
		if (secrets_fetch_trusted_domain_password(dom_name, &dom_pass, &t.domain_sid,
		                                          &t.mod_time)) {

			t.uni_name_len = strnlen_w(trustdom[0]->name, 32);
			strncpy_w(t.uni_name, trustdom[0]->name, t.uni_name_len);
			safe_strcpy(t.pass, dom_pass, FSTRING_LEN - 1);
			t.flags = PASS_DOMAIN_TRUST_NT;

			SAFE_FREE(dom_pass);
			talloc_destroy(mem_ctx);
			trust->private = t;
			return nt_status;
		} else {
			talloc_destroy(mem_ctx);
			return NT_STATUS_UNSUCCESSFUL;
		}
	}
	
	/*
	 * NT machine trust password
	 */
	
	if (secrets_lock_trust_account_password(lp_workgroup(), True)) {
		sec_chan = get_default_sec_channel();
		if (secrets_fetch_trust_account_password(lp_workgroup(), mach_pass, &t.mod_time,
		                                         &sec_chan)) {
			
			t.uni_name_len = strlen(lp_workgroup());
			push_ucs2_talloc(mem_ctx, &uni_dom_name, lp_workgroup());
			strncpy_w(t.uni_name, uni_dom_name, t.uni_name_len);
			safe_strcpy(t.pass, mach_pass, FSTRING_LEN - 1);
			t.flags = PASS_MACHINE_TRUST_NT;
			if (!secrets_fetch_domain_sid(lp_workgroup(), &t.domain_sid)) {
				talloc_destroy(mem_ctx);
				return NT_STATUS_UNSUCCESSFUL;
			}
			
			talloc_destroy(mem_ctx);
			trust->private = t;
			return NT_STATUS_OK;
		}
		secrets_lock_trust_account_password(lp_workgroup(), False);
	} else {
		talloc_destroy(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/*
	 * ADS machine trust password (TODO)
	 */

	talloc_destroy(mem_ctx);
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
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	BOOL status = False;
	TALLOC_CTX *mem_ctx;
	
	char* domain = NULL;
	struct trust_passwd_data t = trust->private;
	uint32 sec_chan;

	mem_ctx = talloc_init("tdbsam_add_trust_passwd: storing new trust password");
		
	/* convert unicode name to char* (used to form the key) */
	pull_ucs2_talloc(mem_ctx, &domain, t.uni_name);
	
	/* add nt machine trust password */
	if (t.flags & (PASS_MACHINE_TRUST_NT | PASS_SERVER_TRUST_NT)) {
		sec_chan = (t.flags & PASS_MACHINE_TRUST_NT) ? SEC_CHAN_WKSTA : SEC_CHAN_BDC;
		status = secrets_store_machine_password(t.pass, domain, sec_chan);
		if (status)
			status = secrets_store_domain_sid(domain, &t.domain_sid);
		
		nt_status = status ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
		
	/* add nt domain trust password */
	} else if (t.flags & PASS_DOMAIN_TRUST_NT) {
		status = secrets_store_trusted_domain_password(domain, t.uni_name, t.uni_name_len,
		                                               t.pass, t.domain_sid);
		nt_status = status ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
		
	/* add ads machine trust password (TODO) */
	} else if (t.flags & PASS_MACHINE_TRUST_ADS) {
	}

	talloc_destroy(mem_ctx);	
	return nt_status;
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
	NTSTATUS nt_status = NT_STATUS_NOT_IMPLEMENTED;
	return nt_status;
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
	NTSTATUS nt_status = NT_STATUS_NOT_IMPLEMENTED;
	return nt_status;
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
	(*pdb_method)->gettrustpwent = tdbsam_gettrustpwent;
	(*pdb_method)->gettrustpwsid = tdbsam_gettrustpwsid;
	(*pdb_method)->add_trust_passwd = tdbsam_add_trust_passwd;
	(*pdb_method)->update_trust_passwd = tdbsam_update_trust_passwd;
	(*pdb_method)->delete_trust_passwd = tdbsam_delete_trust_passwd;

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
