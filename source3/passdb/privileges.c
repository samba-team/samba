/*
 * Unix SMB/CIFS implementation. 
 *
 * default privileges backend for passdb
 *
 * Copyright (C) Andrew Tridgell 2003
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

/*
  this is a local implementation of a privileges backend, with
  privileges stored in a tdb. Most passdb implementations will
  probably use this backend, although some (such as pdb_ldap) will
  store the privileges in another manner.

  The basic principle is that the backend should store a list of SIDs
  associated with each right, where a right is a string name such as
  'SeTakeOwnershipPrivilege'. The SIDs can be of any type, and do not
  need to belong to the local domain.

  The way this is used is that certain places in the code which
  require access control will ask the privileges backend 'does this
  user have the following privilege'. The 'user' will be a NT_TOKEN,
  which is essentially just a list of SIDs. If any of those SIDs are
  listed in the list of SIDs for that privilege then the answer will
  be 'yes'. That will usually mean that the user gets unconditional
  access to that functionality, regradless of any ACLs. In this way
  privileges act in a similar fashion to unix setuid bits.
*/

/*
  The terms 'right' and 'privilege' are used interchangably in this
  file. This follows MSDN convention where the LSA calls are calls on
  'rights', which really means privileges. My apologies for the
  confusion.
*/


/* 15 seconds seems like an ample time for timeouts on the privileges db */
#define LOCK_TIMEOUT 15


/* the tdb handle for the privileges database */
static TDB_CONTEXT *tdb;


/* initialise the privilege database */
BOOL privilege_init(void)
{
	tdb = tdb_open_log(lock_path("privilege.tdb"), 0, TDB_DEFAULT, 
			   O_RDWR|O_CREAT, 0600);
	if (!tdb) {
		DEBUG(0,("Failed to open privilege database\n"));
		return False;
	}

	return True;
}

/* 
   lock the record for a particular privilege (write lock)
*/
static NTSTATUS privilege_lock_right(const char *right) 
{
	if (tdb_lock_bystring(tdb, right, LOCK_TIMEOUT) != 0) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	return NT_STATUS_OK;
}

/* 
   unlock the record for a particular privilege (write lock)
*/
static void privilege_unlock_right(const char *right) 
{
	tdb_unlock_bystring(tdb, right);
}


/* 
   return a list of SIDs that have a particular right
*/
NTSTATUS privilege_enum_account_with_right(const char *right, 
					   uint32 *count, 
					   DOM_SID **sids)
{
	TDB_DATA data;
	char *p;
	int i;

	if (!tdb) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	data = tdb_fetch_bystring(tdb, right);
	if (!data.dptr) {
		*count = 0;
		*sids = NULL;
		return NT_STATUS_OK;
	}

	/* count them */
	for (i=0, p=data.dptr; p<data.dptr+data.dsize; i++) {
		p += strlen(p) + 1;
	}
	*count = i;

	/* allocate and parse */
	*sids = malloc(sizeof(DOM_SID) * *count);
	if (! *sids) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0, p=data.dptr; p<data.dptr+data.dsize; i++) {
		if (!string_to_sid(&(*sids)[i], p)) {
			free(data.dptr);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		p += strlen(p) + 1;
	}
	
	free(data.dptr);

	return NT_STATUS_OK;
}

/* 
   set what accounts have a given right - this is an internal interface
*/
static NTSTATUS privilege_set_accounts_with_right(const char *right, 
						  uint32 count, 
						  DOM_SID *sids)
{
	TDB_DATA data;
	char *p;
	int i;

	if (!tdb) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* allocate the maximum size that we might use */
	data.dptr = malloc(count * ((MAXSUBAUTHS*11) + 30));
	if (!data.dptr) {
		return NT_STATUS_NO_MEMORY;
	}

	p = data.dptr;

	for (i=0;i<count;i++) {
		sid_to_string(p, &sids[i]);
		p += strlen(p) + 1;
	}

	data.dsize = PTR_DIFF(p, data.dptr);

	if (tdb_store_bystring(tdb, right, data, TDB_REPLACE) != 0) {
		free(data.dptr);
		return NT_STATUS_INTERNAL_ERROR;
	}

	free(data.dptr);
	return NT_STATUS_OK;
}


/* 
   add a SID to the list of SIDs for a right
*/
NTSTATUS privilege_add_account_right(const char *right, 
				     DOM_SID *sid)
{
	NTSTATUS status;
	DOM_SID *current_sids;
	uint32 current_count;
	int i;

	status = privilege_lock_right(right);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = privilege_enum_account_with_right(right, &current_count, &current_sids);
	if (!NT_STATUS_IS_OK(status)) {
		privilege_unlock_right(right);
		return status;
	}	

	/* maybe that SID is already listed? this is not an error */
	for (i=0;i<current_count;i++) {
		if (sid_equal(&current_sids[i], sid)) {
			privilege_unlock_right(right);
			free(current_sids);
			return NT_STATUS_OK;
		}
	}

	/* add it in */
	current_sids = Realloc(current_sids, sizeof(current_sids[0]) * (current_count+1));
	if (!current_sids) {
		privilege_unlock_right(right);
		return NT_STATUS_NO_MEMORY;
	}

	sid_copy(&current_sids[current_count], sid);
	current_count++;
	
	status = privilege_set_accounts_with_right(right, current_count, current_sids);

	free(current_sids);
	privilege_unlock_right(right);

	return status;
}


/* 
   remove a SID from the list of SIDs for a right
*/
NTSTATUS privilege_remove_account_right(const char *right, 
					DOM_SID *sid)
{
	NTSTATUS status;
	DOM_SID *current_sids;
	uint32 current_count;
	int i;

	status = privilege_lock_right(right);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = privilege_enum_account_with_right(right, &current_count, &current_sids);
	if (!NT_STATUS_IS_OK(status)) {
		privilege_unlock_right(right);
		return status;
	}	

	for (i=0;i<current_count;i++) {
		if (sid_equal(&current_sids[i], sid)) {
			/* found it - so remove it */
			if (current_count-i > 1) {
				memmove(&current_sids[i], &current_sids[i+1],
					sizeof(current_sids[0]) * ((current_count-i)-1));
			}
			current_count--;
			status = privilege_set_accounts_with_right(right, 
								   current_count, 
								   current_sids);
			free(current_sids);
			privilege_unlock_right(right);
			return status;
		}
	}

	/* removing a right that you don't have is not an error */
	
	safe_free(current_sids);
	privilege_unlock_right(right);
	return NT_STATUS_OK;
}


/*
  an internal function for checking if a SID has a right
*/
static BOOL privilege_sid_has_right(DOM_SID *sid, const char *right)
{
	NTSTATUS status;
	uint32 count;
	DOM_SID *sids;
	int i;

	status = privilege_enum_account_with_right(right, &count, &sids);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	for (i=0;i<count;i++) {
		if (sid_equal(sid, &sids[i])) {
			free(sids);
			return True;
		}
	}	

	safe_free(sids);
	return False;
}

/* 
   list the rights for an account. This involves traversing the database
*/
NTSTATUS privilege_enum_account_rights(DOM_SID *sid,
				       uint32 *count,
				       char ***rights)
{
	TDB_DATA key, nextkey;
	char *right;

	if (!tdb) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	*rights = NULL;
	*count = 0;

	for (key = tdb_firstkey(tdb); key.dptr; key = nextkey) {
		nextkey = tdb_nextkey(tdb, key);

		right = key.dptr;
		
		if (privilege_sid_has_right(sid, right)) {
			(*rights) = (char **)Realloc(*rights,sizeof(char *) * ((*count)+1));
			if (! *rights) {
				safe_free(nextkey.dptr);
				free(key.dptr);
				return NT_STATUS_NO_MEMORY;
			}

			(*rights)[*count] = strdup(right);
			(*count)++;
		}

		free(key.dptr);
	}

	return NT_STATUS_OK;
}
