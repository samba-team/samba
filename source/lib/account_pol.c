/* 
 *  Unix SMB/CIFS implementation.
 *  account policy storage
 *  Copyright (C) Jean François Micouleau      1998-2001.
 *  Copyright (C) Andrew Bartlett              2002
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
static TDB_CONTEXT *tdb; /* used for driver files */

#define DATABASE_VERSION 1

/****************************************************************************
 Open the account policy tdb.
****************************************************************************/

BOOL init_account_policy(void)
{
	static pid_t local_pid;
	const char *vstring = "INFO/version";
	uint32 version;

	if (tdb && local_pid == sys_getpid())
		return True;
	tdb = tdb_open_log(lock_path("account_policy.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
	if (!tdb) {
		DEBUG(0,("Failed to open account policy database\n"));
		return False;
	}

	local_pid = sys_getpid();

	/* handle a Samba upgrade */
	tdb_lock_bystring(tdb, vstring,0);
	if (!tdb_fetch_uint32(tdb, vstring, &version) || version != DATABASE_VERSION) {
		tdb_traverse(tdb, tdb_traverse_delete_fn, NULL);
		tdb_store_uint32(tdb, vstring, DATABASE_VERSION);
		
		account_policy_set(AP_MIN_PASSWORD_LEN, MINPASSWDLENGTH);   /* 5 chars minimum             */
		account_policy_set(AP_PASSWORD_HISTORY, 0);		    /* don't keep any old password */
		account_policy_set(AP_USER_MUST_LOGON_TO_CHG_PASS, 0);	    /* don't force user to logon   */
		account_policy_set(AP_MAX_PASSWORD_AGE, (uint32)-1);        /* don't expire		   */
		account_policy_set(AP_MIN_PASSWORD_AGE, 0);		    /* 0 days                      */
		account_policy_set(AP_LOCK_ACCOUNT_DURATION, 30);	    /* lockout for 30 minutes      */
		account_policy_set(AP_RESET_COUNT_TIME, 30);		    /* reset after 30 minutes      */
		account_policy_set(AP_BAD_ATTEMPT_LOCKOUT, 0);		    /* don't lockout               */
		account_policy_set(AP_TIME_TO_LOGOUT, -1);		    /* don't force logout          */
	}
	tdb_unlock_bystring(tdb, vstring);

	return True;
}

static const struct {
	int field;
	const char *string;
} account_policy_names[] = {
	{AP_MIN_PASSWORD_LEN, "min password length"},
	{AP_PASSWORD_HISTORY, "password history"},
	{AP_USER_MUST_LOGON_TO_CHG_PASS, "user must logon to change password"},
	{AP_MAX_PASSWORD_AGE, "maximum password age"},
	{AP_MIN_PASSWORD_AGE,"minimum password age"},
	{AP_LOCK_ACCOUNT_DURATION, "lockout duration"},
	{AP_RESET_COUNT_TIME, "reset count minutes"},
	{AP_BAD_ATTEMPT_LOCKOUT, "bad lockout attempt"},
	{AP_TIME_TO_LOGOUT, "disconnect time"},
	{0, NULL}
};

/****************************************************************************
Get the account policy name as a string from its #define'ed number
****************************************************************************/

static const char *decode_account_policy_name(int field)
{
	int i;
	for (i=0; account_policy_names[i].string; i++) {
		if (field == account_policy_names[i].field)
			return account_policy_names[i].string;
	}
	return NULL;

}

/****************************************************************************
Get the account policy name as a string from its #define'ed number
****************************************************************************/

int account_policy_name_to_fieldnum(const char *name)
{
	int i;
	for (i=0; account_policy_names[i].string; i++) {
		if (strcmp(name, account_policy_names[i].string) == 0)
			return account_policy_names[i].field;
	}
	return 0;

}


/****************************************************************************
****************************************************************************/
BOOL account_policy_get(int field, uint32 *value)
{
	fstring name;

	if(!init_account_policy())return False;

	*value = 0;

	fstrcpy(name, decode_account_policy_name(field));
	if (!*name) {
		DEBUG(1, ("account_policy_get: Field %d is not a valid account policy type!  Cannot get, returning 0.\n", field));
		return False;
	}
	if (!tdb_fetch_uint32(tdb, name, value)) {
		DEBUG(1, ("account_policy_get: tdb_fetch_uint32 failed for efild %d (%s), returning 0", field, name));
		return False;
	}
	DEBUG(10,("account_policy_get: %s:%d\n", name, *value));
	return True;
}


/****************************************************************************
****************************************************************************/
BOOL account_policy_set(int field, uint32 value)
{
	fstring name;

	if(!init_account_policy())return False;

	fstrcpy(name, decode_account_policy_name(field));
	if (!*name) {
		DEBUG(1, ("Field %d is not a valid account policy type!  Cannot set.\n", field));
		return False;
	}

	if (!tdb_store_uint32(tdb, name, value)) {
		DEBUG(1, ("tdb_store_uint32 failed for field %d (%s) on value %u", field, name, value));
		return False;
	}

	DEBUG(10,("account_policy_set: %s:%d\n", name, value));
	
	return True;
}

