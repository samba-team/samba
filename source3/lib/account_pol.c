/* 
 *  Unix SMB/CIFS implementation.
 *  account policy storage
 *  Copyright (C) Jean François Micouleau      1998-2001.
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
	char *vstring = "INFO/version";

	if (tdb && local_pid == sys_getpid())
		return True;
	tdb = tdb_open_log(lock_path("account_policy.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
	if (!tdb) {
		DEBUG(0,("Failed to open account policy database\n"));
		return False;
	}

	local_pid = sys_getpid();

	/* handle a Samba upgrade */
	tdb_lock_bystring(tdb, vstring);
	if (tdb_fetch_int32(tdb, vstring) != DATABASE_VERSION) {
		tdb_traverse(tdb, tdb_traverse_delete_fn, NULL);
		tdb_store_int32(tdb, vstring, DATABASE_VERSION);
		
		account_policy_set(AP_MIN_PASSWORD_LEN, MINPASSWDLENGTH);   /* 5 chars minimum             */
		account_policy_set(AP_PASSWORD_HISTORY, 0);		    /* don't keep any old password */
		account_policy_set(AP_USER_MUST_LOGON_TO_CHG_PASS, 0);	    /* don't force user to logon   */
		account_policy_set(AP_MAX_PASSWORD_AGE, MAX_PASSWORD_AGE);  /* 21 days                     */
		account_policy_set(AP_MIN_PASSWORD_AGE, 0);		    /* 0 days                      */
		account_policy_set(AP_LOCK_ACCOUNT_DURATION, 0);	    /* lockout for 0 minutes       */
		account_policy_set(AP_RESET_COUNT_TIME, 0);		    /* reset immediatly            */
		account_policy_set(AP_BAD_ATTEMPT_LOCKOUT, 0);		    /* don't lockout               */
		account_policy_set(AP_TIME_TO_LOGOUT, -1);		    /* don't force logout          */
	}
	tdb_unlock_bystring(tdb, vstring);

	return True;
}

/****************************************************************************
****************************************************************************/

static char *decode_account_policy_name(int field)
{
	switch (field) {
		case AP_MIN_PASSWORD_LEN:
			return "min password length";
		case AP_PASSWORD_HISTORY:
			return "password history";
		case AP_USER_MUST_LOGON_TO_CHG_PASS:
			return "user must logon to change password";
		case AP_MAX_PASSWORD_AGE:
			return "maximum password age";
		case AP_MIN_PASSWORD_AGE:
			return "minimum password age";
		case AP_LOCK_ACCOUNT_DURATION:
			return "lockout duration";
		case AP_RESET_COUNT_TIME:
			return "reset count minutes";
		case AP_BAD_ATTEMPT_LOCKOUT:
			return "bad lockout attempt";
		case AP_TIME_TO_LOGOUT:
			return "disconnect time";
		default:
			return "undefined value";
	}
}


/****************************************************************************
****************************************************************************/
BOOL account_policy_get(int field, uint32 *value)
{
	fstring name;

	init_account_policy();

	fstrcpy(name, decode_account_policy_name(field));
	*value=tdb_fetch_int32(tdb, name);
	DEBUG(10,("account_policy_get: %s:%d\n", name, *value));
	return True;
}


/****************************************************************************
****************************************************************************/
BOOL account_policy_set(int field, uint32 value)
{
	fstring name;

	init_account_policy();

	fstrcpy(name, decode_account_policy_name(field));
	if ( tdb_store_int32(tdb, name, value)== -1)
		return False;
	DEBUG(10,("account_policy_set: %s:%d\n", name, value));
	
	return True;
}

