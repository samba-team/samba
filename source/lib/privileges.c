/*
   Unix SMB/CIFS implementation.
   Privileges handling functions
   Copyright (C) Jean François Micouleau	1998-2001
   Copyright (C) Simo Sorce			2002-2003
   Copyright (C) Gerald (Jerry) Carter          2004
   
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

#define PRIVPREFIX              "PRIV_"

#define ALLOC_CHECK(ptr, err, label, str) do { if ((ptr) == NULL) \
	{ DEBUG(0, ("%s: out of memory!\n", str)); err = NT_STATUS_NO_MEMORY; goto label; } } while(0)
	
PRIVS privs[] = {
	{SE_NETWORK_LOGON,		"SeNetworkLogonRight",			"Access this computer from the network"},
	{SE_INTERACTIVE_LOGON,		"SeInteractiveLogonRight",		"Log on locally"},
	{SE_BATCH_LOGON,		"SeBatchLogonRight",			"Log on as a batch job"},
	{SE_SERVICE_LOGON,		"SeServiceLogonRight",			"Log on as a service"},

	{SE_MACHINE_ACCOUNT,		"SeMachineAccountPrivilege",		"Add machines to domain"},
	{SE_PRINT_OPERATOR,		"SePrintOperatorPrivilege",		"Printer Admin"},
	{SE_ADD_USERS,			"SeAddUsersPrivilege",			"Add users and groups to the domain"},

	{SE_END,			"",					""}
};
	

#if 0	/* not needed currently */
PRIVS privs[] = {
	{SE_ASSIGN_PRIMARY_TOKEN,	"SeAssignPrimaryTokenPrivilege",	"Assign Primary Token"},
	{SE_CREATE_TOKEN,		"SeCreateTokenPrivilege",		"Create Token"},
	{SE_LOCK_MEMORY,		"SeLockMemoryPrivilege",		"Lock Memory"},
	{SE_INCREASE_QUOTA,		"SeIncreaseQuotaPrivilege",		"Increase Quota"},
	{SE_UNSOLICITED_INPUT,		"SeUnsolicitedInputPrivilege",		"Unsolicited Input"},
	{SE_MACHINE_ACCOUNT,		"SeMachineAccountPrivilege",		"Can add Machine Accounts to the Domain"},
	{SE_TCB,			"SeTcbPrivilege",			"Act as part of the operating system"},
	{SE_SECURITY,			"SeSecurityPrivilege",			"Security Privilege"},
	{SE_TAKE_OWNERSHIP,		"SeTakeOwnershipPrivilege",		"Take Ownership Privilege"},
	{SE_LOAD_DRIVER,		"SeLocalDriverPrivilege",		"Local Driver Privilege"},
	{SE_SYSTEM_PROFILE,		"SeSystemProfilePrivilege",		"System Profile Privilege"},
	{SE_SYSTEM_TIME,		"SeSystemtimePrivilege",		"System Time"},
	{SE_PROF_SINGLE_PROCESS,	"SeProfileSingleProcessPrivilege",	"Profile Single Process Privilege"},
	{SE_INC_BASE_PRIORITY,		"SeIncreaseBasePriorityPrivilege",	"Increase Base Priority Privilege"},
	{SE_CREATE_PAGEFILE,		"SeCreatePagefilePrivilege",		"Create Pagefile Privilege"},
	{SE_CREATE_PERMANENT,		"SeCreatePermanentPrivilege",		"Create Permanent"},
	{SE_BACKUP,			"SeBackupPrivilege",			"Backup Privilege"},
	{SE_RESTORE,			"SeRestorePrivilege",			"Restore Privilege"},
	{SE_SHUTDOWN,			"SeShutdownPrivilege",			"Shutdown Privilege"},
	{SE_DEBUG,			"SeDebugPrivilege",			"Debug Privilege"},
	{SE_AUDIT,			"SeAuditPrivilege",			"Audit"},
	{SE_SYSTEM_ENVIRONMENT,		"SeSystemEnvironmentPrivilege",		"System Environment Privilege"},
	{SE_CHANGE_NOTIFY,		"SeChangeNotifyPrivilege",		"Change Notify"},
	{SE_REMOTE_SHUTDOWN,		"SeRemoteShutdownPrivilege",		"Remote Shutdown Privilege"},
	{SE_UNDOCK,			"SeUndockPrivilege",			"Undock"},
	{SE_SYNC_AGENT,			"SeSynchronizationAgentPrivilege",	"Synchronization Agent"},
	{SE_ENABLE_DELEGATION,		"SeEnableDelegationPrivilege",		"Enable Delegation"},
	{SE_PRINT_OPERATOR,		"SePrintOperatorPrivilege",		"Printer Operator"},
	{SE_ADD_USERS,			"SeAddUsersPrivilege",			"Add Users"},
	{SE_ALL_PRIVS,			"SeAllPrivileges",			"All Privileges"}
	{SE_END,			"",					""}
};
#endif

typedef struct priv_sid_list {
	uint32 se_priv;
	SID_LIST sids;
} PRIV_SID_LIST;

/***************************************************************************
 Retrieve the privilege mask (set) for a given SID
****************************************************************************/

static uint32 get_privileges( const DOM_SID *sid )
{
	TDB_CONTEXT *tdb = get_account_pol_tdb();
	fstring keystr;
	uint32 priv_mask;
	
	if ( !tdb )
		return 0;

	fstr_sprintf( keystr, "%s%s", PRIVPREFIX, sid_string_static(sid) );

	if ( !tdb_fetch_uint32( tdb, keystr, &priv_mask ) ) {
		DEBUG(3,("get_privileges: No privileges assigned to SID [%s]\n",
			sid_string_static(sid)));
		return 0;
	}
	
	return priv_mask;
}

/***************************************************************************
 Store the privilege mask (set) for a given SID
****************************************************************************/

static BOOL set_privileges( const DOM_SID *sid, uint32 mask )
{
	TDB_CONTEXT *tdb = get_account_pol_tdb();
	fstring keystr;
	
	if ( !tdb )
		return False;

	fstr_sprintf( keystr, "%s%s", PRIVPREFIX, sid_string_static(sid) );

	return tdb_store_uint32( tdb, keystr, mask );
}

/****************************************************************************
 check if the privilege is in the privilege list
****************************************************************************/

static BOOL check_priv_in_privilege(PRIVILEGE_SET *priv_set, LUID_ATTR set)
{
	int i;

	if ( !priv_set )
		return False;

	for ( i = 0; i < priv_set->count; i++ ) {
		LUID_ATTR *cur_set;

		cur_set = &priv_set->set[i];

		/* check only the low and high part. Checking the attr 
		   field has no meaning */

		if ( (cur_set->luid.low == set.luid.low) 
			&& (cur_set->luid.high == set.luid.high) ) 
		{
			return True;
		}
	}

	return False;
}

/****************************************************************************
 add a privilege to a privilege array
 ****************************************************************************/

static NTSTATUS add_privilege(PRIVILEGE_SET *priv_set, LUID_ATTR set)
{
	NTSTATUS ret;
	LUID_ATTR *new_set;

	/* check if the privilege is not already in the list */

	if ( check_priv_in_privilege(priv_set, set) )
		return NT_STATUS_OK;

	/* we can allocate memory to add the new privilege */

	new_set = TALLOC_REALLOC_ARRAY(priv_set->mem_ctx, priv_set->set, LUID_ATTR, priv_set->count + 1);
	ALLOC_CHECK(new_set, ret, done, "add_privilege");

	new_set[priv_set->count].luid.high = set.luid.high;
	new_set[priv_set->count].luid.low = set.luid.low;
	new_set[priv_set->count].attr = set.attr;

	priv_set->count++;
	priv_set->set = new_set;

	ret = NT_STATUS_OK;

done:
	return ret;
}

/*********************************************************************
 Generate the LUID_ATTR structure based on a bitmask
*********************************************************************/

static LUID_ATTR get_privilege_luid( uint32 mask )
{
	LUID_ATTR priv_luid;

	priv_luid.attr = 0;
	priv_luid.luid.high = 0;
	priv_luid.luid.low = mask;

	return priv_luid;
}

/*********************************************************************
 Convert a privilege mask to an LUID_ATTR[] and add the privileges to 
 the PRIVILEGE_SET
*********************************************************************/

static void add_privilege_set( PRIVILEGE_SET *privset, uint32 mask )
{
	LUID_ATTR luid;
	int i;
	
	for (i=0; privs[i].se_priv != SE_END; i++) {

		/* skip if the privilege is not part of the mask */

		if ( !(mask & privs[i].se_priv) ) 
			continue;

		/* remove the bit from the mask */

		mask &= ~privs[i].se_priv;	
		
		luid = get_privilege_luid( privs[i].se_priv );
		
		add_privilege( privset, luid );
	}

	/* log an error if we have anything left at this point */
	if ( mask )
		DEBUG(0,("add_privilege_set: leftover bits! [0x%x]\n", mask ));
}

/*********************************************************************
 get a list of all privleges for all sids the in list
*********************************************************************/

void get_privileges_for_sids(PRIVILEGE_SET *privset, DOM_SID *slist, int scount)
{
	uint32 priv_mask;
	int i;
	
	for ( i=0; i<scount; i++ ) {
		priv_mask = get_privileges( &slist[i] );

		/* don't add unless we actually have a privilege assigned */

		if ( priv_mask == 0 )
			continue;
		
		DEBUG(5,("get_privileges_for_sids: sid = %s, privilege mask = 0x%x\n",
			sid_string_static(&slist[i]), priv_mask));
			
		add_privilege_set( privset, priv_mask );
	}
}


/*********************************************************************
 travseral functions for privilege_enumerate_accounts
*********************************************************************/

static int priv_traverse_fn(TDB_CONTEXT *t, TDB_DATA key, TDB_DATA data, void *state)
{
	PRIV_SID_LIST *priv = state;
	int  prefixlen = strlen(PRIVPREFIX);
	DOM_SID sid;
	fstring sid_string;

	/* check we have a PRIV_+SID entry */

	if ( strncmp(key.dptr, PRIVPREFIX, prefixlen) != 0)
		return 0;
		
	/* check to see if we are looking for a particular privilege */

	if ( priv->se_priv != SE_NONE ) {
		uint32 mask = SVAL(data.dptr, 0);
		
		/* if the SID does not have the specified privilege 
		   then just return */
		   
		if ( !(mask & priv->se_priv) )
			return 0;
	}
		
	fstrcpy( sid_string, &key.dptr[strlen(PRIVPREFIX)] );

	if ( !string_to_sid(&sid, sid_string) ) {
		DEBUG(0,("travsersal_fn_enum__acct: Could not convert SID [%s]\n",
			sid_string));
		return 0;
	}

	add_sid_to_array( &sid, &priv->sids.list, &priv->sids.count );
	
	return 0;
}

/*********************************************************************
 Retreive list of privileged SIDs (for _lsa_enumerate_accounts()
*********************************************************************/

NTSTATUS privilege_enumerate_accounts(DOM_SID **sids, int *num_sids)
{
	TDB_CONTEXT *tdb = get_account_pol_tdb();
	PRIV_SID_LIST priv;
	
	ZERO_STRUCT(priv);
	priv.se_priv = SE_NONE;

	tdb_traverse( tdb, priv_traverse_fn, &priv);

	/* give the memory away; caller will free */
	
	*sids      = priv.sids.list;
	*num_sids  = priv.sids.count;

	return NT_STATUS_OK;
}

/***************************************************************************
 Retrieve the SIDs assigned to a given privilege
****************************************************************************/

NTSTATUS priv_get_sids(const char *privname, DOM_SID **sids, int *num_sids)
{
	TDB_CONTEXT *tdb = get_account_pol_tdb();
	PRIV_SID_LIST priv;
	
	ZERO_STRUCT(priv);	
	priv.se_priv = 
	

	tdb_traverse( tdb, priv_traverse_fn, &priv);

	/* give the memory away; caller will free */
	
	*sids      = priv.sids.list;
	*num_sids  = priv.sids.count;

	return NT_STATUS_OK;
}

/***************************************************************************
 Add privilege to sid
****************************************************************************/

BOOL grant_privilege(const DOM_SID *sid, uint32 priv_mask)
{
	uint32 old_mask, new_mask;
	
	old_mask = get_privileges( sid );
	
	new_mask = old_mask | priv_mask;

	DEBUG(10,("grant_privilege: %s, orig priv set = 0x%x, new privilege set = 0x%x\n",
		sid_string_static(sid), old_mask, new_mask ));
	
	return set_privileges( sid, new_mask );
}

/***************************************************************************
 Remove privilege from sid
****************************************************************************/

BOOL revoke_privilege(const DOM_SID *sid, uint32 priv_mask)
{
	uint32 old_mask, new_mask;
	
	old_mask = get_privileges( sid );
	
	new_mask = old_mask & ~priv_mask;

        DEBUG(10,("revoke_privilege: %s, orig priv set = 0x%x, new priv set = 0x%x\n",
                sid_string_static(sid), old_mask, new_mask ));
	
	return set_privileges( sid, new_mask );
}

/***************************************************************************
 Retrieve the SIDs assigned to a given privilege
****************************************************************************/

NTSTATUS privilege_create_account(const DOM_SID *sid )
{
	return ( grant_privilege( sid, SE_NONE ) ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL);
}

/****************************************************************************
 initialise a privilege list and set the talloc context 
 ****************************************************************************/
NTSTATUS privilege_set_init(PRIVILEGE_SET *priv_set)
{
	NTSTATUS ret;
	
	ZERO_STRUCTP( priv_set );

	TALLOC_CTX *mem_ctx = talloc_init("privilege set");
	ALLOC_CHECK(mem_ctx, ret, done, "init_privilege");

	priv_set->mem_ctx = mem_ctx;

	ret = NT_STATUS_OK;

done:
	return ret;
}

/****************************************************************************
  initialise a privilege list and with someone else's talloc context 
****************************************************************************/

NTSTATUS privilege_set_init_by_ctx(TALLOC_CTX *mem_ctx, PRIVILEGE_SET *priv_set)
{
	ZERO_STRUCTP( priv_set );
	
	priv_set->mem_ctx = mem_ctx;
	priv_set->ext_ctx = True;

	return NT_STATUS_OK;
}

/****************************************************************************
 Free all memory used by a PRIVILEGE_SET
****************************************************************************/

void privilege_set_free(PRIVILEGE_SET *priv_set)
{
	if ( !priv_set )
		return;

	if ( !( priv_set->ext_ctx ) )
		talloc_destroy( priv_set->mem_ctx );

	ZERO_STRUCTP( priv_set );
}

/****************************************************************************
 duplicate alloc luid_attr
 ****************************************************************************/

NTSTATUS dup_luid_attr(TALLOC_CTX *mem_ctx, LUID_ATTR **new_la, LUID_ATTR *old_la, int count)
{
	NTSTATUS ret;
	int i;

	/* don't crash if the source pointer is NULL (since we don't
	   do priviledges now anyways) */

	if ( !old_la )
		return NT_STATUS_OK;

	*new_la = TALLOC_ARRAY(mem_ctx, LUID_ATTR, count);
	ALLOC_CHECK(new_la, ret, done, "dupalloc_luid_attr");

	for (i=0; i<count; i++) {
		(*new_la)[i].luid.high = old_la[i].luid.high;
		(*new_la)[i].luid.low = old_la[i].luid.low;
		(*new_la)[i].attr = old_la[i].attr;
	}
	
	ret = NT_STATUS_OK;

done:
	return ret;
}

/****************************************************************************
 Performa deep copy of a PRIVILEGE_SET structure.  Assumes an initialized 
 destination structure.
*****************************************************************************/

BOOL dup_privilege_set( PRIVILEGE_SET *dest, PRIVILEGE_SET *src )
{
	NTSTATUS result;
	
	if ( !dest || !src )
		return False;

	result = dup_luid_attr( dest->mem_ctx, &dest->set, src->set, src->count );
	if ( !NT_STATUS_IS_OK(result) ) {
		DEBUG(0,("dup_privilege_set: Failed to dup LUID_ATTR array [%s]\n", 
			nt_errstr(result) ));
		return False;
	}
	
	dest->control  = src->control;
	dest->count    = src->count;

	return True;
}

/****************************************************************************
 Does the user have the specified privilege ?  We only deal with one privilege
 at a time here.
*****************************************************************************/

BOOL user_has_privilege(NT_USER_TOKEN *token, uint32 privilege)
{
	return check_priv_in_privilege( &token->privileges, get_privilege_luid(privilege) );
}

/****************************************************************************
 Convert a LUID to a named string
****************************************************************************/

char* luid_to_privilege_name(const LUID *set)
{
	static fstring name;
	int i = 0;

	if (set->high != 0)
		return NULL;

	for ( i=0; privs[i].se_priv!=SE_END; i++ ) {
		if (set->low == privs[i].se_priv) {
			fstrcpy(name, privs[i].name);
			return name;
		}
	}

	return NULL;
}

/****************************************************************************
 Convert an LUID to a 32-bit mask
****************************************************************************/

uint32 luid_to_privilege_mask(const LUID *set)
{
	int i = 0;

	if (set->high != 0)
		return SE_END;

	for ( i=0; privs[i].se_priv != SE_END; i++ ) {
		if (set->low == privs[i].se_priv)
			return privs[i].se_priv;
	}

	return SE_END;
}

/*******************************************************************
 return the number of elements in the privlege array
*******************************************************************/

int count_all_privileges( void )
{
	static int count;
	
	if ( count )
		return count;

	/* loop over the array and count it */	
	for ( count=0; privs[count].se_priv != SE_END; count++ ) ;

	return count;
}

