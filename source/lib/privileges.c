/*
   Unix SMB/CIFS implementation.
   Privileges handling functions
   Copyright (C) Jean François Micouleau	1998-2001
   Copyright (C) Simo Sorce			2002-2003
   Copyright (C) Gerald (Jerry) Carter          2005
   
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

#define GENERATE_LUID_LOW(x)	(x)+1;

static const SE_PRIV se_priv_all  = SE_ALL_PRIVS;
static const SE_PRIV se_priv_end  = SE_END;

/* Define variables for all privileges so we can use the
   SE_PRIV* in the various se_priv_XXX() functions */

const SE_PRIV se_priv_none       = SE_NONE;
const SE_PRIV se_machine_account = SE_MACHINE_ACCOUNT;
const SE_PRIV se_print_operator  = SE_PRINT_OPERATOR;
const SE_PRIV se_add_users       = SE_ADD_USERS;
const SE_PRIV se_disk_operators  = SE_DISK_OPERATOR;
const SE_PRIV se_remote_shutdown = SE_REMOTE_SHUTDOWN;

/********************************************************************
 This is a list of privileges reported by a WIndows 2000 SP4 AD DC
 just for reference purposes:

            SeCreateTokenPrivilege  Create a token object
     SeAssignPrimaryTokenPrivilege  Replace a process level token
             SeLockMemoryPrivilege  Lock pages in memory
          SeIncreaseQuotaPrivilege  Increase quotas
         SeMachineAccountPrivilege  Add workstations to domain
                    SeTcbPrivilege  Act as part of the operating system
               SeSecurityPrivilege  Manage auditing and security log
          SeTakeOwnershipPrivilege  Take ownership of files or other objects
             SeLoadDriverPrivilege  Load and unload device drivers
          SeSystemProfilePrivilege  Profile system performance
             SeSystemtimePrivilege  Change the system time
   SeProfileSingleProcessPrivilege  Profile single process
   SeIncreaseBasePriorityPrivilege  Increase scheduling priority
         SeCreatePagefilePrivilege  Create a pagefile
        SeCreatePermanentPrivilege  Create permanent shared objects
                 SeBackupPrivilege  Back up files and directories
                SeRestorePrivilege  Restore files and directories
               SeShutdownPrivilege  Shut down the system
                  SeDebugPrivilege  Debug programs
                  SeAuditPrivilege  Generate security audits
      SeSystemEnvironmentPrivilege  Modify firmware environment values
           SeChangeNotifyPrivilege  Bypass traverse checking
         SeRemoteShutdownPrivilege  Force shutdown from a remote system
                 SeUndockPrivilege  Remove computer from docking station
              SeSyncAgentPrivilege  Synchronize directory service data
       SeEnableDelegationPrivilege  Enable computer and user accounts to be trusted for delegation
           SeManageVolumePrivilege  Perform volume maintenance tasks
            SeImpersonatePrivilege  Impersonate a client after authentication
           SeCreateGlobalPrivilege  Create global objects

********************************************************************/


PRIVS privs[] = {
#if 0	/* usrmgr will display these twice if you include them.  We don't 
	   use them but we'll keep the bitmasks reserved in privileges.h anyways */
	   
	{SE_NETWORK_LOGON,		"SeNetworkLogonRight",			"Access this computer from network"},
	{SE_INTERACTIVE_LOGON,		"SeInteractiveLogonRight",		"Log on locally"},
	{SE_BATCH_LOGON,		"SeBatchLogonRight",			"Log on as a batch job"},
	{SE_SERVICE_LOGON,		"SeServiceLogonRight",			"Log on as a service"},
#endif
	{SE_MACHINE_ACCOUNT,		"SeMachineAccountPrivilege",		"Add machines to domain"},
	{SE_PRINT_OPERATOR,		"SePrintOperatorPrivilege",		"Manage printers"},
	{SE_ADD_USERS,			"SeAddUsersPrivilege",			"Add users and groups to the domain"},
	{SE_REMOTE_SHUTDOWN,		"SeRemoteShutdownPrivilege",		"Force shutdown from a remote system"},
	{SE_DISK_OPERATOR,		"SeDiskOperatorPrivilege",		"Manage disk shares"},

	{SE_END,			"",					""}
};

typedef struct priv_sid_list {
	SE_PRIV privilege;
	SID_LIST sids;
} PRIV_SID_LIST;


/***************************************************************************
 copy an SE_PRIV structure
****************************************************************************/

BOOL se_priv_copy( SE_PRIV *dst, const SE_PRIV *src )
{
	if ( !dst || !src )
		return False;
		
	memcpy( dst, src, sizeof(SE_PRIV) );
	
	return True;
}

/***************************************************************************
 combine 2 SE_PRIV structures and store the resulting set in mew_mask
****************************************************************************/

void se_priv_add( SE_PRIV *mask, const SE_PRIV *addpriv )
{
	int i;

	for ( i=0; i<SE_PRIV_MASKSIZE; i++ ) {
		mask->mask[i] |= addpriv->mask[i];
	}
}

/***************************************************************************
 remove one SE_PRIV sytucture from another and store the resulting set 
 in mew_mask
****************************************************************************/

void se_priv_remove( SE_PRIV *mask, const SE_PRIV *removepriv )
{	
	int i;

	for ( i=0; i<SE_PRIV_MASKSIZE; i++ ) {
		mask->mask[i] &= ~removepriv->mask[i];
	}
}

/***************************************************************************
 invert a given SE_PRIV and store the set in new_mask
****************************************************************************/

static void se_priv_invert( SE_PRIV *new_mask, const SE_PRIV *mask )
{	
	SE_PRIV allprivs;
	
	se_priv_copy( &allprivs, &se_priv_all );
	se_priv_remove( &allprivs, mask );
	se_priv_copy( new_mask, &allprivs );
}

/***************************************************************************
 check if 2 SE_PRIV structure are equal
****************************************************************************/

static BOOL se_priv_equal( const SE_PRIV *mask1, const SE_PRIV *mask2 )
{	
	return ( memcmp(mask1, mask2, sizeof(SE_PRIV)) == 0 );
}

/***************************************************************************
 check if a SE_PRIV has any assigned privileges
****************************************************************************/

static BOOL se_priv_empty( const SE_PRIV *mask )
{
	SE_PRIV p1;
	int i;
	
	se_priv_copy( &p1, mask );

	for ( i=0; i<SE_PRIV_MASKSIZE; i++ ) {
		p1.mask[i] &= se_priv_all.mask[i];
	}
	
	return se_priv_equal( &p1, &se_priv_none );
}

/*********************************************************************
 Lookup the SE_PRIV value for a privilege name 
*********************************************************************/

BOOL se_priv_from_name( const char *name, SE_PRIV *mask )
{
	int i;

	for ( i=0; !se_priv_equal(&privs[i].se_priv, &se_priv_end); i++ ) {
		if ( strequal( privs[i].name, name ) ) {
			se_priv_copy( mask, &privs[i].se_priv );
			return True;
		}
	}

	return False;
}

/***************************************************************************
 dump an SE_PRIV structure to the log files
****************************************************************************/

void dump_se_priv( int dbg_cl, int dbg_lvl, const SE_PRIV *mask )
{
	int i;
	
	DEBUGADDC( dbg_cl, dbg_lvl,("SE_PRIV "));
	
	for ( i=0; i<SE_PRIV_MASKSIZE; i++ ) {
		DEBUGADDC( dbg_cl, dbg_lvl,(" 0x%x", mask->mask[i] ));
	}
		
	DEBUGADDC( dbg_cl, dbg_lvl, ("\n"));
}

/***************************************************************************
 Retrieve the privilege mask (set) for a given SID
****************************************************************************/

static BOOL get_privileges( const DOM_SID *sid, SE_PRIV *mask )
{
	TDB_CONTEXT *tdb = get_account_pol_tdb();
	fstring keystr;
	TDB_DATA key, data;

	/* Fail if the admin has not enable privileges */
	
	if ( !lp_enable_privileges() ) {
		return False;
	}
	
	if ( !tdb )
		return False;

	/* PRIV_<SID> (NULL terminated) as the key */
	
	fstr_sprintf( keystr, "%s%s", PRIVPREFIX, sid_string_static(sid) );
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data = tdb_fetch( tdb, key );
	
	if ( !data.dptr ) {
		DEBUG(3,("get_privileges: No privileges assigned to SID [%s]\n",
			sid_string_static(sid)));
		return False;
	}
	
	SMB_ASSERT( data.dsize == sizeof( SE_PRIV ) );
	
	se_priv_copy( mask, (SE_PRIV*)data.dptr );
	SAFE_FREE(data.dptr);

	return True;
}

/***************************************************************************
 Store the privilege mask (set) for a given SID
****************************************************************************/

static BOOL set_privileges( const DOM_SID *sid, SE_PRIV *mask )
{
	TDB_CONTEXT *tdb = get_account_pol_tdb();
	fstring keystr;
	TDB_DATA key, data;
	
	if ( !lp_enable_privileges() )
		return False;

	if ( !tdb )
		return False;

	/* PRIV_<SID> (NULL terminated) as the key */
	
	fstr_sprintf( keystr, "%s%s", PRIVPREFIX, sid_string_static(sid) );
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;
	
	/* no packing.  static size structure, just write it out */
	
	data.dptr  = (char*)mask;
	data.dsize = sizeof(SE_PRIV);

	return ( tdb_store(tdb, key, data, TDB_REPLACE) != -1 );
}

/****************************************************************************
 check if the privilege is in the privilege list
****************************************************************************/

static BOOL is_privilege_assigned( SE_PRIV *privileges, const SE_PRIV *check )
{
	SE_PRIV p1, p2;

	if ( !privileges || !check )
		return False;
	
	/* everyone has privileges if you aren't checking for any */
	
	if ( se_priv_empty( check ) ) {
		DEBUG(1,("is_privilege_assigned: no privileges in check_mask!\n"));
		return True;
	}
	
	se_priv_copy( &p1, check );
	
	/* invert the SE_PRIV we want to check for and remove that from the 
	   original set.  If we are left with the SE_PRIV we are checking 
	   for then return True */
	   
	se_priv_invert( &p1, check );
	se_priv_copy( &p2, privileges );
	se_priv_remove( &p2, &p1 );
	
	return se_priv_equal( &p2, check );
}

/****************************************************************************
 check if the privilege is in the privilege list
****************************************************************************/

static BOOL is_any_privilege_assigned( SE_PRIV *privileges, const SE_PRIV *check )
{
	SE_PRIV p1, p2;

	if ( !privileges || !check )
		return False;
	
	/* everyone has privileges if you aren't checking for any */
	
	if ( se_priv_empty( check ) ) {
		DEBUG(1,("is_any_privilege_assigned: no privileges in check_mask!\n"));
		return True;
	}
	
	se_priv_copy( &p1, check );
	
	/* invert the SE_PRIV we want to check for and remove that from the 
	   original set.  If we are left with the SE_PRIV we are checking 
	   for then return True */
	   
	se_priv_invert( &p1, check );
	se_priv_copy( &p2, privileges );
	se_priv_remove( &p2, &p1 );
	
	/* see if we have any bits left */
	
	return !se_priv_empty( &p2 );
}

/****************************************************************************
 add a privilege to a privilege array
 ****************************************************************************/

static BOOL privilege_set_add(PRIVILEGE_SET *priv_set, LUID_ATTR set)
{
	LUID_ATTR *new_set;

	/* we can allocate memory to add the new privilege */

	new_set = TALLOC_REALLOC_ARRAY(priv_set->mem_ctx, priv_set->set, LUID_ATTR, priv_set->count + 1);
	if ( !new_set ) {
		DEBUG(0,("privilege_set_add: failed to allocate memory!\n"));
		return False;
	}	

	new_set[priv_set->count].luid.high = set.luid.high;
	new_set[priv_set->count].luid.low = set.luid.low;
	new_set[priv_set->count].attr = set.attr;

	priv_set->count++;
	priv_set->set = new_set;

	return True;
}

/*********************************************************************
 Generate the LUID_ATTR structure based on a bitmask
*********************************************************************/

LUID_ATTR get_privilege_luid( SE_PRIV *mask )
{
	LUID_ATTR priv_luid;
	int i;

	priv_luid.attr = 0;
	priv_luid.luid.high = 0;
	
	for ( i=0; !se_priv_equal(&privs[i].se_priv, &se_priv_end); i++ ) {
	
		if ( se_priv_equal( &privs[i].se_priv, mask ) ) {
			priv_luid.luid.low = GENERATE_LUID_LOW(i);
			break;
		}
	}

	return priv_luid;
}

/*********************************************************************
 Generate the LUID_ATTR structure based on a bitmask
*********************************************************************/

const char* get_privilege_dispname( const char *name )
{
	int i;

	for ( i=0; !se_priv_equal(&privs[i].se_priv, &se_priv_end); i++ ) {
	
		if ( strequal( privs[i].name, name ) ) {
			return privs[i].description;
		}
	}

	return NULL;
}

/*********************************************************************
 get a list of all privleges for all sids the in list
*********************************************************************/

BOOL get_privileges_for_sids(SE_PRIV *privileges, DOM_SID *slist, int scount)
{
	SE_PRIV mask;
	int i;
	BOOL found = False;

	se_priv_copy( privileges, &se_priv_none );
	
	for ( i=0; i<scount; i++ ) {
		/* don't add unless we actually have a privilege assigned */

		if ( !get_privileges( &slist[i], &mask ) )
			continue;

		DEBUG(5,("get_privileges_for_sids: sid = %s\nPrivilege set:\n", 
			sid_string_static(&slist[i])));
		dump_se_priv( DBGC_ALL, 5, &mask );
			
		se_priv_add( privileges, &mask );
		found = True;
	}

	return found;
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
	
	/* easy check first */
	
	if ( data.dsize != sizeof(SE_PRIV) )
		return 0;

	/* check we have a PRIV_+SID entry */

	if ( strncmp(key.dptr, PRIVPREFIX, prefixlen) != 0)
		return 0;
		
	/* check to see if we are looking for a particular privilege */

	if ( !se_priv_equal(&priv->privilege, &se_priv_none) ) {
		SE_PRIV mask;
		
		se_priv_copy( &mask, (SE_PRIV*)data.dptr );
		
		/* if the SID does not have the specified privilege 
		   then just return */
		   
		if ( !is_privilege_assigned( &mask, &priv->privilege) )
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

	se_priv_copy( &priv.privilege, &se_priv_none );

	tdb_traverse( tdb, priv_traverse_fn, &priv);

	/* give the memory away; caller will free */
	
	*sids      = priv.sids.list;
	*num_sids  = priv.sids.count;

	return NT_STATUS_OK;
}

/***************************************************************************
 Add privilege to sid
****************************************************************************/

BOOL grant_privilege(const DOM_SID *sid, const SE_PRIV *priv_mask)
{
	SE_PRIV old_mask, new_mask;
	
	if ( get_privileges( sid, &old_mask ) )
		se_priv_copy( &new_mask, &old_mask );
	else
		se_priv_copy( &new_mask, &se_priv_none );

	se_priv_add( &new_mask, priv_mask );

	DEBUG(10,("grant_privilege: %s\n", sid_string_static(sid)));
	
	DEBUGADD( 10, ("original privilege mask:\n"));
	dump_se_priv( DBGC_ALL, 10, &old_mask );
	
	DEBUGADD( 10, ("new privilege mask:\n"));
	dump_se_priv( DBGC_ALL, 10, &new_mask );
	
	return set_privileges( sid, &new_mask );
}

/*********************************************************************
 Add a privilege based on its name
*********************************************************************/

BOOL grant_privilege_by_name(DOM_SID *sid, const char *name)
{
	int i;

	for ( i=0; !se_priv_equal(&privs[i].se_priv, &se_priv_end); i++ ) {
		if ( strequal(privs[i].name, name) ) {
			return grant_privilege( sid, &privs[i].se_priv );
                }
        }

        DEBUG(3, ("grant_privilege_by_name: No Such Privilege Found (%s)\n", name));

        return False;
}

/***************************************************************************
 Remove privilege from sid
****************************************************************************/

BOOL revoke_privilege(const DOM_SID *sid, const SE_PRIV *priv_mask)
{
	SE_PRIV mask;
	
	/* if the user has no privileges, then we can't revoke any */
	
	if ( !get_privileges( sid, &mask ) )
		return True;
	
	DEBUG(10,("revoke_privilege: %s\n", sid_string_static(sid)));
	
	DEBUGADD( 10, ("original privilege mask:\n"));
	dump_se_priv( DBGC_ALL, 10, &mask );

	se_priv_remove( &mask, priv_mask );
	
	DEBUGADD( 10, ("new privilege mask:\n"));
	dump_se_priv( DBGC_ALL, 10, &mask );
	
	return set_privileges( sid, &mask );
}

/*********************************************************************
 Revoke all privileges
*********************************************************************/

BOOL revoke_all_privileges( DOM_SID *sid )
{
	return revoke_privilege( sid, &se_priv_all );
}

/*********************************************************************
 Add a privilege based on its name
*********************************************************************/

BOOL revoke_privilege_by_name(DOM_SID *sid, const char *name)
{
	int i;

	for ( i=0; !se_priv_equal(&privs[i].se_priv, &se_priv_end); i++ ) {
		if ( strequal(privs[i].name, name) ) {
			return revoke_privilege( sid, &privs[i].se_priv );
                }
        }

        DEBUG(3, ("revoke_privilege_by_name: No Such Privilege Found (%s)\n", name));

        return False;
}

/***************************************************************************
 Retrieve the SIDs assigned to a given privilege
****************************************************************************/

NTSTATUS privilege_create_account(const DOM_SID *sid )
{
	return ( grant_privilege(sid, &se_priv_none) ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL);
}

/****************************************************************************
 initialise a privilege list and set the talloc context 
 ****************************************************************************/
NTSTATUS privilege_set_init(PRIVILEGE_SET *priv_set)
{
	TALLOC_CTX *mem_ctx;
	
	ZERO_STRUCTP( priv_set );

	mem_ctx = talloc_init("privilege set");
	if ( !mem_ctx ) {
		DEBUG(0,("privilege_set_init: failed to initialize talloc ctx!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	priv_set->mem_ctx = mem_ctx;

	return NT_STATUS_OK;
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
	int i;

	if ( !old_la )
		return NT_STATUS_OK;

	*new_la = TALLOC_ARRAY(mem_ctx, LUID_ATTR, count);
	if ( !*new_la ) {
		DEBUG(0,("dup_luid_attr: failed to alloc new LUID_ATTR array [%d]\n", count));
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<count; i++) {
		(*new_la)[i].luid.high = old_la[i].luid.high;
		(*new_la)[i].luid.low = old_la[i].luid.low;
		(*new_la)[i].attr = old_la[i].attr;
	}
	
	return NT_STATUS_OK;
}

/****************************************************************************
 Does the user have the specified privilege ?  We only deal with one privilege
 at a time here.
*****************************************************************************/

BOOL user_has_privileges(NT_USER_TOKEN *token, const SE_PRIV *privilege)
{
	if ( !token )
		return False;

	return is_privilege_assigned( &token->privileges, privilege );
}

/****************************************************************************
 Does the user have any of the specified privileges ?  We only deal with one privilege
 at a time here.
*****************************************************************************/

BOOL user_has_any_privilege(NT_USER_TOKEN *token, const SE_PRIV *privilege)
{
	if ( !token )
		return False;

	return is_any_privilege_assigned( &token->privileges, privilege );
}

/****************************************************************************
 Convert a LUID to a named string
****************************************************************************/

char* luid_to_privilege_name(const LUID *set)
{
	static fstring name;
	int max = count_all_privileges();

	if (set->high != 0)
		return NULL;

	if ( set->low > max )
		return NULL;

	fstrcpy( name, privs[set->low - 1].name );
	
	return name;
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
	for ( count=0; !se_priv_equal(&privs[count].se_priv, &se_priv_end); count++ ) ;

	return count;
}

/*******************************************************************
*******************************************************************/

BOOL se_priv_to_privilege_set( PRIVILEGE_SET *set, SE_PRIV *mask )
{
	int i;
	uint32 num_privs = count_all_privileges();
	LUID_ATTR luid;
	
	luid.attr = 0;
	luid.luid.high = 0;
	
	for ( i=0; i<num_privs; i++ ) {
		if ( !is_privilege_assigned(mask, &privs[i].se_priv) )
			continue;
		
		luid.luid.low = GENERATE_LUID_LOW(i);
		
		if ( !privilege_set_add( set, luid ) )
			return False;
	}

	return True;
}

/*******************************************************************
*******************************************************************/

BOOL privilege_set_to_se_priv( SE_PRIV *mask, PRIVILEGE_SET *privset )
{
	int i;
	uint32 num_privs = count_all_privileges();
	
	ZERO_STRUCTP( mask );
	
	for ( i=0; i<privset->count; i++ ) {
		SE_PRIV r;
	
		/* sanity check for invalid privilege.  we really
		   only care about the low 32 bits */
		   
		if ( privset->set[i].luid.high != 0 )
			return False;
		
		/* make sure :LUID.low is in range */	
		if ( privset->set[i].luid.low == 0 || privset->set[i].luid.low > num_privs )
			return False;
		
		r = privs[privset->set[i].luid.low - 1].se_priv;
		se_priv_add( mask, &r );
	}

	return True;
}

/*******************************************************************
*******************************************************************/

BOOL is_privileged_sid( DOM_SID *sid )
{
	SE_PRIV mask;
	
	return get_privileges( sid, &mask );
}
