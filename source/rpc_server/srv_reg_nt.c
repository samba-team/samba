/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell               1992-1997.
 *  Copyright (C) Luke Kenneth Casson Leighton  1996-1997.
 *  Copyright (C) Paul Ashton                        1997.
 *  Copyright (C) Jeremy Allison                     2001.
 *  Copyright (C) Gerald Carter                      2002.
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

/* Implementation of registry functions. */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define REGSTR_PRODUCTTYPE		"ProductType"
#define REG_PT_WINNT			"WinNT"
#define REG_PT_LANMANNT			"LanmanNT"
#define REG_PT_SERVERNT			"ServerNT"

#define OUR_HANDLE(hnd) (((hnd)==NULL)?"NULL":(IVAL((hnd)->data5,4)==(uint32)sys_getpid()?"OURS":"OTHER")), \
((unsigned int)IVAL((hnd)->data5,4)),((unsigned int)sys_getpid())


static REGISTRY_KEY *regkeys_list;


/******************************************************************
 free() function for REGISTRY_KEY
 *****************************************************************/
 
static void free_regkey_info(void *ptr)
{
	REGISTRY_KEY *info = (REGISTRY_KEY*)ptr;
	
	DLIST_REMOVE(regkeys_list, info);

	SAFE_FREE(info);
}

/******************************************************************
 Find a registry key handle and return a REGISTRY_KEY
 *****************************************************************/

static REGISTRY_KEY *find_regkey_index_by_hnd(pipes_struct *p, POLICY_HND *hnd)
{
	REGISTRY_KEY *regkey = NULL;

	if(!find_policy_by_hnd(p,hnd,(void **)&regkey)) {
		DEBUG(2,("find_regkey_index_by_hnd: Registry Key not found: "));
		return NULL;
	}

	return regkey;
}


/*******************************************************************
 Function for open a new registry handle and creating a handle 
 Note that P should be valid & hnd should already have space
 
 When we open a key, we store the full path to the key as 
 HK[LM|U]\<key>\<key>\...
 *******************************************************************/
 
static NTSTATUS open_registry_key(pipes_struct *p, POLICY_HND *hnd, REGISTRY_KEY *parent,
				const char *subkeyname, uint32 access_granted  )
{
	REGISTRY_KEY 	*regkey = NULL;
	NTSTATUS     	result = NT_STATUS_OK;
	REGSUBKEY_CTR	subkeys;
	pstring		subkeyname2;
	int		subkey_len;
	
	DEBUG(7,("open_registry_key: name = [%s][%s]\n", 
		parent ? parent->name : "NULL", subkeyname));

	/* strip any trailing '\'s */
	pstrcpy( subkeyname2, subkeyname );
	subkey_len = strlen ( subkeyname2 );
	if ( subkey_len && subkeyname2[subkey_len-1] == '\\' )
		subkeyname2[subkey_len-1] = '\0';

	if ((regkey=(REGISTRY_KEY*)malloc(sizeof(REGISTRY_KEY))) == NULL)
		return NT_STATUS_NO_MEMORY;
		
	ZERO_STRUCTP( regkey );
	
	/* 
	 * very crazy, but regedit.exe on Win2k will attempt to call 
	 * REG_OPEN_ENTRY with a keyname of "".  We should return a new 
	 * (second) handle here on the key->name.  regedt32.exe does 
	 * not do this stupidity.   --jerry
	 */
	
	if ( !subkey_len ) {
		pstrcpy( regkey->name, parent->name );	
	}
	else {
		pstrcpy( regkey->name, "" );
		if ( parent ) {
			pstrcat( regkey->name, parent->name );
			pstrcat( regkey->name, "\\" );
		}
		pstrcat( regkey->name, subkeyname2 );
	}
	
	/* Look up the table of registry I/O operations */

	if ( !(regkey->hook = reghook_cache_find( regkey->name )) ) {
		DEBUG(0,("open_registry_key: Failed to assigned a REGISTRY_HOOK to [%s]\n",
			regkey->name ));
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}
	
	/* check if the path really exists; failed is indicated by -1 */
	/* if the subkey count failed, bail out */

	ZERO_STRUCTP( &subkeys );
	
	regsubkey_ctr_init( &subkeys );
	
	if ( fetch_reg_keys( regkey, &subkeys ) == -1 )  {
	
		/* don't really know what to return here */
		result = NT_STATUS_NO_SUCH_FILE;
	}
	else {
		/* 
		 * This would previously return NT_STATUS_TOO_MANY_SECRETS
		 * that doesn't sound quite right to me  --jerry
		 */
		
		if ( !create_policy_hnd( p, hnd, free_regkey_info, regkey ) )
			result = NT_STATUS_OBJECT_NAME_NOT_FOUND; 
	}
	
	/* clean up */

	regsubkey_ctr_destroy( &subkeys );
	
	if ( ! NT_STATUS_IS_OK(result) )
		SAFE_FREE( regkey );
	else
		DLIST_ADD( regkeys_list, regkey );

	
	DEBUG(7,("open_registry_key: exit\n"));

	return result;
}

/*******************************************************************
 Function for open a new registry handle and creating a handle 
 Note that P should be valid & hnd should already have space
 *******************************************************************/

static BOOL close_registry_key(pipes_struct *p, POLICY_HND *hnd)
{
	REGISTRY_KEY *regkey = find_regkey_index_by_hnd(p, hnd);
	
	if ( !regkey ) {
		DEBUG(2,("close_registry_key: Invalid handle (%s:%u:%u)\n", OUR_HANDLE(hnd)));
		return False;
	}
	
	close_policy_hnd(p, hnd);
	
	return True;
}

/********************************************************************
 retrieve information about the subkeys
 *******************************************************************/
 
static BOOL get_subkey_information( REGISTRY_KEY *key, uint32 *maxnum, uint32 *maxlen )
{
	int 		num_subkeys, i;
	uint32 		max_len;
	REGSUBKEY_CTR 	subkeys;
	uint32 		len;
	
	if ( !key )
		return False;

	ZERO_STRUCTP( &subkeys );
	
	regsubkey_ctr_init( &subkeys );	
	   
	if ( fetch_reg_keys( key, &subkeys ) == -1 )
		return False;

	/* find the longest string */
	
	max_len = 0;
	num_subkeys = regsubkey_ctr_numkeys( &subkeys );
	
	for ( i=0; i<num_subkeys; i++ ) {
		len = strlen( regsubkey_ctr_specific_key(&subkeys, i) );
		max_len = MAX(max_len, len);
	}

	*maxnum = num_subkeys;
	*maxlen = max_len*2;
	
	regsubkey_ctr_destroy( &subkeys );
	
	return True;
}

/********************************************************************
 retrieve information about the values.  We don't store values 
 here.  The registry tdb is intended to be a frontend to oether 
 Samba tdb's (such as ntdrivers.tdb).
 *******************************************************************/
 
static BOOL get_value_information( REGISTRY_KEY *key, uint32 *maxnum, 
                                    uint32 *maxlen, uint32 *maxsize )
{
	REGVAL_CTR 	values;
	REGISTRY_VALUE	*val;
	uint32 		sizemax, lenmax;
	int 		i, num_values;
	
	if ( !key )
		return False;


	ZERO_STRUCTP( &values );
	
	regval_ctr_init( &values );
	
	if ( fetch_reg_values( key, &values ) == -1 )
		return False;
	
	lenmax = sizemax = 0;
	num_values = regval_ctr_numvals( &values );
	
	val = regval_ctr_specific_value( &values, 0 );
	
	for ( i=0; i<num_values && val; i++ ) 
	{
		lenmax  = MAX(lenmax,  strlen(val->valuename)+1 );
		sizemax = MAX(sizemax, val->size );
		
		val = regval_ctr_specific_value( &values, i );
	}

	*maxnum   = num_values;
	*maxlen   = lenmax;
	*maxsize  = sizemax;
	
	regval_ctr_destroy( &values );
	
	return True;
}


/********************************************************************
 reg_close
 ********************************************************************/

NTSTATUS _reg_close(pipes_struct *p, REG_Q_CLOSE *q_u, REG_R_CLOSE *r_u)
{
	/* set up the REG unknown_1 response */
	ZERO_STRUCT(r_u->pol);

	/* close the policy handle */
	if (!close_registry_key(p, &q_u->pol))
		return NT_STATUS_OBJECT_NAME_INVALID;

	return NT_STATUS_OK;
}

/*******************************************************************
 ********************************************************************/

NTSTATUS _reg_open_hklm(pipes_struct *p, REG_Q_OPEN_HKLM *q_u, REG_R_OPEN_HKLM *r_u)
{
	return open_registry_key( p, &r_u->pol, NULL, KEY_HKLM, 0x0 );
}

/*******************************************************************
 ********************************************************************/

NTSTATUS _reg_open_hkcr(pipes_struct *p, REG_Q_OPEN_HKCR *q_u, REG_R_OPEN_HKCR *r_u)
{
	return open_registry_key( p, &r_u->pol, NULL, KEY_HKCR, 0x0 );
}

/*******************************************************************
 ********************************************************************/

NTSTATUS _reg_open_hku(pipes_struct *p, REG_Q_OPEN_HKU *q_u, REG_R_OPEN_HKU *r_u)
{
	return open_registry_key( p, &r_u->pol, NULL, KEY_HKU, 0x0 );
}

/*******************************************************************
 reg_reply_open_entry
 ********************************************************************/

NTSTATUS _reg_open_entry(pipes_struct *p, REG_Q_OPEN_ENTRY *q_u, REG_R_OPEN_ENTRY *r_u)
{
	POLICY_HND pol;
	fstring name;
	REGISTRY_KEY *key = find_regkey_index_by_hnd(p, &q_u->pol);
	NTSTATUS result;

	DEBUG(5,("reg_open_entry: Enter\n"));

	if ( !key )
		return NT_STATUS_INVALID_HANDLE;

	rpcstr_pull(name,q_u->uni_name.buffer,sizeof(name),q_u->uni_name.uni_str_len*2,0);
	
	result = open_registry_key( p, &pol, key, name, 0x0 );
	
	init_reg_r_open_entry( r_u, &pol, result );

	DEBUG(5,("reg_open_entry: Exit\n"));

	return r_u->status;
}

/*******************************************************************
 reg_reply_info
 ********************************************************************/

NTSTATUS _reg_info(pipes_struct *p, REG_Q_INFO *q_u, REG_R_INFO *r_u)
{
	NTSTATUS 		status = NT_STATUS_NO_SUCH_FILE;
	fstring 		name;
	const char              *value_ascii = "";
	fstring                 value;
	int                     value_length;
	REGISTRY_KEY 		*regkey = find_regkey_index_by_hnd( p, &q_u->pol );
	REGISTRY_VALUE		*val = NULL;
	REGVAL_CTR		regvals;
	int			i;

	DEBUG(5,("_reg_info: Enter\n"));

	if ( !regkey )
		return NT_STATUS_INVALID_HANDLE;
		
	DEBUG(7,("_reg_info: policy key name = [%s]\n", regkey->name));
	
	rpcstr_pull(name, q_u->uni_type.buffer, sizeof(name), q_u->uni_type.uni_str_len*2, 0);

	DEBUG(5,("reg_info: looking up value: [%s]\n", name));

	ZERO_STRUCTP( &regvals );
	
	regval_ctr_init( &regvals );

	/* couple of hard coded registry values */
	
	if ( strequal(name, "RefusePasswordChange") ) {
		if ( (val = (REGISTRY_VALUE*)malloc(sizeof(REGISTRY_VALUE))) == NULL ) {
			DEBUG(0,("_reg_info: malloc() failed!\n"));
			return NT_STATUS_NO_MEMORY;
		}
		ZERO_STRUCTP( val );
	
		goto out;
	}

	if ( strequal(name, REGSTR_PRODUCTTYPE) ) {
		/* This makes the server look like a member server to clients */
		/* which tells clients that we have our own local user and    */
		/* group databases and helps with ACL support.                */
		
		switch (lp_server_role()) {
			case ROLE_DOMAIN_PDC:
			case ROLE_DOMAIN_BDC:
				value_ascii = REG_PT_LANMANNT;
				break;
			case ROLE_STANDALONE:
				value_ascii = REG_PT_SERVERNT;
				break;
			case ROLE_DOMAIN_MEMBER:
				value_ascii = REG_PT_WINNT;
				break;
		}
		value_length = push_ucs2(value, value, value_ascii,
					 sizeof(value),
					 STR_TERMINATE|STR_NOALIGN);
		regval_ctr_addvalue(&regvals, REGSTR_PRODUCTTYPE, REG_SZ,
				    value, value_length);
		
		val = dup_registry_value( regval_ctr_specific_value( &regvals, 0 ) );
		
		status = NT_STATUS_OK;
		
		goto out;
	}

	/* else fall back to actually looking up the value */
	
	for ( i=0; fetch_reg_values_specific(regkey, &val, i); i++ ) 
	{
		DEBUG(10,("_reg_info: Testing value [%s]\n", val->valuename));
		if ( StrCaseCmp( val->valuename, name ) == 0 ) {
			DEBUG(10,("_reg_info: Found match for value [%s]\n", name));
			status = NT_STATUS_OK;
			break;
		}
		
		free_registry_value( val );
	}

  
out:
	new_init_reg_r_info(q_u->ptr_buf, r_u, val, status);
	
	regval_ctr_destroy( &regvals );
	free_registry_value( val );

	DEBUG(5,("_reg_info: Exit\n"));

	return status;
}


/*****************************************************************************
 Implementation of REG_QUERY_KEY
 ****************************************************************************/
 
NTSTATUS _reg_query_key(pipes_struct *p, REG_Q_QUERY_KEY *q_u, REG_R_QUERY_KEY *r_u)
{
	NTSTATUS 	status = NT_STATUS_OK;
	REGISTRY_KEY	*regkey = find_regkey_index_by_hnd( p, &q_u->pol );
	
	DEBUG(5,("_reg_query_key: Enter\n"));
	
	if ( !regkey )
		return NT_STATUS_INVALID_HANDLE;	
	
	if ( !get_subkey_information( regkey, &r_u->num_subkeys, &r_u->max_subkeylen ) )
		return NT_STATUS_ACCESS_DENIED;
		
	if ( !get_value_information( regkey, &r_u->num_values, &r_u->max_valnamelen, &r_u->max_valbufsize ) )
		return NT_STATUS_ACCESS_DENIED;	

		
	r_u->sec_desc = 0x00000078;	/* size for key's sec_desc */
	
	/* Win9x set this to 0x0 since it does not keep timestamps.
	   Doing the same here for simplicity   --jerry */
	   
	ZERO_STRUCT(r_u->mod_time);	

	DEBUG(5,("_reg_query_key: Exit\n"));
	
	return status;
}


/*****************************************************************************
 Implementation of REG_UNKNOWN_1A
 ****************************************************************************/
 
NTSTATUS _reg_unknown_1a(pipes_struct *p, REG_Q_UNKNOWN_1A *q_u, REG_R_UNKNOWN_1A *r_u)
{
	NTSTATUS 	status = NT_STATUS_OK;
	REGISTRY_KEY	*regkey = find_regkey_index_by_hnd( p, &q_u->pol );
	
	DEBUG(5,("_reg_unknown_1a: Enter\n"));
	
	if ( !regkey )
		return NT_STATUS_INVALID_HANDLE;	
	
	r_u->unknown = 0x00000005;	/* seems to be consistent...no idea what it means */
	
	DEBUG(5,("_reg_unknown_1a: Exit\n"));
	
	return status;
}


/*****************************************************************************
 Implementation of REG_ENUM_KEY
 ****************************************************************************/
 
NTSTATUS _reg_enum_key(pipes_struct *p, REG_Q_ENUM_KEY *q_u, REG_R_ENUM_KEY *r_u)
{
	NTSTATUS 	status = NT_STATUS_OK;
	REGISTRY_KEY	*regkey = find_regkey_index_by_hnd( p, &q_u->pol );
	char		*subkey = NULL;
	
	
	DEBUG(5,("_reg_enum_key: Enter\n"));
	
	if ( !regkey )
		return NT_STATUS_INVALID_HANDLE;	

	DEBUG(8,("_reg_enum_key: enumerating key [%s]\n", regkey->name));
	
	if ( !fetch_reg_keys_specific( regkey, &subkey, q_u->key_index ) )
	{
		status = NT_STATUS_NO_MORE_ENTRIES;
		goto done;
	}
	
	DEBUG(10,("_reg_enum_key: retrieved subkey named [%s]\n", subkey));
	
	/* subkey has the string name now */
	
	init_reg_r_enum_key( r_u, subkey, q_u->unknown_1, q_u->unknown_2 );
	
	DEBUG(5,("_reg_enum_key: Exit\n"));
	
done:	
	SAFE_FREE( subkey );
	return status;
}

/*****************************************************************************
 Implementation of REG_ENUM_VALUE
 ****************************************************************************/
 
NTSTATUS _reg_enum_value(pipes_struct *p, REG_Q_ENUM_VALUE *q_u, REG_R_ENUM_VALUE *r_u)
{
	NTSTATUS 	status = NT_STATUS_OK;
	REGISTRY_KEY	*regkey = find_regkey_index_by_hnd( p, &q_u->pol );
	REGISTRY_VALUE	*val;
	
	
	DEBUG(5,("_reg_enum_value: Enter\n"));
	
	if ( !regkey )
		return NT_STATUS_INVALID_HANDLE;	

	DEBUG(8,("_reg_enum_key: enumerating values for key [%s]\n", regkey->name));

	if ( !fetch_reg_values_specific( regkey, &val, q_u->val_index ) )
	{
		status = NT_STATUS_NO_MORE_ENTRIES;
		goto done;
	}
	
	DEBUG(10,("_reg_enum_value: retrieved value named  [%s]\n", val->valuename));
	
	/* subkey has the string name now */
	
	init_reg_r_enum_val( r_u, val );


	DEBUG(5,("_reg_enum_value: Exit\n"));
	
done:	
	free_registry_value( val );
	
	return status;
}


/*******************************************************************
 reg_shutdwon
 ********************************************************************/

#define SHUTDOWN_R_STRING "-r"
#define SHUTDOWN_F_STRING "-f"


NTSTATUS _reg_shutdown(pipes_struct *p, REG_Q_SHUTDOWN *q_u, REG_R_SHUTDOWN *r_u)
{
	NTSTATUS status = NT_STATUS_OK;
	pstring shutdown_script;
	UNISTR2 unimsg = q_u->uni_msg;
	pstring message;
	pstring chkmsg;
	fstring timeout;
	fstring r;
	fstring f;
	
	/* message */
	rpcstr_pull (message, unimsg.buffer, sizeof(message), unimsg.uni_str_len*2,0);
		/* security check */
	alpha_strcpy (chkmsg, message, NULL, sizeof(message));
	/* timeout */
	fstr_sprintf(timeout, "%d", q_u->timeout);
	/* reboot */
	fstr_sprintf(r, (q_u->reboot) ? SHUTDOWN_R_STRING : "");
	/* force */
	fstr_sprintf(f, (q_u->force) ? SHUTDOWN_F_STRING : "");

	pstrcpy(shutdown_script, lp_shutdown_script());

	if(*shutdown_script) {
		int shutdown_ret;
		all_string_sub(shutdown_script, "%m", chkmsg, sizeof(shutdown_script));
		all_string_sub(shutdown_script, "%t", timeout, sizeof(shutdown_script));
		all_string_sub(shutdown_script, "%r", r, sizeof(shutdown_script));
		all_string_sub(shutdown_script, "%f", f, sizeof(shutdown_script));
		shutdown_ret = smbrun(shutdown_script,NULL);
		DEBUG(3,("_reg_shutdown: Running the command `%s' gave %d\n",shutdown_script,shutdown_ret));
	}

	return status;
}

/*******************************************************************
 reg_abort_shutdwon
 ********************************************************************/

NTSTATUS _reg_abort_shutdown(pipes_struct *p, REG_Q_ABORT_SHUTDOWN *q_u, REG_R_ABORT_SHUTDOWN *r_u)
{
	NTSTATUS status = NT_STATUS_OK;
	pstring abort_shutdown_script;

	pstrcpy(abort_shutdown_script, lp_abort_shutdown_script());

	if(*abort_shutdown_script) {
		int abort_shutdown_ret;
		abort_shutdown_ret = smbrun(abort_shutdown_script,NULL);
		DEBUG(3,("_reg_abort_shutdown: Running the command `%s' gave %d\n",abort_shutdown_script,abort_shutdown_ret));
	}

	return status;
}

/*******************************************************************
 REG_SAVE_KEY (0x14)
 ********************************************************************/

NTSTATUS _reg_save_key(pipes_struct *p, REG_Q_SAVE_KEY  *q_u, REG_R_SAVE_KEY *r_u)
{
	REGISTRY_KEY	*regkey = find_regkey_index_by_hnd( p, &q_u->pol );
	
	DEBUG(5,("_reg_save_key: Enter\n"));
	
	/* 
	 * basically this is a no op function which just gverifies 
	 * that the client gave us a valid registry key handle 
	 */
	 
	if ( !regkey )
		return NT_STATUS_INVALID_HANDLE;	

	DEBUG(8,("_reg_save_key: berifying backup of key [%s]\n", regkey->name));
	

	return NT_STATUS_OK;
}


