/* 
 *  Unix SMB/CIFS implementation.
 *  Service Control API Implementation
 * 
 *  Copyright (C) Marcin Krzysztof Porwit         2005.
 *  Largely Rewritten by:
 *  Copyright (C) Gerald (Jerry) Carter           2005.
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

/********************************************************************
********************************************************************/

static SEC_DESC* construct_service_sd( TALLOC_CTX *ctx )
{
	SEC_ACE ace[4];	
	SEC_ACCESS mask;
	size_t i = 0;
	SEC_DESC *sd;
	SEC_ACL *acl;
	size_t sd_size;
	
	/* basic access for Everyone */
	
	init_sec_access(&mask, SERVICE_READ_ACCESS );
	init_sec_ace(&ace[i++], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
		
	init_sec_access(&mask,SERVICE_EXECUTE_ACCESS );
	init_sec_ace(&ace[i++], &global_sid_Builtin_Power_Users, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	
	init_sec_access(&mask,SERVICE_ALL_ACCESS );
	init_sec_ace(&ace[i++], &global_sid_Builtin_Server_Operators, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	init_sec_ace(&ace[i++], &global_sid_Builtin_Administrators, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	
	/* create the security descriptor */
	
	if ( !(acl = make_sec_acl(ctx, NT4_ACL_REVISION, i, ace)) )
		return NULL;

	if ( !(sd = make_sec_desc(ctx, SEC_DESC_REVISION, SEC_DESC_SELF_RELATIVE, NULL, NULL, NULL, acl, &sd_size)) )
		return NULL;

	return sd;
}

/********************************************************************
 This is where we do the dirty work of filling in things like the
 Display name, Description, etc...
********************************************************************/

static void fill_service_values( const char *name, REGVAL_CTR *values )
{
	UNISTR2 data, dname, ipath, description;
	uint32 dword;
	pstring pstr;
	
	/* These values are hardcoded in all QueryServiceConfig() replies.
	   I'm just storing them here for cosmetic purposes */
	
	dword = SVCCTL_AUTO_START;
	regval_ctr_addvalue( values, "Start", REG_DWORD, (char*)&dword, sizeof(uint32));
	
	dword = SVCCTL_WIN32_OWN_PROC;
	regval_ctr_addvalue( values, "Type", REG_DWORD, (char*)&dword, sizeof(uint32));

	dword = SVCCTL_SVC_ERROR_NORMAL;
	regval_ctr_addvalue( values, "ErrorControl", REG_DWORD, (char*)&dword, sizeof(uint32));
	
	/* everything runs as LocalSystem */
	
	init_unistr2( &data, "LocalSystem", UNI_STR_TERMINATE );
	regval_ctr_addvalue( values, "ObjectName", REG_SZ, (char*)data.buffer, data.uni_str_len*2);
	
	/* special considerations for internal services and the DisplayName value */
	
	if ( strequal(name, "Spooler") ) {
		pstr_sprintf( pstr, "%s/%s/smbd",dyn_LIBDIR, SVCCTL_SCRIPT_DIR );
		init_unistr2( &ipath, pstr, UNI_STR_TERMINATE );
		init_unistr2( &description, "Internal service for spooling files to print devices", UNI_STR_TERMINATE );
		init_unistr2( &dname, "Print Spooler", UNI_STR_TERMINATE );
	} 
	else if ( strequal(name, "NETLOGON") ) {
		pstr_sprintf( pstr, "%s/%s/smbd",dyn_LIBDIR, SVCCTL_SCRIPT_DIR );
		init_unistr2( &ipath, pstr, UNI_STR_TERMINATE );
		init_unistr2( &description, "File service providing access to policy and profile data", UNI_STR_TERMINATE );
		init_unistr2( &dname, "Net Logon", UNI_STR_TERMINATE );
	} 
	else if ( strequal(name, "RemoteRegistry") ) {
		pstr_sprintf( pstr, "%s/%s/smbd",dyn_LIBDIR, SVCCTL_SCRIPT_DIR );
		init_unistr2( &ipath, pstr, UNI_STR_TERMINATE );
		init_unistr2( &description, "Internal service providing remote access to the Samba registry", UNI_STR_TERMINATE );
		init_unistr2( &dname, "Remote Registry Service", UNI_STR_TERMINATE );
	} 
	else {
		pstr_sprintf( pstr, "%s/%s/%s",dyn_LIBDIR, SVCCTL_SCRIPT_DIR, name );
		init_unistr2( &ipath, pstr, UNI_STR_TERMINATE );
		init_unistr2( &description, "External Unix Service", UNI_STR_TERMINATE );
		init_unistr2( &dname, name, UNI_STR_TERMINATE );
	}
	regval_ctr_addvalue( values, "DisplayName", REG_SZ, (char*)dname.buffer, dname.uni_str_len*2);
	regval_ctr_addvalue( values, "ImagePath", REG_SZ, (char*)ipath.buffer, ipath.uni_str_len*2);
	regval_ctr_addvalue( values, "Description", REG_SZ, (char*)description.buffer, description.uni_str_len*2);
	
	return;
}

/********************************************************************
********************************************************************/

static void add_new_svc_name( REGISTRY_KEY *key_parent, REGSUBKEY_CTR *subkeys, 
                              const char *name )
{
	REGISTRY_KEY *key_service, *key_secdesc;
	WERROR wresult;
	pstring path;
	REGVAL_CTR *values;
	REGSUBKEY_CTR *svc_subkeys;
	SEC_DESC *sd;
	prs_struct ps;

	/* add to the list and create the subkey path */

	regsubkey_ctr_addkey( subkeys, name );
	store_reg_keys( key_parent, subkeys );

	/* open the new service key */

	pstr_sprintf( path, "%s\\%s", KEY_SERVICES, name );
	wresult = regkey_open_internal( &key_service, path, get_root_nt_token(), 
		REG_KEY_ALL );
	if ( !W_ERROR_IS_OK(wresult) ) {
		DEBUG(0,("add_new_svc_name: key lookup failed! [%s] (%s)\n", 
			path, dos_errstr(wresult)));
		return;
	}
	
	/* add the 'Security' key */

	if ( !(svc_subkeys = TALLOC_ZERO_P( key_service, REGSUBKEY_CTR )) ) {
		DEBUG(0,("add_new_svc_name: talloc() failed!\n"));
		return;
	}
	
	fetch_reg_keys( key_service, svc_subkeys );
	regsubkey_ctr_addkey( svc_subkeys, "Security" );
	store_reg_keys( key_service, svc_subkeys );

	/* now for the service values */
	
	if ( !(values = TALLOC_ZERO_P( key_service, REGVAL_CTR )) ) {
		DEBUG(0,("add_new_svc_name: talloc() failed!\n"));
		return;
	}

	fill_service_values( name, values );
	store_reg_values( key_service, values );

	/* cleanup the service key*/

	TALLOC_FREE( key_service );

	/* now add the security descriptor */

	pstr_sprintf( path, "%s\\%s\\%s", KEY_SERVICES, name, "Security" );
	wresult = regkey_open_internal( &key_secdesc, path, get_root_nt_token(), 
		REG_KEY_ALL );
	if ( !W_ERROR_IS_OK(wresult) ) {
		DEBUG(0,("add_new_svc_name: key lookup failed! [%s] (%s)\n", 
			path, dos_errstr(wresult)));
		return;
	}

	if ( !(values = TALLOC_ZERO_P( key_secdesc, REGVAL_CTR )) ) {
		DEBUG(0,("add_new_svc_name: talloc() failed!\n"));
		return;
	}

	if ( !(sd = construct_service_sd(key_secdesc)) ) {
		DEBUG(0,("add_new_svc_name: Failed to create default sec_desc!\n"));
		TALLOC_FREE( key_secdesc );
		return;
	}
	
	/* stream the printer security descriptor */
	
	prs_init( &ps, RPC_MAX_PDU_FRAG_LEN, key_secdesc, MARSHALL);
	
	if ( sec_io_desc("sec_desc", &sd, &ps, 0 ) ) {
		uint32 offset = prs_offset( &ps );
		regval_ctr_addvalue( values, "Security", REG_BINARY, prs_data_p(&ps), offset );
		store_reg_values( key_secdesc, values );
	}
	
	/* finally cleanup the Security key */
	
	prs_mem_free( &ps );
	TALLOC_FREE( key_secdesc );

	return;
}

/********************************************************************
********************************************************************/

void svcctl_init_keys( void )
{
	const char **service_list = lp_svcctl_list();
	int i;
	REGSUBKEY_CTR *subkeys;
	REGISTRY_KEY *key = NULL;
	WERROR wresult;
	BOOL new_services = False;
	
	/* bad mojo here if the lookup failed.  Should not happen */
	
	wresult = regkey_open_internal( &key, KEY_SERVICES, get_root_nt_token(), 
		REG_KEY_ALL );

	if ( !W_ERROR_IS_OK(wresult) ) {
		DEBUG(0,("init_services_keys: key lookup failed! (%s)\n", 
			dos_errstr(wresult)));
		return;
	}
	
	/* lookup the available subkeys */	
	
	if ( !(subkeys = TALLOC_ZERO_P( key, REGSUBKEY_CTR )) ) {
		DEBUG(0,("init_services_keys: talloc() failed!\n"));
		return;
	}
	
	fetch_reg_keys( key, subkeys );
	
	/* the builting services exist */
	
	add_new_svc_name( key, subkeys, "Spooler" );
	add_new_svc_name( key, subkeys, "NETLOGON" );
	add_new_svc_name( key, subkeys, "RemoteRegistry" );
		
	for ( i=0; service_list[i]; i++ ) {
	
		/* only add new services */
		if ( regsubkey_ctr_key_exists( subkeys, service_list[i] ) )
			continue;

		/* Add the new service key and initialize the appropriate values */

		add_new_svc_name( key, subkeys, service_list[i] );

		new_services = True;
	}

	TALLOC_FREE( key );

	/* initialize the control hooks */

	init_service_op_table();

	return;
}

/********************************************************************
 This is where we do the dirty work of filling in things like the
 Display name, Description, etc...Always return a default secdesc 
 in case of any failure.
********************************************************************/

SEC_DESC* svcctl_get_secdesc( TALLOC_CTX *ctx, const char *name, NT_USER_TOKEN *token )
{
	REGISTRY_KEY *key;
	prs_struct ps;
	REGVAL_CTR *values;
	REGISTRY_VALUE *val;
	SEC_DESC *sd = NULL;
	SEC_DESC *ret_sd = NULL;
	pstring path;
	WERROR wresult;
	
	/* now add the security descriptor */

	pstr_sprintf( path, "%s\\%s\\%s", KEY_SERVICES, name, "Security" );
	wresult = regkey_open_internal( &key, path, token, REG_KEY_ALL );
	if ( !W_ERROR_IS_OK(wresult) ) {
		DEBUG(0,("svcctl_get_secdesc: key lookup failed! [%s] (%s)\n", 
			path, dos_errstr(wresult)));
		return NULL;
	}

	if ( !(values = TALLOC_ZERO_P( key, REGVAL_CTR )) ) {
		DEBUG(0,("add_new_svc_name: talloc() failed!\n"));
		TALLOC_FREE( key );
		return NULL;
	}

	fetch_reg_values( key, values );
	
	if ( !(val = regval_ctr_getvalue( values, "Security" )) ) {
		DEBUG(6,("svcctl_get_secdesc: constructing default secdesc for service [%s]\n", 
			name));
		TALLOC_FREE( key );
		return construct_service_sd( ctx );
	}
	

	/* stream the printer security descriptor */
	
	prs_init( &ps, 0, key, UNMARSHALL);
	prs_give_memory( &ps, regval_data_p(val), regval_size(val), False );
	
	if ( !sec_io_desc("sec_desc", &sd, &ps, 0 ) ) {
		TALLOC_FREE( key );
		return construct_service_sd( ctx );
	}
	
	ret_sd = dup_sec_desc( ctx, sd );
	
	/* finally cleanup the Security key */
	
	prs_mem_free( &ps );
	TALLOC_FREE( key );

	return ret_sd;
}

/********************************************************************
********************************************************************/

char* svcctl_lookup_dispname( const char *name, NT_USER_TOKEN *token )
{
	static fstring display_name;
	REGISTRY_KEY *key;
	REGVAL_CTR *values;
	REGISTRY_VALUE *val;
	pstring path;
	WERROR wresult;
	
	/* now add the security descriptor */

	pstr_sprintf( path, "%s\\%s", KEY_SERVICES, name );
	wresult = regkey_open_internal( &key, path, token, REG_KEY_ALL );
	if ( !W_ERROR_IS_OK(wresult) ) {
		DEBUG(0,("svcctl_lookup_dispname: key lookup failed! [%s] (%s)\n", 
			path, dos_errstr(wresult)));
		return NULL;
	}

	if ( !(values = TALLOC_ZERO_P( key, REGVAL_CTR )) ) {
		DEBUG(0,("svcctl_lookup_dispname: talloc() failed!\n"));
		TALLOC_FREE( key );
		return NULL;
	}

	fetch_reg_values( key, values );
	
	if ( !(val = regval_ctr_getvalue( values, "DisplayName" )) )
		fstrcpy( display_name, name );
	else
		rpcstr_pull( display_name, regval_data_p(val), sizeof(display_name), regval_size(val), 0 );

	TALLOC_FREE( key );
	
	return display_name;
}

/********************************************************************
********************************************************************/

char* svcctl_lookup_description( const char *name, NT_USER_TOKEN *token )
{
	static fstring description;
	REGISTRY_KEY *key;
	REGVAL_CTR *values;
	REGISTRY_VALUE *val;
	pstring path;
	WERROR wresult;
	
	/* now add the security descriptor */

	pstr_sprintf( path, "%s\\%s", KEY_SERVICES, name );
	wresult = regkey_open_internal( &key, path, token, REG_KEY_ALL );
	if ( !W_ERROR_IS_OK(wresult) ) {
		DEBUG(0,("svcctl_lookup_dispname: key lookup failed! [%s] (%s)\n", 
			path, dos_errstr(wresult)));
		return NULL;
	}

	if ( !(values = TALLOC_ZERO_P( key, REGVAL_CTR )) ) {
		DEBUG(0,("svcctl_lookup_dispname: talloc() failed!\n"));
		TALLOC_FREE( key );
		return NULL;
	}

	fetch_reg_values( key, values );
	
	if ( !(val = regval_ctr_getvalue( values, "Description" )) )
		fstrcpy( description, "Unix Service");
	else
		rpcstr_pull( description, regval_data_p(val), sizeof(description), regval_size(val), 0 );

	TALLOC_FREE( key );
	
	return description;
}


/********************************************************************
********************************************************************/

REGVAL_CTR* svcctl_fetch_regvalues( const char *name, NT_USER_TOKEN *token )
{
	REGISTRY_KEY *key;
	REGVAL_CTR *values;
	pstring path;
	WERROR wresult;
	
	/* now add the security descriptor */

	pstr_sprintf( path, "%s\\%s", KEY_SERVICES, name );
	wresult = regkey_open_internal( &key, path, token, REG_KEY_ALL );
	if ( !W_ERROR_IS_OK(wresult) ) {
		DEBUG(0,("svcctl_fetch_regvalues: key lookup failed! [%s] (%s)\n", 
			path, dos_errstr(wresult)));
		return NULL;
	}

	if ( !(values = TALLOC_ZERO_P( NULL, REGVAL_CTR )) ) {
		DEBUG(0,("svcctl_fetch_regvalues: talloc() failed!\n"));
		TALLOC_FREE( key );
		return NULL;
	}
	
	fetch_reg_values( key, values );

	TALLOC_FREE( key );
	
	return values;
}

