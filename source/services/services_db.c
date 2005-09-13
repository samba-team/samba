/* 
 *  Unix SMB/CIFS implementation.
 *  Service Control API Implementation
 *  Copyright (C) Gerald Carter                   2005.
 *  Copyright (C) Marcin Krzysztof Porwit         2005.
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

#if 0
/********************************************************************
  Gather information on the "external services". These are services 
  listed in the smb.conf file, and found to exist through checks in 
  this code. Note that added will be incremented on the basis of the 
  number of services added.  svc_ptr should have enough memory allocated 
  to accommodate all of the services that exist. 

  Typically num_external_services is used to "size" the amount of
  memory allocated, but does little/no work. 

  enum_external_services() actually examines each of the specified 
  external services, populates the memory structures, and returns.

  ** note that 'added' may end up with less than the number of services 
  found in _num_external_services, such as the case when a service is
  called out, but the actual service doesn't exist or the file can't be 
  read for the service information.
********************************************************************/

WERROR enum_external_services(TALLOC_CTX *tcx,ENUM_SERVICES_STATUS **svc_ptr, int existing_services,int *added) 
{
	/* *svc_ptr must have pre-allocated memory */
	int num_services = 0;
	int i = 0;
	ENUM_SERVICES_STATUS *services=NULL;
	char **svc_list,**svcname;
	pstring command, keystring, external_services_string;
	int ret;
	int fd = -1;
	Service_info *si;
	TDB_DATA key_data;

	*added = num_services;

	if (!service_tdb) {
		DEBUG(8,("enum_external_services: service database is not open!!!\n"));
	} else {
		pstrcpy(keystring,"EXTERNAL_SERVICES");
		key_data = tdb_fetch_bystring(service_tdb, keystring);
		if ((key_data.dptr != NULL) && (key_data.dsize != 0)) {
			strncpy(external_services_string,key_data.dptr,key_data.dsize);
			external_services_string[key_data.dsize] = 0;
			DEBUG(8,("enum_external_services: services list is %s, size is %d\n",
				external_services_string,(int)key_data.dsize));
		}
	} 
	svc_list = str_list_make(external_services_string,NULL);
 
	num_services = str_list_count( (const char **)svc_list);

	if (0 == num_services) {
		DEBUG(8,("enum_external_services: there are no external services\n"));
		*added = num_services;
		return WERR_OK;
	}
	DEBUG(8,("enum_external_services: there are [%d] external services\n",num_services));
	si=TALLOC_ARRAY( tcx, Service_info, 1 );
	if (si == NULL) { 
		DEBUG(8,("enum_external_services: Failed to alloc si\n"));
		return WERR_NOMEM;
	}

	/* *svc_ptr has the pointer to the array if there is one already. NULL if not. */
	if ((existing_services>0) && svc_ptr && *svc_ptr) { /* reallocate vs. allocate */
		DEBUG(8,("enum_external_services: REALLOCing %x to %d services\n", *svc_ptr, existing_services+num_services));

		services=TALLOC_REALLOC_ARRAY(tcx,*svc_ptr,ENUM_SERVICES_STATUS,existing_services+num_services);
		DEBUG(8,("enum_external_services: REALLOCed to %x services\n", services));

		if (!services) return WERR_NOMEM;
			*svc_ptr = services;
	} else {
		if ( !(services = TALLOC_ARRAY( tcx, ENUM_SERVICES_STATUS, num_services )) )
			return WERR_NOMEM;
	}

	if (!svc_ptr || !(*svc_ptr)) 
		return WERR_NOMEM;
	services = *svc_ptr;
	if (existing_services > 0) {
		i+=existing_services;
	}

	svcname = svc_list;
	DEBUG(8,("enum_external_services: enumerating %d external services starting at index %d\n", num_services,existing_services));

	while (*svcname) {
		DEBUG(10,("enum_external_services: Reading information on service %s, index %d\n",*svcname,i));
		/* get_LSB_data(*svcname,si);  */
		if (!get_service_info(service_tdb,*svcname, si)) {
			DEBUG(1,("enum_external_services: CAN'T FIND INFO FOR SERVICE %s in the services DB\n",*svcname));
		}

		if ((si->filename == NULL) || (*si->filename == 0)) {
			init_unistr(&services[i].servicename, *svcname );
		} else {
			init_unistr( &services[i].servicename, si->filename );    
			/* init_unistr( &services[i].servicename, si->servicename ); */
		}

		if ((si->provides == NULL) || (*si->provides == 0)) {
			init_unistr(&services[i].displayname, *svcname );
		} else {
			init_unistr( &services[i].displayname, si->provides );
		}

		/* TODO - we could keep the following info in the DB, too... */

		DEBUG(8,("enum_external_services: Service name [%s] displayname [%s]\n",
		si->filename, si->provides)); 
		services[i].status.type               = SVCCTL_WIN32_OWN_PROC; 
		services[i].status.win32_exit_code    = 0x0;
		services[i].status.service_exit_code  = 0x0;
		services[i].status.check_point        = 0x0;
		services[i].status.wait_hint          = 0x0;

		/* TODO - do callout here to get the status */

		memset(command, 0, sizeof(command));
		slprintf(command, sizeof(command)-1, "%s%s%s %s", dyn_LIBDIR, SVCCTL_SCRIPT_DIR, *svcname, "status");

		DEBUG(10, ("enum_external_services: status command is [%s]\n", command));

		/* TODO  - wrap in privilege check */

		ret = smbrun(command, &fd);
		DEBUGADD(10, ("returned [%d]\n", ret));
		close(fd);
		if(ret != 0)
			DEBUG(10, ("enum_external_services: Command returned  [%d]\n", ret));
		services[i].status.state              = SVCCTL_STOPPED;
		if (ret == 0) {
			services[i].status.state              = SVCCTL_RUNNING;
			services[i].status.controls_accepted  = SVCCTL_CONTROL_SHUTDOWN | SVCCTL_CONTROL_STOP;
		} else {
			services[i].status.state              = SVCCTL_STOPPED;
			services[i].status.controls_accepted  = 0;
		}
		svcname++; 
		i++;
	} 

	DEBUG(10,("enum_external_services: Read services %d\n",num_services));
	*added = num_services;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

BOOL get_service_info(TDB_CONTEXT *stdb,char *service_name, Service_info *si) 
{
	pstring keystring,sn;
	TDB_DATA kbuf, dbuf;

	if ((stdb == NULL) || (si == NULL) || (service_name==NULL) || (*service_name == 0)) 
		return False;

	/* TODO  - error handling -- what if the service isn't in the DB?  */

	slprintf(keystring, sizeof(keystring)-1, "SVCCTL/SERVICE_INFO/%s", service_name);

	/* tdb_lock_bystring(stdb, keystring, 0); */

	DEBUGADD(10, ("_svcctl_read_service_tdb_to_si: Key is  [%s]\n", keystring));
	kbuf.dptr = keystring;
	kbuf.dsize = strlen(keystring)+1;
	dbuf = tdb_fetch(stdb, kbuf);

	if (!dbuf.dptr) {
		DEBUGADD(10, ("_svcctl_read_service_tdb_to_si: Could not find record associated with [%s]\n", keystring));
		return False;
	}
	tdb_unpack(dbuf.dptr, dbuf.dsize, "PPPPPPPPPPP",
			  sn,
			  si->servicetype,
			  si->filename,
			  si->provides,
			  si->dependencies,
			  si->shouldstart,
			  si->shouldstop,
			  si->requiredstart,
			  si->requiredstop,
			  si->description,
			  si->shortdescription);

	SAFE_FREE(dbuf.dptr);

	return True;
}

/*********************************************************************
*********************************************************************/

BOOL store_service_info(TDB_CONTEXT *stdb,char *service_name, Service_info *si) 
{
	pstring keystring;
	pstring pbuf;
	int len;
	TDB_DATA kbuf,dbuf;

	/* Note -- when we write to the tdb, we "index" on the filename field, not the nice name.
	   when a service is "opened", it is opened by the nice (SERVICENAME) name, not the file name. So there needs to be a mapping from
	   nice name back to the file name. */

	if ((stdb == NULL) || (si == NULL) || (service_name==NULL) || (*service_name == 0)) 
		return False;

	/* todo - mayke the service type an ENUM, add any security descriptor structures into it */

	len= tdb_pack(pbuf,sizeof(pbuf),"PPPPPPPPPPP",
		      service_name,si->servicetype,si->filename,si->provides,si->dependencies,
		      si->shouldstart,si->shouldstop,si->requiredstart,si->requiredstop,si->description,
		      (si->shortdescription && (0 != strlen(si->shortdescription))?si->shortdescription:si->description));
	if (len > sizeof(pbuf)) {
		/* todo error here */
		return False;
	}

	slprintf(keystring, sizeof(keystring)-1, "SVCCTL/SERVICE_INFO/%s", service_name);
	DEBUGADD(10, ("_svcctl_write_si_to_service_tdb: Key is  [%s]\n", keystring));
	kbuf.dsize = strlen(keystring)+1;
	kbuf.dptr = keystring;
	dbuf.dsize = len;
	dbuf.dptr = pbuf;

	return (tdb_store(stdb, kbuf, dbuf, TDB_REPLACE) == 0);
}


#endif

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
	UNISTR2 data;
	
	/* special considerations for internal services */
	if ( strequal(name, "Spooler") ) {
		init_unistr2( &data, "Print Spooler", UNI_STR_TERMINATE );
		regval_ctr_addvalue( values, "DisplayName", REG_SZ, (char*)data.buffer, data.uni_str_len*2);
	
		return;
	}
	
	if ( strequal(name, "NETLOGON") ) {
		init_unistr2( &data, "Net Logon", UNI_STR_TERMINATE );
		regval_ctr_addvalue( values, "DisplayName", REG_SZ, (char*)data.buffer, data.uni_str_len*2);
	
		return;
	}

	if ( strequal(name, "RemoteRegistry") ) {
		init_unistr2( &data, "Remote Registry Service", UNI_STR_TERMINATE );
		regval_ctr_addvalue( values, "DisplayName", REG_SZ, (char*)data.buffer, data.uni_str_len*2);
	
		return;
	}

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
	const char **service_list = lp_enable_svcctl();
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

