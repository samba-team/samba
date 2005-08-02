/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald (Jerry) Carter             2005,
 *  Copyright (C) Marcin Krzysztof Porwit           2005.
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

/* TODO - Do the OpenService service name matching case-independently, or at least make it an option. */


#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define SERVICEDB_VERSION_V1 1 /* Will there be more? */
#define INTERNAL_SERVICES_LIST "NETLOGON Spooler"

/*                                                                                                                     */
/* scripts will execute from the following libdir, if they are in the enable svcctl=<list of scripts>                  */
/* these should likely be symbolic links. Note that information about them will be extracted from the files themselves */
/* using the LSB standard keynames for various information                                                             */

#define SVCCTL_SCRIPT_DIR  "/svcctl/"


struct service_control_op_table {
	const char *name;
	SERVICE_CONTROL_OPS *ops;
};

extern SERVICE_CONTROL_OPS spoolss_svc_ops;

struct service_control_op_table svcctl_ops[] = { 
	{ "Spooler", 	&spoolss_svc_ops },
	{ "NETLOGON", 	NULL },
	{ NULL,		NULL }
};


/********************************************************************
********************************************************************/

static NTSTATUS svcctl_access_check( SEC_DESC *sec_desc, NT_USER_TOKEN *token, 
                                     uint32 access_desired, uint32 *access_granted )
{
	NTSTATUS result;
	
	/* maybe add privilege checks in here later */
	
	se_access_check( sec_desc, token, access_desired, access_granted, &result );
	
	return result;
}

/********************************************************************
********************************************************************/

static SEC_DESC* construct_scm_sd( TALLOC_CTX *ctx )
{
	SEC_ACE ace[2];	
	SEC_ACCESS mask;
	size_t i = 0;
	SEC_DESC *sd;
	SEC_ACL *acl;
	uint32 sd_size;

	/* basic access for Everyone */
	
	init_sec_access(&mask, SC_MANAGER_READ_ACCESS );
	init_sec_ace(&ace[i++], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	
	/* Full Access 'BUILTIN\Administrators' */
	
	init_sec_access(&mask,SC_MANAGER_ALL_ACCESS );
	init_sec_ace(&ace[i++], &global_sid_Builtin_Administrators, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	
	
	/* create the security descriptor */
	
	if ( !(acl = make_sec_acl(ctx, NT4_ACL_REVISION, i, ace)) )
		return NULL;

	if ( !(sd = make_sec_desc(ctx, SEC_DESC_REVISION, SEC_DESC_SELF_RELATIVE, NULL, NULL, NULL, acl, &sd_size)) )
		return NULL;

	return sd;
}

/********************************************************************
********************************************************************/

static SEC_DESC* construct_service_sd( TALLOC_CTX *ctx )
{
	SEC_ACE ace[4];	
	SEC_ACCESS mask;
	size_t i = 0;
	SEC_DESC *sd;
	SEC_ACL *acl;
	uint32 sd_size;

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

/******************************************************************
 free() function for REGISTRY_KEY
 *****************************************************************/
 
static void free_service_handle_info(void *ptr)
{
	SERVICE_INFO *info = (SERVICE_INFO*)ptr;
	
	SAFE_FREE(info->name);
	SAFE_FREE(info);
}

/******************************************************************
 Find a registry key handle and return a SERVICE_INFO
 *****************************************************************/

static SERVICE_INFO *find_service_info_by_hnd(pipes_struct *p, POLICY_HND *hnd)
{
	SERVICE_INFO *service_info = NULL;

	if( !find_policy_by_hnd( p, hnd, (void **)&service_info) ) {
		DEBUG(2,("find_service_info_by_hnd: handle not found"));
		return NULL;
	}

	return service_info;
}

/******************************************************************
 *****************************************************************/
 
static WERROR create_open_service_handle( pipes_struct *p, POLICY_HND *handle, 
                                          const char *service, uint32 access_granted )
{
	SERVICE_INFO *info = NULL;
	WERROR result = WERR_OK;
	
	if ( !(info = SMB_MALLOC_P( SERVICE_INFO )) )
		return WERR_NOMEM;

	ZERO_STRUCTP( info );
		
	/* the Service Manager has a NULL name */
	
	if ( !service ) {
		info->type = SVC_HANDLE_IS_SCM;
	} else {
		int i;

		info->type = SVC_HANDLE_IS_SERVICE;
		
		/* lookup the SERVICE_CONTROL_OPS */

		for ( i=0; svcctl_ops[i].name; i++ ) {
			if ( strequal( svcctl_ops[i].name, service ) )  {
				info->ops = svcctl_ops[i].ops;
				break;
			}
		}

		if ( !svcctl_ops[i].name ) {
			result = WERR_NO_SUCH_SERVICE;
			goto done;
		}

		if ( !(info->name  = SMB_STRDUP( service )) ) {
			result = WERR_NOMEM;
			goto done;
		}
	}

	info->access_granted = access_granted;	
	
	/* store the SERVICE_INFO and create an open handle */
	
	if ( !create_policy_hnd( p, handle, free_service_handle_info, info ) ) {
		result = WERR_ACCESS_DENIED;
		goto done;
	}
		
done:
	if ( !W_ERROR_IS_OK(result) )
		free_service_handle_info( info );

	return result;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_open_scmanager(pipes_struct *p, SVCCTL_Q_OPEN_SCMANAGER *q_u, SVCCTL_R_OPEN_SCMANAGER *r_u)
{
	SEC_DESC *sec_desc;
	uint32 access_granted = 0;
	NTSTATUS status;
	
	/* perform access checks */
	
	if ( !(sec_desc = construct_scm_sd( p->mem_ctx )) )
		return WERR_NOMEM;
		
	status = svcctl_access_check( sec_desc, p->pipe_user.nt_user_token, q_u->access, &access_granted );
	if ( !NT_STATUS_IS_OK(status) )
		return ntstatus_to_werror( status );
		
	return create_open_service_handle( p, &r_u->handle, NULL, access_granted );
}

/********************************************************************
********************************************************************/

WERROR _svcctl_open_service(pipes_struct *p, SVCCTL_Q_OPEN_SERVICE *q_u, SVCCTL_R_OPEN_SERVICE *r_u)
{
	SEC_DESC *sec_desc;
	uint32 access_granted = 0;
	NTSTATUS status;
	pstring service;

	rpcstr_pull(service, q_u->servicename.buffer, sizeof(service), q_u->servicename.uni_str_len*2, 0);
	
  	DEBUG(5, ("_svcctl_open_service: Attempting to open Service [%s], \n", service));

	
	/* based on my tests you can open a service if you have a valid scm handle */
	
	if ( !find_service_info_by_hnd( p, &q_u->handle ) )
		return WERR_BADFID;
			
	/* perform access checks */
	
	if ( !(sec_desc = construct_service_sd( p->mem_ctx )) )
		return WERR_NOMEM;
		
	status = svcctl_access_check( sec_desc, p->pipe_user.nt_user_token, q_u->access, &access_granted );
	if ( !NT_STATUS_IS_OK(status) )
		return ntstatus_to_werror( status );
		
#if 0	/* FIXME!!! */
	if ( ! get_service_info(service_tdb, service, info) ) {
		return WERR_NO_SUCH_SERVICE;
#endif
	
	return create_open_service_handle( p, &r_u->handle, service, access_granted );
}

/********************************************************************
********************************************************************/

WERROR _svcctl_close_service(pipes_struct *p, SVCCTL_Q_CLOSE_SERVICE *q_u, SVCCTL_R_CLOSE_SERVICE *r_u)
{
	return close_policy_hnd( p, &q_u->handle ) ? WERR_OK : WERR_BADFID;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_get_display_name(pipes_struct *p, SVCCTL_Q_GET_DISPLAY_NAME *q_u, SVCCTL_R_GET_DISPLAY_NAME *r_u)
{
	fstring service;
	fstring displayname;
	SERVICE_INFO *info = find_service_info_by_hnd( p, &q_u->handle );
	
	/* can only use an SCM handle here */
	
	if ( !info || (info->type != SVC_HANDLE_IS_SCM) )
		return WERR_BADFID;
		
	rpcstr_pull(service, q_u->servicename.buffer, sizeof(service), q_u->servicename.uni_str_len*2, 0);

	/* need a tdb lookup here or something */
	
	fstrcpy( displayname, "FIX ME!" );

	init_svcctl_r_get_display_name( r_u, displayname );

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_query_status(pipes_struct *p, SVCCTL_Q_QUERY_STATUS *q_u, SVCCTL_R_QUERY_STATUS *r_u)
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, &q_u->handle );
	
	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;
		
	if ( !(info->access_granted & SC_RIGHT_SVC_QUERY_STATUS) )
		return WERR_ACCESS_DENIED;
		
	/* try the service specific status call */

	if ( info->ops ) 
		return info->ops->service_status( &r_u->svc_status );

	/* default action for now */

	r_u->svc_status.type = 0x0020;
	r_u->svc_status.state = 0x0004;
	r_u->svc_status.controls_accepted = 0x0005;

	return WERR_OK;
}


/*********************************************************************
 TODO - for internal services, do similar to external services, except 
 we have to call the right status routine...
**********************************************************************/

static WERROR enum_internal_services(TALLOC_CTX *tcx,ENUM_SERVICES_STATUS **svc_ptr, int existing_services, uint32 *added) 
{
	int num_services = 2;
	int i = 0;
	ENUM_SERVICES_STATUS *services=NULL;

	if (!svc_ptr || !(*svc_ptr)) 
		return WERR_NOMEM;

	services = *svc_ptr;

#if 0
	/* *svc_ptr has the pointer to the array if there is one already. NULL if not. */
	if ((existing_services>0) && svc_ptr && *svc_ptr) { /* reallocate vs. allocate */
		DEBUG(8,("enum_internal_services: REALLOCing %d services\n", num_services));
		services = TALLOC_REALLOC_ARRAY(tcx,*svc_ptr,ENUM_SERVICES_STATUS,existing_services+num_services);
		if (!rsvcs) 
			return WERR_NOMEM;
		*svc_ptr = services;
	} else {
		if ( !(services = TALLOC_ARRAY( tcx, ENUM_SERVICES_STATUS, num_services )) )
			return WERR_NOMEM;
	}
#endif

	if (existing_services > 0) {
		i += existing_services;
	}
	DEBUG(8,("enum_internal_services: Creating %d services, starting index %d\n", num_services,existing_services));
				
	init_unistr( &services[i].servicename, "Spooler" );
	init_unistr( &services[i].displayname, "Print Spooler" );
	
	services[i].status.type               = 0x110;
	services[i].status.controls_accepted  = 0x0;
	services[i].status.win32_exit_code    = 0x0;
	services[i].status.service_exit_code  = 0x0;
	services[i].status.check_point        = 0x0;
	services[i].status.wait_hint          = 0x0;
	if ( !lp_disable_spoolss() ) 
		services[i].status.state              = SVCCTL_RUNNING;
	else
		services[i].status.state              = SVCCTL_STOPPED;

	i++;		
	
	init_unistr( &services[i].servicename, "NETLOGON" );
	init_unistr( &services[i].displayname, "Net Logon" );
	
	services[i].status.type               = 0x20;	
	services[i].status.controls_accepted  = 0x0;
	services[i].status.win32_exit_code    = 0x0;
	services[i].status.service_exit_code  = 0x0;
	services[i].status.check_point        = 0x0;
	services[i].status.wait_hint          = 0x0;
	if ( lp_servicenumber("NETLOGON") != -1 ) 
		services[i].status.state              = SVCCTL_RUNNING;
	else
		services[i].status.state              = SVCCTL_STOPPED;

	*added = num_services;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_enum_services_status(pipes_struct *p, SVCCTL_Q_ENUM_SERVICES_STATUS *q_u, SVCCTL_R_ENUM_SERVICES_STATUS *r_u)
{
	ENUM_SERVICES_STATUS *services = NULL;
	uint32 num_int_services = 0;
	uint32 num_ext_services = 0;
	int i = 0;
	size_t buffer_size;
	WERROR result = WERR_OK;
	WERROR ext_result = WERR_OK;
	SERVICE_INFO *info = find_service_info_by_hnd( p, &q_u->handle );
	
	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SCM) )
		return WERR_BADFID;
		
	if ( !(info->access_granted & SC_RIGHT_MGR_ENUMERATE_SERVICE) )
		return WERR_ACCESS_DENIED;

	/* num_services = str_list_count( lp_enable_svcctl() ); */

	/* here's where we'll read the db of external services */
	/* _svcctl_read_LSB_data(NULL,NULL); */
	/* init_svcctl_db(); */
	
	/* num_int_services = num_internal_services(); */

	/* num_ext_services =  num_external_services(); */

	if ( !(services = TALLOC_ARRAY(p->mem_ctx, ENUM_SERVICES_STATUS, num_int_services+num_ext_services )) )
          return WERR_NOMEM;

        result = enum_internal_services(p->mem_ctx, &services, 0, &num_int_services);

	if (W_ERROR_IS_OK(result)) {
		DEBUG(8,("_svcctl_enum_services_status: Got %d internal services\n", num_int_services));
	} 

	/* ext_result=enum_external_services(p->mem_ctx, &services, num_int_services, &num_ext_services); */

	if (W_ERROR_IS_OK(ext_result)) {
		DEBUG(8,("_svcctl_enum_services_status: Got %d external services\n", num_ext_services));
	} 

        DEBUG(8,("_svcctl_enum_services_status: total of %d services\n", num_int_services+num_ext_services));

	buffer_size = 0;
        for (i=0;i<num_int_services+num_ext_services;i++) {
	  buffer_size += svcctl_sizeof_enum_services_status(&services[i]);
	}

	/* */
	buffer_size += buffer_size % 4;
	DEBUG(8,("_svcctl_enum_services_status: buffer size passed %d, we need %d\n",
		 q_u->buffer_size, buffer_size));

	if (buffer_size > q_u->buffer_size ) {
		num_int_services = 0;
		num_ext_services = 0;
		result = WERR_MORE_DATA;
	}

	rpcbuf_init(&r_u->buffer, q_u->buffer_size, p->mem_ctx);

	if ( W_ERROR_IS_OK(result) ) {
		for ( i=0; i<num_int_services+num_ext_services; i++ )
			svcctl_io_enum_services_status( "", &services[i], &r_u->buffer, 0 );
	}

	r_u->needed      = (buffer_size > q_u->buffer_size) ? buffer_size : q_u->buffer_size;
	r_u->returned    = num_int_services+num_ext_services;

	if ( !(r_u->resume = TALLOC_P( p->mem_ctx, uint32 )) )
		return WERR_NOMEM;

	*r_u->resume = 0x0;

	return result;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_start_service(pipes_struct *p, SVCCTL_Q_START_SERVICE *q_u, SVCCTL_R_START_SERVICE *r_u)
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, &q_u->handle );
	
	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;
	
	if ( !(info->access_granted & SC_RIGHT_SVC_START) )
		return WERR_ACCESS_DENIED;
		
	return info->ops->start_service();
}

/********************************************************************
********************************************************************/

WERROR _svcctl_control_service(pipes_struct *p, SVCCTL_Q_CONTROL_SERVICE *q_u, SVCCTL_R_CONTROL_SERVICE *r_u)
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, &q_u->handle );
	
	/* perform access checks */
	/* we only support stop so don't get complicated */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;	
	
	if ( q_u->control != SVCCTL_CONTROL_STOP )
		return WERR_ACCESS_DENIED;
		
	if ( !(info->access_granted & SC_RIGHT_SVC_STOP) )
		return WERR_ACCESS_DENIED;
		
	return info->ops->stop_service( &r_u->svc_status );
}

/********************************************************************
********************************************************************/

WERROR _svcctl_enum_dependent_services( pipes_struct *p, SVCCTL_Q_ENUM_DEPENDENT_SERVICES *q_u, SVCCTL_R_ENUM_DEPENDENT_SERVICES *r_u )
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, &q_u->handle );
	
	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;	
	
	if ( !(info->access_granted & SC_RIGHT_SVC_ENUMERATE_DEPENDENTS) )
		return WERR_ACCESS_DENIED;
			
	/* we have to set the outgoing buffer size to the same as the 
	   incoming buffer size (even in the case of failure */

	rpcbuf_init( &r_u->buffer, q_u->buffer_size, p->mem_ctx );
				
	r_u->needed      = q_u->buffer_size;
	
	/* no dependent services...basically a stub function */
	r_u->returned    = 0;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_query_service_status_ex( pipes_struct *p, SVCCTL_Q_QUERY_SERVICE_STATUSEX *q_u, SVCCTL_R_QUERY_SERVICE_STATUSEX *r_u )
{
        SERVICE_STATUS_PROCESS ssp;
	POLICY_HND *handle;
	SERVICE_INFO *service_info;
	pstring     command;
	SERVICE_INFO *info = find_service_info_by_hnd( p, &q_u->handle );
	
	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;	
	
	if ( !(info->access_granted & SC_RIGHT_SVC_QUERY_STATUS) )
		return WERR_ACCESS_DENIED;

	/* we have to set the outgoing buffer size to the same as the 
	   incoming buffer size (even in the case of failure */

	r_u->needed      = q_u->buffer_size;

        /* need to find the service name by the handle that is open */
	handle = &(q_u->handle);


	/* get rid of the easy errors */

	if (q_u->info_level != SVC_STATUS_PROCESS_INFO) {
 		DEBUG(10, ("_svcctl_query_service_status_ex :  Invalid information level specified\n"));
		return WERR_UNKNOWN_LEVEL; 
	}

	service_info = find_service_info_by_hnd(p, handle);

	if (!service_info) {
 		DEBUG(10, ("_svcctl_query_service_status_ex : Can't find the service for the handle\n"));
		return WERR_BADFID; 
	}
	
	if (r_u->needed < (sizeof(SERVICE_STATUS_PROCESS)+sizeof(uint32)+sizeof(uint32))) {
 		DEBUG(10, ("_svcctl_query_service_status_ex : buffer size of [%d] is too small.\n",r_u->needed));
		return WERR_INSUFFICIENT_BUFFER;
	}

  	ZERO_STRUCT(ssp); 
	    
#if 0
        if (!strwicmp(service_info->servicetype,"EXTERNAL")) 
		ssp.type = SVCCTL_WIN32_OWN_PROC;
	else 
		ssp.type = SVCCTL_WIN32_SHARED_PROC;
#endif

	/* Get the status of the service.. */

        memset(command, 0, sizeof(command));

#if 0
	slprintf(command, sizeof(command)-1, "%s%s%s %s", dyn_LIBDIR, SVCCTL_SCRIPT_DIR, service_info->filename, "status");

        DEBUG(10, ("_svcctl_query_service_status_ex: status command is [%s]\n", command));

	/* TODO  - wrap in privilege check */

	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));
        close(fd);
	if(ret != 0)
		DEBUG(10, ("_svcctl_query_service_status_ex: Command returned  [%d]\n", ret));

	/* SET all service_stats bits here... */
	if (ret == 0) {
		ssp.state              = SVCCTL_RUNNING;
		ssp.controls_accepted  = SVCCTL_CONTROL_SHUTDOWN | SVCCTL_CONTROL_STOP;
	} else {
		ssp.state              = SVCCTL_STOPPED;
		ssp.controls_accepted  = 0;
	}
#endif

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_query_service_config( pipes_struct *p, SVCCTL_Q_QUERY_SERVICE_CONFIG *q_u, SVCCTL_R_QUERY_SERVICE_CONFIG *r_u )
{
	POLICY_HND *handle;
	SERVICE_INFO *service_info;
        uint32      needed_size;
	SERVICE_INFO *info = find_service_info_by_hnd( p, &q_u->handle );
	
	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;	
	
	if ( !(info->access_granted & SC_RIGHT_SVC_QUERY_CONFIG) )
		return WERR_ACCESS_DENIED;

	/* we have to set the outgoing buffer size to the same as the 
	   incoming buffer size (even in the case of failure */

	r_u->needed      = q_u->buffer_size;

        /* need to find the service name by the handle that is open */
	handle = &(q_u->handle);

	service_info = find_service_info_by_hnd(p, handle);

#if 0
	if (q_u->buffer_size < sizeof(Service_info)) {
		/* have to report need more... */
		/* TODO worst case -- should actualy calc what we need here. */
		r_u->needed = sizeof(Service_info)+sizeof(pstring)*5; 
		DEBUG(10, ("_svcctl_query_service_config: NOT ENOUGH BUFFER ALLOCATED FOR RETURN DATA -- provided %d wanted %d\n",
		q_u->buffer_size,r_u->needed));

		return WERR_INSUFFICIENT_BUFFER;
	}
#endif
	if (!service_info) {
 		DEBUG(10, ("_svcctl_query_service_config : Can't find the service for the handle\n"));
		return WERR_BADFID; 
	}

#if 0
	if ( !(service_config = (SERVICE_CONFIG *)TALLOC_ZERO_P(p->mem_ctx, SERVICE_CONFIG)) )
        	return WERR_NOMEM;
#endif

	r_u->config.service_type       = SVCCTL_WIN32_OWN_PROC;
	r_u->config.start_type         = SVCCTL_DEMAND_START;
	r_u->config.error_control      = SVCCTL_SVC_ERROR_IGNORE;
	r_u->config.tag_id = 0x00000000;

	/* Init the strings */

	r_u->config.executablepath = TALLOC_ZERO_P(p->mem_ctx,  UNISTR2);
	r_u->config.loadordergroup = TALLOC_ZERO_P(p->mem_ctx,  UNISTR2);
	r_u->config.dependencies = TALLOC_ZERO_P(p->mem_ctx,  UNISTR2);
	r_u->config.startname = TALLOC_ZERO_P(p->mem_ctx,  UNISTR2);
	r_u->config.displayname = TALLOC_ZERO_P(p->mem_ctx,  UNISTR2);

#if 0
	pstrcpy(fullpathinfo,dyn_LIBDIR);
	pstrcat(fullpathinfo,SVCCTL_SCRIPT_DIR);
	pstrcat(fullpathinfo,service_info->filename);
	/* Get and calculate the size of the fields. Note that we're still building the fields in the "too-small buffer case"
	   even though we throw it away. */
	
	DEBUG(10, ("_svcctl_query_service_config: fullpath info [%s]\n",fullpathinfo));
	init_unistr2(r_u->config.executablepath,fullpathinfo,UNI_STR_TERMINATE);
	init_unistr2(r_u->config.loadordergroup,"",UNI_STR_TERMINATE);
	init_unistr2(r_u->config.dependencies,service_info->dependencies,UNI_STR_TERMINATE);

	/* TODO - if someone really cares, perhaps "LocalSystem" should be changed to something else here... */

	init_unistr2(r_u->config.startname,"LocalSystem",UNI_STR_TERMINATE);
	init_unistr2(r_u->config.displayname,service_info->servicename,UNI_STR_TERMINATE);
#endif

	needed_size = 0x04 + sizeof(SERVICE_CONFIG)+ 2*(
	              r_u->config.executablepath->uni_str_len +
	              r_u->config.loadordergroup->uni_str_len + 
	              r_u->config.dependencies->uni_str_len + 
                      r_u->config.startname->uni_str_len + 
                      r_u->config.displayname->uni_str_len);
	
       	DEBUG(10, ("_svcctl_query_service_config: ****** need to have a buffer of [%d], [%d] for struct \n",needed_size,
		   sizeof(SERVICE_CONFIG)));
	DEBUG(10, ("\tsize of executable path : %d\n",r_u->config.executablepath->uni_str_len));
	DEBUG(10, ("\tsize of loadordergroup  : %d\n", r_u->config.loadordergroup->uni_str_len)); 
	DEBUG(10, ("\tsize of dependencies    : %d\n", r_u->config.dependencies->uni_str_len)); 
	DEBUG(10, ("\tsize of startname       : %d\n", r_u->config.startname->uni_str_len));
	DEBUG(10, ("\tsize of displayname     : %d\n", r_u->config.displayname->uni_str_len));

	if (q_u->buffer_size < needed_size) {
		/* have to report need more...*/
		r_u->needed = needed_size;
       		DEBUG(10, ("_svcctl_query_service_config: ****** zeroing strings for return\n"));
		memset(&r_u->config,0,sizeof(SERVICE_CONFIG));
		DEBUG(10, ("_svcctl_query_service_config: Not enouh buffer provided for return -- provided %d wanted %d\n",
			q_u->buffer_size,needed_size));
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_query_service_config2( pipes_struct *p, SVCCTL_Q_QUERY_SERVICE_CONFIG2 *q_u, SVCCTL_R_QUERY_SERVICE_CONFIG2 *r_u )
{
	POLICY_HND *handle;
	SERVICE_INFO *service_info;
        uint32   level;
	SERVICE_INFO *info = find_service_info_by_hnd( p, &q_u->handle );
	
	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;	
	
	if ( !(info->access_granted & SC_RIGHT_SVC_QUERY_CONFIG) )
		return WERR_ACCESS_DENIED;
 
	/* we have to set the outgoing buffer size to the same as the 
	   incoming buffer size (even in the case of failure */

	r_u->needed      = q_u->buffer_size;
	r_u->description = NULL;               
	r_u->returned = q_u->buffer_size;
	r_u->offset = 4;                       

	handle = &(q_u->handle);

	service_info = find_service_info_by_hnd(p, handle);

	if (!service_info) {
 		DEBUG(10, ("_svcctl_query_service_config2 : Can't find the service for the handle\n"));
		return WERR_BADFID; 
	}
	
	/* 
	   TODO - perhaps move the RPC_DATA_BLOB into the R_QUERY_SERVICE_CONFIG structure, and to the processing in here, vs
           in the *r_query_config2 marshalling routine...
	*/

	level = q_u->info_level;

#if 0
	if (SERVICE_CONFIG_DESCRIPTION == level) {
		if (service_info && service_info->shortdescription) {
			/* length of the string, plus the terminator... */
			string_buffer_size = strlen(service_info->shortdescription)+1; 
			DEBUG(10, ("_svcctl_query_service_config: copying the description [%s] length [%d]\n",
			service_info->shortdescription,string_buffer_size));
	    
			if (q_u->buffer_size >= ((string_buffer_size)*2+4)) {
				r_u->description = TALLOC_ZERO_P(p->mem_ctx,  UNISTR2);
				if (!r_u->description) return WERR_NOMEM;
					init_unistr2(r_u->description,service_info->shortdescription,UNI_STR_TERMINATE);
			}
		}
		else { 
			string_buffer_size = 0;
		}
		DEBUG(10, ("_svcctl_query_service_config2: buffer needed is [%x], return buffer size is [%x]\n",
			string_buffer_size,q_u->buffer_size));
		if (((string_buffer_size)*2+4) > q_u->buffer_size) {
			r_u->needed = (string_buffer_size+1)*2+4;
			DEBUG(10, ("_svcctl_query_service_config2: INSUFFICIENT BUFFER\n"));
			return WERR_INSUFFICIENT_BUFFER;
		}
		DEBUG(10, ("_svcctl_query_service_config2: returning ok, needed is [%x], buffer size is [%x]\n",
		r_u->needed,q_u->buffer_size));

	   	return WERR_OK;    
	} 
#endif

	return WERR_ACCESS_DENIED;
}
