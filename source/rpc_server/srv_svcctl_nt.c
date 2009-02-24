/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *
 *  Copyright (C) Marcin Krzysztof Porwit           2005.
 *
 *  Largely Rewritten (Again) by:
 *  Copyright (C) Gerald (Jerry) Carter             2005.
 *  Copyright (C) Guenther Deschner                 2008.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

struct service_control_op {
	const char *name;
	SERVICE_CONTROL_OPS *ops;
};

#define SVCCTL_NUM_INTERNAL_SERVICES	4

/* handle external services */
extern SERVICE_CONTROL_OPS rcinit_svc_ops;

/* builtin services (see service_db.c and services/svc_*.c */
extern SERVICE_CONTROL_OPS spoolss_svc_ops;
extern SERVICE_CONTROL_OPS netlogon_svc_ops;
extern SERVICE_CONTROL_OPS winreg_svc_ops;
extern SERVICE_CONTROL_OPS wins_svc_ops;

/* make sure this number patches the number of builtin
   SERVICE_CONTROL_OPS structure listed above */

#define SVCCTL_NUM_INTERNAL_SERVICES	4

struct service_control_op *svcctl_ops;

static const struct generic_mapping scm_generic_map =
	{ SC_MANAGER_READ_ACCESS, SC_MANAGER_WRITE_ACCESS, SC_MANAGER_EXECUTE_ACCESS, SC_MANAGER_ALL_ACCESS };
static const struct generic_mapping svc_generic_map =
	{ SERVICE_READ_ACCESS, SERVICE_WRITE_ACCESS, SERVICE_EXECUTE_ACCESS, SERVICE_ALL_ACCESS };


/********************************************************************
********************************************************************/

bool init_service_op_table( void )
{
	const char **service_list = lp_svcctl_list();
	int num_services = SVCCTL_NUM_INTERNAL_SERVICES + str_list_count( service_list );
	int i;

	if ( !(svcctl_ops = TALLOC_ARRAY( NULL, struct service_control_op, num_services+1)) ) {
		DEBUG(0,("init_service_op_table: talloc() failed!\n"));
		return False;
	}

	/* services listed in smb.conf get the rc.init interface */

	for ( i=0; service_list && service_list[i]; i++ ) {
		svcctl_ops[i].name = talloc_strdup( svcctl_ops, service_list[i] );
		svcctl_ops[i].ops  = &rcinit_svc_ops;
	}

	/* add builtin services */

	svcctl_ops[i].name = talloc_strdup( svcctl_ops, "Spooler" );
	svcctl_ops[i].ops  = &spoolss_svc_ops;
	i++;

	svcctl_ops[i].name = talloc_strdup( svcctl_ops, "NETLOGON" );
	svcctl_ops[i].ops  = &netlogon_svc_ops;
	i++;

	svcctl_ops[i].name = talloc_strdup( svcctl_ops, "RemoteRegistry" );
	svcctl_ops[i].ops  = &winreg_svc_ops;
	i++;

	svcctl_ops[i].name = talloc_strdup( svcctl_ops, "WINS" );
	svcctl_ops[i].ops  = &wins_svc_ops;
	i++;

	/* NULL terminate the array */

	svcctl_ops[i].name = NULL;
	svcctl_ops[i].ops  = NULL;

	return True;
}

/********************************************************************
********************************************************************/

static struct service_control_op* find_service_by_name( const char *name )
{
	int i;

	for ( i=0; svcctl_ops[i].name; i++ ) {
		if ( strequal( name, svcctl_ops[i].name ) )
			return &svcctl_ops[i];
	}

	return NULL;
}
/********************************************************************
********************************************************************/

static NTSTATUS svcctl_access_check( SEC_DESC *sec_desc, NT_USER_TOKEN *token,
                                     uint32 access_desired, uint32 *access_granted )
{
	if ( geteuid() == sec_initial_uid() ) {
		DEBUG(5,("svcctl_access_check: using root's token\n"));
		token = get_root_nt_token();
	}

	return se_access_check( sec_desc, token, access_desired, access_granted);
}

/********************************************************************
********************************************************************/

static SEC_DESC* construct_scm_sd( TALLOC_CTX *ctx )
{
	SEC_ACE ace[2];
	size_t i = 0;
	SEC_DESC *sd;
	SEC_ACL *theacl;
	size_t sd_size;

	/* basic access for Everyone */

	init_sec_ace(&ace[i++], &global_sid_World,
		SEC_ACE_TYPE_ACCESS_ALLOWED, SC_MANAGER_READ_ACCESS, 0);

	/* Full Access 'BUILTIN\Administrators' */

	init_sec_ace(&ace[i++], &global_sid_Builtin_Administrators,
		SEC_ACE_TYPE_ACCESS_ALLOWED, SC_MANAGER_ALL_ACCESS, 0);


	/* create the security descriptor */

	if ( !(theacl = make_sec_acl(ctx, NT4_ACL_REVISION, i, ace)) )
		return NULL;

	if ( !(sd = make_sec_desc(ctx, SECURITY_DESCRIPTOR_REVISION_1,
				  SEC_DESC_SELF_RELATIVE, NULL, NULL, NULL,
				  theacl, &sd_size)) )
		return NULL;

	return sd;
}

/******************************************************************
 free() function for REGISTRY_KEY
 *****************************************************************/

static void free_service_handle_info(void *ptr)
{
	TALLOC_FREE( ptr );
}

/******************************************************************
 Find a registry key handle and return a SERVICE_INFO
 *****************************************************************/

static SERVICE_INFO *find_service_info_by_hnd(pipes_struct *p, POLICY_HND *hnd)
{
	SERVICE_INFO *service_info = NULL;

	if( !find_policy_by_hnd( p, hnd, (void **)(void *)&service_info) ) {
		DEBUG(2,("find_service_info_by_hnd: handle not found\n"));
		return NULL;
	}

	return service_info;
}

/******************************************************************
 *****************************************************************/

static WERROR create_open_service_handle( pipes_struct *p, POLICY_HND *handle, uint32 type,
                                          const char *service, uint32 access_granted )
{
	SERVICE_INFO *info = NULL;
	WERROR result = WERR_OK;
	struct service_control_op *s_op;

	if ( !(info = TALLOC_ZERO_P( NULL, SERVICE_INFO )) )
		return WERR_NOMEM;

	/* the Service Manager has a NULL name */

	info->type = SVC_HANDLE_IS_SCM;

	switch ( type ) {
	case SVC_HANDLE_IS_SCM:
		info->type = SVC_HANDLE_IS_SCM;
		break;

	case SVC_HANDLE_IS_DBLOCK:
		info->type = SVC_HANDLE_IS_DBLOCK;
		break;

	case SVC_HANDLE_IS_SERVICE:
		info->type = SVC_HANDLE_IS_SERVICE;

		/* lookup the SERVICE_CONTROL_OPS */

		if ( !(s_op = find_service_by_name( service )) ) {
			result = WERR_NO_SUCH_SERVICE;
			goto done;
		}

		info->ops = s_op->ops;

		if ( !(info->name  = talloc_strdup( info, s_op->name )) ) {
			result = WERR_NOMEM;
			goto done;
		}
		break;

	default:
		result = WERR_NO_SUCH_SERVICE;
		goto done;
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

WERROR _svcctl_OpenSCManagerW(pipes_struct *p,
			      struct svcctl_OpenSCManagerW *r)
{
	SEC_DESC *sec_desc;
	uint32 access_granted = 0;
	NTSTATUS status;

	/* perform access checks */

	if ( !(sec_desc = construct_scm_sd( p->mem_ctx )) )
		return WERR_NOMEM;

	se_map_generic( &r->in.access_mask, &scm_generic_map );
	status = svcctl_access_check( sec_desc, p->pipe_user.nt_user_token, r->in.access_mask, &access_granted );
	if ( !NT_STATUS_IS_OK(status) )
		return ntstatus_to_werror( status );

	return create_open_service_handle( p, r->out.handle, SVC_HANDLE_IS_SCM, NULL, access_granted );
}

/********************************************************************
 _svcctl_OpenServiceW
********************************************************************/

WERROR _svcctl_OpenServiceW(pipes_struct *p,
			    struct svcctl_OpenServiceW *r)
{
	SEC_DESC *sec_desc;
	uint32 access_granted = 0;
	NTSTATUS status;
	const char *service = NULL;

	service = r->in.ServiceName;
	if (!service) {
		return WERR_NOMEM;
	}
	DEBUG(5, ("_svcctl_OpenServiceW: Attempting to open Service [%s], \n", service));

	/* based on my tests you can open a service if you have a valid scm handle */

	if ( !find_service_info_by_hnd( p, r->in.scmanager_handle) )
		return WERR_BADFID;

	/* perform access checks.  Use the root token in order to ensure that we
	   retrieve the security descriptor */

	if ( !(sec_desc = svcctl_get_secdesc( p->mem_ctx, service, get_root_nt_token() )) )
		return WERR_NOMEM;

	se_map_generic( &r->in.access_mask, &svc_generic_map );
	status = svcctl_access_check( sec_desc, p->pipe_user.nt_user_token, r->in.access_mask, &access_granted );
	if ( !NT_STATUS_IS_OK(status) )
		return ntstatus_to_werror( status );

	return create_open_service_handle( p, r->out.handle, SVC_HANDLE_IS_SERVICE, service, access_granted );
}

/********************************************************************
********************************************************************/

WERROR _svcctl_CloseServiceHandle(pipes_struct *p, struct svcctl_CloseServiceHandle *r)
{
	if ( !close_policy_hnd( p, r->in.handle ) )
		return  WERR_BADFID;

	ZERO_STRUCTP(r->out.handle);

	return WERR_OK;
}

/********************************************************************
 _svcctl_GetServiceDisplayNameW
********************************************************************/

WERROR _svcctl_GetServiceDisplayNameW(pipes_struct *p,
				      struct svcctl_GetServiceDisplayNameW *r)
{
	const char *service;
	const char *display_name;
	SERVICE_INFO *info = find_service_info_by_hnd( p, r->in.handle );

	/* can only use an SCM handle here */

	if ( !info || (info->type != SVC_HANDLE_IS_SCM) )
		return WERR_BADFID;

	service = r->in.service_name;

	display_name = svcctl_lookup_dispname(p->mem_ctx, service, p->pipe_user.nt_user_token );
	if (!display_name) {
		display_name = "";
	}

	*r->out.display_name = display_name;
	*r->out.display_name_length = strlen(display_name);

	return WERR_OK;
}

/********************************************************************
 _svcctl_QueryServiceStatus
********************************************************************/

WERROR _svcctl_QueryServiceStatus(pipes_struct *p,
				  struct svcctl_QueryServiceStatus *r)
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, r->in.handle );

	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;

	if ( !(info->access_granted & SC_RIGHT_SVC_QUERY_STATUS) )
		return WERR_ACCESS_DENIED;

	/* try the service specific status call */

	return info->ops->service_status( info->name, r->out.service_status );
}

/********************************************************************
********************************************************************/

static int enumerate_status( TALLOC_CTX *ctx, ENUM_SERVICES_STATUS **status, NT_USER_TOKEN *token )
{
	int num_services = 0;
	int i;
	ENUM_SERVICES_STATUS *st;
	const char *display_name;

	/* just count */
	while ( svcctl_ops[num_services].name )
		num_services++;

	if ( !(st = TALLOC_ARRAY( ctx, ENUM_SERVICES_STATUS, num_services )) ) {
		DEBUG(0,("enumerate_status: talloc() failed!\n"));
		return -1;
	}

	for ( i=0; i<num_services; i++ ) {
		init_unistr( &st[i].servicename, svcctl_ops[i].name );

		display_name = svcctl_lookup_dispname(ctx, svcctl_ops[i].name, token );
		init_unistr( &st[i].displayname, display_name ? display_name : "");

		svcctl_ops[i].ops->service_status( svcctl_ops[i].name, &st[i].status );
	}

	*status = st;

	return num_services;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_enum_services_status(pipes_struct *p, SVCCTL_Q_ENUM_SERVICES_STATUS *q_u, SVCCTL_R_ENUM_SERVICES_STATUS *r_u)
{
	ENUM_SERVICES_STATUS *services = NULL;
	int num_services;
	int i = 0;
	size_t buffer_size = 0;
	WERROR result = WERR_OK;
	SERVICE_INFO *info = find_service_info_by_hnd( p, &q_u->handle );
	NT_USER_TOKEN *token = p->pipe_user.nt_user_token;

	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SCM) )
		return WERR_BADFID;

	if ( !(info->access_granted & SC_RIGHT_MGR_ENUMERATE_SERVICE) ) {
		return WERR_ACCESS_DENIED;
	}

	num_services = enumerate_status( p->mem_ctx, &services, token );
	if (num_services == -1 ) {
		return WERR_NOMEM;
	}

        for ( i=0; i<num_services; i++ ) {
		buffer_size += svcctl_sizeof_enum_services_status(&services[i]);
	}

	buffer_size += buffer_size % 4;

	if (buffer_size > q_u->buffer_size ) {
		num_services = 0;
		result = WERR_MORE_DATA;
	}

	rpcbuf_init(&r_u->buffer, q_u->buffer_size, p->mem_ctx);

	if ( W_ERROR_IS_OK(result) ) {
		for ( i=0; i<num_services; i++ )
			svcctl_io_enum_services_status( "", &services[i], &r_u->buffer, 0 );
	}

	r_u->needed      = (buffer_size > q_u->buffer_size) ? buffer_size : q_u->buffer_size;
	r_u->returned    = (uint32)num_services;

	if ( !(r_u->resume = TALLOC_P( p->mem_ctx, uint32 )) )
		return WERR_NOMEM;

	*r_u->resume = 0x0;

	return result;
}

/********************************************************************
 _svcctl_StartServiceW
********************************************************************/

WERROR _svcctl_StartServiceW(pipes_struct *p,
			     struct svcctl_StartServiceW *r)
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, r->in.handle );

	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;

	if ( !(info->access_granted & SC_RIGHT_SVC_START) )
		return WERR_ACCESS_DENIED;

	return info->ops->start_service( info->name );
}

/********************************************************************
 _svcctl_ControlService
********************************************************************/

WERROR _svcctl_ControlService(pipes_struct *p,
			      struct svcctl_ControlService *r)
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, r->in.handle );

	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;

	switch ( r->in.control ) {
	case SVCCTL_CONTROL_STOP:
		if ( !(info->access_granted & SC_RIGHT_SVC_STOP) )
			return WERR_ACCESS_DENIED;

		return info->ops->stop_service( info->name,
						r->out.service_status );

	case SVCCTL_CONTROL_INTERROGATE:
		if ( !(info->access_granted & SC_RIGHT_SVC_QUERY_STATUS) )
			return WERR_ACCESS_DENIED;

		return info->ops->service_status( info->name,
						  r->out.service_status );
	}

	/* default control action */

	return WERR_ACCESS_DENIED;
}

/********************************************************************
 _svcctl_EnumDependentServicesW
********************************************************************/

WERROR _svcctl_EnumDependentServicesW(pipes_struct *p,
				      struct svcctl_EnumDependentServicesW *r)
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, r->in.service );

	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;

	if ( !(info->access_granted & SC_RIGHT_SVC_ENUMERATE_DEPENDENTS) )
		return WERR_ACCESS_DENIED;

	/* we have to set the outgoing buffer size to the same as the
	   incoming buffer size (even in the case of failure */
	/* this is done in the autogenerated server already - gd */

	*r->out.bytes_needed = r->in.buf_size;

	/* no dependent services...basically a stub function */
	*r->out.services_returned = 0;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_query_service_status_ex( pipes_struct *p, SVCCTL_Q_QUERY_SERVICE_STATUSEX *q_u, SVCCTL_R_QUERY_SERVICE_STATUSEX *r_u )
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, &q_u->handle );
	uint32 buffer_size;

	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;

	if ( !(info->access_granted & SC_RIGHT_SVC_QUERY_STATUS) )
		return WERR_ACCESS_DENIED;

	/* we have to set the outgoing buffer size to the same as the
	   incoming buffer size (even in the case of failure) */

	rpcbuf_init( &r_u->buffer, q_u->buffer_size, p->mem_ctx );
	r_u->needed = q_u->buffer_size;

	switch ( q_u->level ) {
		case SVC_STATUS_PROCESS_INFO:
		{
			SERVICE_STATUS_PROCESS svc_stat_proc;

			/* Get the status of the service.. */
			info->ops->service_status( info->name, &svc_stat_proc.status );
			svc_stat_proc.process_id     = sys_getpid();
			svc_stat_proc.service_flags  = 0x0;

			svcctl_io_service_status_process( "", &svc_stat_proc, &r_u->buffer, 0 );
	                buffer_size = sizeof(SERVICE_STATUS_PROCESS);
			break;
		}

		default:
			return WERR_UNKNOWN_LEVEL;
	}


        buffer_size += buffer_size % 4;
	r_u->needed = (buffer_size > q_u->buffer_size) ? buffer_size : q_u->buffer_size;

        if (buffer_size > q_u->buffer_size )
                return WERR_MORE_DATA;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

static WERROR fill_svc_config( TALLOC_CTX *ctx, const char *name,
			       struct QUERY_SERVICE_CONFIG *config,
			       NT_USER_TOKEN *token )
{
	REGVAL_CTR *values;
	REGISTRY_VALUE *val;

	/* retrieve the registry values for this service */

	if ( !(values = svcctl_fetch_regvalues( name, token )) )
		return WERR_REG_CORRUPT;

	/* now fill in the individual values */

	if ( (val = regval_ctr_getvalue( values, "DisplayName" )) != NULL )
		config->displayname = regval_sz(val);
	else
		config->displayname = name;

	if ( (val = regval_ctr_getvalue( values, "ObjectName" )) != NULL ) {
		config->startname = regval_sz(val);
	}

	if ( (val = regval_ctr_getvalue( values, "ImagePath" )) != NULL ) {
		config->executablepath = regval_sz(val);
	}

	/* a few hard coded values */
	/* loadordergroup and dependencies are empty */

	config->tag_id           = 0x00000000;			/* unassigned loadorder group */
	config->service_type     = SVCCTL_WIN32_OWN_PROC;
	config->error_control    = SVCCTL_SVC_ERROR_NORMAL;

	/* set the start type.  NetLogon and WINS are disabled to prevent
	   the client from showing the "Start" button (if of course the services
	   are not running */

	if ( strequal( name, "NETLOGON" ) && ( lp_servicenumber(name) == -1 ) )
		config->start_type = SVCCTL_DISABLED;
	else if ( strequal( name, "WINS" ) && ( !lp_wins_support() ))
		config->start_type = SVCCTL_DISABLED;
	else
		config->start_type = SVCCTL_DEMAND_START;


	TALLOC_FREE( values );

	return WERR_OK;
}

/********************************************************************
 _svcctl_QueryServiceConfigW
********************************************************************/

WERROR _svcctl_QueryServiceConfigW(pipes_struct *p,
				   struct svcctl_QueryServiceConfigW *r)
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, r->in.handle );
	uint32 buffer_size;
	WERROR wresult;

	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;

	if ( !(info->access_granted & SC_RIGHT_SVC_QUERY_CONFIG) )
		return WERR_ACCESS_DENIED;

	/* we have to set the outgoing buffer size to the same as the
	   incoming buffer size (even in the case of failure */
	*r->out.bytes_needed = r->in.buf_size;

	wresult = fill_svc_config( p->mem_ctx, info->name, r->out.query, p->pipe_user.nt_user_token );
	if ( !W_ERROR_IS_OK(wresult) )
		return wresult;

	buffer_size = ndr_size_QUERY_SERVICE_CONFIG(r->out.query, 0);
	*r->out.bytes_needed = (buffer_size > r->in.buf_size) ? buffer_size : r->in.buf_size;

        if (buffer_size > r->in.buf_size ) {
		ZERO_STRUCTP(r->out.query);
                return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_query_service_config2( pipes_struct *p, SVCCTL_Q_QUERY_SERVICE_CONFIG2 *q_u, SVCCTL_R_QUERY_SERVICE_CONFIG2 *r_u )
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, &q_u->handle );
	uint32 buffer_size;

	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SERVICE) )
		return WERR_BADFID;

	if ( !(info->access_granted & SC_RIGHT_SVC_QUERY_CONFIG) )
		return WERR_ACCESS_DENIED;

	/* we have to set the outgoing buffer size to the same as the
	   incoming buffer size (even in the case of failure */

	rpcbuf_init( &r_u->buffer, q_u->buffer_size, p->mem_ctx );
	r_u->needed = q_u->buffer_size;

	switch ( q_u->level ) {
	case SERVICE_CONFIG_DESCRIPTION:
		{
			SERVICE_DESCRIPTION desc_buf;
			const char *description;

			description = svcctl_lookup_description(p->mem_ctx, info->name, p->pipe_user.nt_user_token );

			ZERO_STRUCTP( &desc_buf );

			init_service_description_buffer( &desc_buf, description ? description : "");
			svcctl_io_service_description( "", &desc_buf, &r_u->buffer, 0 );
	                buffer_size = svcctl_sizeof_service_description( &desc_buf );

			break;
		}
		break;
	case SERVICE_CONFIG_FAILURE_ACTIONS:
		{
			SERVICE_FAILURE_ACTIONS actions;

			/* nothing to say...just service the request */

			ZERO_STRUCTP( &actions );
			svcctl_io_service_fa( "", &actions, &r_u->buffer, 0 );
	                buffer_size = svcctl_sizeof_service_fa( &actions );

			break;
		}
		break;

	default:
		return WERR_UNKNOWN_LEVEL;
	}

	buffer_size += buffer_size % 4;
	r_u->needed = (buffer_size > q_u->buffer_size) ? buffer_size : q_u->buffer_size;

        if (buffer_size > q_u->buffer_size )
                return WERR_INSUFFICIENT_BUFFER;

	return WERR_OK;
}

/********************************************************************
 _svcctl_LockServiceDatabase
********************************************************************/

WERROR _svcctl_LockServiceDatabase(pipes_struct *p,
				   struct svcctl_LockServiceDatabase *r)
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, r->in.handle );

	/* perform access checks */

	if ( !info || (info->type != SVC_HANDLE_IS_SCM) )
		return WERR_BADFID;

	if ( !(info->access_granted & SC_RIGHT_MGR_LOCK) )
		return WERR_ACCESS_DENIED;

	/* Just open a handle.  Doesn't actually lock anything */

	return create_open_service_handle( p, r->out.lock, SVC_HANDLE_IS_DBLOCK, NULL, 0 );
}

/********************************************************************
 _svcctl_UnlockServiceDatabase
********************************************************************/

WERROR _svcctl_UnlockServiceDatabase(pipes_struct *p,
				     struct svcctl_UnlockServiceDatabase *r)
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, r->in.lock );


	if ( !info || (info->type != SVC_HANDLE_IS_DBLOCK) )
		return WERR_BADFID;

	return close_policy_hnd( p, r->out.lock) ? WERR_OK : WERR_BADFID;
}

/********************************************************************
 _svcctl_QueryServiceObjectSecurity
********************************************************************/

WERROR _svcctl_QueryServiceObjectSecurity(pipes_struct *p,
					  struct svcctl_QueryServiceObjectSecurity *r)
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, r->in.handle );
	SEC_DESC *sec_desc;
	NTSTATUS status;
	uint8_t *buffer = NULL;
	size_t len = 0;


	/* only support the SCM and individual services */

	if ( !info || !(info->type & (SVC_HANDLE_IS_SERVICE|SVC_HANDLE_IS_SCM)) )
		return WERR_BADFID;

	/* check access reights (according to MSDN) */

	if ( !(info->access_granted & STD_RIGHT_READ_CONTROL_ACCESS) )
		return WERR_ACCESS_DENIED;

	/* TODO: handle something besides DACL_SECURITY_INFORMATION */

	if ( (r->in.security_flags & DACL_SECURITY_INFORMATION) != DACL_SECURITY_INFORMATION )
		return WERR_INVALID_PARAM;

	/* lookup the security descriptor and marshall it up for a reply */

	if ( !(sec_desc = svcctl_get_secdesc( p->mem_ctx, info->name, get_root_nt_token() )) )
                return WERR_NOMEM;

	*r->out.needed = ndr_size_security_descriptor( sec_desc, 0 );

	if ( *r->out.needed > r->in.buffer_size ) {
		ZERO_STRUCTP( &r->out.buffer );
		return WERR_INSUFFICIENT_BUFFER;
	}

	status = marshall_sec_desc(p->mem_ctx, sec_desc, &buffer, &len);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	*r->out.needed = len;
	r->out.buffer = buffer;

	return WERR_OK;
}

/********************************************************************
 _svcctl_SetServiceObjectSecurity
********************************************************************/

WERROR _svcctl_SetServiceObjectSecurity(pipes_struct *p,
					struct svcctl_SetServiceObjectSecurity *r)
{
	SERVICE_INFO *info = find_service_info_by_hnd( p, r->in.handle );
	SEC_DESC *sec_desc = NULL;
	uint32 required_access;
	NTSTATUS status;

	if ( !info || !(info->type & (SVC_HANDLE_IS_SERVICE|SVC_HANDLE_IS_SCM))  )
		return WERR_BADFID;

	/* can't set the security de4scriptor on the ServiceControlManager */

	if ( info->type == SVC_HANDLE_IS_SCM )
		return WERR_ACCESS_DENIED;

	/* check the access on the open handle */

	switch ( r->in.security_flags ) {
		case DACL_SECURITY_INFORMATION:
			required_access = STD_RIGHT_WRITE_DAC_ACCESS;
			break;

		case OWNER_SECURITY_INFORMATION:
		case GROUP_SECURITY_INFORMATION:
			required_access = STD_RIGHT_WRITE_OWNER_ACCESS;
			break;

		case SACL_SECURITY_INFORMATION:
			return WERR_INVALID_PARAM;
		default:
			return WERR_INVALID_PARAM;
	}

	if ( !(info->access_granted & required_access) )
		return WERR_ACCESS_DENIED;

	/* read the security descfriptor */

	status = unmarshall_sec_desc(p->mem_ctx,
				     r->in.buffer, r->in.buffer_size,
				     &sec_desc);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	/* store the new SD */

	if ( !svcctl_set_secdesc( p->mem_ctx, info->name, sec_desc, p->pipe_user.nt_user_token ) )
		return WERR_ACCESS_DENIED;

	return WERR_OK;
}


WERROR _svcctl_DeleteService(pipes_struct *p, struct svcctl_DeleteService *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_SetServiceStatus(pipes_struct *p, struct svcctl_SetServiceStatus *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_NotifyBootConfigStatus(pipes_struct *p, struct svcctl_NotifyBootConfigStatus *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_SCSetServiceBitsW(pipes_struct *p, struct svcctl_SCSetServiceBitsW *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_ChangeServiceConfigW(pipes_struct *p, struct svcctl_ChangeServiceConfigW *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_CreateServiceW(pipes_struct *p, struct svcctl_CreateServiceW *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_EnumServicesStatusW(pipes_struct *p, struct svcctl_EnumServicesStatusW *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_QueryServiceLockStatusW(pipes_struct *p, struct svcctl_QueryServiceLockStatusW *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_GetServiceKeyNameW(pipes_struct *p, struct svcctl_GetServiceKeyNameW *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_SCSetServiceBitsA(pipes_struct *p, struct svcctl_SCSetServiceBitsA *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_ChangeServiceConfigA(pipes_struct *p, struct svcctl_ChangeServiceConfigA *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_CreateServiceA(pipes_struct *p, struct svcctl_CreateServiceA *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_EnumDependentServicesA(pipes_struct *p, struct svcctl_EnumDependentServicesA *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_EnumServicesStatusA(pipes_struct *p, struct svcctl_EnumServicesStatusA *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_OpenSCManagerA(pipes_struct *p, struct svcctl_OpenSCManagerA *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_OpenServiceA(pipes_struct *p, struct svcctl_OpenServiceA *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_QueryServiceConfigA(pipes_struct *p, struct svcctl_QueryServiceConfigA *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_QueryServiceLockStatusA(pipes_struct *p, struct svcctl_QueryServiceLockStatusA *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_StartServiceA(pipes_struct *p, struct svcctl_StartServiceA *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_GetServiceDisplayNameA(pipes_struct *p, struct svcctl_GetServiceDisplayNameA *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_GetServiceKeyNameA(pipes_struct *p, struct svcctl_GetServiceKeyNameA *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_GetCurrentGroupeStateW(pipes_struct *p, struct svcctl_GetCurrentGroupeStateW *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_EnumServiceGroupW(pipes_struct *p, struct svcctl_EnumServiceGroupW *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_ChangeServiceConfig2A(pipes_struct *p, struct svcctl_ChangeServiceConfig2A *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_ChangeServiceConfig2W(pipes_struct *p, struct svcctl_ChangeServiceConfig2W *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_QueryServiceConfig2A(pipes_struct *p, struct svcctl_QueryServiceConfig2A *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_QueryServiceConfig2W(pipes_struct *p, struct svcctl_QueryServiceConfig2W *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_QueryServiceStatusEx(pipes_struct *p, struct svcctl_QueryServiceStatusEx *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _EnumServicesStatusExA(pipes_struct *p, struct EnumServicesStatusExA *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _EnumServicesStatusExW(pipes_struct *p, struct EnumServicesStatusExW *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _svcctl_SCSendTSMessage(pipes_struct *p, struct svcctl_SCSendTSMessage *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

