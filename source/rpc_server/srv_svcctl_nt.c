/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald (Jerry) Carter             2005
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*
 * sertup the \PIPE\svcctl db API
 */
 
#define SCVCTL_DATABASE_VERSION_V1 1

/********************************************************************
********************************************************************/

#if 0 /* unused static function and static variable*/

static TDB_CONTEXT *svcctl_tdb; /* used for share security descriptors */

static BOOL init_svcctl_db( void )
{
	static pid_t local_pid;
	const char *vstring = "INFO/version";
 
 	/* see if we've already opened the tdb */
	
	if (svcctl_tdb && local_pid == sys_getpid())
		return True;
	
	/* so open it */	
	if ( !(svcctl_tdb = tdb_open_log(lock_path("svcctl.tdb"), 0, TDB_DEFAULT, 
		O_RDWR|O_CREAT, 0600))) 
	{
		DEBUG(0,("Failed to open svcctl database %s (%s)\n", 
			lock_path("svcctl.tdb"), strerror(errno) ));
		return False;
	}
 
	local_pid = sys_getpid();
 
	/***** BEGIN Check the tdb version ******/
	
	tdb_lock_bystring(svcctl_tdb, vstring, 0);
	
	if ( tdb_fetch_int32(svcctl_tdb, vstring) != SCVCTL_DATABASE_VERSION_V1 )
		tdb_store_int32(svcctl_tdb, vstring, SCVCTL_DATABASE_VERSION_V1);

	tdb_unlock_bystring(svcctl_tdb, vstring);
	
	/***** END Check the tdb version ******/

	return True;
}

#endif

/********************************************************************
 TODO
 (a) get and set security descriptors on services
 (b) read and write QUERY_SERVICE_CONFIG structures
 (c) create default secdesc objects for services and SCM
 (d) check access control masks with se_access_check()
 (e) implement SERVICE * for associating with open handles
********************************************************************/

/********************************************************************
********************************************************************/

WERROR _svcctl_open_scmanager(pipes_struct *p, SVCCTL_Q_OPEN_SCMANAGER *q_u, SVCCTL_R_OPEN_SCMANAGER *r_u)
{
	/* just fake it for now */
	
	if ( !create_policy_hnd( p, &r_u->handle, NULL, NULL ) )
		return WERR_ACCESS_DENIED;
	
	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_open_service(pipes_struct *p, SVCCTL_Q_OPEN_SERVICE *q_u, SVCCTL_R_OPEN_SERVICE *r_u)
{
	fstring service;

	rpcstr_pull(service, q_u->servicename.buffer, sizeof(service), q_u->servicename.uni_str_len*2, 0);
	
	/* can only be called on service name (not displayname) */

	if ( !(strequal( service, "NETLOGON") || strequal(service, "Spooler")) )
		return WERR_NO_SUCH_SERVICE;

	if ( !create_policy_hnd( p, &r_u->handle, NULL, NULL ) )
		return WERR_ACCESS_DENIED;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_close_service(pipes_struct *p, SVCCTL_Q_CLOSE_SERVICE *q_u, SVCCTL_R_CLOSE_SERVICE *r_u)
{
	if ( !close_policy_hnd( p, &q_u->handle ) )
		return WERR_BADFID;
	
	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_get_display_name(pipes_struct *p, SVCCTL_Q_GET_DISPLAY_NAME *q_u, SVCCTL_R_GET_DISPLAY_NAME *r_u)
{
	fstring service;
	fstring displayname;

	rpcstr_pull(service, q_u->servicename.buffer, sizeof(service), q_u->servicename.uni_str_len*2, 0);

	DEBUG(10,("_svcctl_get_display_name: service name [%s]\n", service));

	if ( !strequal( service, "NETLOGON" ) )
		return WERR_ACCESS_DENIED;

	fstrcpy( displayname, "Net Logon");
	init_svcctl_r_get_display_name( r_u, displayname );

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_query_status(pipes_struct *p, SVCCTL_Q_QUERY_STATUS *q_u, SVCCTL_R_QUERY_STATUS *r_u)
{

	r_u->svc_status.type = 0x0110;
	r_u->svc_status.state = 0x0004;
	r_u->svc_status.controls_accepted = 0x0005;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_enum_services_status(pipes_struct *p, SVCCTL_Q_ENUM_SERVICES_STATUS *q_u, SVCCTL_R_ENUM_SERVICES_STATUS *r_u)
{
	ENUM_SERVICES_STATUS *services = NULL;
	uint32 num_services = 0;
	int i = 0;
	size_t buffer_size;
	WERROR result = WERR_OK;
		
	/* num_services = str_list_count( lp_enable_svcctl() ); */
	num_services = 2;
	
	if ( !(services = TALLOC_ARRAY( p->mem_ctx, ENUM_SERVICES_STATUS, num_services )) )
		return WERR_NOMEM;
		
	DEBUG(8,("_svcctl_enum_services_status: Enumerating %d services\n", num_services));
				
	init_unistr( &services[i].servicename, "Spooler" );
	init_unistr( &services[i].displayname, "Spooler" );
	
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
	
	init_unistr( &services[i].servicename, "Netlogon" );
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
	
	buffer_size = 0;
	for (i=0; i<num_services; i++ )
		buffer_size += svcctl_sizeof_enum_services_status( &services[i] );
		
	buffer_size += buffer_size % 4;
	
	if ( buffer_size > q_u->buffer_size ) {
		num_services = 0;
		result = WERR_MORE_DATA;
	}
		
	/* we have to set the outgoing buffer size to the same as the 
	   incoming buffer size (even in the case of failure */

	rpcbuf_init( &r_u->buffer, q_u->buffer_size, p->mem_ctx );
		
	if ( W_ERROR_IS_OK(result) ) {
		for ( i=0; i<num_services; i++ )
			svcctl_io_enum_services_status( "", &services[i], &r_u->buffer, 0 );
	}
		
	r_u->needed      = (buffer_size > q_u->buffer_size) ? buffer_size : q_u->buffer_size;
	r_u->returned    = num_services;

	if ( !(r_u->resume = TALLOC_P( p->mem_ctx, uint32 )) )
		return WERR_NOMEM;

	*r_u->resume = 0x0;

	return result;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_start_service(pipes_struct *p, SVCCTL_Q_START_SERVICE *q_u, SVCCTL_R_START_SERVICE *r_u)
{
	return WERR_ACCESS_DENIED;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_control_service(pipes_struct *p, SVCCTL_Q_CONTROL_SERVICE *q_u, SVCCTL_R_CONTROL_SERVICE *r_u)
{
	return WERR_ACCESS_DENIED;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_enum_dependent_services( pipes_struct *p, SVCCTL_Q_ENUM_DEPENDENT_SERVICES *q_u, SVCCTL_R_ENUM_DEPENDENT_SERVICES *r_u )
{
	
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

WERROR _svcctl_query_service_config( pipes_struct *p, SVCCTL_Q_QUERY_SERVICE_CONFIG *q_u, SVCCTL_R_QUERY_SERVICE_CONFIG *r_u )
{
	
	/* we have to set the outgoing buffer size to the same as the 
	   incoming buffer size (even in the case of failure */

	r_u->needed      = q_u->buffer_size;
	
	/* no dependent services...basically a stub function */

	return WERR_ACCESS_DENIED;
}


