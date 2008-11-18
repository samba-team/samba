/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald Carter                   2005 - 2007
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

static bool proxy_svcctl_call(pipes_struct *p, uint8 opnum)
{
	struct api_struct *fns;
	int n_fns;

	svcctl_get_pipe_fns(&fns, &n_fns);

	if (opnum >= n_fns)
		return False;

	if (fns[opnum].opnum != opnum) {
		smb_panic("SVCCTL function table not sorted\n");
	}

	return fns[opnum].fn(p);
}


/*******************************************************************
 ********************************************************************/

static bool api_svcctl_close_service(pipes_struct *p)
{
	return proxy_svcctl_call( p, NDR_SVCCTL_CLOSESERVICEHANDLE );
}

/*******************************************************************
 ********************************************************************/

static bool api_svcctl_open_scmanager(pipes_struct *p)
{
	return proxy_svcctl_call(p, NDR_SVCCTL_OPENSCMANAGERW);
}

/*******************************************************************
 ********************************************************************/

static bool api_svcctl_open_service(pipes_struct *p)
{
	return proxy_svcctl_call(p, NDR_SVCCTL_OPENSERVICEW);
}

/*******************************************************************
 ********************************************************************/

static bool api_svcctl_get_display_name(pipes_struct *p)
{
	return proxy_svcctl_call(p, NDR_SVCCTL_GETSERVICEDISPLAYNAMEW);
}

/*******************************************************************
 ********************************************************************/

static bool api_svcctl_query_status(pipes_struct *p)
{
	return proxy_svcctl_call(p, NDR_SVCCTL_QUERYSERVICESTATUS);
}

/*******************************************************************
 ********************************************************************/

static bool api_svcctl_enum_services_status(pipes_struct *p)
{
	SVCCTL_Q_ENUM_SERVICES_STATUS q_u;
	SVCCTL_R_ENUM_SERVICES_STATUS r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if(!svcctl_io_q_enum_services_status("", &q_u, data, 0))
		return False;

	r_u.status = _svcctl_enum_services_status(p, &q_u, &r_u);

	if(!svcctl_io_r_enum_services_status("", &r_u, rdata, 0))
		return False;

	return True;
}
/*******************************************************************
 ********************************************************************/

static bool api_svcctl_query_service_status_ex(pipes_struct *p)
{
	SVCCTL_Q_QUERY_SERVICE_STATUSEX q_u;
	SVCCTL_R_QUERY_SERVICE_STATUSEX r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if(!svcctl_io_q_query_service_status_ex("", &q_u, data, 0))
		return False;

	r_u.status = _svcctl_query_service_status_ex(p, &q_u, &r_u);

	if(!svcctl_io_r_query_service_status_ex("", &r_u, rdata, 0))
		return False;

	return True;
}
/*******************************************************************
 ********************************************************************/

static bool api_svcctl_enum_dependent_services(pipes_struct *p)
{
	return proxy_svcctl_call(p, NDR_SVCCTL_ENUMDEPENDENTSERVICESW);
}

/*******************************************************************
 ********************************************************************/

static bool api_svcctl_start_service(pipes_struct *p)
{
	return proxy_svcctl_call(p, NDR_SVCCTL_STARTSERVICEW);
}

/*******************************************************************
 ********************************************************************/

static bool api_svcctl_control_service(pipes_struct *p)
{
	return proxy_svcctl_call(p, NDR_SVCCTL_CONTROLSERVICE);
}

/*******************************************************************
 ********************************************************************/

static bool api_svcctl_query_service_config(pipes_struct *p)
{
	return proxy_svcctl_call(p, SVCCTL_QUERY_SERVICE_CONFIG_W);
}

/*******************************************************************
 ********************************************************************/

static bool api_svcctl_query_service_config2(pipes_struct *p)
{
	SVCCTL_Q_QUERY_SERVICE_CONFIG2 q_u;
	SVCCTL_R_QUERY_SERVICE_CONFIG2 r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if(!svcctl_io_q_query_service_config2("", &q_u, data, 0))
		return False;

	r_u.status = _svcctl_query_service_config2(p, &q_u, &r_u);

	if(!svcctl_io_r_query_service_config2("", &r_u, rdata, 0))
		return False;

	return True;
}

/*******************************************************************
 ********************************************************************/

static bool api_svcctl_lock_service_db(pipes_struct *p)
{
	return proxy_svcctl_call(p, NDR_SVCCTL_LOCKSERVICEDATABASE);
}


/*******************************************************************
 ********************************************************************/

static bool api_svcctl_unlock_service_db(pipes_struct *p)
{
	return proxy_svcctl_call(p, NDR_SVCCTL_UNLOCKSERVICEDATABASE);
}

/*******************************************************************
 ********************************************************************/

static bool api_svcctl_query_security_sec(pipes_struct *p)
{
	return proxy_svcctl_call(p, NDR_SVCCTL_QUERYSERVICEOBJECTSECURITY);
}

/*******************************************************************
 ********************************************************************/

static bool api_svcctl_set_security_sec(pipes_struct *p)
{
	return proxy_svcctl_call(p, NDR_SVCCTL_SETSERVICEOBJECTSECURITY);
}


/*******************************************************************
 \PIPE\svcctl commands
 ********************************************************************/

static struct api_struct api_svcctl_cmds[] =
{
      { "SVCCTL_CLOSE_SERVICE"              , SVCCTL_CLOSE_SERVICE              , api_svcctl_close_service },
      { "SVCCTL_OPEN_SCMANAGER_W"           , SVCCTL_OPEN_SCMANAGER_W           , api_svcctl_open_scmanager },
      { "SVCCTL_OPEN_SERVICE_W"             , SVCCTL_OPEN_SERVICE_W             , api_svcctl_open_service },
      { "SVCCTL_GET_DISPLAY_NAME"           , SVCCTL_GET_DISPLAY_NAME           , api_svcctl_get_display_name },
      { "SVCCTL_QUERY_STATUS"               , SVCCTL_QUERY_STATUS               , api_svcctl_query_status },
      { "SVCCTL_QUERY_SERVICE_CONFIG_W"     , SVCCTL_QUERY_SERVICE_CONFIG_W     , api_svcctl_query_service_config },
      { "SVCCTL_QUERY_SERVICE_CONFIG2_W"    , SVCCTL_QUERY_SERVICE_CONFIG2_W    , api_svcctl_query_service_config2 },
      { "SVCCTL_ENUM_SERVICES_STATUS_W"     , SVCCTL_ENUM_SERVICES_STATUS_W     , api_svcctl_enum_services_status },
      { "SVCCTL_ENUM_DEPENDENT_SERVICES_W"  , SVCCTL_ENUM_DEPENDENT_SERVICES_W  , api_svcctl_enum_dependent_services },
      { "SVCCTL_START_SERVICE_W"            , SVCCTL_START_SERVICE_W            , api_svcctl_start_service },
      { "SVCCTL_CONTROL_SERVICE"            , SVCCTL_CONTROL_SERVICE            , api_svcctl_control_service },
      { "SVCCTL_QUERY_SERVICE_STATUSEX_W"   , SVCCTL_QUERY_SERVICE_STATUSEX_W   , api_svcctl_query_service_status_ex },
      { "SVCCTL_LOCK_SERVICE_DB"            , SVCCTL_LOCK_SERVICE_DB            , api_svcctl_lock_service_db },
      { "SVCCTL_UNLOCK_SERVICE_DB"          , SVCCTL_UNLOCK_SERVICE_DB          , api_svcctl_unlock_service_db },
      { "SVCCTL_QUERY_SERVICE_SEC"          , SVCCTL_QUERY_SERVICE_SEC          , api_svcctl_query_security_sec },
      { "SVCCTL_SET_SERVICE_SEC"            , SVCCTL_SET_SERVICE_SEC            , api_svcctl_set_security_sec }
};


void svcctl2_get_pipe_fns( struct api_struct **fns, int *n_fns )
{
        *fns = api_svcctl_cmds;
	*n_fns = sizeof(api_svcctl_cmds) / sizeof(struct api_struct);
}

NTSTATUS rpc_svcctl2_init(void)
{
	return rpc_pipe_register_commands(SMB_RPC_INTERFACE_VERSION,
					  "svcctl", "ntsvcs",
					  &ndr_table_svcctl.syntax_id,
					  api_svcctl_cmds,
					  sizeof(api_svcctl_cmds) / sizeof(struct api_struct));
}
