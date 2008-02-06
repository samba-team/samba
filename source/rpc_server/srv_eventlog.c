/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Marcin Krzysztof Porwit         2005.
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

static bool proxy_eventlog_call(pipes_struct *p, uint8 opnum)
{
	struct api_struct *fns;
	int n_fns;

	eventlog_get_pipe_fns(&fns, &n_fns);

	if (opnum >= n_fns)
		return False;

	if (fns[opnum].opnum != opnum) {
		smb_panic("EVENTLOG function table not sorted\n");
	}

	return fns[opnum].fn(p);
}

static bool api_eventlog_open_eventlog(pipes_struct *p)
{
	return proxy_eventlog_call(p, NDR_EVENTLOG_OPENEVENTLOGW);
}

static bool api_eventlog_close_eventlog(pipes_struct *p)
{
	return proxy_eventlog_call( p, NDR_EVENTLOG_CLOSEEVENTLOG );	
}

static bool api_eventlog_get_num_records(pipes_struct *p)
{
	return proxy_eventlog_call(p, NDR_EVENTLOG_GETNUMRECORDS);
}

static bool api_eventlog_get_oldest_entry(pipes_struct *p)
{
	return proxy_eventlog_call(p, NDR_EVENTLOG_GETOLDESTRECORD);
}

static bool api_eventlog_read_eventlog(pipes_struct *p)
{
	EVENTLOG_Q_READ_EVENTLOG q_u;
	EVENTLOG_R_READ_EVENTLOG r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!(eventlog_io_q_read_eventlog("", &q_u, data, 0))) {
		DEBUG(0, ("eventlog_io_q_read_eventlog: unable to unmarshall EVENTLOG_Q_READ_EVENTLOG.\n"));
		return False;
	}

	r_u.status = _eventlog_read_eventlog(p, &q_u, &r_u);

	if (!(eventlog_io_r_read_eventlog("", &q_u, &r_u, rdata, 0))) {
		DEBUG(0, ("eventlog_io_r_read_eventlog: unable to marshall EVENTLOG_R_READ_EVENTLOG.\n"));
		return False;
	}

	return True;
}

static bool api_eventlog_clear_eventlog(pipes_struct *p)
{
	return proxy_eventlog_call(p, NDR_EVENTLOG_CLEAREVENTLOGW);
}

/*
 \pipe\eventlog commands
*/
struct api_struct api_eventlog_cmds[] =
{
	{"EVENTLOG_OPENEVENTLOG", 	EVENTLOG_OPENEVENTLOG, 		api_eventlog_open_eventlog    },
	{"EVENTLOG_CLOSEEVENTLOG", 	EVENTLOG_CLOSEEVENTLOG, 	api_eventlog_close_eventlog   },
	{"EVENTLOG_GETNUMRECORDS", 	EVENTLOG_GETNUMRECORDS, 	api_eventlog_get_num_records  },
	{"EVENTLOG_GETOLDESTENTRY", 	EVENTLOG_GETOLDESTENTRY, 	api_eventlog_get_oldest_entry },
	{"EVENTLOG_READEVENTLOG", 	EVENTLOG_READEVENTLOG, 		api_eventlog_read_eventlog    },
	{"EVENTLOG_CLEAREVENTLOG", 	EVENTLOG_CLEAREVENTLOG, 	api_eventlog_clear_eventlog   }
};

NTSTATUS rpc_eventlog2_init(void)
{
	return rpc_pipe_register_commands(SMB_RPC_INTERFACE_VERSION, 
		"eventlog", "eventlog", api_eventlog_cmds,
		sizeof(api_eventlog_cmds)/sizeof(struct api_struct));
}

void eventlog2_get_pipe_fns(struct api_struct **fns, int *n_fns)
{
	*fns = api_eventlog_cmds;
	*n_fns = sizeof(api_eventlog_cmds) / sizeof(struct api_struct);
}
