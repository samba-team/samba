/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Marc Jacobsen						2000.
 *  Copyright (C) Jeremy Allison					2001.
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

/* This is the interface for the registry functions. */

#include "includes.h"

/*******************************************************************
 api_reg_close
 ********************************************************************/

static BOOL api_reg_close(pipes_struct *p)
{
	REG_Q_CLOSE q_u;
	REG_R_CLOSE r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	/* grab the reg unknown 1 */
	if(!reg_io_q_close("", &q_u, data, 0))
		return False;

	r_u.status = _reg_close(p, &q_u, &r_u);

	if(!reg_io_r_close("", &r_u, rdata, 0))
		return False;

	return True;
}

/*******************************************************************
 api_reg_open
 ********************************************************************/

static BOOL api_reg_open(pipes_struct *p)
{
	REG_Q_OPEN_HKLM q_u;
	REG_R_OPEN_HKLM r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	/* grab the reg open */
	if(!reg_io_q_open_hklm("", &q_u, data, 0))
		return False;

	r_u.status = _reg_open(p, &q_u, &r_u);

	if(!reg_io_r_open_hklm("", &r_u, rdata, 0))
		return False;

	return True;
}

/*******************************************************************
 api_reg_open_entry
 ********************************************************************/

static BOOL api_reg_open_entry(pipes_struct *p)
{
	REG_Q_OPEN_ENTRY q_u;
	REG_R_OPEN_ENTRY r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	/* grab the reg open entry */
	if(!reg_io_q_open_entry("", &q_u, data, 0))
		return False;

	/* construct reply. */
	r_u.status = _reg_open_entry(p, &q_u, &r_u);

	if(!reg_io_r_open_entry("", &r_u, rdata, 0))
		return False;

	return True;
}

/*******************************************************************
 api_reg_info
 ********************************************************************/

static BOOL api_reg_info(pipes_struct *p)
{
	REG_Q_INFO q_u;
	REG_R_INFO r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	/* grab the reg unknown 0x11*/
	if(!reg_io_q_info("", &q_u, data, 0))
		return False;

	r_u.status = _reg_info(p, &q_u, &r_u);

	if(!reg_io_r_info("", &r_u, rdata, 0))
		return False;

	return True;
}

#if 0
/*******************************************************************
 api_reg_shutdown
 ********************************************************************/

static BOOL api_reg_shutdown(pipes_struct *p)
{
	REG_Q_SHUTDOWN q_u;
	REG_R_SHUTDOWN r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	/* grab the reg shutdown */
	if(!reg_io_q_shutdown("", &q_u, data, 0))
		return False;

	r_u.status = _reg_shutdown(p, &q_u, &r_u);

	if(!reg_io_r_shutdown("", &r_u, rdata, 0))
		return False;

	return True;
}

/*******************************************************************
 api_reg_abort_shutdown
 ********************************************************************/

static BOOL api_reg_abort_shutdown(pipes_struct *p)
{
	REG_Q_ABORT_SHUTDOWN q_u;
	REG_R_ABORT_SHUTDOWN r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	/* grab the reg shutdown */
	if(!reg_io_q_abort_shutdown("", &q_u, data, 0))
		return False;

	r_u.status = _reg_abort_shutdown(p, &q_u, &r_u);

	if(!reg_io_r_abort_shutdown("", &r_u, rdata, 0))
		return False;

	return True;
}
#endif

/*******************************************************************
 array of \PIPE\reg operations
 ********************************************************************/
static struct api_struct api_reg_cmds[] =
{
	{ "REG_CLOSE"        , REG_CLOSE        , api_reg_close        },
	{ "REG_OPEN_ENTRY"   , REG_OPEN_ENTRY   , api_reg_open_entry   },
	{ "REG_OPEN"         , REG_OPEN_HKLM    , api_reg_open         },
	{ "REG_INFO"         , REG_INFO         , api_reg_info         },
#if 0
	{ "REG_SHUTDOWN"     , REG_SHUTDOWN     , api_reg_shutdown     },
	{ "REG_ABORT_SHUTDOWN", REG_ABORT_SHUTDOWN, api_reg_abort_shutdown },
#endif
	{ NULL,                0                , NULL                 }
};

/*******************************************************************
 receives a reg pipe and responds.
 ********************************************************************/

BOOL api_reg_rpc(pipes_struct *p)
{
	return api_rpcTNP(p, "api_reg_rpc", api_reg_cmds);
}
