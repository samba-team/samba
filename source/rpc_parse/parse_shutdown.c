/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Jim McDonough (jmcd@us.ibm.com)   2003.
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
#define DBGC_CLASS DBGC_RPC_PARSE

/*******************************************************************
Inits a structure.
********************************************************************/

void init_shutdown_q_init(SHUTDOWN_Q_INIT *q_s, const char *msg,
			uint32 timeout, BOOL do_reboot, BOOL force)
{
	q_s->ptr_server = 1;
	q_s->server = 1;
	q_s->ptr_msg = 1;

	init_unistr2(&q_s->uni_msg, msg, UNI_FLAGS_NONE);
	init_uni_hdr(&q_s->hdr_msg, &q_s->uni_msg);

	q_s->timeout = timeout;

	q_s->reboot = do_reboot ? 1 : 0;
	q_s->force = force ? 1 : 0;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL shutdown_io_q_init(const char *desc, SHUTDOWN_Q_INIT *q_s, prs_struct *ps,
			int depth)
{
	if (q_s == NULL)
		return False;

	prs_debug(ps, depth, desc, "shutdown_io_q_init");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("ptr_server", ps, depth, &(q_s->ptr_server)))
		return False;
	if (!prs_uint16("server", ps, depth, &(q_s->server)))
		return False;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("ptr_msg", ps, depth, &(q_s->ptr_msg)))
		return False;

	if (!smb_io_unihdr("hdr_msg", &(q_s->hdr_msg), ps, depth))
		return False;
	if (!smb_io_unistr2("uni_msg", &(q_s->uni_msg), q_s->hdr_msg.buffer, ps, depth))
		return False;
	if (!prs_align(ps))
		return False;

	if (!prs_uint32("timeout", ps, depth, &(q_s->timeout)))
		return False;
	if (!prs_uint8("force  ", ps, depth, &(q_s->force)))
		return False;
	if (!prs_uint8("reboot ", ps, depth, &(q_s->reboot)))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL shutdown_io_r_init(const char *desc, SHUTDOWN_R_INIT* r_s, prs_struct *ps,
			int depth)
{
	if (r_s == NULL)
		return False;

	prs_debug(ps, depth, desc, "shutdown_io_r_init");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_s->status))
		return False;

	return True;
}

/*******************************************************************
Inits a structure.
********************************************************************/
void init_shutdown_q_abort(SHUTDOWN_Q_ABORT *q_s)
{

	q_s->ptr_server = 0;

}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL shutdown_io_q_abort(const char *desc, SHUTDOWN_Q_ABORT *q_s,
			 prs_struct *ps, int depth)
{
	if (q_s == NULL)
		return False;

	prs_debug(ps, depth, desc, "shutdown_io_q_abort");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("ptr_server", ps, depth, &(q_s->ptr_server)))
		return False;
	if (q_s->ptr_server != 0)
		if (!prs_uint16("server", ps, depth, &(q_s->server)))
			return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL shutdown_io_r_abort(const char *desc, SHUTDOWN_R_ABORT *r_s,
			 prs_struct *ps, int depth)
{
	if (r_s == NULL)
		return False;

	prs_debug(ps, depth, desc, "shutdown_io_r_abort");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_ntstatus("status", ps, depth, &r_s->status))
		return False;

	return True;
}
