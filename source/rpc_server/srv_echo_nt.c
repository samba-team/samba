/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines for rpcecho
 *  Copyright (C) Tim Potter                   2003.
 *  Copyright (C) Jelmer Vernooij 			   2006.
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

/* This is the interface to the rpcecho pipe. */

#include "includes.h"
#include "nterr.h"

#ifdef DEVELOPER

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/* Add one to the input and return it */

void _echo_AddOne(pipes_struct *p, struct echo_AddOne *r)
{
	DEBUG(10, ("_echo_add_one\n"));

	*r->out.out_data = r->in.in_data + 1;
}

/* Echo back an array of data */

void _echo_EchoData(pipes_struct *p, struct echo_EchoData *r)
{
	DEBUG(10, ("_echo_data\n"));

	memcpy(r->out.out_data, r->in.in_data, r->in.len);
}

/* Sink an array of data */

void _echo_SinkData(pipes_struct *p, struct echo_SinkData *r)
{
	DEBUG(10, ("_sink_data\n"));

	/* My that was some yummy data! */
}

/* Source an array of data */

void _echo_SourceData(pipes_struct *p, struct echo_SourceData *r)
{
	uint32 i;

	DEBUG(10, ("_source_data\n"));

	for (i = 0; i < r->in.len; i++)
		r->out.data[i] = i & 0xff;
}

void _echo_TestCall(pipes_struct *p, struct echo_TestCall *r)
{
	*r->out.s2 = talloc_strdup(p->mem_ctx, r->in.s1);
}

NTSTATUS _echo_TestCall2(pipes_struct *p, struct echo_TestCall2 *r)
{
	switch (r->in.level) {
	case 1:
		r->out.info->info1.v = 10;
		break;
	case 2:
		r->out.info->info2.v = 20;
		break;
	case 3:
		r->out.info->info3.v = 30;
		break;
	case 4:
		r->out.info->info4.v = 40;
		break;
	case 5:
		r->out.info->info5.v1 = 50;
		r->out.info->info5.v2 = 60;
		break;
	case 6:
		r->out.info->info6.v1 = 70;
		r->out.info->info6.info1.v= 80;
		break;
	case 7:
		r->out.info->info7.v1 = 80;
		r->out.info->info7.info4.v = 90;
		break;
	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	return NT_STATUS_OK;
}

uint32 _echo_TestSleep(pipes_struct *p, struct echo_TestSleep *r)
{
	sleep(r->in.seconds);
	return r->in.seconds;
}

void _echo_TestEnum(pipes_struct *p, struct echo_TestEnum *r)
{
}

void _echo_TestSurrounding(pipes_struct *p, struct echo_TestSurrounding *r)
{
	r->out.data->x *= 2;
	r->out.data->surrounding = talloc_zero_array(p->mem_ctx, uint16_t, r->in.data->x);
}

uint16 _echo_TestDoublePointer(pipes_struct *p, struct echo_TestDoublePointer *r)
{
	if (!*r->in.data) 
		return 0;
	if (!**r->in.data)
		return 0;
	return ***r->in.data;
}

#endif /* DEVELOPER */
