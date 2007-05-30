/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines for rpcecho
 *  Copyright (C) Tim Potter                   2003.
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

void _echo_AddOne(pipes_struct *p, struct echo_AddOne *r )
{
	DEBUG(10, ("_echo_add_one\n"));

	*r->out.out_data = r->in.in_data + 1;	
}

/* Echo back an array of data */

void _echo_data(pipes_struct *p, ECHO_Q_ECHO_DATA *q_u, 
		ECHO_R_ECHO_DATA *r_u)
{
	DEBUG(10, ("_echo_data\n"));

	if (q_u->size == 0) {
		r_u->data = NULL;
		r_u->size = 0;
		return;
	}
	r_u->data = TALLOC(p->mem_ctx, q_u->size);
	r_u->size = q_u->size;
	memcpy(r_u->data, q_u->data, q_u->size);
}

/* Sink an array of data */

void _sink_data(pipes_struct *p, ECHO_Q_SINK_DATA *q_u, 
		ECHO_R_SINK_DATA *r_u)
{
	DEBUG(10, ("_sink_data\n"));

	/* My that was some yummy data! */
}

/* Source an array of data */

void _source_data(pipes_struct *p, ECHO_Q_SOURCE_DATA *q_u, 
		  ECHO_R_SOURCE_DATA *r_u)
{
	uint32 i;

	DEBUG(10, ("_source_data\n"));

	if (q_u->size == 0) {
		r_u->data = NULL;
		r_u->size = 0;
		return;
	}
	r_u->data = TALLOC(p->mem_ctx, q_u->size);
	r_u->size = q_u->size;

	for (i = 0; i < r_u->size; i++)
		r_u->data[i] = i & 0xff;
}

void _echo_EchoData(pipes_struct *p, struct echo_EchoData *r)
{
	p->rng_fault_state = True;
	return;
}

void _echo_SinkData(pipes_struct *p, struct echo_SinkData *r)
{
	p->rng_fault_state = True;
	return;
}

void _echo_SourceData(pipes_struct *p, struct echo_SourceData *r)
{
	p->rng_fault_state = True;
	return;
}

void _echo_TestCall(pipes_struct *p, struct echo_TestCall *r)
{
	p->rng_fault_state = True;
	return;
}

NTSTATUS _echo_TestCall2(pipes_struct *p, struct echo_TestCall2 *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_OK;
}

uint32 _echo_TestSleep(pipes_struct *p, struct echo_TestSleep *r)
{
	p->rng_fault_state = True;
	return 0;
}

void _echo_TestEnum(pipes_struct *p, struct echo_TestEnum *r)
{
	p->rng_fault_state = True;
	return;
}

void _echo_TestSurrounding(pipes_struct *p, struct echo_TestSurrounding *r)
{
	p->rng_fault_state = True;
	return;
}

uint16 _echo_TestDoublePointer(pipes_struct *p, struct echo_TestDoublePointer *r)
{
	p->rng_fault_state = True;
	return 0;
}

#endif /* DEVELOPER */
