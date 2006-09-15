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

void _echo_AddOne(pipes_struct *p, uint32_t in_data, uint32_t *out_data)
{
	DEBUG(10, ("_echo_add_one\n"));

	*out_data = in_data + 1;
}

/* Echo back an array of data */

void _echo_EchoData(pipes_struct *p, uint32_t len, uint8_t *in_data, uint8_t *out_data)
{
	DEBUG(10, ("_echo_data\n"));

	memcpy(out_data, in_data, len);
}

/* Sink an array of data */

void _echo_SinkData(pipes_struct *p, uint32_t len, uint8_t *data)
{
	DEBUG(10, ("_sink_data\n"));

	/* My that was some yummy data! */
}

/* Source an array of data */

void _echo_SourceData(pipes_struct *p, uint32_t len, uint8_t *data)
{
	uint32 i;

	DEBUG(10, ("_source_data\n"));

	for (i = 0; i < len; i++)
		data[i] = i & 0xff;
}

void _echo_TestCall(pipes_struct *p, const char *s1, const char **s2)
{
	*s2 = talloc_strdup(p->mem_ctx, s1);
}

NTSTATUS _echo_TestCall2(pipes_struct *p, uint16_t level, union echo_Info *info)
{
	switch (level) {
	case 1:
		info->info1.v = 10;
		break;
	case 2:
		info->info2.v = 20;
		break;
	case 3:
		info->info3.v = 30;
		break;
	case 4:
		info->info4.v = 40;
		break;
	case 5:
		info->info5.v1 = 50;
		info->info5.v2 = 60;
		break;
	case 6:
		info->info6.v1 = 70;
		info->info6.info1.v= 80;
		break;
	case 7:
		info->info7.v1 = 80;
		info->info7.info4.v = 90;
		break;
	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	return NT_STATUS_OK;
}

uint32 _echo_TestSleep(pipes_struct *p, uint32_t seconds)
{
	sleep(seconds);
	return seconds;
}

void _echo_TestEnum(pipes_struct *p, enum echo_Enum1 *foo1, struct echo_Enum2 *foo2, union echo_Enum3 *foo3)
{
}

void _echo_TestSurrounding(pipes_struct *p, struct echo_Surrounding *data)
{
	data->x *= 2;
	data->surrounding = talloc_zero_array(p->mem_ctx, uint16_t, data->x);
}

uint16 _echo_TestDoublePointer(pipes_struct *p, uint16_t ***data)
{
	if (!*data) 
		return 0;
	if (!**data)
		return 0;
	return ***data;
}

#endif /* DEVELOPER */
