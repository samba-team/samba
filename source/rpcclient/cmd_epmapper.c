/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Jim McDonough (jmcd@us.ibm.com) 2003

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "rpcclient.h"


static NTSTATUS cmd_epm_map(struct cli_state *cli, 
			    TALLOC_CTX *mem_ctx,
			    int argc, const char **argv) 
{
	EPM_HANDLE handle, entry_handle;
	EPM_TOWER *towers;
	EPM_FLOOR floors[5];
	uint8 addr[4] = {0,0,0,0};
	uint32 numtowers;
	/* need to allow all this stuff to be passed in, but
	   for now, it demonstrates the call */
	struct uuid if_uuid = {0xe3514235, 0x4b06, 0x11d1, \
			       { 0xab, 0x04 },             \
			       { 0x00, 0xc0,               \
				 0x4f, 0xc2, 0xdc, 0xd2 } },
		   syn_uuid = {0x8a885d04, 0x1ceb, 0x11c9, \
			       { 0x9f, 0xe8 },             \
			       { 0x08, 0x00,               \
				 0x2b, 0x10, 0x48, 0x60 } };

	NTSTATUS result;

	ZERO_STRUCT(handle);
	numtowers = 1;
	init_epm_floor_uuid(&floors[0], if_uuid, 4);
	init_epm_floor_uuid(&floors[1], syn_uuid, 2);
	init_epm_floor_rpc(&floors[2]);

	/* sample for netbios named pipe query 	
	init_epm_floor_np(&floors[3], "\\PIPE\\lsass");
	init_epm_floor_nb(&floors[4], "\\\\psflinux"); 
	*/
	init_epm_floor_tcp(&floors[3], 135);
	init_epm_floor_ip(&floors[4], addr);
	towers = talloc(mem_ctx, sizeof(EPM_TOWER));
	init_epm_tower(mem_ctx, towers, floors, 5);

	result = cli_epm_map(cli, mem_ctx, &handle, &towers, &entry_handle, &numtowers);

	return result;
}

struct cmd_set epm_commands[] = {

	{ "EPMAPPER" },

	{ "map", 		RPC_RTYPE_NTSTATUS, cmd_epm_map, 		NULL, PI_EPM,	"map endpoint",         "" },
	{ NULL }
};


