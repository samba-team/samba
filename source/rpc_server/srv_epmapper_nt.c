
/* 
   Unix SMB/CIFS implementation.
   Samba end point mapper utility and mapping functions
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

/*******************************************************************/
/*  _epm_map - fill out mapping on input and output structs */
/*******************************************************************/
void _epm_map(pipes_struct *ps, const EPM_Q_MAP *q_u, EPM_R_MAP *r_u)
{
	int i;
	uint8 target_address[] = { 9, 53, 95, 27 };
	EPM_FLOOR *floors = talloc(ps->mem_ctx, sizeof(EPM_FLOOR) *
				   q_u->tower->num_floors);
	EPM_TOWER *towers = talloc(ps->mem_ctx, 
				   sizeof(EPM_TOWER) * MAX_TOWERS);
	EPM_TOWER_ARRAY array;

	if (!floors || !towers) {
		DEBUG(0, ("_epm_map: talloc failed!\n"));
		return;
	}

	for (i = 0; i < q_u->tower->num_floors; i++) {
		switch (q_u->tower->floors[i].lhs.protocol) {
                case EPM_FLOOR_UUID:
			init_epm_floor_uuid(&floors[i],
					    &q_u->tower->floors[i].
					    lhs.uuid.uuid,
					    q_u->tower->floors[i].
					    lhs.uuid.version);
			break;
		case EPM_FLOOR_RPC:
			init_epm_floor_rpc(&floors[i]);
			break;
		case EPM_FLOOR_TCP:
			/* for now map all requests to port 135 */
			init_epm_floor_tcp(&floors[i], 135);
			break;
		case EPM_FLOOR_IP:
			init_epm_floor_ip(&floors[i], target_address);
			break;
		}
	}

	init_epm_tower(ps->mem_ctx, &towers[0], floors, 5);
	init_epm_tower_array(ps->mem_ctx, &array, towers, 1);
	init_epm_r_map(ps->mem_ctx, r_u, &q_u->term_handle, &array, 1, 0);

	return;

}
