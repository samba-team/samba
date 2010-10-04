/*
   Unix SMB/CIFS implementation.

   Endpoint server for the epmapper pipe

   Copyright (C) 2010      Andreas Schneider <asn@samba.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "librpc/gen_ndr/srv_epmapper.h"

typedef uint32_t error_status_t;

/*
  epm_Insert
*/
error_status_t _epm_Insert(struct pipes_struct *p,
			   struct epm_Insert *r)
{
	/* Check if we have a priviledged pipe/handle */

	/* Check if the entry already exits */

	/* Replace the entry if flag is set */

	/* Create new entry */

	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
  epm_Delete
*/
error_status_t _epm_Delete(struct pipes_struct *p,
		   struct epm_Delete *r)
{
	/* Check if we have a priviledged pipe/handle */

	/* Delete the entry */

	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
  epm_Lookup
*/
error_status_t _epm_Lookup(struct pipes_struct *p,
		   struct epm_Lookup *r)
{
	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
 * Apply some algorithm (using the fields in the map_tower) to an endpoint map
 * to produce a list of protocol towers.
 */
error_status_t _epm_Map(struct pipes_struct *p,
			struct epm_Map *r)
{
	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}

/*
  epm_LookupHandleFree
*/
error_status_t _epm_LookupHandleFree(struct pipes_struct *p,
			     struct epm_LookupHandleFree *r)
{
	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
  epm_InqObject
*/
error_status_t _epm_InqObject(struct pipes_struct *p,
		      struct epm_InqObject *r)
{
	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
  epm_MgmtDelete
*/
error_status_t _epm_MgmtDelete(struct pipes_struct *p,
		       struct epm_MgmtDelete *r)
{
	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
  epm_MapAuth
*/
error_status_t _epm_MapAuth(struct pipes_struct *p,
		    struct epm_MapAuth *r)
{
	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
