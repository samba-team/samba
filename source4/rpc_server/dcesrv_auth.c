/* 
   Unix SMB/CIFS implementation.

   server side dcerpc authentication code

   Copyright (C) Andrew Tridgell 2003
   
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


/*
  parse any auth information from a dcerpc bind request
*/
BOOL dcesrv_auth_bind(struct dcesrv_call_state *call)
{
	struct dcerpc_packet *pkt = &call->pkt;

	return True;
}

/*
  add any auth information needed in a bind ack
*/
BOOL dcesrv_auth_bind_ack(struct dcesrv_call_state *call, struct dcerpc_packet *pkt)
{
	return True;
}
