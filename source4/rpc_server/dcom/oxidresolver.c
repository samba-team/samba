/* 
   Unix SMB/CIFS implementation.

   endpoint server for the IOXIDResolver pipe

   Copyright (C) Jelmer Vernooij 2004
   
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
#include "librpc/gen_ndr/ndr_oxidresolver.h"
#include "rpc_server/dcerpc_server.h"

struct OXIDObject
{
	struct GUID OID;
};

struct PingSet
{
	HYPER_T id;
	struct OXIDObject *objects;
	struct PingSet *prev, *next;
};

/* Maximum number of missed ping calls before a client is presumed 
 * gone */
#define MAX_MISSED_PINGS		3

/* Maximum number of seconds between two ping calls */
#define MAX_PING_TIME		   60

/* 
  ResolveOxid 
*/
static WERROR ResolveOxid(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct ResolveOxid *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  SimplePing 
*/
static WERROR SimplePing(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct SimplePing *r)
{
	return WERR_NOT_SUPPORTED;
}

/* 
  ComplexPing 
*/
static WERROR ComplexPing(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct ComplexPing *r)
{
	struct PingSet *ps;
	
	/* If r->in.SetId == 0, create new PingSet */
	
	/* Otherwise, look up pingset by id */
	
	return WERR_NOT_SUPPORTED;
}


/* 
  ServerAlive 
*/
static WERROR ServerAlive(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct ServerAlive *r)
{
	return WERR_OK;
}


/* 
  ResolveOxid2 
*/
static WERROR ResolveOxid2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct ResolveOxid2 *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  ServerAlive2 
*/
static WERROR ServerAlive2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct ServerAlive2 *r)
{
	return WERR_NOT_SUPPORTED;
}

/* FIXME: Regularly ping objects in use by local programs on 
 * remote servers */


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_oxidresolver_s.c"
