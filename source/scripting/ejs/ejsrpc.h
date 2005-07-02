/* 
   Unix SMB/CIFS implementation.

   ejs <-> rpc interface definitions

   Copyright (C) Andrew Tridgell 2005
   
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

struct ejs_rpc {

};

typedef NTSTATUS (*ejs_pull_function_t)(struct ejs_rpc *, struct MprVar *, void *);
typedef NTSTATUS (*ejs_push_function_t)(struct ejs_rpc *, struct MprVar *, const void *);


NTSTATUS ejs_pull_rpc(struct MprVar *v, void *ptr, ejs_pull_function_t ejs_pull);
NTSTATUS ejs_push_rpc(struct MprVar *v, const void *ptr, ejs_push_function_t ejs_push);
NTSTATUS ejs_pull_uint32(struct ejs_rpc *ejs, 
			 struct MprVar *v, const char *name, uint32_t *r);
NTSTATUS ejs_push_uint32(struct ejs_rpc *ejs, 
			 struct MprVar *v, const char *name, uint32_t r);


/* echo calls */

#include "librpc/gen_ndr/ndr_echo.h"

NTSTATUS ejs_pull_echo_AddOne(struct ejs_rpc *ejs, 
			      struct MprVar *v, struct echo_AddOne *r);
NTSTATUS ejs_push_echo_AddOne(struct ejs_rpc *ejs, 
			      struct MprVar *v, 
			      const struct echo_AddOne *r);

