/* 
   Unix SMB/CIFS implementation.

   general name resolution interface

   Copyright (C) Andrew Tridgell 2005
   
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

#ifndef __RESOLVE_H__
#define __RESOLVE_H__

#include "../libcli/nbt/libnbt.h"
typedef struct composite_context *(*resolve_name_send_fn)(TALLOC_CTX *mem_ctx, struct event_context *, void *privdata, struct nbt_name *);
typedef NTSTATUS (*resolve_name_recv_fn)(struct composite_context *, TALLOC_CTX *, const char **);
#include "libcli/resolve/proto.h"
struct interface;
#include "libcli/resolve/lp_proto.h"

#endif /* __RESOLVE_H__ */
