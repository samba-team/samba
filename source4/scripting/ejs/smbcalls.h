/* 
   Unix SMB/CIFS implementation.

   provide hooks into smbd C calls from ejs scripts

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

#include "lib/appweb/ejs/ejs.h"
#include "lib/ldb/include/ldb.h"

void mpr_Return(int eid, struct MprVar);
NTSTATUS mprSetVar(struct MprVar *v, const char *name, struct MprVar val);
NTSTATUS mprGetVar(struct MprVar **v, const char *name);
void mprAddArray(struct MprVar *var, int i, struct MprVar v);
void mprSetCFunction(struct MprVar *obj, const char *name, MprCFunction fn);
void mprSetStringCFunction(struct MprVar *obj, const char *name, MprStringCFunction fn);

struct smbcalls_context {
	struct event_context *event_ctx;
	struct messaging_context *msg_ctx;
};

struct ldb_context;
struct ldb_message;
struct cli_credentials;

#include "scripting/ejs/proto.h"
