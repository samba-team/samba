/* 
   Unix SMB/CIFS implementation.

   provides interfaces to libnet calls from ejs scripts

   Copyright (C) Rafal Szczesniak  2005-2007
   
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
#include "lib/appweb/ejs/ejs.h"
#include "libnet/libnet.h"
#include "scripting/ejs/ejsnet/proto.h"
#include "scripting/ejs/smbcalls.h"
#include "events/events.h"
#include "auth/credentials/credentials.h"


static int ejs_net_domainlist(MprVarHandle eid, int argc, char **argv);


/*
  Usage:
  hostCtx = net.HostMgr(hostname = <default from credentials>)
*/
int ejs_net_hostman(MprVarHandle eid, int argc, struct MprVar** argv)
{
	struct libnet_context *ctx;
	const char *hostname;
	struct MprVar obj;

	/* libnet context */
	ctx = mprGetThisPtr(eid, "ctx");
	if (ctx == NULL) {
		ejsSetErrorMsg(eid, "ctx property returns null pointer");
		return 0;
	}

	/* fetch the arguments: host name */
	if (argc == 0) {
		/* default host (machine) name is supplied in credentials */
		hostname = cli_credentials_get_workstation(ctx->cred);

	} else if (argc == 1 && mprVarIsString(argv[0]->type)) {
		/* host name has been specified */
		hostname = mprToString(argv[0]);

	} else {
		ejsSetErrorMsg(eid, "too many arguments");
		return 0;
	}

	/* create the NetHostCtx object */
	obj = mprObject("NetHostCtx");
	
	/* create a copy of the string for the object */
	hostname = talloc_strdup(ctx, hostname);

	/* add internal libnet_context pointer to the NetHostCtx object */
	mprSetPtrChild(&obj, "ctx", ctx);
	mprSetPtrChild(&obj, "hostname", hostname);
	
	/* add methods to the object */
	mprSetStringCFunction(&obj, "DomainList", ejs_net_domainlist);

	/* set the object returned by this function */
	mpr_Return(eid, obj);

	return 0;
}


static int ejs_net_domainlist(MprVarHandle eid, int argc, char **argv)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	const char* hostname;
	struct libnet_context *ctx;
	struct libnet_DomainList req;
	struct MprVar mprDomains;

	mem_ctx = talloc_new(mprMemCtx());
	if (mem_ctx == NULL) {
		ejsSetErrorMsg(eid, "could not create memory context - out of memory");
		goto done;
	}

	/* libnet context */
	ctx = mprGetThisPtr(eid, "ctx");
	if (ctx == NULL) {
		ejsSetErrorMsg(eid, "ctx property returns null pointer");
		goto done;
	}

	hostname = mprGetThisPtr(eid, "hostname");
	if (hostname == NULL) {
		ejsSetErrorMsg(eid, "hostname property returns null pointer");
		goto done;
	}

	/* call the libnet function */
	req.in.hostname = hostname;
	
	status = libnet_DomainList(ctx, mem_ctx, &req);
	mprDomains = mprDomainsList(mem_ctx, &req, status);

done:
	talloc_free(mem_ctx);
	mpr_Return(eid, mprDomains);
	return 0;
}
