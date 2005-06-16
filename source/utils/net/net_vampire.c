/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 

   Copyright (C) 2004 Stefan Metzmacher <metze@samba.org>
   Copyright (C) 2005 Andrew Bartlett <abartlet@samba.org>

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
#include "utils/net/net.h"
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_samr.h"

int net_samdump(struct net_context *ctx, int argc, const char **argv) 
{
	NTSTATUS status;
	struct libnet_context *libnetctx;
	union libnet_SamDump r;

	libnetctx = libnet_context_init(NULL);
	if (!libnetctx) {
		return -1;	
	}
	libnetctx->cred = ctx->credentials;

	/* prepare password change */
	r.generic.level	       = LIBNET_SAMDUMP_GENERIC;
	r.generic.error_string = NULL;

	/* do the domain join */
	status = libnet_SamDump(libnetctx, ctx->mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("libnet_SamDump returned %s: %s\n",
			 nt_errstr(status),
			 r.generic.error_string));
		return -1;
	}

	talloc_free(libnetctx);

	return 0;
}

int net_samdump_usage(struct net_context *ctx, int argc, const char **argv)
{
	d_printf("net samdump\n");
	return 0;	
}

int net_samdump_help(struct net_context *ctx, int argc, const char **argv)
{
	d_printf("Dumps the sam of the domain we are joined to.\n");
	return 0;	
}
