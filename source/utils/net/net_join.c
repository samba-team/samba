/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 

   Copyright (C) 2004 Stefan Metzmacher (metze@samba.org)

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

static int net_join_domain(struct net_context *ctx, int argc, const char **argv)
{
	NTSTATUS status;
	struct libnet_context *libnetctx;
	union libnet_JoinDomain r;
	char *tmp;
	const char *domain_name;

	switch (argc) {
		case 0: /* no args -> fail */
			DEBUG(0,("net_join_domain: no args\n"));
			return -1;
		case 1: /* only DOMAIN */
			tmp = talloc_strdup(ctx->mem_ctx, argv[0]);
			break;
		default: /* too mayn args -> fail */
			DEBUG(0,("net_join_domain: too many args [%d]\n",argc));
			return -1;
	}

	domain_name = tmp;

	libnetctx = libnet_context_init();
	if (!libnetctx) {
		return -1;	
	}
	libnetctx->user.account_name	= ctx->user.account_name;
	libnetctx->user.domain_name	= ctx->user.domain_name;
	libnetctx->user.password	= ctx->user.password;

	/* prepare password change */
	r.generic.level			= LIBNET_JOIN_DOMAIN_GENERIC;
	r.generic.in.domain_name	= domain_name;
	r.generic.in.account_name       = talloc_asprintf(ctx->mem_ctx, "%s$", lp_netbios_name());
	r.generic.in.acct_type          = ACB_SVRTRUST;

	/* do the domain join */
	status = libnet_JoinDomain(libnetctx, ctx->mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("net_join_domain: %s\n",r.generic.out.error_string));
		return -1;
	}

	libnet_context_destroy(&libnetctx);

	return 0;
}

static int net_join_domain_usage(struct net_context *ctx, int argc, const char **argv)
{
	d_printf("net_join_domain_usage: TODO\n");
	return 0;	
}

static int net_join_domain_help(struct net_context *ctx, int argc, const char **argv)
{
	d_printf("net_join_domain_help: TODO\n");
	return 0;	
}

static const struct net_functable net_password_functable[] = {
	{"domain", net_join_domain, net_join_domain_usage,  net_join_domain_help},
	{NULL, NULL}
};

int net_join(struct net_context *ctx, int argc, const char **argv) 
{
	
	return net_run_function(ctx, argc, argv, net_password_functable, net_password_usage);
}

int net_join_usage(struct net_context *ctx, int argc, const char **argv)
{
	d_printf("net_password_usage: TODO\n");
	return 0;	
}

int net_join_help(struct net_context *ctx, int argc, const char **argv)
{
	d_printf("net_password_help: TODO\n");
	return 0;	
}
