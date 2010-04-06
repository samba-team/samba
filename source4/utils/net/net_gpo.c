/*
   Samba Unix/Linux SMB client library
   net ads commands for Group Policy

   Copyright (C) 2005-2008 Guenther Deschner
   Copyright (C) 2009 Wilco Baan Hofman

   Based on Guenther's work in net_ads_gpo.h (samba 3)

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
#include "utils/net/net.h"
#include "libgpo/gpo.h"

static int net_gpo_list_all(struct net_context *c, int argc, const char **argv)
{
	struct gp_context *gp_ctx;
	struct gp_object **gpo;
	unsigned int i;
	NTSTATUS rv;

	rv = gp_init(c, c->lp_ctx, c->credentials, c->event_ctx, &gp_ctx);
	if (!NT_STATUS_IS_OK(rv)) {
		DEBUG(0, ("Failed to connect to DC's LDAP: %s\n", get_friendly_nt_error_msg(rv)));
		return 1;
	}

	rv = gp_list_all_gpos(gp_ctx, &gpo);
	if (!NT_STATUS_IS_OK(rv)) {
		DEBUG(0, ("Failed to list all GPO's: %s\n", get_friendly_nt_error_msg(rv)));
		return 1;
	}

	for (i = 0; gpo[i] != NULL; i++) {
		d_printf("GPO          : %s\n", gpo[i]->name);
		d_printf("display name : %s\n", gpo[i]->display_name);
		d_printf("path         : %s\n", gpo[i]->file_sys_path);
		d_printf("dn           : %s\n", gpo[i]->dn);
		d_printf("version      : %d\n", gpo[i]->version);
		d_printf("flags        : %d\n", gpo[i]->flags);
		d_printf("\n");
	}
	talloc_free(gp_ctx);

	return 0;
}

static const struct net_functable net_gpo_functable[] = {
/*	{ "apply", "Apply GPO to container\n", net_gpo_apply, net_gpo_usage }, */
//	{ "getgpo", "List specificied GPO\n", net_gpo_get_gpo, net_gpo_usage },
//	{ "linkadd", "Link a GPO to a container\n", net_gpo_link_add, net_gpo_usage },
/*	{ "linkdelete", "Delete GPO link from a container\n", net_gpo_link_delete, net_gpo_usage }, */
//	{ "linkget", "List gPLink of container\n", net_gpo_link_get, net_gpo_usage },
//	{ "list", "List all GPO's for machine/user\n", net_gpo_list, net_gpo_usage },
	{ "listall", "List all GPO's on a DC\n", net_gpo_list_all, net_gpo_usage },
//	{ "refresh", "List all GPO's for machine/user and download them\n", net_gpo_refresh, net_gpo_refresh_usage },
	{ NULL, NULL }
};


int net_gpo(struct net_context *ctx, int argc, const char **argv)
{
	return net_run_function(ctx, argc, argv, net_gpo_functable, net_gpo_usage);
}


int net_gpo_usage(struct net_context *ctx, int argc, const char **argv)
{
	d_printf("Syntax: net gpo <command> [options]\n");
	d_printf("For available commands please type net gpo help\n");
	return 0;
}
