/*
   Unix SMB/CIFS implementation.

   Winbind daemon - miscellaneous other functions

   Copyright (C) Tim Potter      2000
   Copyright (C) Andrew Bartlett 2002

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
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND


static const struct winbindd_child_dispatch_table locator_dispatch_table[];

static struct winbindd_child static_locator_child;

void init_locator_child(void)
{
	setup_child(&static_locator_child,
		    locator_dispatch_table,
		    "log.winbindd", "locator");
}

struct winbindd_child *locator_child(void)
{
	return &static_locator_child;
}

void winbindd_dsgetdcname(struct winbindd_cli_state *state)
{
	state->request.domain_name
		[sizeof(state->request.domain_name)-1] = '\0';

	DEBUG(3, ("[%5lu]: dsgetdcname for %s\n", (unsigned long)state->pid,
		  state->request.domain_name));

	sendto_child(state, locator_child());
}

static enum winbindd_result dual_dsgetdcname(struct winbindd_domain *domain,
					     struct winbindd_cli_state *state)
{
	NTSTATUS result;
	struct netr_DsRGetDCNameInfo *info = NULL;
	const char *dc = NULL;

	state->request.domain_name
		[sizeof(state->request.domain_name)-1] = '\0';

	DEBUG(3, ("[%5lu]: dsgetdcname for %s\n", (unsigned long)state->pid,
		  state->request.domain_name));

	result = dsgetdcname(state->mem_ctx, winbind_messaging_context(),
			     state->request.domain_name,
			     NULL, NULL, state->request.flags, &info);

	if (!NT_STATUS_IS_OK(result)) {
		return WINBINDD_ERROR;
	}

	if (info->dc_address) {
		dc = strip_hostname(info->dc_address);
	}

	if ((!dc || !is_ipaddress_v4(dc)) && info->dc_unc) {
		dc = strip_hostname(info->dc_unc);
	}

	if (!dc || !*dc) {
		return WINBINDD_ERROR;
	}

	fstrcpy(state->response.data.dc_name, dc);

	return WINBINDD_OK;
}

static const struct winbindd_child_dispatch_table locator_dispatch_table[] = {
	{
		.name		= "DSGETDCNAME",
		.struct_cmd	= WINBINDD_DSGETDCNAME,
		.struct_fn	= dual_dsgetdcname,
	},{
		.name		= NULL,
	}
};
