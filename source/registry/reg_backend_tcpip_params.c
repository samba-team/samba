/*
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter     2002-2005
 *  Copyright (C) Michael Adam      2008
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * TCP/IP parameters registry backend.
 *
 * This replaces the former dynamic tcpip parameters overlay.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

extern REGISTRY_OPS regdb_ops;

static int tcpip_params_fetch_values(const char *key, REGVAL_CTR *regvals)
{
	fstring value;
	int value_length;
	char *hname;
	char *mydomainname = NULL;

	hname = myhostname();
	value_length = push_ucs2(value, value, hname, sizeof(value),
				 STR_TERMINATE|STR_NOALIGN);
	regval_ctr_addvalue(regvals, "Hostname",REG_SZ, value, value_length);

	mydomainname = get_mydnsdomname(talloc_tos());
	if (!mydomainname) {
		return -1;
	}

	value_length = push_ucs2(value, value, mydomainname, sizeof(value),
				 STR_TERMINATE|STR_NOALIGN);
	regval_ctr_addvalue(regvals, "Domain", REG_SZ, value, value_length);

	return regval_ctr_numvals(regvals);
}

static int tcpip_params_fetch_subkeys(const char *key,
				      struct regsubkey_ctr *subkey_ctr)
{
	return regdb_ops.fetch_subkeys(key, subkey_ctr);
}

REGISTRY_OPS tcpip_params_reg_ops = {
	.fetch_values = tcpip_params_fetch_values,
	.fetch_subkeys = tcpip_params_fetch_subkeys,
};
