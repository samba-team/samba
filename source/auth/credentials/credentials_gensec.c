/* 
   Unix SMB/CIFS implementation.

   User credentials handling

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   
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
#include "auth/gensec/gensec.h"

const struct gensec_security_ops **cli_credentials_gensec_list(struct cli_credentials *creds) 
{
	if (!creds || !creds->gensec_list) {
		return gensec_security_all();
	}
	return creds->gensec_list;
}

static NTSTATUS cli_credentials_gensec_remove_mech(struct cli_credentials *creds,
						   const struct gensec_security_ops *remove_mech) 
{
	const struct gensec_security_ops **gensec_list;
	const struct gensec_security_ops **new_gensec_list;
	int i, j;

	gensec_list = cli_credentials_gensec_list(creds);

	for (i=0; gensec_list && gensec_list[i]; i++) {
		/* noop */
	}

	new_gensec_list = talloc_array(creds, const struct gensec_security_ops *, i + 1);
	if (!new_gensec_list) {
		return NT_STATUS_NO_MEMORY;
	}

	j = 0;
	for (i=0; gensec_list && gensec_list[i]; i++) {
		if (gensec_list[i] != remove_mech) {
			new_gensec_list[j] = gensec_list[i];
			j++;
		}
	}
	new_gensec_list[j] = NULL; 
	
	creds->gensec_list = new_gensec_list;

	return NT_STATUS_OK;
}

NTSTATUS cli_credentials_gensec_remove_oid(struct cli_credentials *creds,
					   const char *oid) 
{
	const struct gensec_security_ops *gensec_by_oid;

	gensec_by_oid = gensec_security_by_oid(NULL, oid);
	if (!gensec_by_oid) {
		return NT_STATUS_OK;
	}

	return cli_credentials_gensec_remove_mech(creds, gensec_by_oid);
}
