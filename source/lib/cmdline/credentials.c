/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Jelmer Vernooij 2005

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
#include "version.h"
#include "system/filesys.h"
#include "system/passwd.h"
#include "lib/cmdline/popt_common.h"

static const char *cmdline_get_userpassword(struct cli_credentials *credentials)
{
	char *prompt;
	char *ret;
	const char *domain;
	const char *username;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	const char *bind_dn = cli_credentials_get_bind_dn(credentials);
	
	if (bind_dn) {
		prompt = talloc_asprintf(mem_ctx, "Password for [%s]:", 
					 bind_dn);
	} else {
		cli_credentials_get_ntlm_username_domain(credentials, mem_ctx, &username, &domain);
		if (domain && domain[0]) {
			prompt = talloc_asprintf(mem_ctx, "Password for [%s\\%s]:", 
						 domain, username);
		} else {
			prompt = talloc_asprintf(mem_ctx, "Password for [%s]:", 
						 username);
		}
	}

	ret = getpass(prompt);

	talloc_free(mem_ctx);
	return ret;
}

void cli_credentials_set_cmdline_callbacks(struct cli_credentials *cred)
{
	cli_credentials_set_password_callback(cred, cmdline_get_userpassword);
}
