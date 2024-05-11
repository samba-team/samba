/* 
   samba -- Unix SMB/CIFS implementation.

   Client credentials structure

   Copyright (C) Jelmer Vernooij 2004-2006
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

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

#ifndef __CREDENTIALS_KRB5_H__
#define __CREDENTIALS_KRB5_H__

#include "system/gssapi.h"
#include "system/kerberos.h"

struct gssapi_creds_container {
	gss_cred_id_t creds;
};

/* Manually prototyped here to avoid needing gss headers in most callers */
int cli_credentials_set_client_gss_creds(struct cli_credentials *cred, 
					 struct loadparm_context *lp_ctx,
					 gss_cred_id_t gssapi_cred,
					 enum credentials_obtained obtained,
					 const char **error_string);

struct cli_credentials *cli_credentials_shallow_copy(TALLOC_CTX *mem_ctx,
						struct cli_credentials *src);

int cli_credentials_get_kerberos_key(struct cli_credentials *cred,
				     TALLOC_CTX *mem_ctx,
				     struct loadparm_context *lp_ctx,
				     krb5_enctype enctype,
				     bool previous,
				     DATA_BLOB *key_blob);


#endif /* __CREDENTIALS_KRB5_H__ */
