/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   
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

%module(docstring="Python bindings for miscellaneous Samba functions.",package="samba.misc") misc

%{
#include "includes.h"
#include "ldb.h"
#include "param/param.h"
#include "auth/credentials/credentials.h"
#include "dsdb/samdb/samdb.h"
#include "lib/ldb-samba/ldif_handlers.h"
#include "librpc/ndr/libndr.h"
#include "version.h"
%}

%import "stdint.i"
%include "exception.i"
%import "../../../lib/talloc/talloc.i"
%import "../../lib/ldb/ldb.i"
%import "../../auth/credentials/credentials.i"
%import "../../param/param.i"
%import "../../libcli/security/security.i"
%include "../../libcli/util/errors.i"

%feature("docstring") generate_random_str "S.random_password(len) -> string\n" \
                                          "Generate random password with specified length.";

%rename(random_password) generate_random_str;
char *generate_random_str(TALLOC_CTX *mem_ctx, size_t len);

%feature("docstring") ldb_set_credentials "S.set_credentials(credentials)\n"
                                          "Set credentials to use when connecting.";

%feature("docstring") ldb_set_session_info "S.set_session_info(session_info)\n"
                                          "Set session info to use when connecting.";

%feature("docstring") ldb_set_loadparm "S.set_loadparm(session_info)\n"
                                          "Set loadparm context to use when connecting.";

%inline %{
void ldb_set_credentials(struct ldb_context *ldb, struct cli_credentials *creds)
{
    ldb_set_opaque(ldb, "credentials", creds);
}

void ldb_set_session_info(struct ldb_context *ldb, struct auth_session_info *session_info)
{
    ldb_set_opaque(ldb, "sessionInfo", session_info);
}

void ldb_set_loadparm(struct ldb_context *ldb, struct loadparm_context *lp_ctx)
{
    ldb_set_opaque(ldb, "loadparm", lp_ctx);
}

%}

%feature("docstring") samdb_set_domain_sid "S.set_domain_sid(sid)\n"
                                          "Set SID of domain to use.";
bool samdb_set_domain_sid(struct ldb_context *ldb, 
                          const struct dom_sid *dom_sid_in);

WERROR dsdb_attach_schema_from_ldif_file(struct ldb_context *ldb, const char *pf, const char *df);

%feature("docstring") version "version()\n"
                              "Obtain the Samba version.";

%inline {
const char *version(void) 
{ 
    return SAMBA_VERSION_STRING; 
}
}
int dsdb_set_global_schema(struct ldb_context *ldb);
%feature("docstring") ldb_register_samba_handlers "register_samba_handlers()\n"
                                          "Register Samba-specific LDB modules and schemas.";
int ldb_register_samba_handlers(struct ldb_context *ldb);

%inline %{
bool dsdb_set_ntds_invocation_id(struct ldb_context *ldb, const char *guid)
{
    struct GUID invocation_id_in;
    if (NT_STATUS_IS_ERR(GUID_from_string(guid, &invocation_id_in))) {
        return false;
    }
    return samdb_set_ntds_invocation_id(ldb, &invocation_id_in);
}
%}

char *private_path(TALLOC_CTX* mem_ctx, struct loadparm_context *lp_ctx,
               const char *name);

typedef unsigned long time_t;

/*
  convert from unix time to NT time
*/
%inline %{
uint64_t unix2nttime(time_t t)
{
	NTTIME nt;
	unix_to_nt_time(&nt, t);
	return (uint64_t)nt;
}
%}
