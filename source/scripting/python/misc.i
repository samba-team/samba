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

%module(package="samba.misc") misc

%{
#include "includes.h"
#include "ldb.h"
#include "param/param.h"
#include "auth/credentials/credentials.h"
#include "dsdb/samdb/samdb.h"
#include "lib/ldb-samba/ldif_handlers.h"
#include "librpc/ndr/libndr.h"
%}

%import "stdint.i"
%include "exception.i"
%import "../../lib/talloc/talloc.i"
%import "../../lib/ldb/ldb.i"
%import "../../auth/credentials/credentials.i"
%import "../../param/param.i"
%import "../../libcli/security/security.i"
%import "../../libcli/util/errors.i"

%rename(random_password) generate_random_str;
char *generate_random_str(TALLOC_CTX *mem_ctx, size_t len);

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

bool samdb_set_domain_sid(struct ldb_context *ldb, 
                          const struct dom_sid *dom_sid_in);

WERROR dsdb_attach_schema_from_ldif_file(struct ldb_context *ldb, const char *pf, const char *df);

%rename(version) samba_version_string;
const char *samba_version_string(void);
int dsdb_set_global_schema(struct ldb_context *ldb);
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
