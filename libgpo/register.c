/*
   Unix SMB/CIFS implementation.
   Copyright (C) David Mulder <dmulder@suse.com> 2018

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
#include "version.h"
#include "gpo.h"
#include "ads.h"
#include "secrets.h"
#include "../libds/common/flags.h"
#include "libgpo/gpo_proto.h"
#include "registry.h"
#include "registry/reg_api.h"
#include "../libcli/registry/util_reg.h"
#include "../libgpo/gpext/gpext.h"
#include "registry/reg_objects.h"
#include "libgpo/register.h"

static void get_gp_registry_context(TALLOC_CTX *ctx,
				    uint32_t desired_access,
				    struct gp_registry_context **reg_ctx,
				    const char *smb_conf)
{
	struct security_token *token;
	WERROR werr;

	lp_load_initial_only(smb_conf ? smb_conf : get_dyn_CONFIGFILE());

	token = registry_create_system_token(ctx);
	if (!token) {
		return;
	}
	werr = gp_init_reg_ctx(ctx, KEY_WINLOGON_GPEXT_PATH, desired_access,
			       token, reg_ctx);
	if (!W_ERROR_IS_OK(werr)) {
		return;
	}
}

int register_gp_extension(const char *guid_name,
			  const char *gp_ext_cls,
			  const char *module_path,
			  const char *smb_conf,
			  int machine,
			  int user)
{
	TALLOC_CTX *frame = talloc_stackframe();
	WERROR werr;
	struct gp_registry_context *reg_ctx = NULL;
	struct registry_key *key = NULL;
	int ret = 0;

	get_gp_registry_context(frame, REG_KEY_WRITE, &reg_ctx, smb_conf);
	if (!reg_ctx) {
		goto out;
	}

	werr = gp_store_reg_subkey(frame, guid_name,
				   reg_ctx->curr_key, &key);
	if (!W_ERROR_IS_OK(werr)) {
		goto out;
	}
	werr = gp_store_reg_val_sz(frame, key, "DllName", module_path);
	if (!W_ERROR_IS_OK(werr)) {
		goto out;
	}
	werr = gp_store_reg_val_sz(frame, key, "ProcessGroupPolicy",
				   gp_ext_cls);
	if (!W_ERROR_IS_OK(werr)) {
		goto out;
	}
	werr = gp_store_reg_val_dword(frame, key, "NoMachinePolicy", !machine);
	if (!W_ERROR_IS_OK(werr)) {
		goto out;
	}
	werr = gp_store_reg_val_dword(frame, key, "NoUserPolicy", !user);
	if (!W_ERROR_IS_OK(werr)) {
		goto out;
	}

	ret = 1;
out:
	TALLOC_FREE(frame);
	return ret;
}
