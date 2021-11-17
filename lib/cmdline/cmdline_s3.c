/*
 * Copyright (c) 2020      Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "lib/replace/replace.h"
#include <talloc.h>
#include "lib/param/param.h"
#include "lib/util/debug.h"
#include "lib/util/fault.h"
#include "source3/param/loadparm.h"
#include "dynconfig/dynconfig.h"
#include "source3/lib/interface.h"
#include "auth/credentials/credentials.h"
#include "dynconfig/dynconfig.h"
#include "cmdline_private.h"
#include "source3/include/secrets.h"

static bool _require_smbconf;
static enum samba_cmdline_config_type _config_type;

static bool _samba_cmdline_load_config_s3(void)
{
	struct loadparm_context *lp_ctx = samba_cmdline_get_lp_ctx();
	const char *config_file = NULL;
	bool ok = false;

	/* Load smb conf */
	config_file = lpcfg_configfile(lp_ctx);
	if (config_file == NULL) {
		if (is_default_dyn_CONFIGFILE()) {
			const char *env = getenv("SMB_CONF_PATH");
			if (env != NULL && strlen(env) > 0) {
				set_dyn_CONFIGFILE(env);
			}
		}
	}

	config_file = get_dyn_CONFIGFILE();

	switch (_config_type) {
	case SAMBA_CMDLINE_CONFIG_NONE:
		return true;
	case SAMBA_CMDLINE_CONFIG_CLIENT:
		ok = lp_load_client(config_file);
		break;
	case SAMBA_CMDLINE_CONFIG_SERVER:
	{
		const struct samba_cmdline_daemon_cfg *cmdline_daemon_cfg =
			samba_cmdline_get_daemon_cfg();

		if (!cmdline_daemon_cfg->interactive) {
			setup_logging(getprogname(), DEBUG_FILE);
		}

		ok = lp_load_global(config_file);
		break;
	}
	}

	if (!ok) {
		fprintf(stderr,
			"Can't load %s - run testparm to debug it\n",
			config_file);

		if (_require_smbconf) {
			return false;
		}
	}

	load_interfaces();

	return true;
}

static NTSTATUS _samba_cmd_set_machine_account_s3(
	struct cli_credentials *cred,
	struct loadparm_context *lp_ctx)
{
	struct db_context *db_ctx = secrets_db_ctx();
	NTSTATUS status;

	if (db_ctx == NULL) {
		DBG_WARNING("failed to open secrets.tdb to obtain our "
			    "trust credentials for %s\n",
			    lpcfg_workgroup(lp_ctx));;
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = cli_credentials_set_machine_account_db_ctx(
		cred, lp_ctx, db_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("cli_credentials_set_machine_account_db_ctx "
			    "failed: %s\n",
			    nt_errstr(status));
	}

	return status;
}

bool samba_cmdline_init(TALLOC_CTX *mem_ctx,
			enum samba_cmdline_config_type config_type,
			bool require_smbconf)
{
	struct loadparm_context *lp_ctx = NULL;
	struct cli_credentials *creds = NULL;
	bool ok;

	ok = samba_cmdline_init_common(mem_ctx);
	if (!ok) {
		return false;
	}

	lp_ctx = loadparm_init_s3(mem_ctx, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		return false;
	}
	ok = samba_cmdline_set_lp_ctx(lp_ctx);
	if (!ok) {
		return false;
	}

	_require_smbconf = require_smbconf;
	_config_type = config_type;

	creds = cli_credentials_init(mem_ctx);
	if (creds == NULL) {
		return false;
	}
	ok = samba_cmdline_set_creds(creds);
	if (!ok) {
		return false;
	}

	samba_cmdline_set_load_config_fn(_samba_cmdline_load_config_s3);
	samba_cmdline_set_machine_account_fn(
		_samba_cmd_set_machine_account_s3);

	return true;
}
