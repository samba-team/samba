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

#include "includes.h"
#include "lib/param/param.h"
#include "cmdline_private.h"

static TALLOC_CTX *cmdline_mem_ctx;
static struct loadparm_context *cmdline_lp_ctx;
static struct cli_credentials *cmdline_creds;

/* PRIVATE */
bool samba_cmdline_set_talloc_ctx(TALLOC_CTX *mem_ctx)
{
	if (cmdline_mem_ctx != NULL) {
		return false;
	}

	cmdline_mem_ctx = mem_ctx;
	return true;
}

TALLOC_CTX *samba_cmdline_get_talloc_ctx(void)
{
	return cmdline_mem_ctx;
}

static void _samba_cmdline_talloc_log(const char *message)
{
	DBG_ERR("%s", message);
}

bool samba_cmdline_init_common(TALLOC_CTX *mem_ctx)
{
	bool ok;

	ok = samba_cmdline_set_talloc_ctx(mem_ctx);
	if (!ok) {
		return false;
	}

	fault_setup();

	/*
	 * Log to stdout by default.
	 * This can be changed to stderr using the option: --debug-stderr
	 */
	setup_logging(getprogname(), DEBUG_DEFAULT_STDOUT);

	talloc_set_log_fn(_samba_cmdline_talloc_log);
	talloc_set_abort_fn(smb_panic);

	return true;
}

/* PUBLIC */
bool samba_cmdline_set_lp_ctx(struct loadparm_context *lp_ctx)
{
	if (lp_ctx == NULL) {
		return false;
	}
	cmdline_lp_ctx = lp_ctx;

	return true;
}

struct loadparm_context *samba_cmdline_get_lp_ctx(void)
{
	return cmdline_lp_ctx;
}

bool samba_cmdline_set_creds(struct cli_credentials *creds)
{
	if (creds == NULL) {
		return false;
	}

	TALLOC_FREE(cmdline_creds);
	cmdline_creds = creds;

	return true;
}

struct cli_credentials *samba_cmdline_get_creds(void)
{
	return cmdline_creds;
}
