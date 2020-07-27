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
#include "auth/credentials/credentials.h"
#include "cmdline_private.h"

static bool _require_smbconf;

bool samba_cmdline_init(TALLOC_CTX *mem_ctx, bool require_smbconf)
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

	creds = cli_credentials_init(mem_ctx);
	if (creds == NULL) {
		return false;
	}
	ok = samba_cmdline_set_creds(creds);
	if (!ok) {
		return false;
	}

	return true;
}
