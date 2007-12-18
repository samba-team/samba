/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Support
 *  Copyright (C) Guenther Deschner 2007
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

#include "includes.h"
#include "lib/netapi/netapi.h"

extern bool AllowDebugChange;

static bool libnetapi_initialized = false;

NET_API_STATUS libnetapi_init(struct libnetapi_ctx **context)
{
	struct libnetapi_ctx *ctx = NULL;
	TALLOC_CTX *frame = NULL;

	if (libnetapi_initialized) {
		return W_ERROR_V(WERR_OK);
	}

	frame = talloc_stackframe();

	ctx = talloc_zero(frame, struct libnetapi_ctx);
	if (!ctx) {
		TALLOC_FREE(frame);
		return W_ERROR_V(WERR_NOMEM);
	}

	DEBUGLEVEL = 0;
	DEBUGLEVEL_CLASS[DBGC_ALL] = 0;
	dbf = x_stderr;
	x_setbuf(x_stderr, NULL);
	AllowDebugChange = false;

	load_case_tables();

	setup_logging("libnetapi", true);

	if (!lp_load(get_dyn_CONFIGFILE(), true, false, false, false)) {
		TALLOC_FREE(frame);
		return W_ERROR_V(WERR_GENERAL_FAILURE);
	}

	init_names();
	load_interfaces();
	reopen_logs();

	BlockSignals(True, SIGPIPE);

	libnetapi_initialized = true;

	*context = ctx;

	return W_ERROR_V(WERR_OK);
}

NET_API_STATUS libnetapi_free(struct libnetapi_ctx *ctx)
{
	TALLOC_FREE(ctx);
	return W_ERROR_V(WERR_OK);
}
