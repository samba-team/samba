/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Support
 *  Copyright (C) Guenther Deschner 2007-2008
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

struct libnetapi_ctx *stat_ctx = NULL;
TALLOC_CTX *frame = NULL;
static bool libnetapi_initialized = false;

NET_API_STATUS libnetapi_init(struct libnetapi_ctx **context)
{
	struct libnetapi_ctx *ctx = NULL;

	if (stat_ctx && libnetapi_initialized) {
		*context = stat_ctx;
		return W_ERROR_V(WERR_OK);
	}

	frame = talloc_stackframe();

	ctx = talloc_zero(frame, struct libnetapi_ctx);
	if (!ctx) {
		TALLOC_FREE(frame);
		return W_ERROR_V(WERR_NOMEM);
	}

	DEBUGLEVEL = 0;
	setup_logging("libnetapi", true);

	dbf = x_stderr;
	x_setbuf(x_stderr, NULL);
	AllowDebugChange = false;

	load_case_tables();

	if (!lp_load(get_dyn_CONFIGFILE(), true, false, false, false)) {
		TALLOC_FREE(frame);
		return W_ERROR_V(WERR_GENERAL_FAILURE);
	}

	AllowDebugChange = true;

	init_names();
	load_interfaces();
	reopen_logs();

	BlockSignals(True, SIGPIPE);

	libnetapi_initialized = true;

	*context = stat_ctx = ctx;

	return W_ERROR_V(WERR_OK);
}

NET_API_STATUS libnetapi_getctx(struct libnetapi_ctx **ctx)
{
	if (stat_ctx) {
		*ctx = stat_ctx;
		return W_ERROR_V(WERR_OK);
	}

	return libnetapi_init(ctx);
}

NET_API_STATUS libnetapi_free(struct libnetapi_ctx *ctx)
{
	gfree_names();
	gfree_loadparm();
	gfree_case_tables();
	gfree_charcnv();
	gfree_interfaces();

	gencache_shutdown();
	secrets_shutdown();

	TALLOC_FREE(ctx);
	TALLOC_FREE(frame);

	gfree_debugsyms();

	return W_ERROR_V(WERR_OK);
}

NET_API_STATUS libnetapi_set_debuglevel(struct libnetapi_ctx *ctx,
					const char *debuglevel)
{
	AllowDebugChange = true;
	ctx->debuglevel = debuglevel;
	if (!debug_parse_levels(debuglevel)) {
		return W_ERROR_V(WERR_GENERAL_FAILURE);
	}
	return W_ERROR_V(WERR_OK);
}

NET_API_STATUS libnetapi_get_debuglevel(struct libnetapi_ctx *ctx,
					const char **debuglevel)
{
	*debuglevel = ctx->debuglevel;
	return W_ERROR_V(WERR_OK);
}

NET_API_STATUS libnetapi_set_username(struct libnetapi_ctx *ctx,
				      const char *username)
{
	TALLOC_FREE(ctx->username);
	ctx->username = talloc_strdup(ctx, username);
	if (!ctx->username) {
		return W_ERROR_V(WERR_NOMEM);
	}
	return W_ERROR_V(WERR_OK);
}

NET_API_STATUS libnetapi_set_password(struct libnetapi_ctx *ctx,
				      const char *password)
{
	TALLOC_FREE(ctx->password);
	ctx->password = talloc_strdup(ctx, password);
	if (!ctx->password) {
		return W_ERROR_V(WERR_NOMEM);
	}
	return W_ERROR_V(WERR_OK);
}

NET_API_STATUS libnetapi_set_workgroup(struct libnetapi_ctx *ctx,
				       const char *workgroup)
{
	TALLOC_FREE(ctx->workgroup);
	ctx->workgroup = talloc_strdup(ctx, workgroup);
	if (!ctx->workgroup) {
		return W_ERROR_V(WERR_NOMEM);
	}
	return W_ERROR_V(WERR_OK);
}

const char *libnetapi_errstr(struct libnetapi_ctx *ctx,
			     NET_API_STATUS status)
{
	if (status & 0xc0000000) {
		return get_friendly_nt_error_msg(NT_STATUS(status));
	}

	return get_friendly_werror_msg(W_ERROR(status));
}
