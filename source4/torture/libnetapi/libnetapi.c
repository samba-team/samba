/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Guenther Deschner 2009

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

#include "source3/include/includes.h"
#include "torture/smbtorture.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/popt_common.h"
#include "source3/lib/netapi/netapi.h"
#include "source3/lib/netapi/netapi_private.h"
#include "lib/param/param.h"
#include "torture/libnetapi/proto.h"

bool torture_libnetapi_init_context(struct torture_context *tctx,
				    struct libnetapi_ctx **ctx_p)
{
	NET_API_STATUS status;
	struct libnetapi_ctx *ctx;
	TALLOC_CTX *frame = talloc_stackframe();

	if (!lp_load_global(lpcfg_configfile(tctx->lp_ctx))) {
		fprintf(stderr, "error loading %s\n", lpcfg_configfile(tctx->lp_ctx));
		talloc_free(frame);
		return W_ERROR_V(WERR_GEN_FAILURE);
	}

	init_names();
	load_interfaces();

	status = libnetapi_net_init(&ctx);
	if (status != 0) {
		talloc_free(frame);
		return false;
	}

	libnetapi_set_username(ctx,
		cli_credentials_get_username(popt_get_cmdline_credentials()));
	libnetapi_set_password(ctx,
		cli_credentials_get_password(popt_get_cmdline_credentials()));

	*ctx_p = ctx;

	talloc_free(frame);
	return true;
}

static bool torture_libnetapi_initialize(struct torture_context *tctx)
{
        NET_API_STATUS status;
	struct libnetapi_ctx *ctx;

	/* We must do this first, as otherwise we fail if we don't
	 * have an smb.conf in the default path (we need to use the
	 * torture smb.conf */
	torture_assert(tctx, torture_libnetapi_init_context(tctx, &ctx),
		       "failed to initialize libnetapi");

	status = libnetapi_init(&ctx);

	torture_assert(tctx, ctx != NULL, "Failed to get a libnetapi_ctx");
	torture_assert_int_equal(tctx, status, 0, "libnetapi_init failed despite alredy being set up");

	libnetapi_free(ctx);

	return true;
}

NTSTATUS torture_libnetapi_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite;

	suite = torture_suite_create(ctx, "netapi");

	torture_suite_add_simple_test(suite, "server", torture_libnetapi_server);
	torture_suite_add_simple_test(suite, "group", torture_libnetapi_group);
	torture_suite_add_simple_test(suite, "user", torture_libnetapi_user);
	torture_suite_add_simple_test(suite, "initialize", torture_libnetapi_initialize);

	suite->description = talloc_strdup(suite, "libnetapi convenience interface tests");

	torture_register_suite(ctx, suite);

	return NT_STATUS_OK;
}
