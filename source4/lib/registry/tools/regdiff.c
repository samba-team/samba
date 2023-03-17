/*
   Unix SMB/CIFS implementation.
   simple registry frontend

   Copyright (C) Jelmer Vernooij 2004-2007
   Copyright (C) Wilco Baan Hofman 2006

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
#include "lib/registry/registry.h"
#include "lib/events/events.h"
#include "lib/cmdline/cmdline.h"
#include "lib/registry/tools/common.h"
#include "param/param.h"

enum reg_backend { REG_UNKNOWN, REG_LOCAL, REG_REMOTE, REG_NULL };

static struct registry_context *open_backend(TALLOC_CTX *mem_ctx,
					     poptContext pc,
					     struct tevent_context *ev_ctx,
					     struct loadparm_context *lp_ctx,
					     enum reg_backend backend,
					     const char *remote_host)
{
	WERROR error;
	struct registry_context *ctx;
	struct cli_credentials *creds = samba_cmdline_get_creds();

	switch (backend) {
	case REG_UNKNOWN:
		poptPrintUsage(pc, stderr, 0);
		return NULL;
	case REG_LOCAL:
		error = reg_open_samba(mem_ctx, &ctx, ev_ctx, lp_ctx, NULL,
				creds);
		break;
	case REG_REMOTE:
		error = reg_open_remote(mem_ctx, &ctx, creds, lp_ctx,
					remote_host, ev_ctx);
		break;
	case REG_NULL:
		error = reg_open_local(mem_ctx, &ctx);
		break;
	}

	if (!W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Error: %s\n", win_errstr(error));
		return NULL;
	}

	return ctx;
}

int main(int argc, char **argv)
{
	const char **argv_const = discard_const_p(const char *, argv);
	int opt;
	poptContext pc;
	char *outputfile = NULL;
	enum reg_backend backend1 = REG_UNKNOWN, backend2 = REG_UNKNOWN;
	const char *remote1 = NULL, *remote2 = NULL;
	struct registry_context *h1 = NULL, *h2 = NULL;
	WERROR error;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"output", 'o', POPT_ARG_STRING, &outputfile, 0, "output file to use", NULL },
		{"null", 'n', POPT_ARG_NONE, NULL, 'n', "Diff from NULL", NULL },
		{"remote", 'R', POPT_ARG_STRING, NULL, 'R', "Connect to remote server" , NULL },
		{"local", 'L', POPT_ARG_NONE, NULL, 'L', "Open local registry", NULL },
		POPT_COMMON_SAMBA
		POPT_COMMON_CREDENTIALS
		POPT_COMMON_VERSION
		{0}
	};
	TALLOC_CTX *ctx;
	void *callback_data;
	struct tevent_context *ev_ctx;
	struct reg_diff_callbacks *callbacks;
	struct loadparm_context *lp_ctx = NULL;
	bool ok;

	ctx = talloc_init("regdiff");
	if (ctx == NULL) {
		exit(ENOMEM);
	}

	ok = samba_cmdline_init(ctx,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(ctx);
		exit(1);
	}

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv_const,
				    long_options,
				    0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(ctx);
		exit(1);
	}

	while((opt = poptGetNextOpt(pc)) != -1) {
		error = WERR_OK;
		switch(opt)	{
		case 'L':
			if (backend1 == REG_UNKNOWN)
				backend1 = REG_LOCAL;
			else if (backend2 == REG_UNKNOWN)
				backend2 = REG_LOCAL;
			break;
		case 'n':
			if (backend1 == REG_UNKNOWN)
				backend1 = REG_NULL;
			else if (backend2 == REG_UNKNOWN)
				backend2 = REG_NULL;
			break;
		case 'R':
			if (backend1 == REG_UNKNOWN) {
				backend1 = REG_REMOTE;
				remote1 = poptGetOptArg(pc);
			} else if (backend2 == REG_UNKNOWN) {
				backend2 = REG_REMOTE;
				remote2 = poptGetOptArg(pc);
			}
			break;
		case POPT_ERROR_BADOPT:
			fprintf(stderr, "\nInvalid option %s: %s\n\n",
				poptBadOption(pc, 0), poptStrerror(opt));
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}

	}

	ev_ctx = s4_event_context_init(ctx);
	lp_ctx = samba_cmdline_get_lp_ctx();

	h1 = open_backend(ctx, pc, ev_ctx, lp_ctx, backend1, remote1);
	if (h1 == NULL)
		return 1;

	h2 = open_backend(ctx, pc, ev_ctx, lp_ctx, backend2, remote2);
	if (h2 == NULL)
		return 1;

	poptFreeContext(pc);
	samba_cmdline_burn(argc, argv);

	error = reg_dotreg_diff_save(ctx, outputfile, &callbacks, &callback_data);
	if (!W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Problem saving registry diff to '%s': %s\n",
			outputfile, win_errstr(error));
		return -1;
	}

	error = reg_generate_diff(h1, h2, callbacks, callback_data);
	if (!W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Unable to generate diff between keys: %s\n",
			win_errstr(error));
		return -1;
	}

	return 0;
}
