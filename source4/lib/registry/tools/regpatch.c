/*
   Unix SMB/CIFS implementation.
   simple registry frontend

   Copyright (C) 2004-2007 Jelmer Vernooij, jelmer@samba.org

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
#include "lib/events/events.h"
#include "lib/registry/registry.h"
#include "lib/cmdline/cmdline.h"
#include "lib/registry/tools/common.h"
#include "param/param.h"
#include "events/events.h"

int main(int argc, char **argv)
{
	const char **argv_const = discard_const_p(const char *, argv);
	bool ok;
	TALLOC_CTX *mem_ctx = NULL;
  	int opt;
	poptContext pc;
	const char *patch;
	struct registry_context *h;
	const char *file = NULL;
	const char *remote = NULL;
	struct tevent_context *ev_ctx;
	struct loadparm_context *lp_ctx = NULL;
	struct cli_credentials *creds = NULL;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"remote", 'R', POPT_ARG_STRING, &remote, 0, "connect to specified remote server", NULL},
		{"file", 'F', POPT_ARG_STRING, &file, 0, "file path", NULL },
		POPT_COMMON_SAMBA
		POPT_COMMON_CREDENTIALS
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};

	mem_ctx = talloc_init("regtree.c/main");
	if (mem_ctx == NULL) {
		exit(ENOMEM);
	}

	ok = samba_cmdline_init(mem_ctx,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(mem_ctx);
		exit(1);
	}

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv_const,
				    long_options,
				    0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(mem_ctx);
		exit(1);
	}

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case POPT_ERROR_BADOPT:
			fprintf(stderr, "\nInvalid option %s: %s\n\n",
				poptBadOption(pc, 0), poptStrerror(opt));
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}
	}

	ev_ctx = s4_event_context_init(NULL);
	lp_ctx = samba_cmdline_get_lp_ctx();
	creds = samba_cmdline_get_creds();

	if (remote) {
		h = reg_common_open_remote (remote, ev_ctx, lp_ctx, creds);
	} else {
		h = reg_common_open_local (creds, ev_ctx, lp_ctx);
	}

	if (h == NULL) {
		TALLOC_FREE(mem_ctx);
		return 1;
	}

	patch = talloc_strdup(mem_ctx, poptGetArg(pc));
	if (patch == NULL) {
		poptPrintUsage(pc, stderr, 0);
		TALLOC_FREE(mem_ctx);
		return 1;
	}

	poptFreeContext(pc);
	samba_cmdline_burn(argc, argv);

	reg_diff_apply(h, patch);

	TALLOC_FREE(mem_ctx);

	return 0;
}
