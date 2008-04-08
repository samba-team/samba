/*
 *  Unix SMB/CIFS implementation.
 *  libsmbconf - Samba configuration library: testsuite
 *  Copyright (C) Michael Adam 2008
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


static bool torture_smbconf_txt(void)
{
	WERROR werr;
	bool ret = true;
	struct smbconf_ctx *conf_ctx = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	printf("test: text backend\n");

	printf("test: init\n");
	werr = smbconf_init_txt_simple(mem_ctx, &conf_ctx, NULL, true);
	if (!W_ERROR_IS_OK(werr)) {
		printf("failure: init failed: %s\n", dos_errstr(werr));
		ret = false;
		goto done;
	}
	printf("success: init\n");

	smbconf_shutdown(conf_ctx);

	ret = true;

	printf("success: text backend\n");

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static bool torture_smbconf_reg(void)
{
	WERROR werr;
	bool ret = true;
	struct smbconf_ctx *conf_ctx = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	printf("test: registry backend\n");

	printf("test: init\n");
	werr = smbconf_init_reg(mem_ctx, &conf_ctx, NULL);
	if (!W_ERROR_IS_OK(werr)) {
		printf("failure: init failed: %s\n", dos_errstr(werr));
		ret = false;
		goto done;
	}
	printf("success: init\n");

	smbconf_shutdown(conf_ctx);

	ret = true;

	printf("success: registry backend\n");

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static bool torture_smbconf(void)
{
	bool ret = true;
	ret &= torture_smbconf_txt();
	printf("\n");
	ret &= torture_smbconf_reg();
	return ret;
}

int main(int argc, const char **argv)
{
	bool ret;
	poptContext pc;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	struct poptOption long_options[] = {
		POPT_COMMON_CONFIGFILE
		{0, 0, 0, 0}
	};

	load_case_tables();

	/* parse options */
	pc = poptGetContext("smbconftort", argc, (const char **)argv,
			    long_options, 0);

	while(poptGetNextOpt(pc) != -1) { }

	poptFreeContext(pc);

	ret = lp_load(get_dyn_CONFIGFILE(),
		      true,  /* globals_only */
		      false, /* save_defaults */
		      false, /* add_ipc */
		      true   /* initialize globals */);

	if (!ret) {
		printf("failure: error loading the configuration\n");
		goto done;
	}

	ret = torture_smbconf();

done:
	TALLOC_FREE(mem_ctx);
	return ret ? 0 : -1;
}
