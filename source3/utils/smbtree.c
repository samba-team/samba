/* 
   Unix SMB/CIFS implementation.
   Network neighbourhood browser.
   
   Copyright (C) Tim Potter      2000
   Copyright (C) Jelmer Vernooij 2003
   
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
#include "popt_common_cmdline.h"
#include "rpc_client/cli_pipe.h"
#include "../librpc/gen_ndr/ndr_srvsvc_c.h"
#include "libsmb/libsmb.h"
#include "libsmb/namequery.h"
#include "libsmb/clirap.h"
#include "../libcli/smb/smbXcli_base.h"
#include "nameserv.h"
#include "libsmbclient.h"

/* How low can we go? */

enum tree_level {LEV_WORKGROUP, LEV_SERVER, LEV_SHARE};
static enum tree_level level = LEV_SHARE;

static void get_auth_data_with_context_fn(
	SMBCCTX *context,
	const char *server,
	const char *share,
	char *domain,
	int domain_len,
	char *user,
	int user_len,
	char *password,
	int password_len)
{
	struct user_auth_info *auth = popt_get_cmdline_auth_info();
	size_t len;

	if (auth == NULL) {
		return;
	}

	len = strlcpy(domain, get_cmdline_auth_info_domain(auth), domain_len);
	if ((int)len >= domain_len) {
		return;
	}
	len = strlcpy(
		user, get_cmdline_auth_info_username(auth), user_len);
	if ((int)len >= user_len) {
		return;
	}
	len = strlcpy(
		password, get_cmdline_auth_info_password(auth), password_len);
	if ((int)len >= password_len) {
		/* pointless, but what can you do... */
		return;
	}
}

/****************************************************************************
  main program
****************************************************************************/
int main(int argc, char *argv[])
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char **argv_const = discard_const_p(const char *, argv);
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "domains",
			.shortName  = 'D',
			.argInfo    = POPT_ARG_VAL,
			.arg        = &level,
			.val        = LEV_WORKGROUP,
			.descrip    = "List only domains (workgroups) of tree" ,
		},
		{
			.longName   = "servers",
			.shortName  = 'S',
			.argInfo    = POPT_ARG_VAL,
			.arg        = &level,
			.val        = LEV_SERVER,
			.descrip    = "List domains(workgroups) and servers of tree" ,
		},
		POPT_COMMON_SAMBA
		POPT_COMMON_CREDENTIALS
		POPT_TABLEEND
	};
	poptContext pc;
	SMBCCTX *ctx = NULL;
	SMBCFILE *workgroups = NULL;
	struct smbc_dirent *dirent = NULL;
	bool ok;
	int ret, result = 1;
	int debuglevel;

	/* Initialise samba stuff */
	smb_init_locale();

	setlinebuf(stdout);

	setup_logging(argv[0], DEBUG_STDERR);

	popt_common_credentials_set_ignore_missing_conf();

	pc = poptGetContext("smbtree", argc, argv_const, long_options,
			    POPT_CONTEXT_KEEP_FIRST);
	while(poptGetNextOpt(pc) != -1);
	popt_burn_cmdline_password(argc, argv);

	debuglevel = DEBUGLEVEL;

	ctx = smbc_new_context();
	if (ctx == NULL) {
		perror("smbc_new_context");
		goto fail;
	}
	ret = smbc_setConfiguration(ctx, get_dyn_CONFIGFILE());
	if (ret == -1) {
		perror("smbc_setConfiguration");
		goto fail;
	}
	smbc_setDebug(ctx, debuglevel);
	ok = smbc_setOptionProtocols(ctx, NULL, "NT1");
	if (!ok) {
		perror("smbc_setOptionProtocols");
		goto fail;
	}
	smbc_setFunctionAuthDataWithContext(
		ctx, get_auth_data_with_context_fn);

	ok = smbc_init_context(ctx);
	if (!ok) {
		perror("smbc_init_context");
		goto fail;
	}

	workgroups = smbc_getFunctionOpendir(ctx)(ctx, "smb://");
	if (workgroups == NULL) {
		perror("smbc_opendir");
		goto fail;
	}

	while ((dirent = smbc_getFunctionReaddir(ctx)(ctx, workgroups))
	       != NULL) {
		char *url = NULL;
		SMBCFILE *servers = NULL;

		if (dirent->smbc_type != SMBC_WORKGROUP) {
			continue;
		}

		printf("%s\n", dirent->name);

		if (level == LEV_WORKGROUP) {
			continue;
		}

		url = talloc_asprintf(
			talloc_tos(), "smb://%s/", dirent->name);
		if (url == NULL) {
			perror("talloc_asprintf");
			goto fail;
		}

		servers = smbc_getFunctionOpendir(ctx)(ctx, url);
		if (servers == NULL) {
			perror("smbc_opendir");
			goto fail;
		}
		TALLOC_FREE(url);

		while ((dirent = smbc_getFunctionReaddir(ctx)(ctx, servers))
		       != NULL) {
			SMBCFILE *shares = NULL;
			char *servername = NULL;

			if (dirent->smbc_type != SMBC_SERVER) {
				continue;
			}

			printf("\t\\\\%-15s\t\t%s\n",
			       dirent->name,
			       dirent->comment);

			if (level == LEV_SERVER) {
				continue;
			}

			/*
			 * The subsequent readdir for shares will
			 * overwrite the "server" readdir
			 */
			servername = talloc_strdup(talloc_tos(), dirent->name);
			if (servername == NULL) {
				continue;
			}

			url = talloc_asprintf(
				talloc_tos(), "smb://%s/", servername);
			if (url == NULL) {
				perror("talloc_asprintf");
				goto fail;
			}

			shares = smbc_getFunctionOpendir(ctx)(ctx, url);
			if (shares == NULL) {
				perror("smbc_opendir");
				goto fail;
			}

			while ((dirent = smbc_getFunctionReaddir(
					ctx)(ctx, shares))
			       != NULL) {
				printf("\t\t\\\\%s\\%-15s\t%s\n",
				       servername,
				       dirent->name,
				       dirent->comment);
			}

			ret = smbc_getFunctionClosedir(ctx)(ctx, shares);
			if (ret == -1) {
				perror("smbc_closedir");
				goto fail;
			}

			TALLOC_FREE(servername);
			TALLOC_FREE(url);
		}

		ret = smbc_getFunctionClosedir(ctx)(ctx, servers);
		if (ret == -1) {
			perror("smbc_closedir");
			goto fail;
		}
	}

	ret = smbc_getFunctionClosedir(ctx)(ctx, workgroups);
	if (ret == -1) {
		perror("smbc_closedir");
		goto fail;
	}

	popt_free_cmdline_auth_info();

	result = 0;
fail:
	if (ctx != NULL) {
		smbc_free_context(ctx, 0);
		ctx = NULL;
	}
	poptFreeContext(pc);
	TALLOC_FREE(frame);
	return result;
}
