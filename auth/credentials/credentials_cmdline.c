/*
 * Copyright (c) 2005      Jelmer Vernooij <jelmer@samba.org>
 * Copyright (c) 2016      Stefan Metzmacher <metze@samba.org>
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
#include "system/filesys.h"
#include "auth/credentials/credentials.h"

static const char *cmdline_get_userpassword(struct cli_credentials *creds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *name = NULL;
	char *label = NULL;
	char *ret = NULL;
	char pwd[256] = {0};
	int rc;

	name = cli_credentials_get_unparsed_name(creds, frame);
	if (name == NULL) {
		goto fail;
	}
	label = talloc_asprintf(frame, "Password for [%s]:", name);
	if (label == NULL) {
		goto fail;
	}
	rc = samba_getpass(label, pwd, sizeof(pwd), false, false);
	if (rc != 0) {
		goto fail;
	}
	ret = talloc_strdup(creds, pwd);
	if (ret == NULL) {
		goto fail;
	}
	talloc_set_name_const(ret, __location__);
	talloc_keep_secret(ret);
fail:
	ZERO_STRUCT(pwd);
	TALLOC_FREE(frame);
	return ret;
}

/**
 * @brief Set the command line password callback.
 *
 * This will set the callback to get the password from the command prompt or
 * read it from 'stdin'.
 *
 * @param[in]  cred   The credential context.
 *
 * @return On success true, false otherwise.
 */
bool cli_credentials_set_cmdline_callbacks(struct cli_credentials *cred)
{
	/*
	 * If there is no tty, we will try to read the password from
	 * stdin.
	 */
	return cli_credentials_set_password_callback(cred,
						     cmdline_get_userpassword);
}
