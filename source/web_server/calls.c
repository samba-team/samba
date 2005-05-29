/* 
   Unix SMB/CIFS implementation.

   provide hooks into C calls from esp scripts

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "pwd.h"
#include "web_server/esp/esp.h"
#include "param/loadparm.h"
#include "lib/ldb/include/ldb.h"


/* try to authenticate the user/password pair against system auth mechanisms
   returns 0 on success
   returns -1 on error

   fills in the session structure properly in case of success
   NOTE: Currently only PAM Auth is supported
*/

static int esp_unixAuth(struct EspRequest *ep, int argc, struct MprVar **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ep);
	const char *username;
	const char *password;
	struct passwd *pwd;
	int ret;

	if (argc != 2 || argv[0]->type != MPR_TYPE_STRING ||
			argv[1]->type != MPR_TYPE_STRING) {
		espError(ep, "unixAuth invalid arguments");
		ret = -1;
		goto done;
	}

	username = mprToString(argv[0]);
	password = mprToString(argv[1]);

	if (username == NULL || password == NULL) {
		espError(ep, "unixAuth invalid arguments");
		ret = -1;
		goto done;
	}

	/* TODO: find out how to pass the real client name/address here */
	if (NT_STATUS_IS_OK(unix_passcheck(tmp_ctx, "client", username, password))) {

		pwd = getpwnam(username);
		if (!pwd) {
			espSetReturn(ep, mprCreateIntegerVar(-1));
			ret = -1;
			goto done;
		}

		mprSetPropertyValue(&ep->variables[ESP_SESSION_OBJ],
					"AUTHENTICATED", mprCreateStringVar("1", 0));
		mprSetPropertyValue(&ep->variables[ESP_SESSION_OBJ],
					"USERNAME", mprCreateStringVar(username, 0));

		if (pwd->pw_uid == 0) { /* we are root */

			mprSetPropertyValue(&ep->variables[ESP_SESSION_OBJ],
					"PRIVILEGE", mprCreateStringVar("ADMIN", 0));
		} else {
			mprSetPropertyValue(&ep->variables[ESP_SESSION_OBJ],
					"PRIVILEGE", mprCreateStringVar("USER", 0));
		}

		espSetReturn(ep, mprCreateIntegerVar(0));
	} else {
		if (mprGetProperty(&ep->variables[ESP_SESSION_OBJ], "AUTHENTICATED", 0) != 0) {
			mprDeleteProperty(&ep->variables[ESP_SESSION_OBJ], "AUTHENTICATED");
		}
		espSetReturn(ep, mprCreateIntegerVar(-1));
	}

done:
	talloc_free(tmp_ctx);
	return ret;
}

/*
  setup the C functions that be called from ejs
*/
void http_setup_ejs_functions(void)
{
	espDefineCFunction(NULL, "unixAuth", esp_unixAuth, NULL);
}
