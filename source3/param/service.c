/*
   Unix SMB/CIFS implementation.
   service (connection) opening and closing
   Copyright (C) Andrew Tridgell 1992-1998

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
#include "system/filesys.h"
#include "../lib/tsocket/tsocket.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../librpc/gen_ndr/netlogon.h"
#include "../libcli/security/security.h"
#include "printing/pcap.h"
#include "passdb/lookup_sid.h"
#include "auth.h"
#include "lib/param/loadparm.h"

static int load_registry_service(const char *servicename)
{
	if (!lp_registry_shares()) {
		return -1;
	}

	if ((servicename == NULL) || (*servicename == '\0')) {
		return -1;
	}

	if (strequal(servicename, GLOBAL_NAME)) {
		return -2;
	}

	if (!process_registry_service(servicename)) {
		return -1;
	}

	return lp_servicenumber(servicename);
}

void load_registry_shares(void)
{
	DEBUG(8, ("load_registry_shares()\n"));
	if (!lp_registry_shares()) {
		return;
	}

	process_registry_shares();

	return;
}

/****************************************************************************
 Add a home service. Returns the new service number or -1 if fail.
****************************************************************************/

int add_home_service(const char *service, const char *username, const char *homedir)
{
	int iHomeService;

	if (!service || !homedir || homedir[0] == '\0')
		return -1;

	if ((iHomeService = lp_servicenumber(HOMES_NAME)) < 0) {
		if ((iHomeService = load_registry_service(HOMES_NAME)) < 0) {
			return -1;
		}
	}

	/*
	 * If this is a winbindd provided username, remove
	 * the domain component before adding the service.
	 * Log a warning if the "path=" parameter does not
	 * include any macros.
	 */

	{
		const char *p = strchr(service,*lp_winbind_separator());

		/* We only want the 'user' part of the string */
		if (p) {
			service = p + 1;
		}
	}

	if (!lp_add_home(service, iHomeService, username, homedir)) {
		return -1;
	}

	return lp_servicenumber(service);

}

/**
 * Find a service entry.
 *
 * @param service is modified (to canonical form??)
 **/

int find_service(TALLOC_CTX *ctx, const char *service_in, char **p_service_out)
{
	int iService;

	if (!service_in) {
		return -1;
	}

	/* First make a copy. */
	*p_service_out = talloc_strdup(ctx, service_in);
	if (!*p_service_out) {
		return -1;
	}

	all_string_sub(*p_service_out,"\\","/",0);

	iService = lp_servicenumber(*p_service_out);

	/* now handle the special case of a home directory */
	if (iService < 0) {
		char *phome_dir = get_user_home_dir(ctx, *p_service_out);

		if(!phome_dir) {
			/*
			 * Try mapping the servicename, it may
			 * be a Windows to unix mapped user name.
			 */
			if(map_username(ctx, *p_service_out, p_service_out)) {
				if (*p_service_out == NULL) {
					/* Out of memory. */
					return -1;
				}
				phome_dir = get_user_home_dir(
						ctx, *p_service_out);
			}
		}

		DEBUG(3,("checking for home directory %s gave %s\n",*p_service_out,
			phome_dir?phome_dir:"(NULL)"));

		iService = add_home_service(*p_service_out,*p_service_out /* 'username' */, phome_dir);
	}

	/* If we still don't have a service, attempt to add it as a printer. */
	if (iService < 0) {
		int iPrinterService;

		if ((iPrinterService = lp_servicenumber(PRINTERS_NAME)) < 0) {
			iPrinterService = load_registry_service(PRINTERS_NAME);
		}
		if (iPrinterService >= 0) {
			DEBUG(3,("checking whether %s is a valid printer name...\n",
				*p_service_out));
			if (pcap_printername_ok(*p_service_out)) {
				DEBUG(3,("%s is a valid printer name\n",
					*p_service_out));
				DEBUG(3,("adding %s as a printer service\n",
					*p_service_out));
				lp_add_printer(*p_service_out, iPrinterService);
				iService = lp_servicenumber(*p_service_out);
				if (iService < 0) {
					DEBUG(0,("failed to add %s as a printer service!\n",
						*p_service_out));
				}
			} else {
				DEBUG(3,("%s is not a valid printer name\n",
					*p_service_out));
			}
		}
	}

	/* Check for default vfs service?  Unsure whether to implement this */
	if (iService < 0) {
	}

	if (iService < 0) {
		iService = load_registry_service(*p_service_out);
	}

	/* Is it a usershare service ? */
	if (iService < 0 && *lp_usershare_path(talloc_tos())) {
		/* Ensure the name is canonicalized. */
		if (!strlower_m(*p_service_out)) {
			goto fail;
		}
		iService = load_usershare_service(*p_service_out);
	}

	/* just possibly it's a default service? */
	if (iService < 0) {
		char *pdefservice = lp_defaultservice(talloc_tos());
		if (pdefservice &&
				*pdefservice &&
				!strequal(pdefservice, *p_service_out)
				&& !strstr_m(*p_service_out,"..")) {
			/*
			 * We need to do a local copy here as lp_defaultservice()
			 * returns one of the rotating lp_string buffers that
			 * could get overwritten by the recursive find_service() call
			 * below. Fix from Josef Hinteregger <joehtg@joehtg.co.at>.
			 */
			char *defservice = talloc_strdup(ctx, pdefservice);

			if (!defservice) {
				goto fail;
			}

			/* Disallow anything except explicit share names. */
			if (strequal(defservice,HOMES_NAME) ||
					strequal(defservice, PRINTERS_NAME) ||
					strequal(defservice, "IPC$")) {
				TALLOC_FREE(defservice);
				goto fail;
			}

			iService = find_service(ctx, defservice, p_service_out);
			if (!*p_service_out) {
				TALLOC_FREE(defservice);
				iService = -1;
				goto fail;
			}
			if (iService >= 0) {
				all_string_sub(*p_service_out, "_","/",0);
				iService = lp_add_service(*p_service_out, iService);
			}
			TALLOC_FREE(defservice);
		}
	}

	if (iService >= 0) {
		if (!VALID_SNUM(iService)) {
			DEBUG(0,("Invalid snum %d for %s\n",iService,
				*p_service_out));
			iService = -1;
		}
	}

  fail:

	if (iService < 0) {
		DEBUG(3,("find_service() failed to find service %s\n",
			*p_service_out));
	}

	return (iService);
}


struct share_params *get_share_params(TALLOC_CTX *mem_ctx,
				      const char *sharename)
{
	struct share_params *result;
	char *sname = NULL;
	int snum;

	snum = find_service(mem_ctx, sharename, &sname);
	if (snum < 0 || sname == NULL) {
		return NULL;
	}

	if (!(result = talloc(mem_ctx, struct share_params))) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	result->service = snum;
	return result;
}
