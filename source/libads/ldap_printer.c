/* 
   Unix SMB/CIFS implementation.
   ads (active directory) printer utility library
   Copyright (C) Jim McDonough 2002
   
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

#ifdef HAVE_ADS

/*
  find a printer given the name and the hostname
    Note that results "res" may be allocated on return so that the
    results can be used.  It should be freed using ads_msgfree.
*/
ADS_STATUS ads_find_printer_on_server(ADS_STRUCT *ads, void **res,
				      char *printer, char *servername)
{
	ADS_STATUS status;
	char *srv_dn, *exp;
	const char *attrs[] = {"*", "nTSecurityDescriptor", NULL};

	status = ads_find_machine_acct(ads, res, servername);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1, ("ads_add_printer: cannot find host %s in ads\n",
			  servername));
		return status;
	}
	srv_dn = ldap_get_dn(ads->ld, *res);
	ads_msgfree(ads, *res);

	asprintf(&exp, "(printerName=%s)", printer);
	status = ads_do_search(ads, srv_dn, LDAP_SCOPE_SUBTREE, 
			       exp, &attrs, res);

	free(exp);
	return status;	
}

/*
  modify an entire printer entry in the directory
*/
ADS_STATUS ads_mod_printer_entry(ADS_STRUCT *ads, char *prt_dn,
				 const ADS_PRINTER_ENTRY *prt)
{
	void **mods;
	ADS_STATUS status;

	/* allocate the list */
	mods = ads_mod_list_start(sizeof(ADS_PRINTER_ENTRY) / sizeof(char *));

	/* add the attributes to the list - required ones first */
	ads_mod_repl(mods, "printerName", prt->printerName);
	ads_mod_repl(mods, "serverName", prt->serverName);
	ads_mod_repl(mods, "shortServerName", prt->shortServerName);
	ads_mod_repl(mods, "uNCName", prt->uNCName);
	ads_mod_repl(mods, "versionNumber", prt->versionNumber);
	/* now the optional ones - not ready yet, since it will
	   fail if the attributes don't exist already 
	ads_mod_repl_list(mods, "description", prt->description);
	ads_mod_repl(mods, "driverName", prt->driverName);
	ads_mod_repl(mods, "location", prt->location);
	ads_mod_repl_list(mods, "portName", prt->portName);
	ads_mod_repl(mods, "printStartTime", prt->printStartTime);
	ads_mod_repl(mods, "printEndTime", prt->printEndTime);
	ads_mod_repl_list(mods, "printBinNames", prt->printBinNames);

	... and many others */

	/* do the ldap modify */
	status = ads_gen_mod(ads, prt_dn, mods);

	/* free mod list, mods, and values */
	ads_mod_list_end(mods); 

	return status;
}
	

/*
  add a printer to the directory
*/
static ADS_STATUS ads_add_printer_entry(ADS_STRUCT *ads, char *prt_dn,
					const ADS_PRINTER_ENTRY *prt)
{
        ADS_STATUS status;
 
	/* These are the fields a printQueue must contain */
	status = ads_gen_add(ads, prt_dn,
			     "uNCName", prt->uNCName, NULL,
			     "versionNumber", prt->versionNumber, NULL,
			     "serverName", prt->serverName, NULL,
			     "shortServerName", prt->shortServerName, NULL,
			     "printerName", prt->printerName, NULL,
			     "objectClass", "printQueue", NULL,
			     NULL);

        return status;
}

/*
  publish a printer in the ADS
*/

ADS_STATUS ads_add_printer(ADS_STRUCT *ads, const ADS_PRINTER_ENTRY *prt)
{
	ADS_STATUS status;
	void *res;
	char *host_dn, *prt_dn;
	const char *attrs[] = {"*", "nTSecurityDescriptor", NULL};

	status = ads_find_machine_acct(ads, (void **)&res,
				       prt->shortServerName);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1, ("ads_add_printer: cannot find host %s in ads\n",
			  prt->shortServerName));
		return status;
	}
	host_dn = ldap_get_dn(ads->ld, res);
	ads_msgfree(ads, res);

	/* printer dn is cn=server-printer followed by host dn */
	asprintf(&prt_dn, "cn=%s-%s,%s", prt->shortServerName,
		 prt->printerName, host_dn);

	status = ads_search_dn(ads, &res, prt_dn, attrs);

	if (ADS_ERR_OK(status) && ads_count_replies(ads, res)) {
		DEBUG(1, ("ads_add_printer: printer %s already exists\n",
			  prt->printerName));
		/* nothing to do, just free results */
		ads_msgfree(ads, res);
	} else {
		ads_msgfree(ads, res);
		status = ads_add_printer_entry(ads, prt_dn, prt);
		if (!ADS_ERR_OK(status)) {
			DEBUG(0, ("ads_add_printer: ads_add_printer_entry failed\n"));
			return status;
		}
	}

	status = ads_mod_printer_entry(ads, prt_dn, prt);

	return status;
}

#endif
