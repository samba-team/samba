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
				      const char *printer, const char *servername)
{
	ADS_STATUS status;
	char *srv_dn, **srv_cn, *exp;
	const char *attrs[] = {"*", "nTSecurityDescriptor", NULL};

	status = ads_find_machine_acct(ads, res, servername);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1, ("ads_add_printer: cannot find host %s in ads\n",
			  servername));
		return status;
	}
	srv_dn = ldap_get_dn(ads->ld, *res);
	srv_cn = ldap_explode_dn(srv_dn, 1);
	ads_msgfree(ads, *res);

	asprintf(&exp, "(cn=%s-%s)", srv_cn[0], printer);
	status = ads_search(ads, res, exp, attrs);

	ldap_memfree(srv_dn);
	ldap_value_free(srv_cn);
	free(exp);
	return status;	
}

/*
  modify an entire printer entry in the directory
*/
ADS_STATUS ads_mod_printer_entry(ADS_STRUCT *ads, char *prt_dn,
				 const ADS_PRINTER_ENTRY *prt)
{
	ADS_MODLIST mods;
	ADS_STATUS status;
	TALLOC_CTX *ctx;

	if (!(ctx = talloc_init_named("mod_printer_entry")))
		return ADS_ERROR(LDAP_NO_MEMORY);

	/* allocate the list */
	mods = ads_init_mods(ctx);

	/* add the attributes to the list - required ones first */
	ads_mod_str(ctx, &mods, "printerName", prt->printerName);
	ads_mod_str(ctx, &mods, "serverName", prt->serverName);
	ads_mod_str(ctx, &mods, "shortServerName", prt->shortServerName);
	ads_mod_str(ctx, &mods, "uNCName", prt->uNCName);
	ads_mod_str(ctx, &mods, "versionNumber", prt->versionNumber);

	/* now the optional ones */
	ads_mod_strlist(ctx, &mods, "description", (const char **)prt->description);
	ads_mod_str(ctx, &mods, "assetNumber",prt->assetNumber);
	ads_mod_str(ctx, &mods, "bytesPerMinute",prt->bytesPerMinute);
	ads_mod_str(ctx, &mods, "defaultPriority",prt->defaultPriority);
	ads_mod_str(ctx, &mods, "driverName", prt->driverName);
	ads_mod_str(ctx, &mods, "driverVersion",prt->driverVersion);
	ads_mod_str(ctx, &mods, "location", prt->location);
	ads_mod_str(ctx, &mods, "operatingSystem",prt->operatingSystem);
	ads_mod_str(ctx, &mods, "operatingSystemHotfix",
		     prt->operatingSystemHotfix);
	ads_mod_str(ctx, &mods, "operatingSystemServicePack",
		     prt->operatingSystemServicePack);
	ads_mod_str(ctx, &mods, "operatingSystemVersion",
		     prt->operatingSystemVersion);
	ads_mod_str(ctx, &mods, "physicalLocationObject",
		     prt->physicalLocationObject);
	ads_mod_strlist(ctx, &mods, "portName", (const char **)prt->portName);
	ads_mod_str(ctx, &mods, "printStartTime", prt->printStartTime);
	ads_mod_str(ctx, &mods, "printEndTime", prt->printEndTime);
	ads_mod_strlist(ctx, &mods, "printBinNames", (const char **)prt->printBinNames);
	/*... and many others */

	/* do the ldap modify */
	status = ads_gen_mod(ads, prt_dn, mods);

	/* free mod list, mods, and values */
	talloc_destroy(ctx); 

	return status;
}

/*
  add a printer to the directory
*/
static ADS_STATUS ads_add_printer_entry(ADS_STRUCT *ads, char *prt_dn,
					const ADS_PRINTER_ENTRY *prt)
{
        ADS_STATUS status;
	TALLOC_CTX *ctx;
	ADS_MODLIST mods;

	if (!(ctx = talloc_init_named("add_printer_entry")))
		return ADS_ERROR(LDAP_NO_MEMORY);

	if (!(mods = ads_init_mods(ctx)))
		return ADS_ERROR(LDAP_NO_MEMORY);

	/* These are the fields a printQueue must contain */
	ads_mod_str(ctx, &mods, "uNCName", prt->uNCName);
	ads_mod_str(ctx, &mods, "versionNumber", prt->versionNumber);
	ads_mod_str(ctx, &mods, "serverName", prt->serverName);
	ads_mod_str(ctx, &mods, "shortServerName", prt->shortServerName);
	ads_mod_str(ctx, &mods, "printerName", prt->printerName);
	ads_mod_str(ctx, &mods, "objectClass", "printQueue");


	status = ads_gen_add(ads, prt_dn, mods);

	talloc_destroy(ctx);

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
	host_dn = ads_get_dn(ads, res);
	ads_msgfree(ads, res);

	ads_find_printer_on_server(ads, &res, prt->printerName, 
				   prt->shortServerName);

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

	status = ads_search_dn(ads, &res, prt_dn, attrs);

	if (ADS_ERR_OK(status) && ads_count_replies(ads, res)) {
		/* need to retrieve GUID from results
		   prt->GUID */
		status = ads_mod_printer_entry(ads, prt_dn, prt);
	}

	ads_msgfree(ads, res);


	return status;
}

#endif
