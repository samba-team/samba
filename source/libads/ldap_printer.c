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
  modify a printer entry in the directory
*/
ADS_STATUS ads_mod_printer_entry(ADS_STRUCT *ads, char *prt_dn,
				 TALLOC_CTX *ctx, const ADS_MODLIST *mods)
{
	return ads_gen_mod(ads, prt_dn, *mods);
}

/*
  add a printer to the directory
*/
ADS_STATUS ads_add_printer_entry(ADS_STRUCT *ads, char *prt_dn,
					TALLOC_CTX *ctx, ADS_MODLIST *mods)
{
	ads_mod_str(ctx, mods, "objectClass", "printQueue");
	return ads_gen_add(ads, prt_dn, *mods);
}

/*
  map a REG_SZ to an ldap mod
*/
static BOOL map_sz(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
			    const REGISTRY_VALUE *value)
{
	char *str_value = NULL;

	if (value->type != REG_SZ)
		return False;

	if (value->size && *((smb_ucs2_t *) value->data_p)) {
		pull_ucs2_talloc(ctx, (void **) &str_value, 
				 (const smb_ucs2_t *) value->data_p);
		return ADS_ERR_OK(ads_mod_str(ctx, mods, value->valuename, 
					      str_value));
	}
	return True;
		
}

/*
  map a REG_DWORD to an ldap mod
*/
static BOOL map_dword(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
		      const REGISTRY_VALUE *value)
{
	char *str_value = NULL;

	if (value->type != REG_DWORD)
		return False;
	str_value = talloc_asprintf(ctx, "%d", *((uint32 *) value->data_p));
	return ADS_ERR_OK(ads_mod_str(ctx, mods, value->valuename, str_value));
}

/*
  map a boolean REG_BINARY to an ldap mod
*/
static BOOL map_bool(TALLOC_CTX *ctx, ADS_MODLIST *mods,
		     const REGISTRY_VALUE *value)
{
	char *str_value;

	if ((value->type != REG_BINARY) || (value->size != 1))
		return False;
	str_value =  talloc_asprintf(ctx, "%s", 
				     *(value->data_p) ? "TRUE" : "FALSE");
	return ADS_ERR_OK(ads_mod_str(ctx, mods, value->valuename, str_value));
}

/*
  map a REG_MULTI_SZ to an ldap mod
*/
static BOOL map_multi_sz(TALLOC_CTX *ctx, ADS_MODLIST *mods,
			 const REGISTRY_VALUE *value)
{
	char **str_values = NULL;
	smb_ucs2_t *cur_str = (smb_ucs2_t *) value->data_p;
        uint32 size = 0, num_vals = 0, i=0;

	if (value->type != REG_MULTI_SZ)
		return False;

	while(cur_str && *cur_str && (size < value->size)) {		
		size += 2 * (strlen_w(cur_str) + 1);
		cur_str += strlen_w(cur_str) + 1;
		num_vals++;
	};

	if (num_vals) {
		str_values = talloc(ctx, 
				    (num_vals + 1) * sizeof(smb_ucs2_t *));
		memset(str_values, '\0', 
		       (num_vals + 1) * sizeof(smb_ucs2_t *));

		cur_str = (smb_ucs2_t *) value->data_p;
		for (i=0; i < num_vals; i++)
			cur_str += pull_ucs2_talloc(ctx, 
						    (void **) &str_values[i], 
						    cur_str);

		return ADS_ERR_OK(ads_mod_strlist(ctx, mods, value->valuename, 
						  (const char **) str_values));
	} 
	return True;
}

struct valmap_to_ads {
	char *valname;
	BOOL (*fn)(TALLOC_CTX *, ADS_MODLIST *, const REGISTRY_VALUE *);
};

/*
  map a REG_SZ to an ldap mod
*/
static void map_regval_to_ads(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
			      REGISTRY_VALUE *value)
{
	struct valmap_to_ads map[] = {
		{"assetNumber", map_sz},
		{"bytesPerMinute", map_dword},
		{"defaultPriority", map_dword},
		{"driverName", map_sz},
		{"driverVersion", map_dword},
		{"flags", map_dword},
		{"location", map_sz},
		{"operatingSystem", map_sz},
		{"operatingSystemHotfix", map_sz},
		{"operatingSystemServicePack", map_sz},
		{"operatingSystemVersion", map_sz},
		{"portName", map_multi_sz},
		{"printAttributes", map_dword},
		{"printBinNames", map_multi_sz},
		{"printCollate", map_bool},
		{"printColor", map_bool},
		{"printDuplexSupported", map_bool},
		{"printEndTime", map_dword},
		{"printFormName", map_sz},
		{"printKeepPrintedJobs", map_bool},
		{"printLanguage", map_multi_sz},
		{"printMACAddress", map_sz},
		{"printMaxCopies", map_sz},
		{"printMaxResolutionSupported", map_dword},
		{"printMaxXExtent", map_dword},
		{"printMaxYExtent", map_dword},
		{"printMediaReady", map_multi_sz},
		{"printMediaSupported", map_multi_sz},
		{"printMemory", map_dword},
		{"printMinXExtent", map_dword},
		{"printMinYExtent", map_dword},
		{"printNetworkAddress", map_sz},
		{"printNotify", map_sz},
		{"printNumberUp", map_dword},
		{"printOrientationsSupported", map_multi_sz},
		{"printOwner", map_sz},
		{"printPagesPerMinute", map_dword},
		{"printRate", map_dword},
		{"printRateUnit", map_sz},
		{"printSeparatorFile", map_sz},
		{"printShareName", map_sz},
		{"printSpooling", map_sz},
		{"printStaplingSupported", map_bool},
		{"printStartTime", map_dword},
		{"printStatus", map_sz},
		{"priority", map_dword},
		{"serverName", map_sz},
		{"shortServerName", map_sz},
		{"uNCName", map_sz},
		{"url", map_sz},
		{"versionNumber", map_dword},
		{NULL, NULL}
	};
	int i;

	for (i=0; map[i].valname; i++) {
		if (StrCaseCmp(map[i].valname, value->valuename) == 0) {
			if (!map[i].fn(ctx, mods, value)) {
				DEBUG(5, ("Add of value %s to modlist failed\n", value->valuename));
			} else {
				DEBUG(7, ("Mapped value %s\n", value->valuename));
			}
			
		}
	}
}


WERROR get_remote_printer_publishing_data(struct cli_state *cli, 
					  TALLOC_CTX *mem_ctx,
					  ADS_MODLIST *mods,
					  char *printer)
{
	WERROR result;
	char *printername, *servername;
	REGVAL_CTR dsdriver_ctr, dsspooler_ctr;
	uint32 needed, i;
	POLICY_HND pol;

	asprintf(&servername, "\\\\%s", cli->desthost);
	asprintf(&printername, "%s\\%s", servername, printer);
	if (!servername || !printername) {
		DEBUG(3, ("Insufficient memory\n"));
		return WERR_NOMEM;
	}
	
	result = cli_spoolss_open_printer_ex(cli, mem_ctx, printername, 
					     "", MAXIMUM_ALLOWED_ACCESS, 
					     servername, cli->user_name, &pol);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(3, ("Unable to open printer %s, error is %s.\n",
			  printername, dos_errstr(result)));
		return result;
	}
	
	result = cli_spoolss_enumprinterdataex(cli, mem_ctx, 0, &needed, 
					       &pol, "DsDriver", NULL);

	if (W_ERROR_V(result) == ERRmoredata)
		result = cli_spoolss_enumprinterdataex(cli, mem_ctx, needed, 
						       NULL, &pol, "DsDriver",
						       &dsdriver_ctr);

	if (!W_ERROR_IS_OK(result)) {
		DEBUG(3, ("Unable to do enumdataex on %s, error is %s.\n",
			  printername, dos_errstr(result)));
		cli_spoolss_close_printer(cli, mem_ctx, &pol);
		return result;
	}

	/* Have the data we need now, so start building */

	for (i=0; i < dsdriver_ctr.num_values; i++)
		map_regval_to_ads(mem_ctx, mods, dsdriver_ctr.values[i]);
	
	result = cli_spoolss_enumprinterdataex(cli, mem_ctx, 0, &needed, 
					       &pol, "DsSpooler", NULL);

	if (W_ERROR_V(result) == ERRmoredata)
		result = cli_spoolss_enumprinterdataex(cli, mem_ctx, needed, 
						       NULL, &pol, "DsSpooler",
						       &dsspooler_ctr);

	if (!W_ERROR_IS_OK(result)) {
		DEBUG(3, ("Unable to do enumdataex on %s, error is %s.\n",
			  printername, dos_errstr(result)));
		regval_ctr_destroy(&dsdriver_ctr);
		cli_spoolss_close_printer(cli, mem_ctx, &pol);
		return result;
	}
	for (i=0; i < dsspooler_ctr.num_values; i++)
		map_regval_to_ads(mem_ctx, mods, dsspooler_ctr.values[i]);
	
	ads_mod_str(mem_ctx, mods, "printerName", printername);

	regval_ctr_destroy(&dsdriver_ctr);
	regval_ctr_destroy(&dsspooler_ctr);
	cli_spoolss_close_printer(cli, mem_ctx, &pol);

	return result;
}

BOOL get_local_printer_publishing_data(TALLOC_CTX *mem_ctx,
				       ADS_MODLIST *mods,
				       NT_PRINTER_DATA *data)
{
	uint32 key,val;

	for (key=0; key < data->num_keys; key++) {
		REGVAL_CTR ctr = data->keys[key].values;
		for (val=0; val < ctr.num_values; val++)
			map_regval_to_ads(mem_ctx, mods, ctr.values[val]);
	}
	return True;
}

#endif

