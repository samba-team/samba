/* 
   Unix SMB/CIFS implementation.
   ads (active directory) printer utility library
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002
   
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
#include "ads.h"
#include "rpc_client/rpc_client.h"
#include "../librpc/gen_ndr/ndr_spoolss_c.h"
#include "rpc_client/cli_spoolss.h"
#include "registry.h"
#include "libcli/registry/util_reg.h"

#ifdef HAVE_ADS

/*
  find a printer given the name and the hostname
    Note that results "res" may be allocated on return so that the
    results can be used.  It should be freed using ads_msgfree.
*/
 ADS_STATUS ads_find_printer_on_server(ADS_STRUCT *ads, LDAPMessage **res,
				       const char *printer,
				       const char *servername)
{
	ADS_STATUS status;
	char *srv_dn, **srv_cn, *s = NULL;
	const char *attrs[] = {"*", "nTSecurityDescriptor", NULL};

	status = ads_find_machine_acct(ads, res, servername);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1, ("ads_find_printer_on_server: cannot find host %s in ads\n",
			  servername));
		return status;
	}
	if (ads_count_replies(ads, *res) != 1) {
		ads_msgfree(ads, *res);
		*res = NULL;
		return ADS_ERROR(LDAP_NO_SUCH_OBJECT);
	}
	srv_dn = ldap_get_dn(ads->ldap.ld, *res);
	if (srv_dn == NULL) {
		ads_msgfree(ads, *res);
		*res = NULL;
		return ADS_ERROR(LDAP_NO_MEMORY);
	}
	srv_cn = ldap_explode_dn(srv_dn, 1);
	if (srv_cn == NULL) {
		ldap_memfree(srv_dn);
		ads_msgfree(ads, *res);
		*res = NULL;
		return ADS_ERROR(LDAP_INVALID_DN_SYNTAX);
	}
	ads_msgfree(ads, *res);
	*res = NULL;

	if (asprintf(&s, "(cn=%s-%s)", srv_cn[0], printer) == -1) {
		ldap_memfree(srv_dn);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}
	status = ads_search(ads, res, s, attrs);

	ldap_memfree(srv_dn);
	ldap_value_free(srv_cn);
	SAFE_FREE(s);
	return status;	
}

 ADS_STATUS ads_find_printers(ADS_STRUCT *ads, LDAPMessage **res)
{
	const char *ldap_expr;
	const char *attrs[] = { "objectClass", "printerName", "location", "driverName",
				"serverName", "description", NULL };

	/* For the moment only display all printers */

	ldap_expr = "(&(!(showInAdvancedViewOnly=TRUE))(uncName=*)"
		"(objectCategory=printQueue))";

	return ads_search(ads, res, ldap_expr, attrs);
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
static bool map_sz(TALLOC_CTX *ctx, ADS_MODLIST *mods,
		   const char *name, struct registry_value *value)
{
	const char *str_value = NULL;
	ADS_STATUS status;

	if (value->type != REG_SZ)
		return false;

	if (value->data.length  && value->data.data) {
		if (!pull_reg_sz(ctx, &value->data, &str_value)) {
			return false;
		}
		status = ads_mod_str(ctx, mods, name, str_value);
		return ADS_ERR_OK(status);
	}
	return true;
}

/*
  map a REG_DWORD to an ldap mod
*/
static bool map_dword(TALLOC_CTX *ctx, ADS_MODLIST *mods,
		      const char *name, struct registry_value *value)
{
	char *str_value = NULL;
	ADS_STATUS status;

	if (value->type != REG_DWORD) {
		return false;
	}
	if (value->data.length != sizeof(uint32)) {
		return false;
	}
	str_value = talloc_asprintf(ctx, "%d", IVAL(value->data.data, 0));
	if (!str_value) {
		return false;
	}
	status = ads_mod_str(ctx, mods, name, str_value);
	return ADS_ERR_OK(status);
}

/*
  map a boolean REG_BINARY to an ldap mod
*/
static bool map_bool(TALLOC_CTX *ctx, ADS_MODLIST *mods,
		     const char *name, struct registry_value *value)
{
	const char *str_value;
	ADS_STATUS status;

	if (value->type != REG_BINARY) {
		return false;
	}
	if (value->data.length != 1) {
		return false;
	}

	str_value =  *value->data.data ? "TRUE" : "FALSE";

	status = ads_mod_str(ctx, mods, name, str_value);
	return ADS_ERR_OK(status);
}

/*
  map a REG_MULTI_SZ to an ldap mod
*/
static bool map_multi_sz(TALLOC_CTX *ctx, ADS_MODLIST *mods,
			 const char *name, struct registry_value *value)
{
	const char **str_values = NULL;
	ADS_STATUS status;

	if (value->type != REG_MULTI_SZ) {
		return false;
	}

	if (value->data.length  && value->data.data) {
		if (!pull_reg_multi_sz(ctx, &value->data, &str_values)) {
			return false;
		}
		status = ads_mod_strlist(ctx, mods, name, str_values);
		return ADS_ERR_OK(status);
	}
	return true;
}

struct valmap_to_ads {
	const char *valname;
	bool (*fn)(TALLOC_CTX *, ADS_MODLIST *, const char *, struct registry_value *);
};

/*
  map a REG_SZ to an ldap mod
*/
static void map_regval_to_ads(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
			      const char *name, struct registry_value *value)
{
	const struct valmap_to_ads map[] = {
		{SPOOL_REG_ASSETNUMBER, map_sz},
		{SPOOL_REG_BYTESPERMINUTE, map_dword},
		{SPOOL_REG_DEFAULTPRIORITY, map_dword},
		{SPOOL_REG_DESCRIPTION, map_sz},
		{SPOOL_REG_DRIVERNAME, map_sz},
		{SPOOL_REG_DRIVERVERSION, map_dword},
		{SPOOL_REG_FLAGS, map_dword},
		{SPOOL_REG_LOCATION, map_sz},
		{SPOOL_REG_OPERATINGSYSTEM, map_sz},
		{SPOOL_REG_OPERATINGSYSTEMHOTFIX, map_sz},
		{SPOOL_REG_OPERATINGSYSTEMSERVICEPACK, map_sz},
		{SPOOL_REG_OPERATINGSYSTEMVERSION, map_sz},
		{SPOOL_REG_PORTNAME, map_multi_sz},
		{SPOOL_REG_PRINTATTRIBUTES, map_dword},
		{SPOOL_REG_PRINTBINNAMES, map_multi_sz},
		{SPOOL_REG_PRINTCOLLATE, map_bool},
		{SPOOL_REG_PRINTCOLOR, map_bool},
		{SPOOL_REG_PRINTDUPLEXSUPPORTED, map_bool},
		{SPOOL_REG_PRINTENDTIME, map_dword},
		{SPOOL_REG_PRINTFORMNAME, map_sz},
		{SPOOL_REG_PRINTKEEPPRINTEDJOBS, map_bool},
		{SPOOL_REG_PRINTLANGUAGE, map_multi_sz},
		{SPOOL_REG_PRINTMACADDRESS, map_sz},
		{SPOOL_REG_PRINTMAXCOPIES, map_sz},
		{SPOOL_REG_PRINTMAXRESOLUTIONSUPPORTED, map_dword},
		{SPOOL_REG_PRINTMAXXEXTENT, map_dword},
		{SPOOL_REG_PRINTMAXYEXTENT, map_dword},
		{SPOOL_REG_PRINTMEDIAREADY, map_multi_sz},
		{SPOOL_REG_PRINTMEDIASUPPORTED, map_multi_sz},
		{SPOOL_REG_PRINTMEMORY, map_dword},
		{SPOOL_REG_PRINTMINXEXTENT, map_dword},
		{SPOOL_REG_PRINTMINYEXTENT, map_dword},
		{SPOOL_REG_PRINTNETWORKADDRESS, map_sz},
		{SPOOL_REG_PRINTNOTIFY, map_sz},
		{SPOOL_REG_PRINTNUMBERUP, map_dword},
		{SPOOL_REG_PRINTORIENTATIONSSUPPORTED, map_multi_sz},
		{SPOOL_REG_PRINTOWNER, map_sz},
		{SPOOL_REG_PRINTPAGESPERMINUTE, map_dword},
		{SPOOL_REG_PRINTRATE, map_dword},
		{SPOOL_REG_PRINTRATEUNIT, map_sz},
		{SPOOL_REG_PRINTSEPARATORFILE, map_sz},
		{SPOOL_REG_PRINTSHARENAME, map_sz},
		{SPOOL_REG_PRINTSPOOLING, map_sz},
		{SPOOL_REG_PRINTSTAPLINGSUPPORTED, map_bool},
		{SPOOL_REG_PRINTSTARTTIME, map_dword},
		{SPOOL_REG_PRINTSTATUS, map_sz},
		{SPOOL_REG_PRIORITY, map_dword},
		{SPOOL_REG_SERVERNAME, map_sz},
		{SPOOL_REG_SHORTSERVERNAME, map_sz},
		{SPOOL_REG_UNCNAME, map_sz},
		{SPOOL_REG_URL, map_sz},
		{SPOOL_REG_VERSIONNUMBER, map_dword},
		{NULL, NULL}
	};
	int i;

	for (i=0; map[i].valname; i++) {
		if (strcasecmp_m(map[i].valname, name) == 0) {
			if (!map[i].fn(ctx, mods, name, value)) {
				DEBUG(5, ("Add of value %s to modlist failed\n", name));
			} else {
				DEBUG(7, ("Mapped value %s\n", name));
			}
		}
	}
}


WERROR get_remote_printer_publishing_data(struct rpc_pipe_client *cli, 
					  TALLOC_CTX *mem_ctx,
					  ADS_MODLIST *mods,
					  const char *printer)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	WERROR result;
	char *printername;
	struct spoolss_PrinterEnumValues *info;
	uint32_t count;
	uint32 i;
	struct policy_handle pol;
	WERROR werr;

	if ((asprintf(&printername, "%s\\%s", cli->srv_name_slash, printer) == -1)) {
		DEBUG(3, ("Insufficient memory\n"));
		return WERR_NOMEM;
	}

	result = rpccli_spoolss_openprinter_ex(cli, mem_ctx,
					       printername,
					       SEC_FLAG_MAXIMUM_ALLOWED,
					       &pol);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(3, ("Unable to open printer %s, error is %s.\n",
			  printername, win_errstr(result)));
		SAFE_FREE(printername);
		return result;
	}

	result = rpccli_spoolss_enumprinterdataex(cli, mem_ctx, &pol,
						  SPOOL_DSDRIVER_KEY,
						  0,
						  &count,
						  &info);

	if (!W_ERROR_IS_OK(result)) {
		DEBUG(3, ("Unable to do enumdataex on %s, error is %s.\n",
			  printername, win_errstr(result)));
	} else {
		/* Have the data we need now, so start building */
		for (i=0; i < count; i++) {
			struct registry_value v;
			v.type = info[i].type;
			v.data = *info[i].data;

			map_regval_to_ads(mem_ctx, mods, info[i].value_name, &v);
		}
	}

	result = rpccli_spoolss_enumprinterdataex(cli, mem_ctx, &pol,
						  SPOOL_DSSPOOLER_KEY,
						  0,
						  &count,
						  &info);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(3, ("Unable to do enumdataex on %s, error is %s.\n",
			  printername, win_errstr(result)));
	} else {
		for (i=0; i < count; i++) {
			struct registry_value v;
			v.type = info[i].type;
			v.data = *info[i].data;

			map_regval_to_ads(mem_ctx, mods, info[i].value_name, &v);
		}
	}

	ads_mod_str(mem_ctx, mods, SPOOL_REG_PRINTERNAME, printer);

	dcerpc_spoolss_ClosePrinter(b, mem_ctx, &pol, &werr);
	SAFE_FREE(printername);

	return result;
}

#endif
