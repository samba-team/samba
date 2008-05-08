/*
 *  Unix SMB/CIFS implementation.
 *  Group Policy Object Support
 *  Copyright (C) Guenther Deschner 2005-2007
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

#define DEFAULT_DOMAIN_POLICY "Default Domain Policy"
#define DEFAULT_DOMAIN_CONTROLLERS_POLICY "Default Domain Controllers Policy"

/* should we store a parsed guid ? */
struct gp_table {
	const char *name;
	const char *guid_string;
};

#if 0 /* unused */
static struct gp_table gpo_default_policy[] = {
	{ DEFAULT_DOMAIN_POLICY,
		"31B2F340-016D-11D2-945F-00C04FB984F9" },
	{ DEFAULT_DOMAIN_CONTROLLERS_POLICY,
		"6AC1786C-016F-11D2-945F-00C04fB984F9" },
	{ NULL, NULL }
};
#endif

/* the following is seen in gPCMachineExtensionNames / gPCUserExtensionNames */

static struct gp_table gpo_cse_extensions[] = {
	/* used to be "Administrative Templates Extension" */
	/* "Registry Settings"
	(http://support.microsoft.com/kb/216357/EN-US/) */
	{ "Registry Settings",
		GP_EXT_GUID_REGISTRY },
	{ "Microsoft Disc Quota",
		"3610EDA5-77EF-11D2-8DC5-00C04FA31A66" },
	{ "EFS recovery",
		"B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A" },
	{ "Folder Redirection",
		"25537BA6-77A8-11D2-9B6C-0000F8080861" },
	{ "IP Security",
		"E437BC1C-AA7D-11D2-A382-00C04F991E27" },
	{ "Internet Explorer Branding",
		"A2E30F80-D7DE-11d2-BBDE-00C04F86AE3B" },
	{ "QoS Packet Scheduler",
		"426031c0-0b47-4852-b0ca-ac3d37bfcb39" },
	{ "Scripts",
		GP_EXT_GUID_SCRIPTS },
	{ "Security",
		GP_EXT_GUID_SECURITY },
	{ "Software Installation",
		"C6DC5466-785A-11D2-84D0-00C04FB169F7" },
	{ "Wireless Group Policy",
		"0ACDD40C-75AC-BAA0-BF6DE7E7FE63" },
	{ "Application Management",
		"C6DC5466-785A-11D2-84D0-00C04FB169F7" },
	{ "unknown",
		"3060E8D0-7020-11D2-842D-00C04FA372D4" },
	{ NULL, NULL }
};

/* guess work */
static struct gp_table gpo_cse_snapin_extensions[] = {
	{ "Administrative Templates",
		"0F6B957D-509E-11D1-A7CC-0000F87571E3" },
	{ "Certificates",
		"53D6AB1D-2488-11D1-A28C-00C04FB94F17" },
	{ "EFS recovery policy processing",
		"B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A" },
	{ "Folder Redirection policy processing",
		"25537BA6-77A8-11D2-9B6C-0000F8080861" },
	{ "Folder Redirection",
		"88E729D6-BDC1-11D1-BD2A-00C04FB9603F" },
	{ "Registry policy processing",
		"35378EAC-683F-11D2-A89A-00C04FBBCFA2" },
	{ "Remote Installation Services",
		"3060E8CE-7020-11D2-842D-00C04FA372D4" },
	{ "Security Settings",
		"803E14A0-B4FB-11D0-A0D0-00A0C90F574B" },
	{ "Security policy processing",
		"827D319E-6EAC-11D2-A4EA-00C04F79F83A" },
	{ "unknown",
		"3060E8D0-7020-11D2-842D-00C04FA372D4" },
	{ "unknown2",
		"53D6AB1B-2488-11D1-A28C-00C04FB94F17" },
	{ NULL, NULL }
};

/****************************************************************
****************************************************************/

static const char *name_to_guid_string(const char *name,
				       struct gp_table *table)
{
	int i;

	for (i = 0; table[i].name; i++) {
		if (strequal(name, table[i].name)) {
			return table[i].guid_string;
		}
	}

	return NULL;
}

/****************************************************************
****************************************************************/

static const char *guid_string_to_name(const char *guid_string,
				       struct gp_table *table)
{
	int i;

	for (i = 0; table[i].guid_string; i++) {
		if (strequal(guid_string, table[i].guid_string)) {
			return table[i].name;
		}
	}

	return NULL;
}

/****************************************************************
****************************************************************/

static const char *snapin_guid_string_to_name(const char *guid_string,
					      struct gp_table *table)
{
	int i;
	for (i = 0; table[i].guid_string; i++) {
		if (strequal(guid_string, table[i].guid_string)) {
			return table[i].name;
		}
	}
	return NULL;
}

#if 0 /* unused */
static const char *default_gpo_name_to_guid_string(const char *name)
{
	return name_to_guid_string(name, gpo_default_policy);
}

static const char *default_gpo_guid_string_to_name(const char *guid)
{
	return guid_string_to_name(guid, gpo_default_policy);
}
#endif

/****************************************************************
****************************************************************/

const char *cse_gpo_guid_string_to_name(const char *guid)
{
	return guid_string_to_name(guid, gpo_cse_extensions);
}

/****************************************************************
****************************************************************/

const char *cse_gpo_name_to_guid_string(const char *name)
{
	return name_to_guid_string(name, gpo_cse_extensions);
}

/****************************************************************
****************************************************************/

const char *cse_snapin_gpo_guid_string_to_name(const char *guid)
{
	return snapin_guid_string_to_name(guid, gpo_cse_snapin_extensions);
}

/****************************************************************
****************************************************************/

void dump_gp_ext(struct GP_EXT *gp_ext, int debuglevel)
{
	int lvl = debuglevel;
	int i;

	if (gp_ext == NULL) {
		return;
	}

	DEBUG(lvl,("\t---------------------\n\n"));
	DEBUGADD(lvl,("\tname:\t\t\t%s\n", gp_ext->gp_extension));

	for (i=0; i< gp_ext->num_exts; i++) {

		DEBUGADD(lvl,("\textension:\t\t\t%s\n",
			gp_ext->extensions_guid[i]));
		DEBUGADD(lvl,("\textension (name):\t\t\t%s\n",
			gp_ext->extensions[i]));

		DEBUGADD(lvl,("\tsnapin:\t\t\t%s\n",
			gp_ext->snapins_guid[i]));
		DEBUGADD(lvl,("\tsnapin (name):\t\t\t%s\n",
			gp_ext->snapins[i]));
	}
}

#ifdef HAVE_LDAP

/****************************************************************
****************************************************************/

void dump_gpo(ADS_STRUCT *ads,
	      TALLOC_CTX *mem_ctx,
	      struct GROUP_POLICY_OBJECT *gpo,
	      int debuglevel)
{
	int lvl = debuglevel;

	if (gpo == NULL) {
		return;
	}

	DEBUG(lvl,("---------------------\n\n"));

	DEBUGADD(lvl,("name:\t\t\t%s\n", gpo->name));
	DEBUGADD(lvl,("displayname:\t\t%s\n", gpo->display_name));
	DEBUGADD(lvl,("version:\t\t%d (0x%08x)\n", gpo->version, gpo->version));
	DEBUGADD(lvl,("version_user:\t\t%d (0x%04x)\n",
		GPO_VERSION_USER(gpo->version),
		GPO_VERSION_USER(gpo->version)));
	DEBUGADD(lvl,("version_machine:\t%d (0x%04x)\n",
		GPO_VERSION_MACHINE(gpo->version),
		 GPO_VERSION_MACHINE(gpo->version)));
	DEBUGADD(lvl,("filesyspath:\t\t%s\n", gpo->file_sys_path));
	DEBUGADD(lvl,("dspath:\t\t%s\n", gpo->ds_path));

	DEBUGADD(lvl,("options:\t\t%d ", gpo->options));
	switch (gpo->options) {
		case GPFLAGS_ALL_ENABLED:
			DEBUGADD(lvl,("GPFLAGS_ALL_ENABLED\n"));
			break;
		case GPFLAGS_USER_SETTINGS_DISABLED:
			DEBUGADD(lvl,("GPFLAGS_USER_SETTINGS_DISABLED\n"));
			break;
		case GPFLAGS_MACHINE_SETTINGS_DISABLED:
			DEBUGADD(lvl,("GPFLAGS_MACHINE_SETTINGS_DISABLED\n"));
			break;
		case GPFLAGS_ALL_DISABLED:
			DEBUGADD(lvl,("GPFLAGS_ALL_DISABLED\n"));
			break;
		default:
			DEBUGADD(lvl,("unknown option: %d\n", gpo->options));
			break;
	}

	DEBUGADD(lvl,("link:\t\t\t%s\n", gpo->link));
	DEBUGADD(lvl,("link_type:\t\t%d ", gpo->link_type));
	switch (gpo->link_type) {
		case GP_LINK_UNKOWN:
			DEBUGADD(lvl,("GP_LINK_UNKOWN\n"));
			break;
		case GP_LINK_OU:
			DEBUGADD(lvl,("GP_LINK_OU\n"));
			break;
		case GP_LINK_DOMAIN:
			DEBUGADD(lvl,("GP_LINK_DOMAIN\n"));
			break;
		case GP_LINK_SITE:
			DEBUGADD(lvl,("GP_LINK_SITE\n"));
			break;
		case GP_LINK_MACHINE:
			DEBUGADD(lvl,("GP_LINK_MACHINE\n"));
			break;
		default:
			break;
	}

	DEBUGADD(lvl,("machine_extensions:\t%s\n", gpo->machine_extensions));

	if (gpo->machine_extensions) {

		struct GP_EXT *gp_ext = NULL;

		if (!ads_parse_gp_ext(mem_ctx, gpo->machine_extensions,
				      &gp_ext)) {
			return;
		}
		dump_gp_ext(gp_ext, lvl);
	}

	DEBUGADD(lvl,("user_extensions:\t%s\n", gpo->user_extensions));

	if (gpo->user_extensions) {

		struct GP_EXT *gp_ext = NULL;

		if (!ads_parse_gp_ext(mem_ctx, gpo->user_extensions,
				      &gp_ext)) {
			return;
		}
		dump_gp_ext(gp_ext, lvl);
	}

	DEBUGADD(lvl,("security descriptor:\n"));

	ads_disp_sd(ads, mem_ctx, gpo->security_descriptor);
}

/****************************************************************
****************************************************************/

void dump_gpo_list(ADS_STRUCT *ads,
		   TALLOC_CTX *mem_ctx,
		   struct GROUP_POLICY_OBJECT *gpo_list,
		   int debuglevel)
{
	struct GROUP_POLICY_OBJECT *gpo = NULL;

	for (gpo = gpo_list; gpo; gpo = gpo->next) {
		dump_gpo(ads, mem_ctx, gpo, debuglevel);
	}
}

/****************************************************************
****************************************************************/

void dump_gplink(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, struct GP_LINK *gp_link)
{
	ADS_STATUS status;
	int i;
	int lvl = 10;

	if (gp_link == NULL) {
		return;
	}

	DEBUG(lvl,("---------------------\n\n"));

	DEBUGADD(lvl,("gplink: %s\n", gp_link->gp_link));
	DEBUGADD(lvl,("gpopts: %d ", gp_link->gp_opts));
	switch (gp_link->gp_opts) {
		case GPOPTIONS_INHERIT:
			DEBUGADD(lvl,("GPOPTIONS_INHERIT\n"));
			break;
		case GPOPTIONS_BLOCK_INHERITANCE:
			DEBUGADD(lvl,("GPOPTIONS_BLOCK_INHERITANCE\n"));
			break;
		default:
			break;
	}

	DEBUGADD(lvl,("num links: %d\n", gp_link->num_links));

	for (i = 0; i < gp_link->num_links; i++) {

		DEBUGADD(lvl,("---------------------\n\n"));

		DEBUGADD(lvl,("link: #%d\n", i + 1));
		DEBUGADD(lvl,("name: %s\n", gp_link->link_names[i]));

		DEBUGADD(lvl,("opt: %d ", gp_link->link_opts[i]));
		if (gp_link->link_opts[i] & GPO_LINK_OPT_ENFORCED) {
			DEBUGADD(lvl,("GPO_LINK_OPT_ENFORCED "));
		}
		if (gp_link->link_opts[i] & GPO_LINK_OPT_DISABLED) {
			DEBUGADD(lvl,("GPO_LINK_OPT_DISABLED"));
		}
		DEBUGADD(lvl,("\n"));

		if (ads != NULL && mem_ctx != NULL) {

			struct GROUP_POLICY_OBJECT gpo;

			status = ads_get_gpo(ads, mem_ctx,
					     gp_link->link_names[i],
					     NULL, NULL, &gpo);
			if (!ADS_ERR_OK(status)) {
				DEBUG(lvl,("get gpo for %s failed: %s\n",
					gp_link->link_names[i],
					ads_errstr(status)));
				return;
			}
			dump_gpo(ads, mem_ctx, &gpo, lvl);
		}
	}
}

#endif /* HAVE_LDAP */

/****************************************************************
****************************************************************/

NTSTATUS process_extension(ADS_STRUCT *ads,
			   TALLOC_CTX *mem_ctx,
			   uint32_t flags,
			   const struct nt_user_token *token,
			   struct GROUP_POLICY_OBJECT *gpo,
			   const char *extension_guid,
			   const char *snapin_guid)
{
	DEBUG(0,("process_extension: no extension available for:\n"));
	DEBUGADD(0,("%s (%s) (snapin: %s)\n",
		extension_guid,
		cse_gpo_guid_string_to_name(extension_guid),
		snapin_guid));

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

ADS_STATUS gpo_process_a_gpo(ADS_STRUCT *ads,
			     TALLOC_CTX *mem_ctx,
			     const struct nt_user_token *token,
			     struct GROUP_POLICY_OBJECT *gpo,
			     const char *extension_guid_filter,
			     uint32_t flags)
{
	struct GP_EXT *gp_ext = NULL;
	int i;

	DEBUG(10,("gpo_process_a_gpo: processing gpo %s (%s)\n",
		gpo->name, gpo->display_name));
	if (extension_guid_filter) {
		DEBUGADD(10,("gpo_process_a_gpo: using filter %s\n",
			extension_guid_filter));
	}

	if (flags & GPO_LIST_FLAG_MACHINE) {

		if (gpo->machine_extensions) {

			if (!ads_parse_gp_ext(mem_ctx, gpo->machine_extensions,
					      &gp_ext)) {
				return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
			}

		} else {
			/* nothing to apply */
			return ADS_SUCCESS;
		}

	} else {

		if (gpo->user_extensions) {

			if (!ads_parse_gp_ext(mem_ctx, gpo->user_extensions,
					      &gp_ext)) {
				return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
			}
		} else {
			/* nothing to apply */
			return ADS_SUCCESS;
		}
	}

	for (i=0; i<gp_ext->num_exts; i++) {

		NTSTATUS ntstatus;

		if (extension_guid_filter &&
		    !strequal(extension_guid_filter,
		    	      gp_ext->extensions_guid[i])) {
			continue;
		}

		ntstatus = process_extension(ads, mem_ctx,
					     flags, token, gpo,
					     gp_ext->extensions_guid[i],
					     gp_ext->snapins_guid[i]);
		if (!NT_STATUS_IS_OK(ntstatus)) {
			ADS_ERROR_NT(ntstatus);
		}
	}

	return ADS_SUCCESS;
}

/****************************************************************
****************************************************************/

ADS_STATUS gpo_process_gpo_list(ADS_STRUCT *ads,
				TALLOC_CTX *mem_ctx,
				const struct nt_user_token *token,
				struct GROUP_POLICY_OBJECT *gpo_list,
				const char *extensions_guid,
				uint32_t flags)
{
	ADS_STATUS status;
	struct GROUP_POLICY_OBJECT *gpo;

	/* FIXME: ok, this is wrong, windows does process the extensions and
	 * hands the list of gpos to each extension and not process each gpo
	 * with all extensions (this is how the extension can store the list
	 * gplist in the registry) */

	for (gpo = gpo_list; gpo; gpo = gpo->next) {

		status = gpo_process_a_gpo(ads, mem_ctx, token, gpo,
					   extensions_guid, flags);

		if (!ADS_ERR_OK(status)) {
			DEBUG(0,("failed to process gpo: %s\n",
				ads_errstr(status)));
			return status;
		}

	}

	return ADS_SUCCESS;
}

/****************************************************************
 check wether the version number in a GROUP_POLICY_OBJECT match those of the
 locally stored version. If not, fetch the required policy via CIFS
****************************************************************/

NTSTATUS check_refresh_gpo(ADS_STRUCT *ads,
			   TALLOC_CTX *mem_ctx,
			   uint32_t flags,
			   struct GROUP_POLICY_OBJECT *gpo,
			   struct cli_state **cli_out)
{
	NTSTATUS result;
	char *server = NULL;
	char *share = NULL;
	char *nt_path = NULL;
	char *unix_path = NULL;
	uint32_t sysvol_gpt_version = 0;
	char *display_name = NULL;
	struct cli_state *cli = NULL;

	result = gpo_explode_filesyspath(mem_ctx, gpo->file_sys_path,
					 &server, &share, &nt_path, &unix_path);

	if (!NT_STATUS_IS_OK(result)) {
		goto out;
	}

	result = gpo_get_sysvol_gpt_version(mem_ctx,
					    unix_path,
					    &sysvol_gpt_version,
					    &display_name);
	if (!NT_STATUS_IS_OK(result) &&
	    !NT_STATUS_EQUAL(result, NT_STATUS_NO_SUCH_FILE)) {
		DEBUG(10,("check_refresh_gpo: "
			"failed to get local gpt version: %s\n",
			nt_errstr(result)));
		goto out;
	}

	DEBUG(10,("check_refresh_gpo: versions gpo %d sysvol %d\n",
		gpo->version, sysvol_gpt_version));

	/* FIXME: handle GPO_INFO_FLAG_FORCED_REFRESH from flags */

	while (gpo->version > sysvol_gpt_version) {

		DEBUG(1,("check_refresh_gpo: need to refresh GPO\n"));

		if (*cli_out == NULL) {

			result = cli_full_connection(&cli,
					global_myname(),
					ads->config.ldap_server_name,
					/* server */
					NULL, 0,
					share, "A:",
					ads->auth.user_name, NULL,
					ads->auth.password,
					CLI_FULL_CONNECTION_USE_KERBEROS,
					Undefined, NULL);
			if (!NT_STATUS_IS_OK(result)) {
				DEBUG(10,("check_refresh_gpo: "
					"failed to connect: %s\n",
					nt_errstr(result)));
				goto out;
			}

			*cli_out = cli;
		}

		result = gpo_fetch_files(mem_ctx, *cli_out, gpo);
		if (!NT_STATUS_IS_OK(result)) {
			goto out;
		}

		result = gpo_get_sysvol_gpt_version(mem_ctx,
						    unix_path,
						    &sysvol_gpt_version,
						    &display_name);
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(10,("check_refresh_gpo: "
				"failed to get local gpt version: %s\n",
				nt_errstr(result)));
			goto out;
		}

		if (gpo->version == sysvol_gpt_version) {
			break;
		}
	}

	DEBUG(10,("Name:\t\t\t%s (%s)\n", gpo->display_name, gpo->name));
	DEBUGADD(10,("sysvol GPT version:\t%d (user: %d, machine: %d)\n",
		sysvol_gpt_version,
		GPO_VERSION_USER(sysvol_gpt_version),
		GPO_VERSION_MACHINE(sysvol_gpt_version)));
	DEBUGADD(10,("LDAP GPO version:\t%d (user: %d, machine: %d)\n",
		gpo->version,
		GPO_VERSION_USER(gpo->version),
		GPO_VERSION_MACHINE(gpo->version)));

	result = NT_STATUS_OK;

 out:
	return result;

}

/****************************************************************
 check wether the version numbers in the gpo_list match the locally stored, if
 not, go and get each required GPO via CIFS
 ****************************************************************/

NTSTATUS check_refresh_gpo_list(ADS_STRUCT *ads,
				TALLOC_CTX *mem_ctx,
				uint32_t flags,
				struct GROUP_POLICY_OBJECT *gpo_list)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	struct cli_state *cli = NULL;
	struct GROUP_POLICY_OBJECT *gpo;

	if (!gpo_list) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (gpo = gpo_list; gpo; gpo = gpo->next) {

		result = check_refresh_gpo(ads, mem_ctx, flags, gpo, &cli);
		if (!NT_STATUS_IS_OK(result)) {
			goto out;
		}
	}

	result = NT_STATUS_OK;

 out:
	if (cli) {
		cli_shutdown(cli);
	}

	return result;
}

/****************************************************************
****************************************************************/

NTSTATUS gp_find_file(TALLOC_CTX *mem_ctx,
		      uint32_t flags,
		      const char *filename,
		      const char *suffix,
		      const char **filename_out)
{
	const char *tmp = NULL;
	SMB_STRUCT_STAT sbuf;
	const char *path = NULL;

	if (flags & GPO_LIST_FLAG_MACHINE) {
		path = "Machine";
	} else {
		path = "User";
	}

	tmp = talloc_asprintf(mem_ctx, "%s/%s/%s", filename,
			      path, suffix);
	NT_STATUS_HAVE_NO_MEMORY(tmp);

	if (sys_stat(tmp, &sbuf) == 0) {
		*filename_out = tmp;
		return NT_STATUS_OK;
	}

	tmp = talloc_asprintf_strupper_m(mem_ctx, "%s/%s/%s", filename, path,
					 suffix);
	NT_STATUS_HAVE_NO_MEMORY(tmp);

	if (sys_stat(tmp, &sbuf) == 0) {
		*filename_out = tmp;
		return NT_STATUS_OK;
	}

	return NT_STATUS_NO_SUCH_FILE;
}

