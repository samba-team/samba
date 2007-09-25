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

enum GPO_LINK_TYPE {
	GP_LINK_UNKOWN	= 0,
	GP_LINK_MACHINE	= 1,
	GP_LINK_SITE	= 2,
	GP_LINK_DOMAIN	= 3,
	GP_LINK_OU	= 4
};

/* GPO_OPTIONS */
#define GPO_FLAG_DISABLE	0x00000001
#define GPO_FLAG_FORCE		0x00000002

/* GPO_LIST_FLAGS */
#define GPO_LIST_FLAG_MACHINE	0x00000001
#define GPO_LIST_FLAG_SITEONLY	0x00000002

#define GPO_VERSION_USER(x) (x >> 16)
#define GPO_VERSION_MACHINE(x) (x & 0xffff)

struct GROUP_POLICY_OBJECT {
	uint32_t options;	/* GPFLAGS_* */
	uint32_t version;
	const char *ds_path;
	const char *file_sys_path;
	const char *display_name;
	const char *name;
	const char *link;
	enum GPO_LINK_TYPE link_type;
	const char *user_extensions;
	const char *machine_extensions;
	SEC_DESC *security_descriptor;
	struct GROUP_POLICY_OBJECT *next, *prev;
};

/* the following is seen on the DS (see adssearch.pl for details) */

/* the type field in a 'gPLink', the same as GPO_FLAG ? */
#define GPO_LINK_OPT_NONE	0x00000000
#define GPO_LINK_OPT_DISABLED	0x00000001
#define GPO_LINK_OPT_ENFORCED	0x00000002

/* GPO_LINK_OPT_ENFORCED takes precedence over GPOPTIONS_BLOCK_INHERITANCE */

/* 'gPOptions', maybe a bitmask as well */
enum GPO_INHERIT {
	GPOPTIONS_INHERIT		= 0,
	GPOPTIONS_BLOCK_INHERITANCE	= 1
};

/* 'flags' in a 'groupPolicyContainer' object */
#define GPFLAGS_ALL_ENABLED			0x00000000
#define GPFLAGS_USER_SETTINGS_DISABLED		0x00000001
#define GPFLAGS_MACHINE_SETTINGS_DISABLED	0x00000002
#define GPFLAGS_ALL_DISABLED (GPFLAGS_USER_SETTINGS_DISABLED | \
			      GPFLAGS_MACHINE_SETTINGS_DISABLED)

struct GP_LINK {
	const char *gp_link;	/* raw link name */
	uint32_t gp_opts;		/* inheritance options GPO_INHERIT */
	uint32_t num_links;	/* number of links */
	char **link_names;	/* array of parsed link names */
	uint32_t *link_opts;	/* array of parsed link opts GPO_LINK_OPT_* */
};

struct GP_EXT {
	const char *gp_extension;	/* raw extension name */
	uint32_t num_exts;
	char **extensions;
	char **extensions_guid;
	char **snapins;
	char **snapins_guid;
};

#define GPO_CACHE_DIR "gpo_cache"
#define GPT_INI "GPT.INI"

#define GP_EXT_GUID_SECURITY "827D319E-6EAC-11D2-A4EA-00C04F79F83A"
#define GP_EXT_GUID_REGISTRY "35378EAC-683F-11D2-A89A-00C04FBBCFA2"
#define GP_EXT_GUID_SCRIPTS  "42B5FAAE-6536-11D2-AE5A-0000F87571E3"
