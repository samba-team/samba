/* 
   Unix SMB/CIFS implementation.

   ModConfig LDAP backend

   Copyright (C) Simo Sorce 		2003
   Copyright (C) Jim McDonough <jmcd@us.ibm.com>	2003
   Copyright (C) Gerald Carter 		2003
   
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

/*#undef DBGC_CLASS
#define DBGC_CLASS DBGC_CONFIG
*/

#include <lber.h>
#include <ldap.h>

#include "smbldap.h"

#define LDAP_OBJ_SAMBA_CONFIG		"sambaConfig"
#define LDAP_OBJ_SAMBA_SHARE		"sambaShare"
#define LDAP_OBJ_SAMBA_OPTION		"sambaConfigOption"

#define LDAP_ATTR_LIST_END	0
#define LDAP_ATTR_BOOL		1
#define LDAP_ATTR_INTEGER	2
#define LDAP_ATTR_STRING	3
#define LDAP_ATTR_LIST		4
#define LDAP_ATTR_NAME		5


struct ldap_config_state {
	struct smbldap_state *smbldap_state;
	TALLOC_CTX *mem_ctx;
};

ATTRIB_MAP_ENTRY option_attr_list[] = {
	{ LDAP_ATTR_NAME,		"sambaOptionName"	},
	{ LDAP_ATTR_LIST,		"sambaListOption"	},
	{ LDAP_ATTR_STRING,		"sambaStringOption"	},
	{ LDAP_ATTR_INTEGER,		"sambaIntegerOption"	},
	{ LDAP_ATTR_BOOL,		"sambaBoolOption"	},
	{ LDAP_ATTR_LIST_END,		NULL			}
};

static struct ldap_config_state ldap_state;
static char *config_base_dn;

static NTSTATUS ldap_config_close(void);

/*
TODO:
	search each section
	start with global, then with others
	for each section parse all options
*/

static NTSTATUS parse_section(
		const char *dn,
		BOOL (*pfunc)(const char *, const char *))
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	pstring filter;
	pstring option_name;
	pstring option_value;
	char **attr_list = NULL;
	int rc;
	int count;

	mem_ctx = talloc_init("parse_section");
	
	/* search for the options */
	pstr_sprintf(filter, "objectClass=%s",
			LDAP_OBJ_SAMBA_OPTION);

	DEBUG(0, ("Searching for:[%s]\n", filter));

	attr_list = get_attr_list(option_attr_list);
	rc = smbldap_search(ldap_state.smbldap_state,
				dn, LDAP_SCOPE_ONELEVEL,
				filter, attr_list, 0, &result);

	if (rc != LDAP_SUCCESS) {
		DEBUG(0,("parse_section: %s object not found\n", LDAP_OBJ_SAMBA_CONFIG));
		goto done;
	}

	count = ldap_count_entries(ldap_state.smbldap_state->ldap_struct, result);
	entry = ldap_first_entry(ldap_state.smbldap_state->ldap_struct, result);
	while (entry) {
		int o;

		if (!smbldap_get_single_attribute(ldap_state.smbldap_state->ldap_struct, entry, "sambaOptionName", option_name)) {
			goto done;
		}

		option_value[0] = '\0';
		for (o = 1; option_attr_list[o].name != NULL; o++) {
			if (smbldap_get_single_attribute(ldap_state.smbldap_state->ldap_struct, entry, option_attr_list[o].name, option_value)) {
				break;
			}
		}
		if (option_value[0] != '\0') {
			if (!pfunc(option_name, option_value)) {
				goto done;
			}
		} else {
			DEBUG(0,("parse_section: Missing value for option: %s\n", option_name));
			goto done;
		}

		entry = ldap_next_entry(ldap_state.smbldap_state->ldap_struct, entry);
	}

	ret = NT_STATUS_OK;

done:
	talloc_destroy(mem_ctx);
	free_attr_list(attr_list);
	if (result) ldap_msgfree(result);

	return ret;
}

/*****************************************************************************
 load configuration from ldap
*****************************************************************************/

static NTSTATUS ldap_config_load(
		BOOL (*sfunc)(const char *),
		BOOL (*pfunc)(const char *, const char *))
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	pstring filter;
	pstring attr_text;
	char *config_dn = NULL;
	char *temp;
	int rc;
	int count;
	const char *config_attr_list[] = {"description", NULL};
	const char *share_attr_list[] = {"sambaShareName", "description", NULL};
	char **share_dn;
	char **share_name;

	mem_ctx = talloc_init("ldap_config_load");
	
	/* search for the base config dn */
	pstr_sprintf(filter, "objectClass=%s",
			LDAP_OBJ_SAMBA_CONFIG);

	DEBUG(0, ("Searching for:[%s]\n", filter));
	
	rc = smbldap_search(ldap_state.smbldap_state,
				config_base_dn, LDAP_SCOPE_SUBTREE,
				filter, config_attr_list, 0, &result);

	if (rc != LDAP_SUCCESS) {
		DEBUG(0,("ldap_config_load: %s object not found\n", LDAP_OBJ_SAMBA_CONFIG));
		goto done;
	}

	count = ldap_count_entries(ldap_state.smbldap_state->ldap_struct, result);
	if (count != 1) {
		DEBUG(0,("ldap_config_load: single %s object not found\n", LDAP_OBJ_SAMBA_CONFIG));
		goto done;
	}

	if (!(temp = smbldap_get_dn(ldap_state.smbldap_state->ldap_struct, result))) {
		goto done;
	}
	config_dn = talloc_strdup(mem_ctx, temp);
	SAFE_FREE(temp);
	if (!config_dn) {
		goto done;
	}

	entry = ldap_first_entry(ldap_state.smbldap_state->ldap_struct, result);

	if (!smbldap_get_single_attribute(ldap_state.smbldap_state->ldap_struct, entry, "description", attr_text)) {
		DEBUG(0, ("ldap_config_load: no description field in %s object\n", LDAP_OBJ_SAMBA_CONFIG));
	}

	if (result) ldap_msgfree(result);
/* TODO: finish up the last section, see loadparm's lp_load()*/
	
	/* retrive the section list */
	pstr_sprintf(filter, "objectClass=%s",
			LDAP_OBJ_SAMBA_SHARE);

	DEBUG(0, ("Searching for:[%s]\n", filter));
	
	rc = smbldap_search(ldap_state.smbldap_state,
				config_dn, LDAP_SCOPE_SUBTREE,
				filter, share_attr_list, 0, &result);

	if (rc != LDAP_SUCCESS) {
		DEBUG(0,("ldap_config_load: %s object not found\n", LDAP_OBJ_SAMBA_CONFIG));
		goto done;
	}

	count = ldap_count_entries(ldap_state.smbldap_state->ldap_struct, result);
	DEBUG(0, ("config_ldap: Found %d shares\n", count));
	if (count) {
		int i;

		share_dn = talloc(mem_ctx, (count + 1) * sizeof(char *));
		share_name = talloc(mem_ctx, (count) * sizeof(char *));
		if (!share_dn || !share_name) {
			DEBUG(0,("config_ldap: Out of memory!\n"));
			goto done;
		}
		entry = ldap_first_entry(ldap_state.smbldap_state->ldap_struct, result);
		i = 0;
		while (entry) {
			if (!(temp = smbldap_get_dn(ldap_state.smbldap_state->ldap_struct, entry))) {
				goto done;
			}
			if (!smbldap_get_single_attribute(ldap_state.smbldap_state->ldap_struct, entry, "sambaShareName", attr_text)) {
				goto done;
			}
			share_dn[i] = talloc_strdup(mem_ctx, temp);
			share_name[i] = talloc_strdup(mem_ctx, attr_text);
			if (!share_dn[i] || !share_name[i]) {
				DEBUG(0,("config_ldap: Out of memory!\n"));
				goto done;
			}

			DEBUG(0, ("config_ldap: Found share [%s] (%s)\n", attr_text, temp));
			SAFE_FREE(temp);

			entry = ldap_next_entry(ldap_state.smbldap_state->ldap_struct, entry);
			i++;
			if (entry && (count == i)) {
				DEBUG(0, ("Error too many entryes in ldap result\n"));
				goto done;
			}
		}
		share_dn[i] = NULL;
	}

	/* parse global section*/
	if (!sfunc("global")) {
		goto done;
	}
	if (!NT_STATUS_IS_OK(parse_section(config_dn, pfunc))) {
		goto done;
	} else { /* parse shares */
		int i;

		for (i = 0; share_dn[i] != NULL; i++) {
			if (!sfunc(share_name[i])) {
				goto done;
			}
			if (!NT_STATUS_IS_OK(parse_section(share_dn[i], pfunc))) {
				goto done;
			}
		}
	}

done:
	talloc_destroy(mem_ctx);
	if (result) ldap_msgfree(result);

	return ret;
}

/*****************************************************************************
 Initialise config_ldap module
*****************************************************************************/

static NTSTATUS ldap_config_init(char *params)
{
	NTSTATUS nt_status;
	const char *location;
	const char *basedn;

	ldap_state.mem_ctx = talloc_init("config_ldap");
	if (!ldap_state.mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	/* we assume only location is passed through an inline parameter
	 * other options go via parametrical options */
	if (params) {
		location = params;
	} else {
		location = lp_parm_const_string(GLOBAL_SECTION_SNUM, "config_ldap", "url", "ldap://localhost");
	}
	DEBUG(0,("config_ldap: location=%s\n", location));
	basedn = lp_parm_const_string(GLOBAL_SECTION_SNUM, "config_ldap", "basedn", NULL);
	if (basedn) config_base_dn = smb_xstrdup(basedn);
	
	if (!NT_STATUS_IS_OK(nt_status = 
			     smbldap_init(ldap_state.mem_ctx, location, 
					  &ldap_state.smbldap_state))) {
		talloc_destroy(ldap_state.mem_ctx);
		DEBUG(0,("config_ldap: smbldap_init failed!\n"));
		return nt_status;
	}

	return NT_STATUS_OK;
}

/*****************************************************************************
 End the LDAP session
*****************************************************************************/

static NTSTATUS ldap_config_close(void)
{

	smbldap_free_struct(&(ldap_state).smbldap_state);
	talloc_destroy(ldap_state.mem_ctx);
	
	DEBUG(5,("The connection to the LDAP server was closed\n"));
	/* maybe free the results here --metze */
	
	return NT_STATUS_OK;
}

static struct config_functions functions = {
	ldap_config_init,
	ldap_config_load,
	ldap_config_close
};

NTSTATUS config_ldap_init(void)
{
	return smb_register_config(SAMBA_CONFIG_INTERFACE_VERSION, "ldap", &functions);
}
