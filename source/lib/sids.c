/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-2000,
   Copyright (C) Elrond               2000
   
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
#include "rpc_client.h"
#include "sids.h"


extern int DEBUGLEVEL;
extern pstring global_myname;

/*
 * This is set on startup - it defines the SID for this
 * machine, and therefore the SAM database for which it is
 * responsible.
 */

DOM_SID global_sam_sid;

/*
 * This is the name associated with the SAM database for
 * which this machine is responsible.  In the case of a PDC
 * or PDC, this name is the same as the workgroup.  In the
 * case of "security = domain" mode, this is the same as
 * the name of the server (global_myname).
 */

fstring global_sam_name; 

/*
 * This is obtained on startup - it defines the SID for which
 * this machine is a member.  It is therefore only set, and
 * used, in "security = domain" mode.
 */

DOM_SID global_member_sid;

/*
 * note the lack of a "global_member_name" - this is because
 * this is the same as "global_myworkgroup".
 */

extern fstring global_myworkgroup;
/* fstring global_member_dom_name; */

/*
 * some useful sids
 */

DOM_SID global_sid_S_1_5_32; /* local well-known domain */
DOM_SID global_sid_S_1_1;    /* Global Domain */
static DOM_SID global_sid_S_1_1_0;  /* everyone */

static DOM_SID global_sid_S_1_5_18; /* System */

const DOM_SID *global_sid_everyone = NULL;
const DOM_SID *global_sid_system = NULL;   /* NT System */
const DOM_SID *global_sid_builtin = NULL;

struct sid_map
{
	DOM_SID *sid;
	char *name;
	uint32 type;
};

struct sid_map_fill
{
	char *name;
	DOM_SID *sid;
	uint32 type;
	const char *sid_str;
};

static const struct sid_map_fill static_sid_name_map[] =
{
	{ "BUILTIN",              &global_sid_S_1_5_32, SID_NAME_DOMAIN, NULL },
	{ "Global Domain",        &global_sid_S_1_1,    SID_NAME_DOMAIN, NULL },
	{ "Everyone",             &global_sid_S_1_1_0,  SID_NAME_WKN_GRP, NULL },
	{ "LOCAL",                NULL,                 SID_NAME_WKN_GRP, "S-1-2-0" }, /* what is this ?? */
	{ "Creator Owner",        NULL,                 SID_NAME_WKN_GRP, "S-1-3-0" },
	{ "Creator Group",        NULL,                 SID_NAME_WKN_GRP, "S-1-3-1" },
	{ "Creator Server Owner", NULL,                 SID_NAME_WKN_GRP, "S-1-3-2" },
	{ "Creator Server Group", NULL,                 SID_NAME_WKN_GRP, "S-1-3-3" },
	{ "NT Authority",         NULL,                 SID_NAME_DOMAIN, "S-1-5" },
	{ "DIALUP",               NULL,                 SID_NAME_WKN_GRP, "S-1-5-1" },
	{ "NETWORK",              NULL,                 SID_NAME_WKN_GRP, "S-1-5-2" },
	{ "BATCH",                NULL,                 SID_NAME_WKN_GRP, "S-1-5-3" },
	{ "Interactive",          NULL,                 SID_NAME_WKN_GRP, "S-1-5-4" }, /* right name? */
	{ "Service",              NULL,                 SID_NAME_WKN_GRP, "S-1-5-6" }, /* right name? */
	{ "",                     NULL,                 SID_NAME_USER, "S-1-5-7" }, /* not known, but NT responds! */
	{ "SERVER LOGON",         NULL,                 SID_NAME_WKN_GRP, "S-1-5-9" },
	{ "Authenticated Users",  NULL,                 SID_NAME_WKN_GRP, "S-1-5-11" },
	{ "SYSTEM",               &global_sid_S_1_5_18, SID_NAME_WKN_GRP, NULL },
	{ global_sam_name,        &global_sam_sid,      SID_NAME_DOMAIN, NULL },
	{ global_myworkgroup,     &global_member_sid,   SID_NAME_DOMAIN, NULL },
	{ NULL,                   NULL,                 0, NULL}
};

static struct sid_map **sid_name_map = NULL;
static uint32 num_maps = 0;

static struct sid_map *sid_map_dup(const struct sid_map *from)
{
	if (from != NULL)
	{
		struct sid_map *copy = g_new(struct sid_map, 1);

		if (copy != NULL)
		{
			ZERO_STRUCTP(copy);
			if (from->name != NULL)
			{
				copy->name  = strdup(from->name );
			}
			if (from->sid != NULL)
			{
				copy->sid = sid_dup(from->sid);
			}
			copy->type = from->type;
		}
		return copy;
	}
	return NULL;
}

static void sid_map_free(struct sid_map *map)
{
	if (map->name != NULL)
	{
		free(map->name);
	}
	if (map->sid != NULL)
	{
		free(map->sid);
	}
	free(map);
}

/****************************************************************************
free a sid map array
****************************************************************************/
static void free_sidmap_array(uint32 num_entries, struct sid_map **entries)
{
	void(*fn)(void*) = (void(*)(void*))&sid_map_free;
	free_void_array(num_entries, (void**)entries, *fn);
}

/****************************************************************************
add a sid map state to the array
****************************************************************************/
struct sid_map* add_sidmap_to_array(uint32 *len, struct sid_map ***array,
				const struct sid_map *name)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&sid_map_dup;
	return (struct sid_map*)add_copy_to_array(len,
	                     (void***)array, (const void*)name, *fn, False);
				
}

/****************************************************************************
 sets up the name associated with the SAM database for which we are responsible
****************************************************************************/
static void get_sam_domain_name(void)
{
	switch (lp_server_role())
	{
		case ROLE_DOMAIN_PDC:
		case ROLE_DOMAIN_BDC:
		{
			/* we are PDC (or BDC) for a Domain */
			fstrcpy(global_sam_name, lp_workgroup());
			DEBUG(5,("get_sam_domain_name: PDC/BDC "));
			break;
		}
		case ROLE_DOMAIN_MEMBER:
		case ROLE_STANDALONE:
		{
			/* we are a "PDC", but FOR LOCAL SAM DATABASE ONLY */
			fstrcpy(global_sam_name, global_myname);
			DEBUG(5,("get_sam_domain_name: Local SAM Database "));
			break;
		}
		default:
		{
			/* no domain role, probably due to "security = share" */
			memset(global_sam_name, 0, sizeof(global_sam_name));
			DEBUG(0,("get_sam_domain_name: unknown role type!\n"));
			DEBUG(5,("get_sam_domain_name: no SAM name"));
			break;
		}
	}
	DEBUG(5,("%s\n", global_sam_name));
}

/****************************************************************************
 obtain the sid from the PDC.
****************************************************************************/
BOOL get_member_domain_sid(void)
{
	DEBUG(10,("get_member_domain_sid: "));
	switch (lp_server_role())
	{
		case ROLE_STANDALONE:
		{
			ZERO_STRUCT(global_member_sid);
			DEBUG(10,("none\n"));
			return True;
		}
		case ROLE_DOMAIN_PDC:
		{
			fstring sidstr;
			sid_copy(&global_member_sid, &global_sam_sid);
			sid_to_string(sidstr, &global_member_sid);
			DEBUG(10,("%s\n", sidstr));
			return True;
		}
		default:
		{
			/* member or BDC, we're going for connection to PDC */
			break;
		}
	}

	return get_domain_sids(lp_workgroup(), NULL, &global_member_sid);
}

/****************************************************************************
 generates and adds well known (and other) sids
****************************************************************************/
static void generate_and_add_sids(void)
{
	int i;

	for (i = 0; static_sid_name_map[i].name != NULL; i++)
	{
		struct sid_map map;
		DOM_SID sid;

		map.name = static_sid_name_map[i].name;
		map.sid = static_sid_name_map[i].sid;
		map.type = static_sid_name_map[i].type;
		if (static_sid_name_map[i].sid_str != NULL)
		{
			if (map.sid == NULL)
				map.sid = &sid;
			string_to_sid(map.sid,
				      static_sid_name_map[i].sid_str);
		}
		else
		{
			if (map.sid == NULL)
			{
				DEBUG(1, ("static_sid_name_map: invalid entry %s\n", map.name));
				continue;
			}
		}
		add_sidmap_to_array(&num_maps, &sid_name_map, &map);
	}
}

/****************************************************************************
 creates some useful well known sids
****************************************************************************/
void generate_wellknown_sids(void)
{
	string_to_sid(&global_sid_S_1_5_32, "S-1-5-32");
	string_to_sid(&global_sid_S_1_1   , "S-1-1"   );
	string_to_sid(&global_sid_S_1_1_0 , "S-1-1-0" );
	string_to_sid(&global_sid_S_1_5_18, "S-1-5-18");

	global_sid_everyone = &global_sid_S_1_1_0;
	global_sid_system   = &global_sid_S_1_5_18;
	global_sid_builtin  = &global_sid_S_1_5_32;
}

/****************************************************************************
 create a sid map table
****************************************************************************/
BOOL create_sidmap_table(void)
{
	int i;
	char **doms = NULL;
	uint32 num_doms = 0;

	generate_and_add_sids();

	enumtrustdoms(&doms, &num_doms);

	for (i = 0; i < num_doms; i++)
	{
		struct sid_map map;
		DOM_SID sid;

		map.name = doms[i];
		map.sid  = &sid;
		map.type = SID_NAME_DOMAIN;

		if (!read_sid(map.name, map.sid))
		{
			DEBUG(0, ("Could not read Domain SID %s\n",
				  map.name));
			return False;
		}
		add_sidmap_to_array(&num_maps, &sid_name_map, &map);
	}


	for (i = 0; i < num_maps; i++)
	{
		fstring sidstr;
		sid_to_string(sidstr, sid_name_map[i]->sid);
		DEBUG(10,("Map:\tDomain:\t%s\tSID:\t%s\n",
		         sid_name_map[i]->name, sidstr));
	}

	free_char_array(num_doms, doms);

	return True;
}

/****************************************************************************
 Generate the global machine sid. Look for the DOMAINNAME.SID file first, if
 not found then look in smb.conf and use it to create the DOMAINNAME.SID file.
****************************************************************************/
BOOL generate_sam_sid(char *domain_name, DOM_SID *sid)
{
	char *p;
	pstring sid_file;
	pstring machine_sid_file;
	fstring file_name;

	pstrcpy(sid_file, lp_smb_passwd_file());

	if (sid_file[0] == 0)
	{
		DEBUG(0,("cannot find smb passwd file\n"));
		return False;
	}

	p = strrchr(sid_file, '/');
	if (p != NULL)
	{
		*++p = '\0';
	}

	if (!directory_exist(sid_file, NULL)) {
		if (mkdir(sid_file, 0700) != 0) {
			DEBUG(0,("can't create private directory %s : %s\n",
				 sid_file, strerror(errno)));
			return False;
		}
	}

	pstrcpy(machine_sid_file, sid_file);
	pstrcat(machine_sid_file, "MACHINE.SID");

	slprintf(file_name, sizeof(file_name)-1, "%s.SID", domain_name);
	strupper(file_name);
	pstrcat(sid_file, file_name);
    
	if (file_exist(machine_sid_file, NULL))
	{
		if (file_exist(sid_file, NULL))
		{
			DEBUG(0,("both %s and %s exist when only one should, unable to continue\n",
			          machine_sid_file, sid_file));
			return False;
		}
		if (file_rename(machine_sid_file, sid_file))
		{
			DEBUG(0,("could not rename %s to %s.  Error was %s\n",
			          machine_sid_file, sid_file, strerror(errno)));
			return False;
		}
	}
	
	/* attempt to read the SID from the file */
	if (read_sid(domain_name, sid))
	{
		return True;
	}
  
	if (!create_new_sid(sid))
	{
		return False;
	}
	/* attempt to read the SID from the file */
	if (!write_sid(domain_name, sid))
	{
		return True;
	}
  
	/* during the attempt to write, someone else wrote? */

	/* attempt to read the SID from the file */
	if (read_sid(domain_name, sid))
	{
		return True;
	}
  
	return True;
}   

/*************************************************************
 initialise password databases, domain names, domain sid.
**************************************************************/
BOOL pwdb_initialise(BOOL is_server)
{
	get_sam_domain_name();

	if (!init_myworkgroup())
	{
		return False;
	}

	generate_wellknown_sids();

	if (is_server)
	{
		if (!generate_sam_sid(global_sam_name, &global_sam_sid))
		{
			DEBUG(0,("ERROR: Samba cannot create a SAM SID for its domain (%s).\n",
				  global_sam_name));
			return False;
		}
		if (!get_member_domain_sid())
		{
			return False;
		}
	}
	else
	{
		if (!get_domain_sids(lp_workgroup(), &global_member_sid,
		                      &global_sam_sid))
		{
			return False;
		}
	}

	return create_sidmap_table();
}

/**************************************************************************
 turns a domain name into a SID.

 *** side-effect: if the domain name is NULL, it is set to our domain ***

***************************************************************************/
BOOL map_domain_name_to_sid(DOM_SID *sid, char **nt_domain)
{
	int i = 0;

	if (nt_domain == NULL)
	{
		sid_copy(sid, &global_sam_sid);
		return True;
	}

	if ((*nt_domain) == NULL)
	{
		DEBUG(5,("map_domain_name_to_sid: overriding NULL name to %s\n",
		          global_sam_name));
		(*nt_domain) = strdup(global_sam_name);
		sid_copy(sid, &global_sam_sid);
		return True;
	}

	if ((*nt_domain)[0] == 0)
	{
		free(*nt_domain);
		(*nt_domain) = strdup(global_sam_name);
		DEBUG(5,("map_domain_name_to_sid: overriding blank name to %s\n",
		          (*nt_domain)));
		sid_copy(sid, &global_sam_sid);
		return True;
	}

	DEBUG(5,("map_domain_name_to_sid: %s\n", (*nt_domain)));

	for (i = 0; i < num_maps; i++)
	{
		DEBUG(5,("compare: %s\n", sid_name_map[i]->name));
		if (strequal(sid_name_map[i]->name, (*nt_domain)))
		{
			fstring sid_str;
			sid_copy(sid, sid_name_map[i]->sid);
			sid_to_string(sid_str, sid_name_map[i]->sid);
			DEBUG(5,("found %s\n", sid_str));
			return True;
		}
	}

	DEBUG(5,("map_domain_name_to_sid: mapping to %s not known\n",
		  (*nt_domain)));
	return False;
}

/**************************************************************************
 turns a well known / domain SID into a name and type.
***************************************************************************/
BOOL map_wk_sid_to_name(const DOM_SID *sid, char *nt_domain, uint32 *type)
{
	fstring sid_str;
	int i = 0;
	sid_to_string(sid_str, sid);

	DEBUG(5, ("map_wk_sid_to_name: %s\n", sid_str));

	for (i = 0; i < num_maps; i++)
	{
		sid_to_string(sid_str, sid_name_map[i]->sid);
		DEBUG(15, ("  compare: %s\n", sid_str));
		if (sid_equal(sid_name_map[i]->sid, sid))
		{
			if (nt_domain)
				fstrcpy(nt_domain, sid_name_map[i]->name);
			if (type)
				*type = sid_name_map[i]->type;
			DEBUG(5, ("  found %s %d\n", sid_name_map[i]->name,
				  sid_name_map[i]->type));
			return True;
		}
	}

	sid_to_string(sid_str, sid);
	DEBUG(1, ("map_wk_sid_to_name: sid %s not found\n", sid_str));

	return False;
}

/**************************************************************************
 turns a domain SID into a name.

***************************************************************************/
BOOL map_domain_sid_to_name(DOM_SID *sid, char *nt_domain)
{
	fstring sid_str;
	int i = 0;
	sid_to_string(sid_str, sid);

	DEBUG(5,("map_domain_sid_to_name: %s\n", sid_str));

	if (nt_domain == NULL)
	{
		return False;
	}

	for (i = 0; i < num_maps; i++)
	{
		sid_to_string(sid_str, sid_name_map[i]->sid);
		DEBUG(5,("compare: %s\n", sid_str));
		if (sid_equal(sid_name_map[i]->sid, sid))
		{
			fstrcpy(nt_domain, sid_name_map[i]->name);
			DEBUG(5,("found %s\n", nt_domain));
			return True;
		}
	}

	DEBUG(0,("map_domain_sid_to_name: mapping NOT IMPLEMENTED\n"));

	return False;
}

/**************************************************************************
 turns a domain SID into a domain controller name.
***************************************************************************/
BOOL map_domain_sid_to_any_dc(DOM_SID *sid, char *dc_name)
{
	fstring domain;

	if (!map_domain_sid_to_name(sid, domain))
	{
		return False;
	}

	return get_any_dc_name(domain, dc_name);
}

/**************************************************************************
 splits a name of format \DOMAIN\name or name into its two components.
 sets the DOMAIN name to global_sam_name if it has not been specified.
***************************************************************************/
BOOL split_domain_name(const char *fullname, char *domain, char *name)
{
	fstring full_name;
	char *p;

	if (fullname == NULL || domain == NULL || name == NULL)
	{
		return False;
	}

	if (fullname[0] == '\\')
	{
		fullname++;
	}
	fstrcpy(full_name, fullname);
	p = strchr(full_name+1, '\\');

	if (p != NULL)
	{
		*p = 0;
		fstrcpy(domain, full_name);
		fstrcpy(name, p+1);
	}
	else
	{
		fstrcpy(domain, global_sam_name);
		fstrcpy(name, full_name);
	}

	DEBUG(10, ("name '%s' split into domain:%s and nt name:%s'\n",
		   fullname, domain, name));
	return True;
}

/**************************************************************************
 enumerates all trusted domains
***************************************************************************/
BOOL enumtrustdoms(char ***doms, uint32 *num_entries)
{
	fstring tmp;
	char *tok;

	/* add trusted domains */

	tok = lp_trusted_domains();
	if (next_token(&tok, tmp, NULL, sizeof(tmp)))
	{
		do
		{
			fstring domain;
			split_at_first_component(tmp, domain, '=', NULL);
			add_chars_to_array(num_entries, doms, domain);

		} while (next_token(NULL, tmp, NULL, sizeof(tmp)));
	}

	return True;
}
