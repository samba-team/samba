/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996 - 1999
   
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
#include "rpcclient.h"


/****************************************************************************
convert a security permissions into a string
****************************************************************************/
static const char *get_sec_mask_str(uint32 type)
{
	static fstring typestr;
	int i;

	switch (type)
	{
		case SEC_RIGHTS_FULL_CONTROL:
		{
			fstrcpy(typestr, "Full Control");
			return typestr;
		}

		case SEC_RIGHTS_READ:
		{
			fstrcpy(typestr, "Read");
			return typestr;
		}
		default:
		{
			break;
		}
	}

	typestr[0] = 0;
	for (i = 0; i < 32; i++)
	{
		if (IS_BITS_SET_ALL(type, 1 << i))
		{
			switch (1 << i)
			{
				case SEC_RIGHTS_QUERY_VALUE    : fstrcat(typestr, "Query " ); break;
				case SEC_RIGHTS_SET_VALUE      : fstrcat(typestr, "Set " ); break;
				case SEC_RIGHTS_CREATE_SUBKEY  : fstrcat(typestr, "Create "); break;
				case SEC_RIGHTS_ENUM_SUBKEYS   : fstrcat(typestr, "Enum "); break;
				case SEC_RIGHTS_NOTIFY         : fstrcat(typestr, "Notify "); break;
				case SEC_RIGHTS_CREATE_LINK    : fstrcat(typestr, "CreateLink "); break;
				case SEC_RIGHTS_DELETE         : fstrcat(typestr, "Delete "); break;
				case SEC_RIGHTS_READ_CONTROL   : fstrcat(typestr, "ReadControl "); break;
				case SEC_RIGHTS_WRITE_DAC      : fstrcat(typestr, "WriteDAC "); break;
				case SEC_RIGHTS_WRITE_OWNER    : fstrcat(typestr, "WriteOwner "); break;
			}
			type &= ~(1 << i);
		}
	}

	/* remaining bits get added on as-is */
	if (type != 0)
	{
		fstring tmp;
		slprintf(tmp, sizeof(tmp)-1, "[%08x]", type);
		fstrcat(typestr, tmp);
	}

	/* remove last space */
	i = strlen(typestr)-1;
	if (typestr[i] == ' ') typestr[i] = 0;

	return typestr;
}

/****************************************************************************
 display sec_access structure
 ****************************************************************************/
static void display_sec_access(FILE *out_hnd, enum action_type action, SEC_ACCESS *const info)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			report(out_hnd, "\t\tPermissions:\t%s\n", 
			        get_sec_mask_str(info->mask));
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
 display sec_ace structure
 ****************************************************************************/
static void display_sec_ace(FILE *out_hnd, enum action_type action, SEC_ACE *const ace)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "\tACE\n");
			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring sid_str;

			report(out_hnd,
			       "\t\tType:%2x  Flags:%2x  Perms:%04x\n",
			       ace->type, ace->flags,
			       (uint32) ace->info.mask);

			display_sec_access(out_hnd, ACTION_HEADER   , &ace->info);
			display_sec_access(out_hnd, ACTION_ENUMERATE, &ace->info);
			display_sec_access(out_hnd, ACTION_FOOTER   , &ace->info);

			sid_to_string(sid_str, &ace->sid);
			report(out_hnd, "\t\tSID:\t%s\n", sid_str);
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
 display sec_acl structure
 ****************************************************************************/
static void display_sec_acl(FILE *out_hnd, enum action_type action, SEC_ACL *const sec_acl)
{
	if (sec_acl == NULL)
	{
		return;
	}
	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "\tACL\tNum ACEs:\t%d\trevision:\t%x\n", 
			                 sec_acl->num_aces, sec_acl->revision); 
			report(out_hnd, "\t---\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			if (sec_acl->size != 0 && sec_acl->num_aces != 0)
			{
				int i;
				for (i = 0; i < sec_acl->num_aces; i++)
				{
					display_sec_ace(out_hnd, ACTION_HEADER   , &sec_acl->ace[i]);
					display_sec_ace(out_hnd, ACTION_ENUMERATE, &sec_acl->ace[i]);
					display_sec_ace(out_hnd, ACTION_FOOTER   , &sec_acl->ace[i]);
				}
			}
				
			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}

/****************************************************************************
 display sec_desc structure
 ****************************************************************************/
void display_sec_desc(FILE *out_hnd, enum action_type action, SEC_DESC *const sec)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "\tSecurity Descriptor\trevision:\t%x\ttype:\t%x\n", 
			                 sec->revision, sec->type); 
			report(out_hnd, "\t-------------------\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring sid_str;

			if (sec->off_sacl != 0)
			{
				display_sec_acl(out_hnd, ACTION_HEADER   , sec->sacl);
				display_sec_acl(out_hnd, ACTION_ENUMERATE, sec->sacl);
				display_sec_acl(out_hnd, ACTION_FOOTER   , sec->sacl);
			}
			if (sec->off_dacl != 0)
			{
				display_sec_acl(out_hnd, ACTION_HEADER   , sec->dacl);
				display_sec_acl(out_hnd, ACTION_ENUMERATE, sec->dacl);
				display_sec_acl(out_hnd, ACTION_FOOTER   , sec->dacl);
			}
			if (sec->off_owner_sid != 0)
			{
				sid_to_string(sid_str, sec->owner_sid);
				report(out_hnd, "\tOwner SID:\t%s\n", sid_str);
			}
			if (sec->off_grp_sid != 0)
			{
				sid_to_string(sid_str, sec->grp_sid);
				report(out_hnd, "\tParent SID:\t%s\n", sid_str);
			}
				
			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}

