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


/****************************************************************************
convert a security permissions into a string
****************************************************************************/
char *get_svc_start_type_str(uint32 type)
{
	static fstring typestr;

	switch (type)
	{
		case 0x00: fstrcpy(typestr, "Boot"    ); return typestr;
		case 0x01: fstrcpy(typestr, "System"  ); return typestr;
		case 0x02: fstrcpy(typestr, "Auto"    ); return typestr;
		case 0x03: fstrcpy(typestr, "Manual"  ); return typestr;
		case 0x04: fstrcpy(typestr, "Disabled"); return typestr;
		default  : break;
	}
	slprintf(typestr, sizeof(typestr)-1, "[%d]", type);
	return typestr;
}


/****************************************************************************
 display structure
 ****************************************************************************/
void display_query_svc_cfg(FILE *out_hnd, enum action_type action, 
				const QUERY_SERVICE_CONFIG *const cfg)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fstring service;

			unistr2_to_ascii(service, &cfg->uni_display_name, sizeof(service)-1);
			report(out_hnd, "\tService:\t%s\n", service);
			report(out_hnd, "\t-------\n");
			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring temp;

			unistr2_to_ascii(temp, &cfg->uni_bin_path_name, sizeof(temp)-1);
			report(out_hnd, "\tPath:\t%s\n", temp);

			unistr2_to_ascii(temp, &cfg->uni_load_order_grp, sizeof(temp)-1);
			report(out_hnd, "\tLoad Order:\t%s\n", temp);

			unistr2_to_ascii(temp, &cfg->uni_dependencies, sizeof(temp)-1);
			report(out_hnd, "\tDependencies:\t%s\n", temp);

			unistr2_to_ascii(temp, &cfg->uni_service_start_name, sizeof(temp)-1);
			report(out_hnd, "\tService Start:\t%s\n", temp);

			report(out_hnd, "\tService Type:\t%d\n", cfg->service_type);
			report(out_hnd, "\tStart Type:\t%s\n" , get_svc_start_type_str(cfg->start_type));
			report(out_hnd, "\tError Control:\t%d\n" , cfg->error_control);
			report(out_hnd, "\tTag Id:\t%d\n" , cfg->tag_id);
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
 display structure
 ****************************************************************************/
void display_svc_info(FILE *out_hnd, enum action_type action,
				const ENUM_SRVC_STATUS *const svc)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring name;

			unistr_to_ascii(name, svc->uni_srvc_name.buffer, 
					sizeof(name)-1); /* service name */
			report(out_hnd, "\t%s:", name);

			unistr_to_ascii(name, svc->uni_disp_name.buffer, 
					sizeof(name)-1); /* display name */
			report(out_hnd, "\t%s\n", name);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

