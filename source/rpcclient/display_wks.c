/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) David Flynn                       2000
   
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
 display structure (written by David Flynn)
 ****************************************************************************/
void display_wks_info_100(FILE * out_hnd, enum action_type action,
			  const WKS_INFO_100 * const svc)
{
	switch (action)

	{
		case ACTION_HEADER:

		{
			break;
		}
		case ACTION_ENUMERATE:

		{
			fstring temp;
			unistr_to_ascii(temp, svc->uni_compname.buffer,
					sizeof(temp) - 1);
			report(out_hnd, "Name:\t\t%s\n", temp);
			unistr_to_ascii(temp, svc->uni_lan_grp.buffer,
					sizeof(temp) - 1);
			report(out_hnd, "Domain:\t\t%s\n", temp);
			report(out_hnd, "Platform:\t%d\n", svc->platform_id);
			report(out_hnd, "Version:\t%d.%d\n",
			       svc->ver_major, svc->ver_minor);
			break;
		}
		case ACTION_FOOTER:

		{
			break;
		}
	}
}
