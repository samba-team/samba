/* 
 *  Unix SMB/CIFS implementation.
 *  Group Policy Object Support
 *  Copyright (C) Guenther Deschner 2005
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

#ifdef HAVE_LDAP

#define GPT_INI_SECTION_GENERAL "General"
#define GPT_INI_PARAMETER_VERSION "Version"
#define GPT_INI_PARAMETER_DISPLAYNAME "displayName"

struct gpt_ini {
	uint32 version;
	const char *display_name;
};

static uint32 version;

static BOOL do_section(const char *section)
{
	DEBUG(10,("do_section: %s\n", section));

	return True;
}

static BOOL do_parameter(const char *parameter, const char *value)
{
	DEBUG(10,("do_parameter: %s, %s\n", parameter, value));
	
	if (strequal(parameter, GPT_INI_PARAMETER_VERSION)) {
		version = atoi(value);
	}
	return True;
}

/*

perfectly parseable with pm_process() :))

[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 42
MinimumPasswordLength = 7
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 0
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 0
ClearTextPassword = 0
[Kerberos Policy]
MaxTicketAge = 10
MaxRenewAge = 7
MaxServiceAge = 600
MaxClockSkew = 5
TicketValidateClient = 1
[Version]
signature="$CHICAGO$"
Revision=1
*/

#endif /* HAVE_LDAP */
