/* 
   Unix SMB/CIFS implementation.
   SAM_DOMAIN access routines
   Copyright (C) Luke Kenneth Casson Leighton 	1996-1998
   Copyright (C) Andrew Bartlett			2002
   Copyright (C) Stefan (metze) Metzmacher	2002
   Copyright (C) Jelmer Vernooij 			2002
      
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SAM

NTSTATUS sam_get_domain_sid(SAM_DOMAIN_HANDLE *domain, DOM_SID **sid)
{
	if (!domain || !sid) return NT_STATUS_UNSUCCESSFUL;

	*sid = &(domain->private.sid);

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_num_accounts(SAM_DOMAIN_HANDLE *domain, uint32 *num_accounts)
{
	if (!domain || !num_accounts) return NT_STATUS_UNSUCCESSFUL;

	*num_accounts = domain->private.num_accounts;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_num_groups(SAM_DOMAIN_HANDLE *domain, uint32 *num_groups)
{
	if (!domain || !num_groups) return NT_STATUS_UNSUCCESSFUL;

	*num_groups = domain->private.num_groups;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_num_aliases(SAM_DOMAIN_HANDLE *domain, uint32 *num_aliases)
{
	if (!domain || !num_aliases) return NT_STATUS_UNSUCCESSFUL;

	*num_aliases = domain->private.num_aliases;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_name(SAM_DOMAIN_HANDLE *domain, char **domain_name)
{
	if (!domain || !domain_name) return NT_STATUS_UNSUCCESSFUL;

	*domain_name = domain->private.name;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_server(SAM_DOMAIN_HANDLE *domain, char **server_name)
{
	if (!domain || !server_name) return NT_STATUS_UNSUCCESSFUL;

	*server_name = domain->private.servername;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_max_pwdage(SAM_DOMAIN_HANDLE *domain, NTTIME *max_passwordage)
{
	if (!domain || !max_passwordage) return NT_STATUS_UNSUCCESSFUL;

	*max_passwordage = domain->private.max_passwordage;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_min_pwdage(SAM_DOMAIN_HANDLE *domain, NTTIME *min_passwordage)
{
	if (!domain || !min_passwordage) return NT_STATUS_UNSUCCESSFUL;

	*min_passwordage = domain->private.min_passwordage;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_lockout_duration(SAM_DOMAIN_HANDLE *domain, NTTIME *lockout_duration)
{
	if (!domain || !lockout_duration) return NT_STATUS_UNSUCCESSFUL;

	*lockout_duration = domain->private.lockout_duration;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_reset_count(SAM_DOMAIN_HANDLE *domain, NTTIME *reset_lockout_count)
{
	if (!domain || !reset_lockout_count) return NT_STATUS_UNSUCCESSFUL;
	
	*reset_lockout_count = domain->private.reset_count;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_min_pwdlength(SAM_DOMAIN_HANDLE *domain, uint16 *min_passwordlength)
{
	if (!domain || !min_passwordlength) return NT_STATUS_UNSUCCESSFUL;

	*min_passwordlength = domain->private.min_passwordlength;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_pwd_history(SAM_DOMAIN_HANDLE *domain, uint16 *password_history)
{
	if (!domain || !password_history) return NT_STATUS_UNSUCCESSFUL;

	*password_history = domain->private.password_history;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_lockout_count(SAM_DOMAIN_HANDLE *domain, uint16 *lockout_count)
{
	if (!domain || !lockout_count) return NT_STATUS_UNSUCCESSFUL;

	*lockout_count = domain->private.lockout_count;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_force_logoff(SAM_DOMAIN_HANDLE *domain, BOOL *force_logoff)
{
	if (!domain || !force_logoff) return NT_STATUS_UNSUCCESSFUL;

	*force_logoff = domain->private.force_logoff;

	return NT_STATUS_OK;
}


NTSTATUS sam_get_domain_login_pwdchange(SAM_DOMAIN_HANDLE *domain, BOOL *login_pwdchange)
{
	if (!domain || !login_pwdchange) return NT_STATUS_UNSUCCESSFUL;

	*login_pwdchange = domain->private.login_pwdchange;

	return NT_STATUS_OK;
}

/* Set */

NTSTATUS sam_set_domain_name(SAM_DOMAIN_HANDLE *domain, char *domain_name)
{
	if (!domain) return NT_STATUS_UNSUCCESSFUL;

	domain->private.name = talloc_strdup(domain->mem_ctx, domain_name);

	return NT_STATUS_OK;
}


NTSTATUS sam_set_domain_max_pwdage(SAM_DOMAIN_HANDLE *domain, NTTIME max_passwordage)
{
	if (!domain) return NT_STATUS_UNSUCCESSFUL;

	domain->private.max_passwordage = max_passwordage;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_min_pwdage(SAM_DOMAIN_HANDLE *domain, NTTIME min_passwordage)
{
	if (!domain) return NT_STATUS_UNSUCCESSFUL;

	domain->private.min_passwordage = min_passwordage;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_lockout_duration(SAM_DOMAIN_HANDLE *domain, NTTIME lockout_duration)
{
	if (!domain) return NT_STATUS_UNSUCCESSFUL;

	domain->private.lockout_duration = lockout_duration;

	return NT_STATUS_OK;
}
NTSTATUS sam_set_domain_reset_count(SAM_DOMAIN_HANDLE *domain, NTTIME reset_lockout_count)
{
	if (!domain) return NT_STATUS_UNSUCCESSFUL;

	domain->private.reset_count = reset_lockout_count;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_min_pwdlength(SAM_DOMAIN_HANDLE *domain, uint16 min_passwordlength)
{
	if (!domain) return NT_STATUS_UNSUCCESSFUL;

	domain->private.min_passwordlength = min_passwordlength;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_pwd_history(SAM_DOMAIN_HANDLE *domain, uint16 password_history)
{
	if (!domain) return NT_STATUS_UNSUCCESSFUL;

	domain->private.password_history = password_history;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_lockout_count(SAM_DOMAIN_HANDLE *domain, uint16 lockout_count)
{
	if (!domain) return NT_STATUS_UNSUCCESSFUL;

	domain->private.lockout_count = lockout_count;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_force_logoff(SAM_DOMAIN_HANDLE *domain, BOOL force_logoff)
{
	if (!domain) return NT_STATUS_UNSUCCESSFUL;

	domain->private.force_logoff = force_logoff;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_login_pwdchange(SAM_DOMAIN_HANDLE *domain, BOOL login_pwdchange)
{
	if (!domain) return NT_STATUS_UNSUCCESSFUL;

	domain->private.login_pwdchange = login_pwdchange;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_server(SAM_DOMAIN_HANDLE *domain, char *server_name)
{
	if (!domain) return NT_STATUS_UNSUCCESSFUL;

	domain->private.servername = talloc_strdup(domain->mem_ctx, server_name);

	return NT_STATUS_OK;
}
