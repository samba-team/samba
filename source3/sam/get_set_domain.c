/* 
   Unix SMB/CIFS implementation.
   SAM_DOMAIN access routines
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

NTSTATUS sam_get_domain_sid(SAM_DOMAIN_HANDLE *domain, const DOM_SID **sid)
{
	SAM_ASSERT(domain &&sid);

	*sid = &(domain->private.sid);

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_num_accounts(SAM_DOMAIN_HANDLE *domain, uint32 *num_accounts)
{
	SAM_ASSERT(domain &&num_accounts);

	*num_accounts = domain->private.num_accounts;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_num_groups(SAM_DOMAIN_HANDLE *domain, uint32 *num_groups)
{
	SAM_ASSERT(domain &&num_groups);

	*num_groups = domain->private.num_groups;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_num_aliases(SAM_DOMAIN_HANDLE *domain, uint32 *num_aliases)
{
	SAM_ASSERT(domain &&num_aliases);

	*num_aliases = domain->private.num_aliases;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_name(SAM_DOMAIN_HANDLE *domain, const char **domain_name)
{
	SAM_ASSERT(domain &&domain_name);

	*domain_name = domain->private.name;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_server(SAM_DOMAIN_HANDLE *domain, const char **server_name)
{
	SAM_ASSERT(domain &&server_name);

	*server_name = domain->private.servername;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_max_pwdage(SAM_DOMAIN_HANDLE *domain, NTTIME *max_passwordage)
{
	SAM_ASSERT(domain &&max_passwordage);

	*max_passwordage = domain->private.max_passwordage;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_min_pwdage(SAM_DOMAIN_HANDLE *domain, NTTIME *min_passwordage)
{
	SAM_ASSERT(domain &&min_passwordage);

	*min_passwordage = domain->private.min_passwordage;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_lockout_duration(SAM_DOMAIN_HANDLE *domain, NTTIME *lockout_duration)
{
	SAM_ASSERT(domain &&lockout_duration);

	*lockout_duration = domain->private.lockout_duration;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_reset_count(SAM_DOMAIN_HANDLE *domain, NTTIME *reset_lockout_count)
{
	SAM_ASSERT(domain &&reset_lockout_count);
	
	*reset_lockout_count = domain->private.reset_count;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_min_pwdlength(SAM_DOMAIN_HANDLE *domain, uint16 *min_passwordlength)
{
	SAM_ASSERT(domain &&min_passwordlength);

	*min_passwordlength = domain->private.min_passwordlength;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_pwd_history(SAM_DOMAIN_HANDLE *domain, uint16 *password_history)
{
	SAM_ASSERT(domain &&password_history);

	*password_history = domain->private.password_history;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_lockout_count(SAM_DOMAIN_HANDLE *domain, uint16 *lockout_count)
{
	SAM_ASSERT(domain &&lockout_count);

	*lockout_count = domain->private.lockout_count;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_domain_force_logoff(SAM_DOMAIN_HANDLE *domain, BOOL *force_logoff)
{
	SAM_ASSERT(domain &&force_logoff);

	*force_logoff = domain->private.force_logoff;

	return NT_STATUS_OK;
}


NTSTATUS sam_get_domain_login_pwdchange(SAM_DOMAIN_HANDLE *domain, BOOL *login_pwdchange)
{
	SAM_ASSERT(domain && login_pwdchange);

	*login_pwdchange = domain->private.login_pwdchange;

	return NT_STATUS_OK;
}

/* Set */

NTSTATUS sam_set_domain_name(SAM_DOMAIN_HANDLE *domain, const char *domain_name)
{
	SAM_ASSERT(domain);

	domain->private.name = talloc_strdup(domain->mem_ctx, domain_name);

	return NT_STATUS_OK;
}


NTSTATUS sam_set_domain_max_pwdage(SAM_DOMAIN_HANDLE *domain, NTTIME max_passwordage)
{
	SAM_ASSERT(domain);

	domain->private.max_passwordage = max_passwordage;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_min_pwdage(SAM_DOMAIN_HANDLE *domain, NTTIME min_passwordage)
{
	SAM_ASSERT(domain);

	domain->private.min_passwordage = min_passwordage;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_lockout_duration(SAM_DOMAIN_HANDLE *domain, NTTIME lockout_duration)
{
	SAM_ASSERT(domain);

	domain->private.lockout_duration = lockout_duration;

	return NT_STATUS_OK;
}
NTSTATUS sam_set_domain_reset_count(SAM_DOMAIN_HANDLE *domain, NTTIME reset_lockout_count)
{
	SAM_ASSERT(domain);

	domain->private.reset_count = reset_lockout_count;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_min_pwdlength(SAM_DOMAIN_HANDLE *domain, uint16 min_passwordlength)
{
	SAM_ASSERT(domain);

	domain->private.min_passwordlength = min_passwordlength;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_pwd_history(SAM_DOMAIN_HANDLE *domain, uint16 password_history)
{
	SAM_ASSERT(domain);

	domain->private.password_history = password_history;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_lockout_count(SAM_DOMAIN_HANDLE *domain, uint16 lockout_count)
{
	SAM_ASSERT(domain);

	domain->private.lockout_count = lockout_count;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_force_logoff(SAM_DOMAIN_HANDLE *domain, BOOL force_logoff)
{
	SAM_ASSERT(domain);

	domain->private.force_logoff = force_logoff;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_login_pwdchange(SAM_DOMAIN_HANDLE *domain, BOOL login_pwdchange)
{
	SAM_ASSERT(domain);

	domain->private.login_pwdchange = login_pwdchange;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_domain_server(SAM_DOMAIN_HANDLE *domain, const char *server_name)
{
	SAM_ASSERT(domain);

	domain->private.servername = talloc_strdup(domain->mem_ctx, server_name);

	return NT_STATUS_OK;
}
