/* 
   Unix SMB/CIFS implementation.

   dcerpc authentication operations

   Copyright (C) Andrew Tridgell 2003
   
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

/*
  do spnego style authentication on a gensec pipe
*/
NTSTATUS dcerpc_bind_auth_spnego(struct dcerpc_pipe *p,
			       const char *uuid, uint_t version,
			       const char *domain,
			       const char *username,
			       const char *password)
{
	NTSTATUS status;

	status = gensec_client_start(&p->security_state.generic_state);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start GENSEC client mode: %s\n", nt_errstr(status)));
		return status;
	}

	status = gensec_set_domain(p->security_state.generic_state, domain);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client domain to %s: %s\n", 
			  domain, nt_errstr(status)));
		return status;
	}

	status = gensec_set_username(p->security_state.generic_state, username);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client username to %s: %s\n", 
			  username, nt_errstr(status)));
		return status;
	}

	status = gensec_set_password(p->security_state.generic_state, password);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client password: %s\n", 
			  nt_errstr(status)));
		return status;
	}

	status = gensec_set_target_hostname(p->security_state.generic_state, p->transport.peer_name(p));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC target hostname: %s\n", 
			  nt_errstr(status)));
		return status;
	}

	status = gensec_start_mech_by_authtype(p->security_state.generic_state, DCERPC_AUTH_TYPE_SPNEGO, dcerpc_auth_level(p));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client SPNEGO mechanism: %s\n",
			  nt_errstr(status)));
		return status;
	}
	
	status = dcerpc_bind_alter(p, DCERPC_AUTH_TYPE_SPNEGO, dcerpc_auth_level(p),
				  uuid, version);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Failed to bind to pipe with SPNEGO: %s\n", nt_errstr(status)));
		return status;
	}

	return status;
}
