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
  do ntlm style authentication on a gensec pipe
*/
NTSTATUS dcerpc_bind_auth_ntlm(struct dcerpc_pipe *p,
			       const char *uuid, uint_t version,
			       const char *domain,
			       const char *username,
			       const char *password)
{
	NTSTATUS status;

	p->security_state.generic_state.user.domain = domain;
	p->security_state.generic_state.user.name = username;
	p->security_state.generic_state.user.password = password;

	status = dcerpc_bind_auth(p, DCERPC_AUTH_TYPE_NTLMSSP,
				  uuid, version);

	return status;
}
