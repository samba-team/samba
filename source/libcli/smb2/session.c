/* 
   Unix SMB/CIFS implementation.

   SMB2 client session handling

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"

/*
  initialise a smb2_session structure
 */
struct smb2_session *smb2_session_init(struct smb2_transport *transport,
				       TALLOC_CTX *parent_ctx, BOOL primary)
{
	struct smb2_session *session;

	session = talloc_zero(parent_ctx, struct smb2_session);
	if (!session) {
		return NULL;
	}
	if (primary) {
		session->transport = talloc_steal(session, transport);
	} else {
		session->transport = talloc_reference(session, transport);
	}

	return session;
}

