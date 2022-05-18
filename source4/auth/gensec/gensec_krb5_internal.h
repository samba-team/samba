/*
   Unix SMB/CIFS implementation.

   Kerberos backend for GENSEC

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   Copyright (C) Stefan Metzmacher 2004-2005

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.


   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "auth/gensec/gensec.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"

enum GENSEC_KRB5_STATE {
	GENSEC_KRB5_SERVER_START,
	GENSEC_KRB5_CLIENT_START,
	GENSEC_KRB5_CLIENT_MUTUAL_AUTH,
	GENSEC_KRB5_DONE
};

struct gensec_krb5_state {
	enum GENSEC_KRB5_STATE state_position;
	struct smb_krb5_context *smb_krb5_context;
	krb5_auth_context auth_context;
	krb5_data enc_ticket;
	krb5_keyblock *keyblock;
	krb5_ticket *ticket;
	bool gssapi;
	krb5_flags ap_req_options;
};
