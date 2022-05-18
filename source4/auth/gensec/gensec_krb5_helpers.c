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
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "gensec_krb5_internal.h"
#include "gensec_krb5_helpers.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"

static struct gensec_krb5_state *get_private_state(const struct gensec_security *gensec_security)
{
	struct gensec_krb5_state *gensec_krb5_state = NULL;

	if (strcmp(gensec_security->ops->name, "krb5") != 0) {
		/* We require that the krb5 mechanism is being used. */
		return NULL;
	}

	gensec_krb5_state = talloc_get_type(gensec_security->private_data,
					    struct gensec_krb5_state);
	return gensec_krb5_state;
}

/*
 * Returns 1 if our ticket has the initial flag set, 0 if not, and -1 in case of
 * error.
 */
int gensec_krb5_initial_ticket(const struct gensec_security *gensec_security)
{
	struct gensec_krb5_state *gensec_krb5_state = NULL;

	gensec_krb5_state = get_private_state(gensec_security);
	if (gensec_krb5_state == NULL) {
		return -1;
	}

	if (gensec_krb5_state->ticket == NULL) {
		/* We don't have a ticket */
		return -1;
	}

#ifdef SAMBA4_USES_HEIMDAL
	return gensec_krb5_state->ticket->ticket.flags.initial;
#else /* MIT KERBEROS */
	return (gensec_krb5_state->ticket->enc_part2->flags & TKT_FLG_INITIAL) ? 1 : 0;
#endif /* SAMBA4_USES_HEIMDAL */
}
