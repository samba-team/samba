/*
   Unix SMB/CIFS implementation.

   KDC Policy

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2010

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
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "param/param.h"
#include "kdc/kdc-policy.h"

void kdc_get_policy(struct loadparm_context *lp_ctx, 
		    struct smb_krb5_context *smb_krb5_context, 
		    struct lsa_DomainInfoKerberos *k)
{
	time_t svc_tkt_lifetime;
	time_t usr_tkt_lifetime;
	time_t renewal_lifetime;

	/* These should be set and stored via Group Policy, but until then, some defaults are in order */

	/* Our KDC always re-validates the client */
	k->authentication_options = LSA_POLICY_KERBEROS_VALIDATE_CLIENT;

	lpcfg_default_kdc_policy(lp_ctx, &svc_tkt_lifetime,
				 &usr_tkt_lifetime, &renewal_lifetime);

	unix_to_nt_time(&k->service_tkt_lifetime, svc_tkt_lifetime);
	unix_to_nt_time(&k->user_tkt_lifetime, usr_tkt_lifetime);
	unix_to_nt_time(&k->user_tkt_renewaltime, renewal_lifetime);
	if (smb_krb5_context) {
		unix_to_nt_time(&k->clock_skew, 
				krb5_get_max_time_skew(smb_krb5_context->krb5_context));
	}
	k->reserved = 0;
}
