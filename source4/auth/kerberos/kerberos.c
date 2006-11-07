/* 
   Unix SMB/CIFS implementation.
   kerberos utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Nalin Dahyabhai 2004.
   Copyright (C) Jeremy Allison 2004.
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005

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
#include "system/kerberos.h"
#include "roken.h"

#ifdef HAVE_KRB5

/*
  simulate a kinit, putting the tgt in the given credentials cache. 
  Orignally by remus@snapserver.com
 
  This version is built to use a keyblock, rather than needing the
  original password.
*/
 int kerberos_kinit_keyblock_cc(krb5_context ctx, krb5_ccache cc, 
				krb5_principal principal, krb5_keyblock *keyblock,
				time_t *expire_time, time_t *kdc_time)
{
	krb5_error_code code = 0;
	krb5_creds my_creds;
	krb5_get_init_creds_opt options;

	krb5_get_init_creds_opt_init(&options);

	krb5_get_init_creds_opt_set_default_flags(ctx, NULL, NULL, &options);

	if ((code = krb5_get_init_creds_keyblock(ctx, &my_creds, principal, keyblock,
						 0, NULL, &options))) {
		return code;
	}
	
	if ((code = krb5_cc_initialize(ctx, cc, principal))) {
		krb5_free_cred_contents(ctx, &my_creds);
		return code;
	}
	
	if ((code = krb5_cc_store_cred(ctx, cc, &my_creds))) {
		krb5_free_cred_contents(ctx, &my_creds);
		return code;
	}
	
	if (expire_time) {
		*expire_time = (time_t) my_creds.times.endtime;
	}

	if (kdc_time) {
		*kdc_time = (time_t) my_creds.times.starttime;
	}

	krb5_free_cred_contents(ctx, &my_creds);
	
	return 0;
}

/*
  simulate a kinit, putting the tgt in the given credentials cache. 
  Orignally by remus@snapserver.com
*/
 int kerberos_kinit_password_cc(krb5_context ctx, krb5_ccache cc, 
				krb5_principal principal, const char *password, 
				time_t *expire_time, time_t *kdc_time)
{
	krb5_error_code code = 0;
	krb5_creds my_creds;
	krb5_get_init_creds_opt options;

	krb5_get_init_creds_opt_init(&options);

	krb5_get_init_creds_opt_set_default_flags(ctx, NULL, NULL, &options);

	if ((code = krb5_get_init_creds_password(ctx, &my_creds, principal, password, 
						 NULL, 
						 NULL, 0, NULL, &options))) {
		return code;
	}
	
	if ((code = krb5_cc_initialize(ctx, cc, principal))) {
		krb5_free_cred_contents(ctx, &my_creds);
		return code;
	}
	
	if ((code = krb5_cc_store_cred(ctx, cc, &my_creds))) {
		krb5_free_cred_contents(ctx, &my_creds);
		return code;
	}
	
	if (expire_time) {
		*expire_time = (time_t) my_creds.times.endtime;
	}

	if (kdc_time) {
		*kdc_time = (time_t) my_creds.times.starttime;
	}

	krb5_free_cred_contents(ctx, &my_creds);
	
	return 0;
}


#endif
