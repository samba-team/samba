/* 
   Unix SMB/CIFS implementation.
   kerberos utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   
   
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

#ifdef HAVE_KRB5

/*
  we use a prompter to avoid a crash bug in the kerberos libs when 
  dealing with empty passwords
  this prompter is just a string copy ...
*/
static krb5_error_code 
kerb_prompter(krb5_context ctx, void *data,
	       const char *name,
	       const char *banner,
	       int num_prompts,
	       krb5_prompt prompts[])
{
	if (num_prompts == 0) return 0;

	memset(prompts[0].reply->data, 0, prompts[0].reply->length);
	if (prompts[0].reply->length > 0) {
		if (data) {
			strncpy(prompts[0].reply->data, data, prompts[0].reply->length-1);
			prompts[0].reply->length = strlen(prompts[0].reply->data);
		} else {
			prompts[0].reply->length = 0;
		}
	}
	return 0;
}

/*
  simulate a kinit, putting the tgt in the default cache location
  remus@snapserver.com
*/
int kerberos_kinit_password(const char *principal, const char *password, int time_offset, time_t *expire_time)
{
	krb5_context ctx;
	krb5_error_code code = 0;
	krb5_ccache cc;
	krb5_principal me;
	krb5_creds my_creds;

	if ((code = krb5_init_context(&ctx)))
		return code;

	if (time_offset != 0) {
		krb5_set_real_time(ctx, time(NULL) + time_offset, 0);
	}
	
	if ((code = krb5_cc_default(ctx, &cc))) {
		krb5_free_context(ctx);
		return code;
	}
	
	if ((code = krb5_parse_name(ctx, principal, &me))) {
		krb5_free_context(ctx);	
		return code;
	}
	
	if ((code = krb5_get_init_creds_password(ctx, &my_creds, me, NULL, 
						 kerb_prompter, 
						 password, 0, NULL, NULL))) {
		krb5_free_principal(ctx, me);
		krb5_free_context(ctx);		
		return code;
	}
	
	if ((code = krb5_cc_initialize(ctx, cc, me))) {
		krb5_free_cred_contents(ctx, &my_creds);
		krb5_free_principal(ctx, me);
		krb5_free_context(ctx);		
		return code;
	}
	
	if ((code = krb5_cc_store_cred(ctx, cc, &my_creds))) {
		krb5_cc_close(ctx, cc);
		krb5_free_cred_contents(ctx, &my_creds);
		krb5_free_principal(ctx, me);
		krb5_free_context(ctx);		
		return code;
	}
	
	if (expire_time)
		*expire_time = (time_t) my_creds.times.endtime;

	krb5_cc_close(ctx, cc);
	krb5_free_cred_contents(ctx, &my_creds);
	krb5_free_principal(ctx, me);
	krb5_free_context(ctx);		
	
	return 0;
}



/* run kinit to setup our ccache */
int ads_kinit_password(ADS_STRUCT *ads)
{
	char *s;
	int ret;

	if (asprintf(&s, "%s@%s", ads->auth.user_name, ads->auth.realm) == -1) {
		return KRB5_CC_NOMEM;
	}

	if (!ads->auth.password) {
		return KRB5_LIBOS_CANTREADPWD;
	}
	
	ret = kerberos_kinit_password(s, ads->auth.password, ads->auth.time_offset, &ads->auth.expire);

	if (ret) {
		DEBUG(0,("kerberos_kinit_password %s failed: %s\n", 
			 s, error_message(ret)));
	}
	free(s);
	return ret;
}

int ads_kdestroy(const char *cc_name)
{
	krb5_error_code code;
	krb5_context ctx;
	krb5_ccache cc;

	if ((code = krb5_init_context (&ctx))) {
		DEBUG(3, ("ads_kdestroy: kdb5_init_context rc=%d\n", code));
		return code;
	}
  
	if (!cc_name) {
		if ((code = krb5_cc_default(ctx, &cc))) {
			krb5_free_context(ctx);
			return code;
		}
	} else {
		if ((code = krb5_cc_resolve(ctx, cc_name, &cc))) {
			DEBUG(3, ("ads_kdestroy: krb5_cc_resolve rc=%d\n",
				  code));
			krb5_free_context(ctx);
			return code;
		}
	}

	if ((code = krb5_cc_destroy (ctx, cc))) {
		DEBUG(3, ("ads_kdestroy: krb5_cc_destroy rc=%d\n", code));
	}

	krb5_free_context (ctx);
	return code;
}

#endif
