/* 
   Unix SMB/CIFS implementation.
   Wrapper for krb5_init_context

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   
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
#include "auth/kerberos/kerberos.h"

static int smb_krb5_context_destroy_1(void *ptr) 
{
	struct smb_krb5_context *ctx = ptr;
	krb5_free_context(ctx->krb5_context); 
	return 0;
}

static int smb_krb5_context_destroy_2(void *ptr) 
{
	struct smb_krb5_context *ctx = ptr;

	/* Otherwise krb5_free_context will try and close what we have already free()ed */
	krb5_set_warn_dest(ctx->krb5_context, NULL);
	krb5_closelog(ctx->krb5_context, ctx->logf);
	smb_krb5_context_destroy_1(ptr);
	return 0;
}

/* We never close down the DEBUG system, and no need to unreference the use */
static void smb_krb5_debug_close(void *private) {
	return;
}

static void smb_krb5_debug_wrapper(const char *timestr, const char *msg, void *private) 
{
	DEBUG(3, ("Kerberos: %s\n", msg));
}

 krb5_error_code smb_krb5_init_context(void *parent_ctx, 
				       struct smb_krb5_context **smb_krb5_context) 
{
	krb5_error_code ret;
	TALLOC_CTX *tmp_ctx;
	
	initialize_krb5_error_table();
	
	tmp_ctx = talloc_new(parent_ctx);
	*smb_krb5_context = talloc(tmp_ctx, struct smb_krb5_context);

	if (!*smb_krb5_context || !tmp_ctx) {
		talloc_free(*smb_krb5_context);
		talloc_free(tmp_ctx);
		return ENOMEM;
	}

	ret = krb5_init_context(&(*smb_krb5_context)->krb5_context);
	if (ret) {
		DEBUG(1,("krb5_init_context failed (%s)\n", 
			 error_message(ret)));
		return ret;
	}

	talloc_set_destructor(*smb_krb5_context, smb_krb5_context_destroy_1);

	if (lp_realm() && *lp_realm()) {
		char *upper_realm = strupper_talloc(tmp_ctx, lp_realm());
		if (!upper_realm) {
			DEBUG(1,("gensec_krb5_start: could not uppercase realm: %s\n", lp_realm()));
			talloc_free(tmp_ctx);
			return ENOMEM;
		}
		ret = krb5_set_default_realm((*smb_krb5_context)->krb5_context, lp_realm());
		if (ret) {
			DEBUG(1,("krb5_set_default_realm failed (%s)\n", 
				 smb_get_krb5_error_message((*smb_krb5_context)->krb5_context, ret, tmp_ctx)));
			talloc_free(tmp_ctx);
			return ret;
		}
	}

	/* TODO: Should we have a different name here? */
	ret = krb5_initlog((*smb_krb5_context)->krb5_context, "Samba", &(*smb_krb5_context)->logf);
	
	if (ret) {
		DEBUG(1,("krb5_initlog failed (%s)\n", 
			 smb_get_krb5_error_message((*smb_krb5_context)->krb5_context, ret, tmp_ctx)));
		talloc_free(tmp_ctx);
		return ret;
	}

	talloc_set_destructor(*smb_krb5_context, smb_krb5_context_destroy_2);

	ret = krb5_addlog_func((*smb_krb5_context)->krb5_context, (*smb_krb5_context)->logf, 0 /* min */, -1 /* max */, 
			       smb_krb5_debug_wrapper, smb_krb5_debug_close, NULL);
	if (ret) {
		DEBUG(1,("krb5_addlog_func failed (%s)\n", 
			 smb_get_krb5_error_message((*smb_krb5_context)->krb5_context, ret, tmp_ctx)));
		talloc_free(tmp_ctx);
		return ret;
	}
	krb5_set_warn_dest((*smb_krb5_context)->krb5_context, (*smb_krb5_context)->logf);

	talloc_steal(parent_ctx, *smb_krb5_context);
	talloc_free(tmp_ctx);

	/* Set options in kerberos */

	(*smb_krb5_context)->krb5_context->fdns = FALSE;
	
	return 0;
}

 void smb_krb5_free_context(struct smb_krb5_context *smb_krb5_context) 
{
	talloc_free(smb_krb5_context);
}
