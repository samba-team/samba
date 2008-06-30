/*
   Unix SMB/CIFS implementation.
   dump the remote SAM using rpc samsync operations

   Copyright (C) Guenther Deschner 2008.

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
#include "libnet/libnet.h"

#ifdef HAVE_KRB5

/****************************************************************
****************************************************************/

static int keytab_close(struct libnet_keytab_context *ctx)
{
	if (!ctx) {
		return 0;
	}

	if (ctx->keytab && ctx->context) {
		krb5_kt_close(ctx->context, ctx->keytab);
	}

	if (ctx->context) {
		krb5_free_context(ctx->context);
	}

	if (ctx->ads) {
		ads_destroy(&ctx->ads);
	}

	TALLOC_FREE(ctx);

	return 0;
}

/****************************************************************
****************************************************************/

krb5_error_code libnet_keytab_init(TALLOC_CTX *mem_ctx,
				   const char *keytab_name,
				   struct libnet_keytab_context **ctx)
{
	krb5_error_code ret = 0;
	krb5_context context = NULL;
	krb5_keytab keytab = NULL;
	const char *keytab_string = NULL;

	struct libnet_keytab_context *r;

	r = TALLOC_ZERO_P(mem_ctx, struct libnet_keytab_context);
	if (!r) {
		return ENOMEM;
	}

	talloc_set_destructor(r, keytab_close);

	initialize_krb5_error_table();
	ret = krb5_init_context(&context);
	if (ret) {
		DEBUG(1,("keytab_init: could not krb5_init_context: %s\n",
			error_message(ret)));
		return ret;
	}

	ret = smb_krb5_open_keytab(context, keytab_name, true, &keytab);
	if (ret) {
		DEBUG(1,("keytab_init: smb_krb5_open_keytab failed (%s)\n",
			error_message(ret)));
		krb5_free_context(context);
		return ret;
	}

	ret = smb_krb5_keytab_name(mem_ctx, context, keytab, &keytab_string);
	if (ret) {
		krb5_kt_close(context, keytab);
		krb5_free_context(context);
		return ret;
	}

	r->context = context;
	r->keytab = keytab;
	r->keytab_name = keytab_string;

	*ctx = r;

	return 0;
}

/****************************************************************
****************************************************************/

krb5_error_code libnet_keytab_add(struct libnet_keytab_context *ctx)
{
#if defined(ENCTYPE_ARCFOUR_HMAC)
	krb5_error_code ret = 0;
	krb5_enctype enctypes[2] = { ENCTYPE_ARCFOUR_HMAC, 0 };
	int i;

	for (i=0; i<ctx->count; i++) {

		struct libnet_keytab_entry *entry = &ctx->entries[i];
		krb5_data password;

		password.data = (char *)entry->password.data;
		password.length = entry->password.length;

		ret = smb_krb5_kt_add_entry_ext(ctx->context,
						ctx->keytab,
						entry->kvno,
						entry->principal,
						enctypes,
						password,
						true);
		if (ret) {
			DEBUG(1,("libnet_keytab_add: "
				"Failed to add entry to keytab file\n"));
			return ret;
		}
	}

	return ret;
#else
	return -1;
#endif /* defined(ENCTYPE_ARCFOUR_HMAC) */
}

#endif /* HAVE_KRB5 */
