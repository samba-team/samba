
#include "includes.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "gensec_krb5.h"

static krb5_error_code smb_krb5_get_longterm_key(krb5_context context,
						 krb5_const_principal server,
						 krb5_kvno kvno,
						 krb5_enctype etype,
						 krb5_keytab keytab,
						 krb5_keyblock **keyblock_out)
{
	krb5_error_code code = EINVAL;

	krb5_keytab_entry kt_entry;

	code = krb5_kt_get_entry(context,
				 keytab,
				 server,
				 kvno,
				 etype,
				 &kt_entry);
	if (code != 0) {
		return code;
	}

	code = krb5_copy_keyblock(context,
				  &kt_entry.key,
				  keyblock_out);
	krb5_free_keytab_entry_contents(context, &kt_entry);

	return code;
}

krb5_error_code smb_krb5_rd_req_decoded(krb5_context context,
					krb5_auth_context *auth_context,
					const krb5_data *request,
					krb5_keytab keytab,
					krb5_principal acceptor_principal,
					krb5_data *reply,
					krb5_ticket **pticket,
					krb5_keyblock **pkeyblock)
{
	krb5_error_code code;
	krb5_flags ap_req_options = 0;
	krb5_ticket *ticket = NULL;
	krb5_keyblock *keyblock = NULL;

	*pticket = NULL;
	*pkeyblock = NULL;
	reply->length = 0;
	reply->data = NULL;

	code = krb5_rd_req(context,
			   auth_context,
			   request,
			   acceptor_principal,
			   keytab,
			   &ap_req_options,
			   &ticket);
	if (code != 0) {
		DBG_ERR("krb5_rd_req failed: %s\n",
			error_message(code));
		return code;
	}

	/*
	 * Get the long term key from the keytab to be able to verify the PAC
	 * signature.
	 *
	 * FIXME: Use ticket->enc_part.kvno ???
	 * Getting the latest kvno with passing 0 fixes:
	 * make -j test TESTS="samba4.winbind.pac.ad_member"
	 */
	code = smb_krb5_get_longterm_key(context,
					 ticket->server,
					 0, /* kvno */
					 ticket->enc_part.enctype,
					 keytab,
					 &keyblock);
	if (code != 0) {
		DBG_ERR("smb_krb5_get_longterm_key failed: %s\n",
			error_message(code));
		krb5_free_ticket(context, ticket);

		return code;
	}

	code = krb5_mk_rep(context, *auth_context, reply);
	if (code != 0) {
		DBG_ERR("krb5_mk_rep failed: %s\n",
			error_message(code));
		krb5_free_ticket(context, ticket);
		krb5_free_keyblock(context, keyblock);
	}

	*pticket = ticket;
	*pkeyblock = keyblock;

	return code;
}
