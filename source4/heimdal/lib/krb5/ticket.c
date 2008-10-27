/*
 * Copyright (c) 1997 - 2001 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code KRB5_LIB_FUNCTION
krb5_free_ticket(krb5_context context,
		 krb5_ticket *ticket)
{
    free_EncTicketPart(&ticket->ticket);
    krb5_free_principal(context, ticket->client);
    krb5_free_principal(context, ticket->server);
    free(ticket);
    return 0;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_copy_ticket(krb5_context context,
		 const krb5_ticket *from,
		 krb5_ticket **to)
{
    krb5_error_code ret;
    krb5_ticket *tmp;

    *to = NULL;
    tmp = malloc(sizeof(*tmp));
    if(tmp == NULL) {
	krb5_set_error_message(context, ENOMEM,
			       N_("malloc: out of memory", ""));
	return ENOMEM;
    }
    if((ret = copy_EncTicketPart(&from->ticket, &tmp->ticket))){
	free(tmp);
	return ret;
    }
    ret = krb5_copy_principal(context, from->client, &tmp->client);
    if(ret){
	free_EncTicketPart(&tmp->ticket);
	free(tmp);
	return ret;
    }
    ret = krb5_copy_principal(context, from->server, &tmp->server);
    if(ret){
	krb5_free_principal(context, tmp->client);
	free_EncTicketPart(&tmp->ticket);
	free(tmp);
	return ret;
    }
    *to = tmp;
    return 0;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_ticket_get_client(krb5_context context,
		       const krb5_ticket *ticket,
		       krb5_principal *client)
{
    return krb5_copy_principal(context, ticket->client, client);
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_ticket_get_server(krb5_context context,
		       const krb5_ticket *ticket,
		       krb5_principal *server)
{
    return krb5_copy_principal(context, ticket->server, server);
}

time_t KRB5_LIB_FUNCTION
krb5_ticket_get_endtime(krb5_context context,
			const krb5_ticket *ticket)
{
    return ticket->ticket.endtime;
}

/**
 * Get the flags from the Kerberos ticket
 *
 * @param context Kerberos context
 * @param ticket Kerberos ticket
 *
 * @return ticket flags
 *
 * @ingroup krb5_ticket
 */
unsigned long
krb5_ticket_get_flags(krb5_context context,
		      const krb5_ticket *ticket)
{
    return TicketFlags2int(ticket->ticket.flags);
}

static int
find_type_in_ad(krb5_context context,
		int type,
		krb5_data *data,
		krb5_boolean *found,
		krb5_boolean failp,
		krb5_keyblock *sessionkey,
		const AuthorizationData *ad,
		int level)
{
    krb5_error_code ret = 0;
    int i;

    if (level > 9) {
	ret = ENOENT; /* XXX */
	krb5_set_error_message(context, ret,
			       N_("Authorization data nested deeper "
				  "then %d levels, stop searching", ""),
			       level);
	goto out;
    }

    /*
     * Only copy out the element the first time we get to it, we need
     * to run over the whole authorization data fields to check if
     * there are any container clases we need to care about.
     */
    for (i = 0; i < ad->len; i++) {
	if (!*found && ad->val[i].ad_type == type) {
	    ret = der_copy_octet_string(&ad->val[i].ad_data, data);
	    if (ret) {
		krb5_set_error_message(context, ret,
				       N_("malloc: out of memory", ""));
		goto out;
	    }
	    *found = TRUE;
	    continue;
	}
	switch (ad->val[i].ad_type) {
	case KRB5_AUTHDATA_IF_RELEVANT: {
	    AuthorizationData child;
	    ret = decode_AuthorizationData(ad->val[i].ad_data.data,
					   ad->val[i].ad_data.length,
					   &child,
					   NULL);
	    if (ret) {
		krb5_set_error_message(context, ret,
				       N_("Failed to decode "
					  "IF_RELEVANT with %d", ""),
				       (int)ret);
		goto out;
	    }
	    ret = find_type_in_ad(context, type, data, found, FALSE,
				  sessionkey, &child, level + 1);
	    free_AuthorizationData(&child);
	    if (ret)
		goto out;
	    break;
	}
#if 0 /* XXX test */
	case KRB5_AUTHDATA_KDC_ISSUED: {
	    AD_KDCIssued child;

	    ret = decode_AD_KDCIssued(ad->val[i].ad_data.data,
				      ad->val[i].ad_data.length,
				      &child,
				      NULL);
	    if (ret) {
		krb5_set_error_message(context, ret,
				       N_("Failed to decode "
					  "AD_KDCIssued with %d", ""),
				       ret);
		goto out;
	    }
	    if (failp) {
		krb5_boolean valid;
		krb5_data buf;
		size_t len;

		ASN1_MALLOC_ENCODE(AuthorizationData, buf.data, buf.length,
				   &child.elements, &len, ret);
		if (ret) {
		    free_AD_KDCIssued(&child);
		    krb5_clear_error_message(context);
		    goto out;
		}
		if(buf.length != len)
		    krb5_abortx(context, "internal error in ASN.1 encoder");

		ret = krb5_c_verify_checksum(context, sessionkey, 19, &buf,
					     &child.ad_checksum, &valid);
		krb5_data_free(&buf);
		if (ret) {
		    free_AD_KDCIssued(&child);
		    goto out;
		}
		if (!valid) {
		    krb5_clear_error_message(context);
		    ret = ENOENT;
		    free_AD_KDCIssued(&child);
		    goto out;
		}
	    }
	    ret = find_type_in_ad(context, type, data, found, failp, sessionkey,
				  &child.elements, level + 1);
	    free_AD_KDCIssued(&child);
	    if (ret)
		goto out;
	    break;
	}
#endif
	case KRB5_AUTHDATA_AND_OR:
	    if (!failp)
		break;
	    ret = ENOENT; /* XXX */
	    krb5_set_error_message(context, ret,
				   N_("Authorization data contains "
				      "AND-OR element that is unknown to the "
				      "application", ""));
	    goto out;
	default:
	    if (!failp)
		break;
	    ret = ENOENT; /* XXX */
	    krb5_set_error_message(context, ret,
				   N_("Authorization data contains "
				      "unknown type (%d) ", ""),
				   ad->val[i].ad_type);
	    goto out;
	}
    }
out:
    if (ret) {
	if (*found) {
	    krb5_data_free(data);
	    *found = 0;
	}
    }
    return ret;
}

/*
 * Extract the authorization data type of `type' from the
 * 'ticket'. Store the field in `data'. This function is to use for
 * kerberos applications.
 */

krb5_error_code KRB5_LIB_FUNCTION
krb5_ticket_get_authorization_data_type(krb5_context context,
					krb5_ticket *ticket,
					int type,
					krb5_data *data)
{
    AuthorizationData *ad;
    krb5_error_code ret;
    krb5_boolean found = FALSE;

    krb5_data_zero(data);

    ad = ticket->ticket.authorization_data;
    if (ticket->ticket.authorization_data == NULL) {
	krb5_set_error_message(context, ENOENT,
			       N_("Ticket have not authorization data", ""));
	return ENOENT; /* XXX */
    }

    ret = find_type_in_ad(context, type, data, &found, TRUE,
			  &ticket->ticket.key, ad, 0);
    if (ret)
	return ret;
    if (!found) {
	krb5_set_error_message(context, ENOENT,
			       N_("Ticket have not "
				  "authorization data of type %d", ""),
			       type);
	return ENOENT; /* XXX */
    }
    return 0;
}
