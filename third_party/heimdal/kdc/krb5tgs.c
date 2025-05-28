/*
 * Copyright (c) 1997-2008 Kungliga Tekniska Högskolan
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

#include "kdc_locl.h"

/*
 * return the realm of a krbtgt-ticket or NULL
 */

static Realm
get_krbtgt_realm(const PrincipalName *p)
{
    if(p->name_string.len == 2
       && strcmp(p->name_string.val[0], KRB5_TGS_NAME) == 0)
	return p->name_string.val[1];
    else
	return NULL;
}

/*
 * return TRUE if client was a synthetic principal, as indicated by
 * authorization data
 */
krb5_boolean
_kdc_synthetic_princ_used_p(krb5_context context, krb5_ticket *ticket)
{
    krb5_data synthetic_princ_used;
    krb5_error_code ret;

    ret = krb5_ticket_get_authorization_data_type(context, ticket,
                                                  KRB5_AUTHDATA_SYNTHETIC_PRINC_USED,
                                                  &synthetic_princ_used);
    if (ret == ENOENT)
	ret = krb5_ticket_get_authorization_data_type(context, ticket,
						      KRB5_AUTHDATA_INITIAL_VERIFIED_CAS,
						      &synthetic_princ_used);

    if (ret == 0)
	krb5_data_free(&synthetic_princ_used);

    return ret == 0;
}

/*
 *
 */

krb5_error_code
_kdc_check_pac(astgs_request_t r,
	       const krb5_principal client_principal,
	       hdb_entry *delegated_proxy,
	       hdb_entry *client,
	       hdb_entry *server,
	       hdb_entry *krbtgt,
	       hdb_entry *ticket_server,
	       const EncryptionKey *server_check_key,
	       const EncryptionKey *krbtgt_check_key,
	       EncTicketPart *tkt,
	       krb5_boolean *kdc_issued,
	       krb5_pac *ppac,
	       krb5_principal *pac_canon_name,
	       uint64_t *pac_attributes)
{
    krb5_context context = r->context;
    krb5_kdc_configuration *config = r->config;
    krb5_pac pac = NULL;
    krb5_error_code ret;
    krb5_boolean signedticket;

    *kdc_issued = FALSE;
    *ppac = NULL;
    if (pac_canon_name)
	*pac_canon_name = NULL;
    if (pac_attributes)
	*pac_attributes = KRB5_PAC_WAS_GIVEN_IMPLICITLY;

    ret = _krb5_kdc_pac_ticket_parse(context, tkt, &signedticket, &pac);
    if (ret)
	return ret;

    if (pac == NULL) {
	if (config->require_pac)
	    ret = KRB5KDC_ERR_TGT_REVOKED;
	return ret;
    }

    /* Verify the server signature. */
    ret = krb5_pac_verify(context, pac, tkt->authtime, client_principal,
			  server_check_key, NULL);
    if (ret) {
	krb5_pac_free(context, pac);
	return ret;
    }

    /* Verify the KDC signatures. */
    ret = _kdc_pac_verify(r,
			  client_principal, delegated_proxy,
			  client, server, krbtgt, tkt, pac);
    if (ret == 0) {
	if (pac_canon_name) {
	    ret = _krb5_pac_get_canon_principal(context, pac, pac_canon_name);
	    if (ret && ret != ENOENT) {
		krb5_pac_free(context, pac);
		return ret;
	    }
	}
	if (pac_attributes &&
	    _krb5_pac_get_attributes_info(context, pac, pac_attributes) != 0)
	    *pac_attributes = KRB5_PAC_WAS_GIVEN_IMPLICITLY;
    } else if (ret == KRB5_PLUGIN_NO_HANDLE) {
	/*
	 * We can't verify the KDC signatures if the ticket was issued by
	 * another realm's KDC.
	 */
	if (krb5_realm_compare(context, server->principal,
			       ticket_server->principal)) {
	    ret = krb5_pac_verify(context, pac, 0, NULL, NULL,
				  krbtgt_check_key);
	    if (ret) {
		krb5_pac_free(context, pac);
		return ret;
	    }
	}

	if (pac_canon_name) {
	    ret = _krb5_pac_get_canon_principal(context, pac, pac_canon_name);
	    if (ret && ret != ENOENT) {
		krb5_pac_free(context, pac);
		return ret;
	    }
	}
	if (pac_attributes &&
	    _krb5_pac_get_attributes_info(context, pac, pac_attributes) != 0)
	    *pac_attributes = KRB5_PAC_WAS_GIVEN_IMPLICITLY;

	/* Discard the PAC if the plugin didn't handle it */
	krb5_pac_free(context, pac);
	ret = krb5_pac_init(context, &pac);
	if (ret)
	    return ret;
    } else {
	krb5_pac_free(context, pac);
	return ret;
    }

    *kdc_issued = signedticket ||
		  krb5_principal_is_krbtgt(context,
					   ticket_server->principal);
    *ppac = pac;

    return 0;
}

static krb5_boolean
is_anon_tgs_request_p(const KDC_REQ_BODY *b,
		      const EncTicketPart *tgt)
{
    KDCOptions f = b->kdc_options;

    /*
     * Versions of Heimdal from 1.0 to 7.6, inclusive, send both the
     * request-anonymous and cname-in-addl-tkt flags for constrained
     * delegation requests. A true anonymous TGS request will only
     * have the request-anonymous flag set. (A corollary of this is
     * that it is not possible to support anonymous constrained
     * delegation requests, although they would be of limited utility.)
     */
    return tgt->flags.anonymous ||
	(f.request_anonymous && !f.cname_in_addl_tkt && !b->additional_tickets);
}

/*
 *
 */

static krb5_error_code
check_tgs_flags(astgs_request_t r, KDC_REQ_BODY *b,
		krb5_const_principal tgt_name,
		const EncTicketPart *tgt, EncTicketPart *et)
{
    KDCOptions f = b->kdc_options;

    if(f.validate){
	if (!tgt->flags.invalid || tgt->starttime == NULL) {
	    kdc_audit_addreason((kdc_request_t)r,
                                "Bad request to validate ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	if(*tgt->starttime > kdc_time){
	    kdc_audit_addreason((kdc_request_t)r,
                                "Early request to validate ticket");
	    return KRB5KRB_AP_ERR_TKT_NYV;
	}
	/* XXX  tkt = tgt */
	et->flags.invalid = 0;
    } else if (tgt->flags.invalid) {
	kdc_audit_addreason((kdc_request_t)r,
                            "Ticket-granting ticket has INVALID flag set");
	return KRB5KRB_AP_ERR_TKT_INVALID;
    }

    if(f.forwardable){
	if (!tgt->flags.forwardable) {
	    kdc_audit_addreason((kdc_request_t)r,
                                "Bad request for forwardable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.forwardable = 1;
    }
    if(f.forwarded){
	if (!tgt->flags.forwardable) {
	    kdc_audit_addreason((kdc_request_t)r,
                                "Request to forward non-forwardable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.forwarded = 1;
	et->caddr = b->addresses;
    }
    if(tgt->flags.forwarded)
	et->flags.forwarded = 1;

    if(f.proxiable){
	if (!tgt->flags.proxiable) {
	    kdc_audit_addreason((kdc_request_t)r,
                                "Bad request for proxiable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.proxiable = 1;
    }
    if(f.proxy){
	if (!tgt->flags.proxiable) {
	    kdc_audit_addreason((kdc_request_t)r,
                                "Request to proxy non-proxiable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.proxy = 1;
	et->caddr = b->addresses;
    }
    if(tgt->flags.proxy)
	et->flags.proxy = 1;

    if(f.allow_postdate){
	if (!tgt->flags.may_postdate) {
	    kdc_audit_addreason((kdc_request_t)r,
                                "Bad request for post-datable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.may_postdate = 1;
    }
    if(f.postdated){
	if (!tgt->flags.may_postdate) {
	    kdc_audit_addreason((kdc_request_t)r,
                                "Bad request for postdated ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	if(b->from)
	    *et->starttime = *b->from;
	et->flags.postdated = 1;
	et->flags.invalid = 1;
    } else if (b->from && *b->from > kdc_time + r->context->max_skew) {
	kdc_audit_addreason((kdc_request_t)r,
                            "Ticket cannot be postdated");
	return KRB5KDC_ERR_CANNOT_POSTDATE;
    }

    if(f.renewable){
	if (!tgt->flags.renewable || tgt->renew_till == NULL) {
	    kdc_audit_addreason((kdc_request_t)r,
                                "Bad request for renewable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.renewable = 1;
	ALLOC(et->renew_till);
	_kdc_fix_time(&b->rtime);
	*et->renew_till = *b->rtime;
    }
    if(f.renew){
	time_t old_life;
	if (!tgt->flags.renewable || tgt->renew_till == NULL) {
	    kdc_audit_addreason((kdc_request_t)r,
                                "Request to renew non-renewable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	old_life = tgt->endtime;
	if(tgt->starttime)
	    old_life -= *tgt->starttime;
	else
	    old_life -= tgt->authtime;
	et->endtime = *et->starttime + old_life;
	if (et->renew_till != NULL)
	    et->endtime = min(*et->renew_till, et->endtime);
    }

    /*
     * RFC 8062 section 3 defines an anonymous ticket as one containing
     * the anonymous principal and the anonymous ticket flag.
     */
    if (tgt->flags.anonymous &&
	!_kdc_is_anonymous(r->context, tgt_name)) {
	kdc_audit_addreason((kdc_request_t)r,
                            "Anonymous ticket flag set without "
			 "anonymous principal");
	return KRB5KDC_ERR_BADOPTION;
    }

    /*
     * RFC 8062 section 4.2 states that if the TGT is anonymous, the
     * anonymous KDC option SHOULD be set, but it is not required.
     * Treat an anonymous TGT as if the anonymous flag was set.
     */
    if (is_anon_tgs_request_p(b, tgt))
	et->flags.anonymous = 1;

    return 0;
}

/*
 * Determine if s4u2self is allowed from this client to this server
 *
 * also:
 *
 * Check that the client (user2user TGT, enc-tkt-in-skey) hosts the
 * service given by the client.
 *
 * For example, regardless of the principal being impersonated, if the
 * 'client' and 'server' (target) are the same, or server is an SPN
 * alias of client, then it's safe.
 */

krb5_error_code
_kdc_check_client_matches_target_service(krb5_context context,
					 krb5_kdc_configuration *config,
					 HDB *clientdb,
					 hdb_entry *client,
					 hdb_entry *target_server,
					 krb5_const_principal target_server_principal)
{
    krb5_error_code ret;

    /*
     * Always allow the plugin to check, this might be faster, allow a
     * policy or audit check and can look into the DB records
     * directly
     */
    if (clientdb->hdb_check_client_matches_target_service) {
	ret = clientdb->hdb_check_client_matches_target_service(context,
								clientdb,
								client,
								target_server);
	if (ret == 0)
	    return 0;
    } else if (krb5_principal_compare(context,
				      client->principal,
				      target_server_principal) == TRUE) {
	/* if client does a s4u2self to itself, and there is no plugin, that is ok */
	return 0;
    } else {
	ret = KRB5KDC_ERR_BADOPTION;
    }
    return ret;
}

/*
 *
 */

krb5_error_code
_kdc_verify_flags(krb5_context context,
		  krb5_kdc_configuration *config,
		  const EncTicketPart *et,
		  const char *pstr)
{
    if(et->endtime < kdc_time){
	kdc_log(context, config, 4, "Ticket expired (%s)", pstr);
	return KRB5KRB_AP_ERR_TKT_EXPIRED;
    }
    if(et->flags.invalid){
	kdc_log(context, config, 4, "Ticket not valid (%s)", pstr);
	return KRB5KRB_AP_ERR_TKT_NYV;
    }
    return 0;
}

/*
 *
 */

static krb5_error_code
fix_transited_encoding(krb5_context context,
		       krb5_kdc_configuration *config,
		       krb5_boolean check_policy,
		       const TransitedEncoding *tr,
		       EncTicketPart *et,
		       const char *client_realm,
		       const char *server_realm,
		       const char *tgt_realm)
{
    krb5_error_code ret = 0;
    char **realms, **tmp;
    unsigned int num_realms;
    size_t i;

    switch (tr->tr_type) {
    case domain_X500_Compress:
	break;
    case 0:
	/*
	 * Allow empty content of type 0 because that is was Microsoft
	 * generates in their TGT.
	 */
	if (tr->contents.length == 0)
	    break;
	kdc_log(context, config, 4,
		"Transited type 0 with non empty content");
	return KRB5KDC_ERR_TRTYPE_NOSUPP;
    default:
	kdc_log(context, config, 4,
		"Unknown transited type: %u", tr->tr_type);
	return KRB5KDC_ERR_TRTYPE_NOSUPP;
    }

    ret = krb5_domain_x500_decode(context,
				  tr->contents,
				  &realms,
				  &num_realms,
				  client_realm,
				  server_realm);
    if(ret){
	krb5_warn(context, ret,
		  "Decoding transited encoding");
	return ret;
    }

    /*
     * If the realm of the presented tgt is neither the client nor the server
     * realm, it is a transit realm and must be added to transited set.
     */
    if (strcmp(client_realm, tgt_realm) != 0 &&
        strcmp(server_realm, tgt_realm) != 0) {
	if (num_realms + 1 > UINT_MAX/sizeof(*realms)) {
	    ret = ERANGE;
	    goto free_realms;
	}
	tmp = realloc(realms, (num_realms + 1) * sizeof(*realms));
	if(tmp == NULL){
	    ret = ENOMEM;
	    goto free_realms;
	}
	realms = tmp;
	realms[num_realms] = strdup(tgt_realm);
	if(realms[num_realms] == NULL){
	    ret = ENOMEM;
	    goto free_realms;
	}
	num_realms++;
    }
    if(num_realms == 0) {
	if (strcmp(client_realm, server_realm) != 0)
	    kdc_log(context, config, 4,
		    "cross-realm %s -> %s", client_realm, server_realm);
    } else {
	size_t l = 0;
	char *rs;
	for(i = 0; i < num_realms; i++)
	    l += strlen(realms[i]) + 2;
	rs = malloc(l);
	if(rs != NULL) {
	    *rs = '\0';
	    for(i = 0; i < num_realms; i++) {
		if(i > 0)
		    strlcat(rs, ", ", l);
		strlcat(rs, realms[i], l);
	    }
	    kdc_log(context, config, 4,
		    "cross-realm %s -> %s via [%s]",
		    client_realm, server_realm, rs);
	    free(rs);
	}
    }
    if(check_policy) {
	ret = krb5_check_transited(context, client_realm,
				   server_realm,
				   realms, num_realms, NULL);
	if(ret) {
	    krb5_warn(context, ret, "cross-realm %s -> %s",
		      client_realm, server_realm);
	    goto free_realms;
	}
	et->flags.transited_policy_checked = 1;
    }
    et->transited.tr_type = domain_X500_Compress;
    ret = krb5_domain_x500_encode(realms, num_realms, &et->transited.contents);
    if(ret)
	krb5_warn(context, ret, "Encoding transited encoding");
  free_realms:
    for(i = 0; i < num_realms; i++)
	free(realms[i]);
    free(realms);
    return ret;
}


static krb5_error_code
tgs_make_reply(astgs_request_t r,
	       const EncTicketPart *tgt,
	       const EncryptionKey *serverkey,
	       const EncryptionKey *krbtgtkey,
	       const krb5_keyblock *sessionkey,
	       krb5_kvno kvno,
	       AuthorizationData *auth_data,
	       const char *tgt_realm,
	       uint16_t rodc_id,
	       krb5_boolean add_ticket_sig)
{
    KDC_REQ_BODY *b = &r->req.req_body;
    krb5_data *reply = r->reply;
    KDC_REP *rep = &r->rep;
    EncTicketPart *et = &r->et;
    EncKDCRepPart *ek = &r->ek;
    KDCOptions f = b->kdc_options;
    krb5_error_code ret;
    int is_weak = 0;
    krb5_boolean check_policy = FALSE;

    heim_assert(r->client_princ != NULL, "invalid client name passed to tgs_make_reply");

    rep->pvno = 5;
    rep->msg_type = krb_tgs_rep;

    if (et->authtime == 0)
        et->authtime = tgt->authtime;
    _kdc_fix_time(&b->till);
    et->endtime = min(tgt->endtime, *b->till);
    ALLOC(et->starttime);
    *et->starttime = kdc_time;

    ret = check_tgs_flags(r, b, r->client_princ, tgt, et);
    if(ret)
	goto out;

    /* We should check the transited encoding if:
       1) the request doesn't ask not to be checked
       2) globally enforcing a check
       3) principal requires checking
       4) we allow non-check per-principal, but principal isn't marked as allowing this
       5) we don't globally allow this
    */

#define GLOBAL_FORCE_TRANSITED_CHECK		\
    (r->config->trpolicy == TRPOLICY_ALWAYS_CHECK)
#define GLOBAL_ALLOW_PER_PRINCIPAL			\
    (r->config->trpolicy == TRPOLICY_ALLOW_PER_PRINCIPAL)
#define GLOBAL_ALLOW_DISABLE_TRANSITED_CHECK			\
    (r->config->trpolicy == TRPOLICY_ALWAYS_HONOUR_REQUEST)
#define GLOBAL_DISABLE_TRANSITED_CHECK		\
    (r->config->trpolicy == TRPOLICY_NEVER_CHECK)

/* these will consult the database in future release */
#define PRINCIPAL_FORCE_TRANSITED_CHECK(P)		0
#define PRINCIPAL_ALLOW_DISABLE_TRANSITED_CHECK(P)	0

    if (GLOBAL_DISABLE_TRANSITED_CHECK) {
	check_policy = FALSE;
    } else if (!f.disable_transited_check) {
	check_policy = TRUE;
    } else if (GLOBAL_FORCE_TRANSITED_CHECK) {
	check_policy = TRUE;
    } else if (PRINCIPAL_FORCE_TRANSITED_CHECK(r->server)) {
	check_policy = TRUE;
    } else if (!((GLOBAL_ALLOW_PER_PRINCIPAL &&
	       PRINCIPAL_ALLOW_DISABLE_TRANSITED_CHECK(r->server)) ||
	       GLOBAL_ALLOW_DISABLE_TRANSITED_CHECK))
    {
	check_policy = TRUE;
    }

    ret = fix_transited_encoding(r->context, r->config,
				 check_policy,
				 &tgt->transited, et,
				 krb5_principal_get_realm(r->context, r->client_princ),
				 krb5_principal_get_realm(r->context, r->server->principal),
				 tgt_realm);

    {
        /*
         * RFC 6806 notes that names MUST NOT be changed in the response to a
         * TGS request. Hence we ignore the setting of the canonicalize KDC
         * option. However, for legacy interoperability we do allow the backend
         * to override this by setting the force-canonicalize HDB flag in the
         * server entry.
         */
        krb5_const_principal rsp;

        if (r->server->flags.force_canonicalize)
            rsp = r->server->principal;
        else
            rsp = r->server_princ;
        if (ret == 0)
            ret = copy_Realm(&rsp->realm, &rep->ticket.realm);
        if (ret == 0)
            ret = _krb5_principal2principalname(&rep->ticket.sname, rsp);
    }

    if (ret == 0)
        ret = copy_Realm(&r->client_princ->realm, &rep->crealm);
    if (ret)
        goto out;

    /*
     * RFC 8062 states "if the ticket in the TGS request is an anonymous
     * one, the client and client realm are copied from that ticket". So
     * whilst the TGT flag check below is superfluous, it is included in
     * order to follow the specification to its letter.
     */
    if (et->flags.anonymous && !tgt->flags.anonymous)
	_kdc_make_anonymous_principalname(&rep->cname);
    else
	ret = copy_PrincipalName(&r->client_princ->name, &rep->cname);
    if (ret)
	goto out;
    rep->ticket.tkt_vno = 5;

    ek->caddr = et->caddr;

    {
	time_t life;
	life = et->endtime - *et->starttime;
	if(r->client && r->client->max_life)
	    life = min(life, *r->client->max_life);
	if(r->server->max_life)
	    life = min(life, *r->server->max_life);
	et->endtime = *et->starttime + life;
    }
    if(f.renewable_ok && tgt->flags.renewable &&
       et->renew_till == NULL && et->endtime < *b->till &&
       tgt->renew_till != NULL)
    {
	et->flags.renewable = 1;
	ALLOC(et->renew_till);
	*et->renew_till = *b->till;
    }
    if(et->renew_till){
	time_t renew;
	renew = *et->renew_till - *et->starttime;
	if(r->client && r->client->max_renew)
	    renew = min(renew, *r->client->max_renew);
	if(r->server->max_renew)
	    renew = min(renew, *r->server->max_renew);
	*et->renew_till = *et->starttime + renew;
    }

    if(et->renew_till){
	*et->renew_till = min(*et->renew_till, *tgt->renew_till);
	*et->starttime = min(*et->starttime, *et->renew_till);
	et->endtime = min(et->endtime, *et->renew_till);
    }

    *et->starttime = min(*et->starttime, et->endtime);

    if(*et->starttime == et->endtime){
	ret = KRB5KDC_ERR_NEVER_VALID;
	goto out;
    }
    if(et->renew_till && et->endtime == *et->renew_till){
	free(et->renew_till);
	et->renew_till = NULL;
	et->flags.renewable = 0;
    }

    et->flags.pre_authent = tgt->flags.pre_authent;
    et->flags.hw_authent  = tgt->flags.hw_authent;
    et->flags.ok_as_delegate = r->server->flags.ok_as_delegate;

    /* See MS-KILE 3.3.5.7.5 Cross-Domain Trust and Referrals */
    if (!r->krbtgt->flags.ok_as_delegate)
	et->flags.ok_as_delegate = 0;

    /* See MS-KILE 3.3.5.1 */
    if (!r->server->flags.forwardable)
	et->flags.forwardable = 0;
    if (!r->server->flags.proxiable)
	et->flags.proxiable = 0;

    if (auth_data) {
	unsigned int i = 0;

	/* XXX check authdata */

	if (et->authorization_data == NULL) {
	    et->authorization_data = calloc(1, sizeof(*et->authorization_data));
	    if (et->authorization_data == NULL) {
		ret = ENOMEM;
		krb5_set_error_message(r->context, ret, "malloc: out of memory");
		goto out;
	    }
	}
	for(i = 0; i < auth_data->len ; i++) {
	    ret = add_AuthorizationData(et->authorization_data, &auth_data->val[i]);
	    if (ret) {
		krb5_set_error_message(r->context, ret, "malloc: out of memory");
		goto out;
	    }
	}
    }

    ret = krb5_copy_keyblock_contents(r->context, sessionkey, &et->key);
    if (ret)
	goto out;
    et->crealm = rep->crealm;
    et->cname = rep->cname;

    ek->key = et->key;
    /* MIT must have at least one last_req */
    ek->last_req.val = calloc(1, sizeof(*ek->last_req.val));
    if (ek->last_req.val == NULL) {
	ret = ENOMEM;
	goto out;
    }
    ek->last_req.len = 1; /* set after alloc to avoid null deref on cleanup */
    ek->nonce = b->nonce;
    ek->flags = et->flags;
    ek->authtime = et->authtime;
    ek->starttime = et->starttime;
    ek->endtime = et->endtime;
    ek->renew_till = et->renew_till;
    ek->srealm = rep->ticket.realm;
    ek->sname = rep->ticket.sname;

    _kdc_log_timestamp(r, "TGS-REQ", et->authtime, et->starttime,
		       et->endtime, et->renew_till);

    if (krb5_enctype_valid(r->context, serverkey->keytype) != 0
	&& _kdc_is_weak_exception(r->server->principal, serverkey->keytype))
    {
	krb5_enctype_enable(r->context, serverkey->keytype);
	is_weak = 1;
    }

    if (r->canon_client_princ) {
	char *cpn;

	(void) krb5_unparse_name(r->context, r->canon_client_princ, &cpn);
	kdc_audit_addkv((kdc_request_t)r, 0, "canon_client_name", "%s",
			cpn ? cpn : "<unknown>");
	krb5_xfree(cpn);
    }

    /*
     * For anonymous tickets, we should filter out positive authorization data
     * that could reveal the client's identity, and return a policy error for
     * restrictive authorization data. Policy for unknown authorization types
     * is implementation dependent.
     */
    if (r->pac && !et->flags.anonymous) {
	kdc_audit_setkv_number((kdc_request_t)r, "pac_attributes",
			       r->pac_attributes);

	/*
	 * PACs are included when issuing TGTs, if there is no PAC_ATTRIBUTES
	 * buffer (legacy behavior) or if the attributes buffer indicates the
	 * AS client requested one.
	 */
	if (_kdc_include_pac_p(r)) {
	    krb5_boolean is_tgs =
		krb5_principal_is_krbtgt(r->context, r->server->principal);

	    ret = _krb5_kdc_pac_sign_ticket(r->context, r->pac, r->client_princ, serverkey,
					    krbtgtkey, rodc_id, NULL, r->canon_client_princ,
					    add_ticket_sig, add_ticket_sig, et,
					    is_tgs ? &r->pac_attributes : NULL);
	    if (ret)
		goto out;
	}
    }

    ret = _kdc_finalize_reply(r);
    if (ret)
	goto out;

    /* It is somewhat unclear where the etype in the following
       encryption should come from. What we have is a session
       key in the passed tgt, and a list of preferred etypes
       *for the new ticket*. Should we pick the best possible
       etype, given the keytype in the tgt, or should we look
       at the etype list here as well?  What if the tgt
       session key is DES3 and we want a ticket with a (say)
       CAST session key. Should the DES3 etype be added to the
       etype list, even if we don't want a session key with
       DES3? */
    ret = _kdc_encode_reply(r->context, r->config, r, b->nonce,
			    serverkey->keytype, kvno,
			    serverkey, 0, r->rk_is_subkey, reply);
    if (is_weak)
	krb5_enctype_disable(r->context, serverkey->keytype);

    _log_astgs_req(r, serverkey->keytype);

out:
    return ret;
}

static krb5_error_code
tgs_check_authenticator(krb5_context context,
			krb5_kdc_configuration *config,
	                krb5_auth_context ac,
			KDC_REQ_BODY *b,
			krb5_keyblock *key)
{
    krb5_authenticator auth;
    krb5_error_code ret;
    krb5_crypto crypto;

    ret = krb5_auth_con_getauthenticator(context, ac, &auth);
    if (ret) {
	kdc_log(context, config, 2,
                "Out of memory checking PA-TGS Authenticator");
        goto out;
    }
    if(auth->cksum == NULL){
	kdc_log(context, config, 4, "No authenticator in request");
	ret = KRB5KRB_AP_ERR_INAPP_CKSUM;
	goto out;
    }

    if (!krb5_checksum_is_collision_proof(context, auth->cksum->cksumtype)) {
	kdc_log(context, config, 4, "Bad checksum type in authenticator: %d",
		auth->cksum->cksumtype);
	ret =  KRB5KRB_AP_ERR_INAPP_CKSUM;
	goto out;
    }

    ret = krb5_crypto_init(context, key, 0, &crypto);
    if (ret) {
	const char *msg = krb5_get_error_message(context, ret);
	kdc_log(context, config, 4, "krb5_crypto_init failed: %s", msg);
	krb5_free_error_message(context, msg);
	goto out;
    }

    /*
     * RFC4120 says the checksum must be collision-proof, but it does
     * not require it to be keyed (as the authenticator is encrypted).
     */
    _krb5_crypto_set_flags(context, crypto, KRB5_CRYPTO_FLAG_ALLOW_UNKEYED_CHECKSUM);
    ret = _kdc_verify_checksum(context,
			       crypto,
			       KRB5_KU_TGS_REQ_AUTH_CKSUM,
			       &b->_save,
			       auth->cksum);
    krb5_crypto_destroy(context, crypto);
    if(ret){
	const char *msg = krb5_get_error_message(context, ret);
	kdc_log(context, config, 4,
		"Failed to verify authenticator checksum: %s", msg);
	krb5_free_error_message(context, msg);
    }
out:
    free_Authenticator(auth);
    free(auth);
    return ret;
}

static krb5_boolean
need_referral(krb5_context context, krb5_kdc_configuration *config,
	      const KDCOptions * const options, krb5_principal server,
	      krb5_realm **realms)
{
    const char *name;

    if(!options->canonicalize && server->name.name_type != KRB5_NT_SRV_INST)
	return FALSE;

    if (server->name.name_string.len == 1)
	name = server->name.name_string.val[0];
    else if (server->name.name_string.len > 1)
	name = server->name.name_string.val[1];
    else
	return FALSE;

    kdc_log(context, config, 5, "Searching referral for %s", name);

    return _krb5_get_host_realm_int(context, name, FALSE, realms) == 0;
}

static krb5_error_code
validate_fast_ad(astgs_request_t r, krb5_authdata *auth_data)
{
    krb5_error_code ret;
    krb5_data data;

    krb5_data_zero(&data);

    if (!r->config->enable_fast)
	return 0;

    ret = _krb5_get_ad(r->context, auth_data, NULL,
		       KRB5_AUTHDATA_FX_FAST_USED, &data);
    if (ret == 0) {
	r->fast_asserted = 1;
	krb5_data_free(&data);
    }

    ret = _krb5_get_ad(r->context, auth_data, NULL,
		       KRB5_AUTHDATA_FX_FAST_ARMOR, &data);
    if (ret == 0) {
	kdc_log(r->context, r->config, 2,
		"Invalid ticket usage: TGS-REQ contains AD-fx-fast-armor");
	krb5_data_free(&data);
	return KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }

    return 0;
}

static krb5_error_code
tgs_parse_request(astgs_request_t r,
		  const PA_DATA *tgs_req,
		  krb5_enctype *krbtgt_etype,
		  const char *from,
		  const struct sockaddr *from_addr,
		  time_t **csec,
		  int **cusec)
{
    krb5_kdc_configuration *config = r->config;
    KDC_REQ_BODY *b = &r->req.req_body;
    static char failed[] = "<unparse_name failed>";
    krb5_ap_req ap_req;
    krb5_error_code ret;
    krb5_principal princ;
    krb5_auth_context ac = NULL;
    krb5_flags ap_req_options;
    krb5_flags verify_ap_req_flags = 0;
    krb5uint32 krbtgt_kvno;     /* kvno used for the PA-TGS-REQ AP-REQ Ticket */
    krb5uint32 krbtgt_kvno_try;
    int kvno_search_tries = 4;  /* number of kvnos to try when tkt_vno == 0 */
    const Keys *krbtgt_keys;/* keyset for TGT tkt_vno */
    Key *tkey;
    krb5_keyblock *subkey = NULL;

    *csec  = NULL;
    *cusec = NULL;

    memset(&ap_req, 0, sizeof(ap_req));
    ret = krb5_decode_ap_req(r->context, &tgs_req->padata_value, &ap_req);
    if(ret){
	const char *msg = krb5_get_error_message(r->context, ret);
	kdc_log(r->context, config, 4, "Failed to decode AP-REQ: %s", msg);
	krb5_free_error_message(r->context, msg);
	goto out;
    }

    if(!krb5_principalname_is_krbtgt(r->context, &ap_req.ticket.sname)){
	/*
	 * Note: this check is not to be depended upon for security. Nothing
	 * prevents a client modifying the sname, as it is located in the
	 * unencrypted part of the ticket.
	 */

	/* XXX check for ticket.sname == req.sname */
	kdc_log(r->context, config, 4, "PA-DATA is not a ticket-granting ticket");
	ret = KRB5KDC_ERR_POLICY; /* ? */
	goto out;
    }

    _krb5_principalname2krb5_principal(r->context,
				       &princ,
				       ap_req.ticket.sname,
				       ap_req.ticket.realm);

    krbtgt_kvno = ap_req.ticket.enc_part.kvno ? *ap_req.ticket.enc_part.kvno : 0;
    ret = _kdc_db_fetch(r->context, config, princ, HDB_F_GET_KRBTGT,
			&krbtgt_kvno, &r->krbtgtdb, &r->krbtgt);

    if (ret == HDB_ERR_NOT_FOUND_HERE) {
	/* XXX Factor out this unparsing of the same princ all over */
	char *p;
	ret = krb5_unparse_name(r->context, princ, &p);
	if (ret != 0)
	    p = failed;
	krb5_free_principal(r->context, princ);
	kdc_log(r->context, config, 5,
		"Ticket-granting ticket account %s does not have secrets at "
		"this KDC, need to proxy", p);
	if (ret == 0)
	    free(p);
	ret = HDB_ERR_NOT_FOUND_HERE;
	goto out;
    } else if (ret == HDB_ERR_KVNO_NOT_FOUND) {
	char *p;
	ret = krb5_unparse_name(r->context, princ, &p);
	if (ret != 0)
	    p = failed;
	krb5_free_principal(r->context, princ);
	kdc_log(r->context, config, 5,
		"Ticket-granting ticket account %s does not have keys for "
		"kvno %d at this KDC", p, krbtgt_kvno);
	if (ret == 0)
	    free(p);
	ret = HDB_ERR_KVNO_NOT_FOUND;
	goto out;
    } else if (ret == HDB_ERR_NO_MKEY) {
	char *p;
	ret = krb5_unparse_name(r->context, princ, &p);
	if (ret != 0)
	    p = failed;
	krb5_free_principal(r->context, princ);
	kdc_log(r->context, config, 5,
		"Missing master key for decrypting keys for ticket-granting "
		"ticket account %s with kvno %d at this KDC", p, krbtgt_kvno);
	if (ret == 0)
	    free(p);
	ret = HDB_ERR_KVNO_NOT_FOUND;
	goto out;
    } else if (ret) {
	const char *msg = krb5_get_error_message(r->context, ret);
	char *p;
	ret = krb5_unparse_name(r->context, princ, &p);
	if (ret != 0)
	    p = failed;
	kdc_log(r->context, config, 4,
		"Ticket-granting ticket %s not found in database: %s", p, msg);
	krb5_free_principal(r->context, princ);
	krb5_free_error_message(r->context, msg);
	if (ret == 0)
	    free(p);
	ret = KRB5KRB_AP_ERR_NOT_US;
	goto out;
    }

    krbtgt_kvno_try = krbtgt_kvno ? krbtgt_kvno : r->krbtgt->kvno;
    *krbtgt_etype = ap_req.ticket.enc_part.etype;

next_kvno:
    krbtgt_keys = hdb_kvno2keys(r->context, r->krbtgt, krbtgt_kvno_try);
    ret = hdb_enctype2key(r->context, r->krbtgt, krbtgt_keys,
			  ap_req.ticket.enc_part.etype, &tkey);
    if (ret && krbtgt_kvno == 0 && kvno_search_tries > 0) {
	kvno_search_tries--;
	krbtgt_kvno_try--;
	goto next_kvno;
    } else if (ret) {
	char *str = NULL, *p = NULL;

	/* We should implement the MIT `trace_format()' concept */
	(void) krb5_enctype_to_string(r->context, ap_req.ticket.enc_part.etype, &str);
	(void) krb5_unparse_name(r->context, princ, &p);
	kdc_log(r->context, config, 4,
		"No server key with enctype %s found for %s",
		str ? str : "<unknown enctype>",
		p ? p : "<unparse_name failed>");
	free(str);
	free(p);
	ret = KRB5KRB_AP_ERR_BADKEYVER;
	goto out;
    }

    if (b->kdc_options.validate)
	verify_ap_req_flags |= KRB5_VERIFY_AP_REQ_IGNORE_INVALID;

    if (r->config->warn_ticket_addresses)
        verify_ap_req_flags |= KRB5_VERIFY_AP_REQ_IGNORE_ADDRS;

    ret = krb5_verify_ap_req2(r->context,
			      &ac,
			      &ap_req,
			      princ,
			      &tkey->key,
			      verify_ap_req_flags,
			      &ap_req_options,
			      &r->ticket,
			      KRB5_KU_TGS_REQ_AUTH);
    if (r->ticket && r->ticket->ticket.caddr)
        kdc_audit_addaddrs((kdc_request_t)r, r->ticket->ticket.caddr, "tixaddrs");
    if (r->config->warn_ticket_addresses && ret == KRB5KRB_AP_ERR_BADADDR &&
        r->ticket != NULL) {
        kdc_audit_setkv_bool((kdc_request_t)r, "wrongaddr", TRUE);
        ret = 0;
    }
    if (ret == KRB5KRB_AP_ERR_BAD_INTEGRITY && kvno_search_tries > 0) {
	kvno_search_tries--;
	krbtgt_kvno_try--;
	goto next_kvno;
    }

    krb5_free_principal(r->context, princ);
    if(ret) {
	const char *msg = krb5_get_error_message(r->context, ret);
	kdc_log(r->context, config, 4, "Failed to verify AP-REQ: %s", msg);
	krb5_free_error_message(r->context, msg);
	goto out;
    }

    r->ticket_key = tkey;

    {
	krb5_authenticator auth;

	ret = krb5_auth_con_getauthenticator(r->context, ac, &auth);
	if (ret == 0) {
	    *csec   = malloc(sizeof(**csec));
	    if (*csec == NULL) {
		krb5_free_authenticator(r->context, &auth);
		kdc_log(r->context, config, 4, "malloc failed");
		goto out;
	    }
	    **csec  = auth->ctime;
	    *cusec  = malloc(sizeof(**cusec));
	    if (*cusec == NULL) {
		krb5_free_authenticator(r->context, &auth);
		kdc_log(r->context, config, 4, "malloc failed");
		goto out;
	    }
	    **cusec  = auth->cusec;

	    ret = validate_fast_ad(r, auth->authorization_data);
	    krb5_free_authenticator(r->context, &auth);
	    if (ret)
		goto out;
	}
    }

    ret = tgs_check_authenticator(r->context, config, ac, b, &r->ticket->ticket.key);
    if (ret) {
	krb5_auth_con_free(r->context, ac);
	goto out;
    }

    r->rk_is_subkey = 1;

    ret = krb5_auth_con_getremotesubkey(r->context, ac, &subkey);
    if(ret){
	const char *msg = krb5_get_error_message(r->context, ret);
	krb5_auth_con_free(r->context, ac);
	kdc_log(r->context, config, 4, "Failed to get remote subkey: %s", msg);
	krb5_free_error_message(r->context, msg);
	goto out;
    }
    if(subkey == NULL){
	r->rk_is_subkey = 0;

	ret = krb5_auth_con_getkey(r->context, ac, &subkey);
	if(ret) {
	    const char *msg = krb5_get_error_message(r->context, ret);
	    krb5_auth_con_free(r->context, ac);
	    kdc_log(r->context, config, 4, "Failed to get session key: %s", msg);
	    krb5_free_error_message(r->context, msg);
	    goto out;
	}
    }
    if(subkey == NULL){
	krb5_auth_con_free(r->context, ac);
	kdc_log(r->context, config, 4,
		"Failed to get key for enc-authorization-data");
	ret = KRB5KRB_AP_ERR_BAD_INTEGRITY; /* ? */
	goto out;
    }

    krb5_free_keyblock_contents(r->context,  &r->reply_key);
    ret = krb5_copy_keyblock_contents(r->context, subkey, &r->reply_key);
    krb5_free_keyblock(r->context, subkey);
    if (ret)
	goto out;

    krb5_free_keyblock_contents(r->context,  &r->enc_ad_key);
    if (b->enc_authorization_data) {
	ret = krb5_copy_keyblock_contents(r->context,
					  &r->reply_key,
					  &r->enc_ad_key);
	if (ret)
	    goto out;
    }

    ret = validate_fast_ad(r, r->ticket->ticket.authorization_data);
    if (ret)
	goto out;

    
    /*
     * Check for FAST request
     */

    ret = _kdc_fast_unwrap_request(r, r->ticket, ac);
    if (ret)
	goto out;

    krb5_auth_con_free(r->context, ac);

out:
    free_AP_REQ(&ap_req);

    return ret;
}

static krb5_error_code
build_server_referral(krb5_context context,
		      krb5_kdc_configuration *config,
		      krb5_crypto session,
		      krb5_const_realm referred_realm,
		      const PrincipalName *true_principal_name,
		      const PrincipalName *requested_principal,
		      krb5_data *outdata)
{
    PA_ServerReferralData ref;
    krb5_error_code ret;
    EncryptedData ed;
    krb5_data data;
    size_t size = 0;

    memset(&ref, 0, sizeof(ref));

    if (referred_realm) {
	ALLOC(ref.referred_realm);
	if (ref.referred_realm == NULL)
	    goto eout;
	*ref.referred_realm = strdup(referred_realm);
	if (*ref.referred_realm == NULL)
	    goto eout;
    }
    if (true_principal_name) {
	ALLOC(ref.true_principal_name);
	if (ref.true_principal_name == NULL)
	    goto eout;
	ret = copy_PrincipalName(true_principal_name, ref.true_principal_name);
	if (ret)
	    goto eout;
    }
    if (requested_principal) {
	ALLOC(ref.requested_principal_name);
	if (ref.requested_principal_name == NULL)
	    goto eout;
	ret = copy_PrincipalName(requested_principal,
				 ref.requested_principal_name);
	if (ret)
	    goto eout;
    }

    ASN1_MALLOC_ENCODE(PA_ServerReferralData,
		       data.data, data.length,
		       &ref, &size, ret);
    free_PA_ServerReferralData(&ref);
    if (ret)
	return ret;
    if (data.length != size)
	krb5_abortx(context, "internal asn.1 encoder error");

    ret = krb5_encrypt_EncryptedData(context, session,
				     KRB5_KU_PA_SERVER_REFERRAL,
				     data.data, data.length,
				     0 /* kvno */, &ed);
    free(data.data);
    if (ret)
	return ret;

    ASN1_MALLOC_ENCODE(EncryptedData,
		       outdata->data, outdata->length,
		       &ed, &size, ret);
    free_EncryptedData(&ed);
    if (ret)
	return ret;
    if (outdata->length != size)
	krb5_abortx(context, "internal asn.1 encoder error");

    return 0;
eout:
    free_PA_ServerReferralData(&ref);
    krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
    return ENOMEM;
}

/*
 * This function is intended to be used when failure to find the client is
 * acceptable.
 */
krb5_error_code
_kdc_db_fetch_client(krb5_context context,
		     krb5_kdc_configuration *config,
		     int flags,
		     krb5_principal cp,
		     const char *cpn,
		     const char *krbtgt_realm,
		     HDB **clientdb,
		     hdb_entry **client_out)
{
    krb5_error_code ret;
    hdb_entry *client = NULL;

    *clientdb = NULL;
    *client_out = NULL;

    ret = _kdc_db_fetch(context, config, cp, HDB_F_GET_CLIENT | flags,
			NULL, clientdb, &client);
    if (ret == HDB_ERR_NOT_FOUND_HERE) {
	/*
	 * This is OK, we are just trying to find out if they have
	 * been disabled or deleted in the meantime; missing secrets
	 * are OK.
	 *
	 * If HDB_F_CROSS_REALM_PRINCIPAL was passed this
	 * indicates the client is remote.
	 */
    } else if (ret) {
	/*
	 * If the client belongs to the same realm as our TGS, it
	 * should exist in the local database.
	 */
	const char *msg;

	if (strcmp(krb5_principal_get_realm(context, cp), krbtgt_realm) == 0) {
	    if (ret == HDB_ERR_NOENTRY)
		ret = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	    kdc_log(context, config, 4, "Client no longer in database: %s", cpn);
	    return ret;
	}

	msg = krb5_get_error_message(context, ret);
	kdc_log(context, config, 4, "Client not found in database: %s", msg);
	krb5_free_error_message(context, msg);
    } else if (client->flags.invalid || !client->flags.client) {
        kdc_log(context, config, 4, "Client has invalid bit set");
	_kdc_free_ent(context, *clientdb, client);
        return KRB5KDC_ERR_POLICY;
    }

    *client_out = client;

    return 0;
}

static krb5_error_code
tgs_build_reply(astgs_request_t priv,
		krb5_enctype krbtgt_etype,
		const struct sockaddr *from_addr)
{
    krb5_context context = priv->context;
    krb5_kdc_configuration *config = priv->config;
    KDC_REQ_BODY *b = &priv->req.req_body;
    const char *from = priv->from;
    krb5_error_code ret, ret2;
    krb5_principal krbtgt_out_principal = NULL;
    krb5_principal user2user_princ = NULL;
    char *spn = NULL, *cpn = NULL, *krbtgt_out_n = NULL;
    char *user2user_name = NULL;
    HDB *user2user_krbtgtdb;
    hdb_entry *user2user_krbtgt = NULL;
    HDB *clientdb = NULL;
    HDB *serverdb = NULL;
    krb5_realm ref_realm = NULL;
    EncTicketPart *tgt = &priv->ticket->ticket;
    const EncryptionKey *ekey;
    krb5_keyblock sessionkey;
    krb5_kvno kvno;
    krb5_pac user2user_pac = NULL;
    uint16_t rodc_id;
    krb5_boolean add_ticket_sig = FALSE;
    const char *tgt_realm = /* Realm of TGT issuer */
        krb5_principal_get_realm(context, priv->krbtgt->principal);
    const char *our_realm = /* Realm of this KDC */
        krb5_principal_get_comp_string(context, priv->krbtgt->principal, 1);
    char **capath = NULL;
    size_t num_capath = 0;
    AuthorizationData *auth_data = NULL;

    HDB *krbtgt_outdb;
    hdb_entry *krbtgt_out = NULL;

    PrincipalName *s;
    Realm r;
    EncTicketPart adtkt;
    char opt_str[128];
    krb5_boolean kdc_issued = FALSE;

    Key *tkey_sign;
    int flags = HDB_F_FOR_TGS_REQ;
    int server_flags;

    int result;

    const PA_DATA *for_user = NULL;
    int for_user_idx = 0;

    memset(&sessionkey, 0, sizeof(sessionkey));
    memset(&adtkt, 0, sizeof(adtkt));

    s = b->sname;
    r = b->realm;

    /*
     * The canonicalize KDC option is passed as a hint to the backend, but
     * can typically be ignored. Per RFC 6806, names are not canonicalized
     * in response to a TGS request (although we make an exception, see
     * force-canonicalize below).
     */
    if (b->kdc_options.canonicalize)
	flags |= HDB_F_CANON;

    server_flags = HDB_F_GET_SERVER | HDB_F_DELAY_NEW_KEYS | flags;
    if (b->kdc_options.enc_tkt_in_skey)
	server_flags |= HDB_F_USER2USER_PRINCIPAL;

    if (s == NULL) {
	ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
        _kdc_set_const_e_text(priv, "No server in request");
	goto out;
    }

    _krb5_principalname2krb5_principal(context, &priv->server_princ, *s, r);
    ret = krb5_unparse_name(context, priv->server_princ, &priv->sname);
    if (ret)
	goto out;
    spn = priv->sname;
    _krb5_principalname2krb5_principal(context, &priv->client_princ,
				       tgt->cname, tgt->crealm);
    ret = krb5_unparse_name(context, priv->client_princ, &priv->cname);
    if (ret)
	goto out;
    cpn = priv->cname;
    result = unparse_flags(KDCOptions2int(b->kdc_options),
			   asn1_KDCOptions_units(),
			   opt_str, sizeof(opt_str));
    if (result > 0)
	kdc_log(context, config, 4,
		"TGS-REQ %s from %s for %s [%s]",
		cpn, from, spn, opt_str);
    else
	kdc_log(context, config, 4,
		"TGS-REQ %s from %s for %s", cpn, from, spn);

    /*
     * Fetch server
     */

server_lookup:
    if (priv->server)
        _kdc_free_ent(context, serverdb, priv->server);
    priv->server = NULL;
    ret = _kdc_db_fetch(context, config, priv->server_princ,
                        server_flags,
			NULL, &serverdb, &priv->server);
    priv->serverdb = serverdb;
    if (ret == HDB_ERR_NOT_FOUND_HERE) {
	kdc_log(context, config, 5, "target %s does not have secrets at this KDC, need to proxy", spn);
        kdc_audit_addreason((kdc_request_t)priv, "Target not found here");
	goto out;
    } else if (ret == HDB_ERR_WRONG_REALM) {
        free(ref_realm);
	ref_realm = strdup(priv->server->principal->realm);
	if (ref_realm == NULL) {
            ret = krb5_enomem(context);
	    goto out;
	}

	kdc_log(context, config, 4,
		"Returning a referral to realm %s for "
		"server %s.",
		ref_realm, spn);
	krb5_free_principal(context, priv->server_princ);
	priv->server_princ = NULL;
	ret = krb5_make_principal(context, &priv->server_princ, r, KRB5_TGS_NAME,
				  ref_realm, NULL);
	if (ret)
	    goto out;
	free(priv->sname);
        priv->sname = NULL;
	ret = krb5_unparse_name(context, priv->server_princ, &priv->sname);
	if (ret)
	    goto out;
	spn = priv->sname;

	goto server_lookup;
    } else if (ret) {
	const char *new_rlm, *msg;
	Realm req_rlm;
	krb5_realm *realms;

	priv->error_code = ret; /* advise policy plugin of failure reason */
	ret2 = _kdc_referral_policy(priv);
	if (ret2 == 0) {
	    krb5_xfree(priv->sname);
	    priv->sname = NULL;
	    ret = krb5_unparse_name(context, priv->server_princ, &priv->sname);
	    if (ret)
		goto out;
	    goto server_lookup;
	} else if (ret2 != KRB5_PLUGIN_NO_HANDLE) {
	    ret = ret2;
	} else if ((req_rlm = get_krbtgt_realm(&priv->server_princ->name)) != NULL) {
            if (capath == NULL) {
                /* With referalls, hierarchical capaths are always enabled */
                ret2 = _krb5_find_capath(context, tgt->crealm, our_realm,
                                         req_rlm, TRUE, &capath, &num_capath);
                if (ret2) {
                    ret = ret2;
                    kdc_audit_addreason((kdc_request_t)priv,
                                        "No trusted path from client realm to ours");
                    goto out;
                }
            }
            new_rlm = num_capath > 0 ? capath[--num_capath] : NULL;
            if (new_rlm) {
                kdc_log(context, config, 5, "krbtgt from %s via %s for "
                        "realm %s not found, trying %s", tgt->crealm,
                        our_realm, req_rlm, new_rlm);

                free(ref_realm);
                ref_realm = strdup(new_rlm);
                if (ref_realm == NULL) {
                    ret = krb5_enomem(context);
                    goto out;
                }

                krb5_free_principal(context, priv->server_princ);
                priv->server_princ = NULL;
                krb5_make_principal(context, &priv->server_princ, r,
                                    KRB5_TGS_NAME, ref_realm, NULL);
                free(priv->sname);
                priv->sname = NULL;
                ret = krb5_unparse_name(context, priv->server_princ, &priv->sname);
                if (ret)
                    goto out;
                spn = priv->sname;
                goto server_lookup;
            }
	} else if (need_referral(context, config, &b->kdc_options, priv->server_princ, &realms)) {
	    if (strcmp(realms[0], priv->server_princ->realm) != 0) {
		kdc_log(context, config, 4,
			"Returning a referral to realm %s for "
			"server %s that was not found",
			realms[0], spn);
		krb5_free_principal(context, priv->server_princ);
                priv->server_princ = NULL;
		krb5_make_principal(context, &priv->server_princ, r, KRB5_TGS_NAME,
				    realms[0], NULL);
		free(priv->sname);
                priv->sname = NULL;
		ret = krb5_unparse_name(context, priv->server_princ, &priv->sname);
		if (ret) {
		    krb5_free_host_realm(context, realms);
		    goto out;
		}
		spn = priv->sname;

                free(ref_realm);
		ref_realm = strdup(realms[0]);

		krb5_free_host_realm(context, realms);
		goto server_lookup;
	    }
	    krb5_free_host_realm(context, realms);
	}
	msg = krb5_get_error_message(context, ret);
	kdc_log(context, config, 3,
		"Server not found in database: %s: %s", spn, msg);
	krb5_free_error_message(context, msg);
	if (ret == HDB_ERR_NOENTRY)
	    ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
        kdc_audit_addreason((kdc_request_t)priv,
                            "Service principal unknown");
	goto out;
    }

    /*
     * Now refetch the primary krbtgt, and get the current kvno (the
     * sign check may have been on an old kvno, and the server may
     * have been an incoming trust)
     */

    ret = krb5_make_principal(context,
                              &krbtgt_out_principal,
                              our_realm,
                              KRB5_TGS_NAME,
                              our_realm,
                              NULL);
    if (ret) {
        kdc_log(context, config, 4,
                "Failed to make krbtgt principal name object for "
                "authz-data signatures");
        goto out;
    }
    ret = krb5_unparse_name(context, krbtgt_out_principal, &krbtgt_out_n);
    if (ret) {
        kdc_log(context, config, 4,
                "Failed to make krbtgt principal name object for "
                "authz-data signatures");
        goto out;
    }

    ret = _kdc_db_fetch(context, config, krbtgt_out_principal,
			HDB_F_GET_KRBTGT, NULL, &krbtgt_outdb, &krbtgt_out);
    if (ret) {
	char *ktpn = NULL;
	ret = krb5_unparse_name(context, priv->krbtgt->principal, &ktpn);
	kdc_log(context, config, 4,
		"No such principal %s (needed for authz-data signature keys) "
		"while processing TGS-REQ for service %s with krbtgt %s",
		krbtgt_out_n, spn, (ret == 0) ? ktpn : "<unknown>");
	free(ktpn);
	ret = KRB5KRB_AP_ERR_NOT_US;
	goto out;
    }

    /*
     * Select enctype, return key and kvno.
     */

    {
	krb5_enctype etype;

	if(b->kdc_options.enc_tkt_in_skey) {
	    Ticket *t;
	    krb5_principal p;
	    Key *uukey;
	    krb5uint32 second_kvno = 0;
	    krb5uint32 *kvno_ptr = NULL;
	    size_t i;
	    HDB *user2user_db;
	    hdb_entry *user2user_client = NULL;
	    krb5_boolean user2user_kdc_issued = FALSE;
	    char *tpn;

	    if(b->additional_tickets == NULL ||
	       b->additional_tickets->len == 0){
		ret = KRB5KDC_ERR_BADOPTION; /* ? */
		kdc_log(context, config, 4,
			"No second ticket present in user-to-user request");
		kdc_audit_addreason((kdc_request_t)priv,
				    "No second ticket present in user-to-user request");
		goto out;
	    }
	    t = &b->additional_tickets->val[0];
	    if(!krb5_principalname_is_krbtgt(context, &t->sname)){
		/*
		 * Note: this check is not to be depended upon for
		 * security. Nothing prevents a client modifying the sname, as
		 * it is located in the unencrypted part of the ticket.
		 */

		kdc_log(context, config, 4,
			"Additional ticket is not a ticket-granting ticket");
		kdc_audit_addreason((kdc_request_t)priv,
				    "Additional ticket is not a ticket-granting ticket");
		ret = KRB5KDC_ERR_POLICY;
		goto out;
	    }
	    ret = _krb5_principalname2krb5_principal(context, &p, t->sname, t->realm);
	    if (ret)
		goto out;

	    ret = krb5_unparse_name(context, p, &tpn);
	    if (ret)
		goto out;
	    if(t->enc_part.kvno){
		second_kvno = *t->enc_part.kvno;
		kvno_ptr = &second_kvno;
	    }
	    ret = _kdc_db_fetch(context, config, p,
				HDB_F_GET_KRBTGT, kvno_ptr,
				&user2user_krbtgtdb, &user2user_krbtgt);
	    krb5_free_principal(context, p);
	    if(ret){
		if (ret == HDB_ERR_NOENTRY)
		    ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
		kdc_audit_addreason((kdc_request_t)priv,
				    "User-to-user service principal (TGS) unknown");
		krb5_xfree(tpn);
		goto out;
	    }
	    ret = hdb_enctype2key(context, user2user_krbtgt, NULL,
				  t->enc_part.etype, &uukey);
	    if(ret){
		ret = KRB5KDC_ERR_ETYPE_NOSUPP; /* XXX */
		kdc_audit_addreason((kdc_request_t)priv,
				    "User-to-user enctype not supported");
		krb5_xfree(tpn);
		goto out;
	    }
	    ret = krb5_decrypt_ticket(context, t, &uukey->key, &adtkt, 0);
	    if(ret) {
		kdc_audit_addreason((kdc_request_t)priv,
				    "User-to-user TGT decrypt failure");
		krb5_xfree(tpn);
		goto out;
	    }

	    ret = _kdc_verify_flags(context, config, &adtkt, tpn);
	    if (ret) {
		kdc_audit_addreason((kdc_request_t)priv,
				    "User-to-user TGT expired or invalid");
		krb5_xfree(tpn);
		goto out;
	    }
	    krb5_xfree(tpn);

	    /* Fetch the name from the TGT. */
	    ret = _krb5_principalname2krb5_principal(context, &user2user_princ,
						     adtkt.cname, adtkt.crealm);
	    if (ret)
		goto out;

	    ret = krb5_unparse_name(context, user2user_princ, &user2user_name);
	    if (ret)
		goto out;

	    /*
	     * Look up the name given in the TGT in the database. The user
	     * claims to have a ticket-granting-ticket to our KDC, so we should
	     * fail hard if we can't find the user - otherwise we can't do
	     * proper checks.
	     */
	    ret = _kdc_db_fetch(context, config, user2user_princ,
				HDB_F_GET_CLIENT | HDB_F_USER2USER_PRINCIPAL | flags,
				NULL, &user2user_db, &user2user_client);
	    if (ret == HDB_ERR_NOENTRY)
		ret = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	    if (ret)
		goto out;

	    /*
	     * The account is present in the database, now check the
	     * account flags.
	     *
	     * We check this as a client (because the purpose of
	     * user2user is that the server flag is not set, because
	     * the long-term key is not strong, but this does mean
	     * that a client with an expired password can't get accept
	     * a user2user ticket.
	     */
	    ret = kdc_check_flags(priv,
				  FALSE,
				  user2user_client,
				  NULL);
	    if (ret) {
		_kdc_free_ent(context, user2user_db, user2user_client);
		goto out;
	    }

	    /*
	     * Also check that the account is the same one specified in the
	     * request.
	     */
	    ret = _kdc_check_client_matches_target_service(context,
							   config,
							   serverdb,
							   priv->server,
							   user2user_client,
							   user2user_princ);
	    if (ret) {
		_kdc_free_ent(context, user2user_db, user2user_client);
		goto out;
	    }

	    /* Verify the PAC of the TGT. */
	    ret = _kdc_check_pac(priv, user2user_princ, NULL,
				 user2user_client, user2user_krbtgt, user2user_krbtgt, user2user_krbtgt,
				 &uukey->key, &priv->ticket_key->key, &adtkt,
				 &user2user_kdc_issued, &user2user_pac, NULL, NULL);
	    _kdc_free_ent(context, user2user_db, user2user_client);
	    if (ret) {
		const char *msg = krb5_get_error_message(context, ret);
		kdc_log(context, config, 0,
			"Verify PAC failed for %s (%s) from %s with %s",
			spn, user2user_name, from, msg);
		krb5_free_error_message(context, msg);
		goto out;
	    }

	    if ((config->require_pac && !user2user_pac)
		|| (user2user_pac && !user2user_kdc_issued))
	    {
		ret = KRB5KDC_ERR_BADOPTION;
		kdc_log(context, config, 0,
			"Ticket not signed with PAC; user-to-user failed (%s).",
			user2user_pac ? "Ticket unsigned" : "No PAC");
		goto out;
	    }

	    ekey = &adtkt.key;
	    for(i = 0; i < b->etype.len; i++)
		if (b->etype.val[i] == adtkt.key.keytype)
		    break;
	    if(i == b->etype.len) {
		kdc_log(context, config, 4,
			"Addition ticket has no matching etypes");
		krb5_clear_error_message(context);
		ret = KRB5KDC_ERR_ETYPE_NOSUPP;
                kdc_audit_addreason((kdc_request_t)priv,
                                    "No matching enctypes for 2nd ticket");
		goto out;
	    }
	    etype = b->etype.val[i];
	    kvno = 0;
	} else {
	    Key *skey;

	    ret = _kdc_find_session_etype(priv, b->etype.val, b->etype.len,
					  priv->server, &etype);
	    if(ret) {
		kdc_log(context, config, 4,
			"Server (%s) has no support for etypes", spn);
                kdc_audit_addreason((kdc_request_t)priv,
                                    "Enctype not supported");
		goto out;
	    }
	    ret = _kdc_get_preferred_key(context, config, priv->server, spn,
					 NULL, &skey);
	    if(ret) {
		kdc_log(context, config, 4,
			"Server (%s) has no supported etypes", spn);
                kdc_audit_addreason((kdc_request_t)priv,
                                    "Enctype not supported");
		goto out;
	    }
	    ekey = &skey->key;
	    kvno = priv->server->kvno;
	}

	ret = krb5_generate_random_keyblock(context, etype, &sessionkey);
	if (ret)
	    goto out;
    }

    /*
     * Check that service is in the same realm as the krbtgt. If it's
     * not the same, it's someone that is using a uni-directional trust
     * backward.
     */

    /* 
     * The first realm is the realm of the service, the second is
     * krbtgt/<this>/@REALM component of the krbtgt DN the request was
     * encrypted to.  The redirection via the krbtgt_out entry allows
     * the DB to possibly correct the case of the realm (Samba4 does
     * this) before the strcmp() 
     */
    if (strcmp(krb5_principal_get_realm(context, priv->server->principal),
	       krb5_principal_get_realm(context, krbtgt_out->principal)) != 0) {
	char *ktpn;
	ret = krb5_unparse_name(context, krbtgt_out->principal, &ktpn);
	kdc_log(context, config, 4,
		"Request with wrong krbtgt: %s",
		(ret == 0) ? ktpn : "<unknown>");
	if(ret == 0)
	    free(ktpn);
	ret = KRB5KRB_AP_ERR_NOT_US;
        kdc_audit_addreason((kdc_request_t)priv, "Request with wrong TGT");
	goto out;
    }

    ret = _kdc_get_preferred_key(context, config, krbtgt_out, krbtgt_out_n,
				 NULL, &tkey_sign);
    if (ret) {
	kdc_log(context, config, 4,
		    "Failed to find key for krbtgt PAC signature");
        kdc_audit_addreason((kdc_request_t)priv,
                            "Failed to find key for krbtgt PAC signature");
	goto out;
    }
    ret = hdb_enctype2key(context, krbtgt_out, NULL,
			  tkey_sign->key.keytype, &tkey_sign);
    if(ret) {
	kdc_log(context, config, 4,
		    "Failed to find key for krbtgt PAC signature");
        kdc_audit_addreason((kdc_request_t)priv,
                            "Failed to find key for krbtgt PAC signature");
	goto out;
    }

    if (_kdc_synthetic_princ_used_p(context, priv->ticket))
	flags |= HDB_F_SYNTHETIC_OK;

    if (!krb5_principal_compare(context, priv->krbtgt->principal, krbtgt_out->principal))
	flags |= HDB_F_CROSS_REALM_PRINCIPAL;

    ret = _kdc_db_fetch_client(context, config, flags, priv->client_princ,
			       cpn, our_realm, &clientdb, &priv->client);
    if (ret)
	goto out;
    /* flags &= ~HDB_F_SYNTHETIC_OK; */ /* `flags' is not used again below */
    priv->clientdb = clientdb;

    /* Validate armor TGT before potentially including device claims */
    if (priv->armor_ticket) {
	ret = _kdc_fast_check_armor_pac(priv, HDB_F_FOR_TGS_REQ);
	if (ret)
	    goto out;
    }

    ret = _kdc_check_pac(priv, priv->client_princ, NULL,
			 priv->client, priv->server,
			 priv->krbtgt, priv->krbtgt,
			 &priv->ticket_key->key, &priv->ticket_key->key, tgt,
			 &kdc_issued, &priv->pac, &priv->canon_client_princ,
			 &priv->pac_attributes);
    if (ret) {
	const char *msg = krb5_get_error_message(context, ret);
        kdc_audit_addreason((kdc_request_t)priv, "PAC check failed");
	kdc_log(context, config, 4,
		"Verify PAC failed for %s (%s) from %s with %s",
		spn, cpn, from, msg);
	krb5_free_error_message(context, msg);
	goto out;
    }

    /*
     * Process request
     */

    /*
     * Services for User: protocol transition and constrained delegation
     */

    if (priv->client != NULL &&
	(for_user = _kdc_find_padata(&priv->req,
				     &for_user_idx,
				     KRB5_PADATA_FOR_USER)) != NULL)
    {
	/* Process an S4U2Self request. */
	ret = _kdc_validate_protocol_transition(priv, for_user);
	if (ret)
	    goto out;
    } else if (priv->client != NULL
	       && b->additional_tickets != NULL
	       && b->additional_tickets->len != 0
	       && b->kdc_options.cname_in_addl_tkt
	       && b->kdc_options.enc_tkt_in_skey == 0)
    {
	/* Process an S4U2Proxy request. */
	ret = _kdc_validate_constrained_delegation(priv);
	if (ret)
	    goto out;
    } else if (priv->pac != NULL) {
	ret = _kdc_pac_update(priv, priv->client_princ, NULL, NULL,
			      priv->client, priv->server, priv->krbtgt,
			      &priv->pac);
	if (ret == KRB5_PLUGIN_NO_HANDLE) {
	    ret = 0;
	}
	if (ret) {
	    const char *msg = krb5_get_error_message(context, ret);
	    kdc_audit_addreason((kdc_request_t)priv, "PAC update failed");
	    kdc_log(context, config, 4,
		    "Update PAC failed for %s (%s) from %s with %s",
		    spn, cpn, from, msg);
	    krb5_free_error_message(context, msg);
	    goto out;
	}

	if (priv->pac == NULL) {
	    /* the plugin may indicate no PAC should be generated */
	    priv->pac_attributes = 0;
	}
    }

    if (b->enc_authorization_data) {
	unsigned auth_data_usage;
	krb5_crypto crypto;
	krb5_data ad;

	if (priv->rk_is_subkey != 0) {
	    auth_data_usage = KRB5_KU_TGS_REQ_AUTH_DAT_SUBKEY;
	} else {
	    auth_data_usage = KRB5_KU_TGS_REQ_AUTH_DAT_SESSION;
	}

	ret = krb5_crypto_init(context, &priv->enc_ad_key, 0, &crypto);
	if (ret) {
	    const char *msg = krb5_get_error_message(context, ret);
	    kdc_audit_addreason((kdc_request_t)priv,
				"krb5_crypto_init() failed for "
				"enc_authorization_data");
	    kdc_log(context, config, 4, "krb5_crypto_init failed: %s", msg);
	    krb5_free_error_message(context, msg);
	    goto out;
	}
	ret = krb5_decrypt_EncryptedData(context,
					 crypto,
					 auth_data_usage,
					 b->enc_authorization_data,
					 &ad);
	krb5_crypto_destroy(context, crypto);
	if(ret){
	    kdc_audit_addreason((kdc_request_t)priv,
				"Failed to decrypt enc-authorization-data");
	    kdc_log(context, config, 4,
		    "Failed to decrypt enc-authorization-data");
	    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY; /* ? */
	    goto out;
	}
	ALLOC(auth_data);
	if (auth_data == NULL) {
	    krb5_data_free(&ad);
	    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY; /* ? */
	    goto out;
	}
	ret = decode_AuthorizationData(ad.data, ad.length, auth_data, NULL);
	krb5_data_free(&ad);
	if(ret){
	    free(auth_data);
	    auth_data = NULL;
	    kdc_audit_addreason((kdc_request_t)priv,
				"Failed to decode authorization data");
	    kdc_log(context, config, 4, "Failed to decode authorization data");
	    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY; /* ? */
	    goto out;
	}
    }

    /*
     * Check flags
     */

    ret = kdc_check_flags(priv, FALSE, priv->client, priv->server);
    if(ret)
	goto out;

    if((b->kdc_options.validate || b->kdc_options.renew) &&
       !krb5_principal_compare(context,
			       priv->krbtgt->principal,
			       priv->server->principal)){
        kdc_audit_addreason((kdc_request_t)priv, "Inconsistent request");
	kdc_log(context, config, 4, "Inconsistent request.");
	ret = KRB5KDC_ERR_SERVER_NOMATCH;
	goto out;
    }

    /* check for valid set of addresses */
    if (!_kdc_check_addresses(priv, tgt->caddr, from_addr)) {
        if (config->check_ticket_addresses) {
            ret = KRB5KRB_AP_ERR_BADADDR;
            kdc_audit_setkv_bool((kdc_request_t)priv, "wrongaddr", TRUE);
            kdc_log(context, config, 4, "Request from wrong address");
            kdc_audit_addreason((kdc_request_t)priv, "Request from wrong address");
            goto out;
        } else if (config->warn_ticket_addresses) {
            kdc_audit_setkv_bool((kdc_request_t)priv, "wrongaddr", TRUE);
        }
    }

    /* check local and per-principal anonymous ticket issuance policy */
    if (is_anon_tgs_request_p(b, tgt)) {
	ret = _kdc_check_anon_policy(priv);
	if (ret)
	    goto out;
    }

    /*
     * If this is an referral, add server referral data to the
     * auth_data reply .
     */
    if (ref_realm) {
	PA_DATA pa;
	krb5_crypto crypto;

	kdc_log(context, config, 3,
		"Adding server referral to %s", ref_realm);

	ret = krb5_crypto_init(context, &sessionkey, 0, &crypto);
	if (ret)
	    goto out;

	ret = build_server_referral(context, config, crypto, ref_realm,
				    NULL, s, &pa.padata_value);
	krb5_crypto_destroy(context, crypto);
	if (ret) {
            kdc_audit_addreason((kdc_request_t)priv, "Referral build failed");
	    kdc_log(context, config, 4,
		    "Failed building server referral");
	    goto out;
	}
	pa.padata_type = KRB5_PADATA_SERVER_REFERRAL;

	ret = add_METHOD_DATA(priv->rep.padata, &pa);
	krb5_data_free(&pa.padata_value);
	if (ret) {
	    kdc_log(context, config, 4,
		    "Add server referral METHOD-DATA failed");
	    goto out;
	}
    }

    /*
     * Only add ticket signature if the requested server is not krbtgt, and
     * either the header server is krbtgt or, in the case of renewal/validation
     * if it was signed with PAC ticket signature and we verified it.
     * Currently Heimdal only allows renewal of krbtgt anyway but that might
     * change one day (see issue #763) so make sure to check for it.
     */

    if (kdc_issued &&
	!krb5_principal_is_krbtgt(context, priv->server->principal)) {

	add_ticket_sig = TRUE;
    }

    /*
     * Active-Directory implementations use the high part of the kvno as the
     * read-only-dc identifier, we need to embed it in the PAC KDC signatures.
     */

    rodc_id = krbtgt_out->kvno >> 16;

    /*
     *
     */

    ret = tgs_make_reply(priv,
			 tgt,
			 ekey,
			 &tkey_sign->key,
			 &sessionkey,
			 kvno,
			 auth_data,
                         tgt_realm,
			 rodc_id,
			 add_ticket_sig);

out:
    free(user2user_name);
    free(krbtgt_out_n);
    _krb5_free_capath(context, capath);

    krb5_free_keyblock_contents(context, &sessionkey);
    if(krbtgt_out)
	_kdc_free_ent(context, krbtgt_outdb, krbtgt_out);
    if(user2user_krbtgt)
	_kdc_free_ent(context, user2user_krbtgtdb, user2user_krbtgt);

    krb5_free_principal(context, user2user_princ);
    krb5_free_principal(context, krbtgt_out_principal);
    free(ref_realm);

    if (auth_data) {
       free_AuthorizationData(auth_data);
       free(auth_data);
    }

    free_EncTicketPart(&adtkt);

    krb5_pac_free(context, user2user_pac);

    return ret;
}

/*
 *
 */

krb5_error_code
_kdc_tgs_rep(astgs_request_t r)
{
    krb5_kdc_configuration *config = r->config;
    KDC_REQ *req = &r->req;
    krb5_data *data = r->reply;
    const char *from = r->from;
    struct sockaddr *from_addr = r->addr;
    int datagram_reply = r->datagram_reply;
    krb5_error_code ret;
    int i = 0;
    const PA_DATA *tgs_req, *pa;
    krb5_enctype krbtgt_etype = ETYPE_NULL;

    time_t *csec = NULL;
    int *cusec = NULL;

    r->e_text = NULL;

    if(req->padata == NULL){
	ret = KRB5KDC_ERR_PREAUTH_REQUIRED; /* XXX ??? */
	kdc_log(r->context, config, 4,
		"TGS-REQ from %s without PA-DATA", from);
	goto out;
    }

    i = 0;
    pa = _kdc_find_padata(&r->req, &i, KRB5_PADATA_FX_FAST_ARMOR);
    if (pa) {
	kdc_log(r->context, r->config, 10, "Found TGS-REQ FAST armor inside TGS-REQ pa-data");
	ret = KRB5KRB_ERR_GENERIC;
	goto out;
    }

    i = 0;
    tgs_req = _kdc_find_padata(req, &i, KRB5_PADATA_TGS_REQ);
    if(tgs_req == NULL){
	ret = KRB5KDC_ERR_PADATA_TYPE_NOSUPP;

	kdc_log(r->context, config, 4,
		"TGS-REQ from %s without PA-TGS-REQ", from);
	goto out;
    }
    ret = tgs_parse_request(r, tgs_req,
			    &krbtgt_etype,
			    from, from_addr,
			    &csec, &cusec);
    if (ret == HDB_ERR_NOT_FOUND_HERE) {
	/* kdc_log() is called in tgs_parse_request() */
	goto out;
    }
    if (ret) {
	kdc_log(r->context, config, 4,
		"Failed parsing TGS-REQ from %s", from);
	goto out;
    }

    ret = _kdc_fast_strengthen_reply_key(r);
    if (ret)
	goto out;

    ALLOC(r->rep.padata);
    if (r->rep.padata == NULL) {
	ret = ENOMEM;
	krb5_set_error_message(r->context, ret, N_("malloc: out of memory", ""));
	goto out;
    }

    ret = tgs_build_reply(r,
			  krbtgt_etype,
			  from_addr);
    if (ret) {
	kdc_log(r->context, config, 4,
		"Failed building TGS-REP to %s", from);
	goto out;
    }

    /* */
    if (datagram_reply && data->length > config->max_datagram_reply_length) {
	krb5_data_free(data);
	ret = KRB5KRB_ERR_RESPONSE_TOO_BIG;
        _kdc_set_const_e_text(r, "Reply packet too large");
    }

out:
    if (ret) {
	/* Overwrite ‘error_code’ only if we have an actual error. */
	r->error_code = ret;
    }
    {
	krb5_error_code ret2 = _kdc_audit_request(r);
	if (ret2) {
	    krb5_data_free(data);
	    ret = ret2;
	}
    }

    if(ret && ret != HDB_ERR_NOT_FOUND_HERE && data->data == NULL){
	METHOD_DATA error_method = { 0, NULL };

	kdc_log(r->context, config, 5, "tgs-req: sending error: %d to client", ret);
	ret = _kdc_fast_mk_error(r,
				 &error_method,
				 r->armor_crypto,
				 &req->req_body,
				 r->error_code ? r->error_code : ret,
				 r->client_princ ? r->client_princ :(r->ticket != NULL ? r->ticket->client : NULL),
				 r->server_princ ? r->server_princ :(r->ticket != NULL ? r->ticket->server : NULL),
				 csec, cusec,
				 data);
	free_METHOD_DATA(&error_method);
    }
    free(csec);
    free(cusec);

    if (r->ek.encrypted_pa_data) {
	free_METHOD_DATA(r->ek.encrypted_pa_data);
	free(r->ek.encrypted_pa_data);
    }

    free_TGS_REP(&r->rep);
    free_TransitedEncoding(&r->et.transited);
    free(r->et.starttime);
    free(r->et.renew_till);
    if(r->et.authorization_data) {
	free_AuthorizationData(r->et.authorization_data);
	free(r->et.authorization_data);
    }
    free_LastReq(&r->ek.last_req);
    if (r->et.key.keyvalue.data) {
	memset_s(r->et.key.keyvalue.data, 0, r->et.key.keyvalue.length,
		 r->et.key.keyvalue.length);
    }
    free_EncryptionKey(&r->et.key);

    if (r->canon_client_princ) {
	krb5_free_principal(r->context, r->canon_client_princ);
	r->canon_client_princ = NULL;
    }
    if (r->armor_crypto) {
	krb5_crypto_destroy(r->context, r->armor_crypto);
	r->armor_crypto = NULL;
    }
    if (r->armor_ticket)
	krb5_free_ticket(r->context, r->armor_ticket);
    if (r->armor_server)
	_kdc_free_ent(r->context, r->armor_serverdb, r->armor_server);
    if (r->armor_client_principal) {
	krb5_free_principal(r->context, r->armor_client_principal);
	r->armor_client_principal = NULL;
    }
    if (r->armor_client)
	_kdc_free_ent(r->context,
		      r->armor_clientdb,
		      r->armor_client);
    if (r->armor_pac)
	krb5_pac_free(r->context, r->armor_pac);
    krb5_free_keyblock_contents(r->context, &r->reply_key);
    krb5_free_keyblock_contents(r->context, &r->enc_ad_key);
    krb5_free_keyblock_contents(r->context, &r->strengthen_key);

    if (r->ticket)
	krb5_free_ticket(r->context, r->ticket);
    if (r->krbtgt)
	_kdc_free_ent(r->context, r->krbtgtdb, r->krbtgt);

    if (r->client)
	_kdc_free_ent(r->context, r->clientdb, r->client);
    krb5_free_principal(r->context, r->client_princ);
    if (r->server)
	_kdc_free_ent(r->context, r->serverdb, r->server);
    krb5_free_principal(r->context, r->server_princ);
    _kdc_free_fast_state(&r->fast);
    krb5_pac_free(r->context, r->pac);

    return ret;
}
