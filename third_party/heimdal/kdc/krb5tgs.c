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
_kdc_check_pac(krb5_context context,
	       krb5_kdc_configuration *config,
	       const krb5_principal client_principal,
	       const krb5_principal delegated_proxy_principal,
	       hdb_entry_ex *client,
	       hdb_entry_ex *server,
	       hdb_entry_ex *krbtgt,
	       hdb_entry_ex *ticket_server,
	       const EncryptionKey *server_check_key,
	       const EncryptionKey *krbtgt_check_key,
	       EncTicketPart *tkt,
	       krb5_boolean *kdc_issued,
	       krb5_pac *ppac,
	       krb5_principal *pac_canon_name,
	       uint64_t *pac_attributes)
{
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

    if (pac_canon_name) {
	ret = _krb5_pac_get_canon_principal(context, pac, pac_canon_name);
	if (ret && ret != ENOENT) {
	    krb5_pac_free(context, pac);
	     return ret;
	}
    }
    if (pac_attributes) {
	ret = _krb5_pac_get_attributes_info(context, pac, pac_attributes);
	if (ret && ret != ENOENT) {
	    krb5_pac_free(context, pac);
	    return ret;
	}
	if (ret == ENOENT)
	    *pac_attributes = KRB5_PAC_WAS_GIVEN_IMPLICITLY;
    }

    /* Verify the KDC signatures. */
    ret = _kdc_pac_verify(context, client_principal, delegated_proxy_principal,
			  client, server, krbtgt, &pac);
    if (ret == 0) {
	if (pac == NULL) {
	    /* the plugin may indicate no PAC should be generated */
	    *pac_attributes = 0;
	}
    } else if (ret == KRB5_PLUGIN_NO_HANDLE) {
	/*
	 * We can't verify the KDC signatures if the ticket was issued by
	 * another realm's KDC.
	 */
	if (krb5_realm_compare(context, server->entry.principal,
			       ticket_server->entry.principal)) {
	    ret = krb5_pac_verify(context, pac, 0, NULL, NULL,
				  krbtgt_check_key);
	    if (ret) {
		krb5_pac_free(context, pac);
		return ret;
	    }
	}

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
					   ticket_server->entry.principal);
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
	    _kdc_audit_addreason((kdc_request_t)r,
                                 "Bad request to validate ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	if(*tgt->starttime > kdc_time){
	    _kdc_audit_addreason((kdc_request_t)r,
                                 "Early request to validate ticket");
	    return KRB5KRB_AP_ERR_TKT_NYV;
	}
	/* XXX  tkt = tgt */
	et->flags.invalid = 0;
    } else if (tgt->flags.invalid) {
	_kdc_audit_addreason((kdc_request_t)r,
                             "Ticket-granting ticket has INVALID flag set");
	return KRB5KRB_AP_ERR_TKT_INVALID;
    }

    if(f.forwardable){
	if (!tgt->flags.forwardable) {
	    _kdc_audit_addreason((kdc_request_t)r,
                                 "Bad request for forwardable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.forwardable = 1;
    }
    if(f.forwarded){
	if (!tgt->flags.forwardable) {
	    _kdc_audit_addreason((kdc_request_t)r,
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
	    _kdc_audit_addreason((kdc_request_t)r,
                                 "Bad request for proxiable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.proxiable = 1;
    }
    if(f.proxy){
	if (!tgt->flags.proxiable) {
	    _kdc_audit_addreason((kdc_request_t)r,
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
	    _kdc_audit_addreason((kdc_request_t)r,
                                 "Bad request for post-datable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.may_postdate = 1;
    }
    if(f.postdated){
	if (!tgt->flags.may_postdate) {
	    _kdc_audit_addreason((kdc_request_t)r,
                                 "Bad request for postdated ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	if(b->from)
	    *et->starttime = *b->from;
	et->flags.postdated = 1;
	et->flags.invalid = 1;
    } else if (b->from && *b->from > kdc_time + r->context->max_skew) {
	_kdc_audit_addreason((kdc_request_t)r,
                             "Ticket cannot be postdated");
	return KRB5KDC_ERR_CANNOT_POSTDATE;
    }

    if(f.renewable){
	if (!tgt->flags.renewable || tgt->renew_till == NULL) {
	    _kdc_audit_addreason((kdc_request_t)r,
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
	    _kdc_audit_addreason((kdc_request_t)r,
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
	_kdc_audit_addreason((kdc_request_t)r,
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
 * Determine if constrained delegation is allowed from this client to this server
 */

static krb5_error_code
check_constrained_delegation(krb5_context context,
			     krb5_kdc_configuration *config,
			     HDB *clientdb,
			     hdb_entry_ex *client,
			     hdb_entry_ex *server,
			     krb5_const_principal target)
{
    const HDB_Ext_Constrained_delegation_acl *acl;
    krb5_error_code ret;
    size_t i;

    /*
     * constrained_delegation (S4U2Proxy) only works within
     * the same realm. We use the already canonicalized version
     * of the principals here, while "target" is the principal
     * provided by the client.
     */
    if(!krb5_realm_compare(context, client->entry.principal, server->entry.principal)) {
	ret = KRB5KDC_ERR_BADOPTION;
	kdc_log(context, config, 4,
	    "Bad request for constrained delegation");
	return ret;
    }

    if (clientdb->hdb_check_constrained_delegation) {
	ret = clientdb->hdb_check_constrained_delegation(context, clientdb, client, target);
	if (ret == 0)
	    return 0;
    } else {
	/* if client delegates to itself, that ok */
	if (krb5_principal_compare(context, client->entry.principal, server->entry.principal) == TRUE)
	    return 0;

	ret = hdb_entry_get_ConstrainedDelegACL(&client->entry, &acl);
	if (ret) {
	    krb5_clear_error_message(context);
	    return ret;
	}

	if (acl) {
	    for (i = 0; i < acl->len; i++) {
		if (krb5_principal_compare(context, target, &acl->val[i]) == TRUE)
		    return 0;
	    }
	}
	ret = KRB5KDC_ERR_BADOPTION;
    }
    kdc_log(context, config, 4,
	    "Bad request for constrained delegation");
    return ret;
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

static krb5_error_code
check_client_matches_target_service(krb5_context context,
				    krb5_kdc_configuration *config,
				    HDB *clientdb,
				    hdb_entry_ex *client,
				    hdb_entry_ex *target_server,
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
				      client->entry.principal,
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
	       krb5_principal tgt_name,
	       const EncTicketPart *tgt,
	       const EncryptionKey *serverkey,
	       const EncryptionKey *krbtgtkey,
	       const krb5_keyblock *sessionkey,
	       krb5_kvno kvno,
	       AuthorizationData *auth_data,
	       hdb_entry_ex *server,
	       krb5_principal server_principal,
	       hdb_entry_ex *client,
	       krb5_principal client_principal,
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

    rep->pvno = 5;
    rep->msg_type = krb_tgs_rep;

    et->authtime = tgt->authtime;
    _kdc_fix_time(&b->till);
    et->endtime = min(tgt->endtime, *b->till);
    ALLOC(et->starttime);
    *et->starttime = kdc_time;

    ret = check_tgs_flags(r, b, tgt_name, tgt, et);
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

/* these will consult the database in future release */
#define PRINCIPAL_FORCE_TRANSITED_CHECK(P)		0
#define PRINCIPAL_ALLOW_DISABLE_TRANSITED_CHECK(P)	0

    ret = fix_transited_encoding(r->context, r->config,
				 !f.disable_transited_check ||
				 GLOBAL_FORCE_TRANSITED_CHECK ||
				 PRINCIPAL_FORCE_TRANSITED_CHECK(server) ||
				 !((GLOBAL_ALLOW_PER_PRINCIPAL &&
				    PRINCIPAL_ALLOW_DISABLE_TRANSITED_CHECK(server)) ||
				   GLOBAL_ALLOW_DISABLE_TRANSITED_CHECK),
				 &tgt->transited, et,
				 krb5_principal_get_realm(r->context, client_principal),
				 krb5_principal_get_realm(r->context, server->entry.principal),
				 tgt_realm);
    if(ret)
	goto out;

    ret = copy_Realm(&server_principal->realm, &rep->ticket.realm);
    if (ret)
	goto out;
    _krb5_principal2principalname(&rep->ticket.sname, server_principal);
    ret = copy_Realm(&tgt_name->realm, &rep->crealm);
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
	ret = copy_PrincipalName(&tgt_name->name, &rep->cname);
    if (ret)
	goto out;
    rep->ticket.tkt_vno = 5;

    ek->caddr = et->caddr;

    {
	time_t life;
	life = et->endtime - *et->starttime;
	if(client && client->entry.max_life)
	    life = min(life, *client->entry.max_life);
	if(server->entry.max_life)
	    life = min(life, *server->entry.max_life);
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
	if(client && client->entry.max_renew)
	    renew = min(renew, *client->entry.max_renew);
	if(server->entry.max_renew)
	    renew = min(renew, *server->entry.max_renew);
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
    et->flags.ok_as_delegate = server->entry.flags.ok_as_delegate;

    /* See MS-KILE 3.3.5.1 */
    if (!server->entry.flags.forwardable)
	et->flags.forwardable = 0;
    if (!server->entry.flags.proxiable)
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
	&& _kdc_is_weak_exception(server->entry.principal, serverkey->keytype))
    {
	krb5_enctype_enable(r->context, serverkey->keytype);
	is_weak = 1;
    }

    if (r->client_princ) {
	char *cpn;

	krb5_unparse_name(r->context, r->client_princ, &cpn);
	_kdc_audit_addkv((kdc_request_t)r, 0, "canon_client_name", "%s",
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
	_kdc_audit_addkv((kdc_request_t)r, 0, "pac_attributes", "%lx",
			 (long)r->pac_attributes);

	/*
	 * PACs are included when issuing TGTs, if there is no PAC_ATTRIBUTES
	 * buffer (legacy behavior) or if the attributes buffer indicates the
	 * AS client requested one.
	 */
	if (_kdc_include_pac_p(r)) {
	    krb5_boolean is_tgs =
		krb5_principal_is_krbtgt(r->context, server->entry.principal);

	    ret = _krb5_kdc_pac_sign_ticket(r->context, r->pac, tgt_name, serverkey,
					    krbtgtkey, rodc_id, NULL, r->client_princ,
					    add_ticket_sig, et,
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

    krb5_auth_con_getauthenticator(context, ac, &auth);
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
    else if (server->name.name_string.len == 3) {
	/*
	  This is used to give referrals for the
	  E3514235-4B06-11D1-AB04-00C04FC2DCD2/NTDSGUID/DNSDOMAIN
	  SPN form, which is used for inter-domain communication in AD
	 */
	name = server->name.name_string.val[2];
	kdc_log(context, config, 4, "Giving 3 part referral for %s", name);
	*realms = malloc(sizeof(char *)*2);
	if (*realms == NULL) {
	    krb5_set_error_message(context, ENOMEM, N_("malloc: out of memory", ""));
	    return FALSE;
	}
	(*realms)[0] = strdup(name);
	(*realms)[1] = NULL;
	return TRUE;
    } else if (server->name.name_string.len > 1)
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
		  hdb_entry_ex **krbtgt,
		  krb5_enctype *krbtgt_etype,
		  krb5_ticket **ticket,
		  const char *from,
		  const struct sockaddr *from_addr,
		  time_t **csec,
		  int **cusec,
		  AuthorizationData **auth_data)
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
    krb5_crypto crypto;
    krb5uint32 krbtgt_kvno;     /* kvno used for the PA-TGS-REQ AP-REQ Ticket */
    krb5uint32 krbtgt_kvno_try;
    int kvno_search_tries = 4;  /* number of kvnos to try when tkt_vno == 0 */
    const Keys *krbtgt_keys;/* keyset for TGT tkt_vno */
    Key *tkey;
    krb5_keyblock *subkey = NULL;
    unsigned usage;

    *auth_data = NULL;
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

    if(!get_krbtgt_realm(&ap_req.ticket.sname)){
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
			&krbtgt_kvno, NULL, krbtgt);

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

    krbtgt_kvno_try = krbtgt_kvno ? krbtgt_kvno : (*krbtgt)->entry.kvno;
    *krbtgt_etype = ap_req.ticket.enc_part.etype;

next_kvno:
    krbtgt_keys = hdb_kvno2keys(r->context, &(*krbtgt)->entry, krbtgt_kvno_try);
    ret = hdb_enctype2key(r->context, &(*krbtgt)->entry, krbtgt_keys,
			  ap_req.ticket.enc_part.etype, &tkey);
    if (ret && krbtgt_kvno == 0 && kvno_search_tries > 0) {
	kvno_search_tries--;
	krbtgt_kvno_try--;
	goto next_kvno;
    } else if (ret) {
	char *str = NULL, *p = NULL;

	krb5_enctype_to_string(r->context, ap_req.ticket.enc_part.etype, &str);
	krb5_unparse_name(r->context, princ, &p);
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
			      ticket,
			      KRB5_KU_TGS_REQ_AUTH);
    if (*ticket && (*ticket)->ticket.caddr)
        _kdc_audit_addaddrs((kdc_request_t)r, (*ticket)->ticket.caddr, "tixaddrs");
    if (r->config->warn_ticket_addresses && ret == KRB5KRB_AP_ERR_BADADDR &&
        *ticket != NULL) {
        _kdc_audit_addkv((kdc_request_t)r, 0, "wrongaddr", "yes");
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

    ret = tgs_check_authenticator(r->context, config, ac, b,
                                  &(*ticket)->ticket.key);
    if (ret) {
	krb5_auth_con_free(r->context, ac);
	goto out;
    }

    usage = KRB5_KU_TGS_REQ_AUTH_DAT_SUBKEY;
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
	usage = KRB5_KU_TGS_REQ_AUTH_DAT_SESSION;
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

    if (b->enc_authorization_data) {
	krb5_data ad;

	ret = krb5_crypto_init(r->context, &r->reply_key, 0, &crypto);
	if (ret) {
	    const char *msg = krb5_get_error_message(r->context, ret);
	    krb5_auth_con_free(r->context, ac);
	    kdc_log(r->context, config, 4, "krb5_crypto_init failed: %s", msg);
	    krb5_free_error_message(r->context, msg);
	    goto out;
	}
	ret = krb5_decrypt_EncryptedData (r->context,
					  crypto,
					  usage,
					  b->enc_authorization_data,
					  &ad);
	krb5_crypto_destroy(r->context, crypto);
	if(ret){
	    krb5_auth_con_free(r->context, ac);
	    kdc_log(r->context, config, 4,
		    "Failed to decrypt enc-authorization-data");
	    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY; /* ? */
	    goto out;
	}
	ALLOC(*auth_data);
	if (*auth_data == NULL) {
	    krb5_auth_con_free(r->context, ac);
	    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY; /* ? */
	    goto out;
	}
	ret = decode_AuthorizationData(ad.data, ad.length, *auth_data, NULL);
	if(ret){
	    krb5_auth_con_free(r->context, ac);
	    free(*auth_data);
	    *auth_data = NULL;
	    kdc_log(r->context, config, 4, "Failed to decode authorization data");
	    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY; /* ? */
	    goto out;
	}
    }

    ret = validate_fast_ad(r, (*ticket)->ticket.authorization_data);
    if (ret)
	goto out;

    
    /*
     * Check for FAST request
     */

    ret = _kdc_fast_unwrap_request(r, *ticket, ac);
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
		     hdb_entry_ex **client_out)
{
    krb5_error_code ret;
    hdb_entry_ex *client = NULL;

    *client_out = NULL;

    ret = _kdc_db_fetch(context, config, cp, HDB_F_GET_CLIENT | flags,
			NULL, clientdb, &client);
    if (ret == HDB_ERR_NOT_FOUND_HERE) {
	/*
	 * This is OK, we are just trying to find out if they have
	 * been disabled or deleted in the meantime; missing secrets
	 * are OK.
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
    } else if (client->entry.flags.invalid || !client->entry.flags.client) {
        kdc_log(context, config, 4, "Client has invalid bit set");
	_kdc_free_ent(context, client);
        return KRB5KDC_ERR_POLICY;
    }

    *client_out = client;

    return 0;
}

static krb5_error_code
tgs_build_reply(astgs_request_t priv,
		hdb_entry_ex *krbtgt,
		krb5_enctype krbtgt_etype,
		krb5_ticket *ticket,
		AuthorizationData **auth_data,
		const struct sockaddr *from_addr)
{
    krb5_context context = priv->context;
    krb5_kdc_configuration *config = priv->config;
    KDC_REQ *req = &priv->req;
    KDC_REQ_BODY *b = &priv->req.req_body;
    const char *from = priv->from;
    krb5_error_code ret, ret2;
    krb5_principal cp = NULL, sp = NULL, rsp = NULL, tp = NULL, dp = NULL;
    krb5_principal krbtgt_out_principal = NULL;
    krb5_principal user2user_princ = NULL;
    char *spn = NULL, *cpn = NULL, *tpn = NULL, *dpn = NULL, *krbtgt_out_n = NULL;
    char *user2user_name = NULL;
    hdb_entry_ex *server = NULL, *client = NULL, *s4u2self_impersonated_client = NULL;
    hdb_entry_ex *user2user_krbtgt = NULL;
    HDB *clientdb, *s4u2self_impersonated_clientdb;
    HDB *serverdb = NULL;
    krb5_realm ref_realm = NULL;
    EncTicketPart *tgt = &ticket->ticket;
    const EncryptionKey *ekey;
    krb5_keyblock sessionkey;
    krb5_kvno kvno;
    krb5_pac user2user_pac = NULL;
    uint16_t rodc_id;
    krb5_boolean add_ticket_sig = FALSE;
    const char *tgt_realm = /* Realm of TGT issuer */
        krb5_principal_get_realm(context, krbtgt->entry.principal);
    const char *our_realm = /* Realm of this KDC */
        krb5_principal_get_comp_string(context, krbtgt->entry.principal, 1);
    char **capath = NULL;
    size_t num_capath = 0;

    hdb_entry_ex *krbtgt_out = NULL;

    PrincipalName *s;
    Realm r;
    EncTicketPart adtkt;
    char opt_str[128];
    krb5_boolean kdc_issued = FALSE;

    Key *tkey_sign;
    int flags = HDB_F_FOR_TGS_REQ;

    int result;

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

    if (s == NULL) {
	ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
        _kdc_set_const_e_text(priv, "No server in request");
	goto out;
    }

    _krb5_principalname2krb5_principal(context, &sp, *s, r);
    ret = krb5_unparse_name(context, sp, &priv->sname);
    if (ret)
	goto out;
    spn = priv->sname;
    _krb5_principalname2krb5_principal(context, &cp, tgt->cname, tgt->crealm);
    ret = krb5_unparse_name(context, cp, &priv->cname);
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
    priv->server = NULL;
    if (server)
        _kdc_free_ent(context, server);
    server = NULL;
    ret = _kdc_db_fetch(context, config, sp,
                        HDB_F_GET_SERVER | HDB_F_DELAY_NEW_KEYS | flags,
			NULL, &serverdb, &server);
    priv->server = server;
    if (ret == HDB_ERR_NOT_FOUND_HERE) {
	kdc_log(context, config, 5, "target %s does not have secrets at this KDC, need to proxy", spn);
        _kdc_audit_addreason((kdc_request_t)priv, "Target not found here");
	goto out;
    } else if (ret == HDB_ERR_WRONG_REALM) {
        free(ref_realm);
	ref_realm = strdup(server->entry.principal->realm);
	if (ref_realm == NULL) {
            ret = krb5_enomem(context);
	    goto out;
	}

	kdc_log(context, config, 4,
		"Returning a referral to realm %s for "
		"server %s.",
		ref_realm, spn);
	krb5_free_principal(context, sp);
	sp = NULL;
	ret = krb5_make_principal(context, &sp, r, KRB5_TGS_NAME,
				  ref_realm, NULL);
	if (ret)
	    goto out;
	free(priv->sname);
        priv->sname = NULL;
	ret = krb5_unparse_name(context, sp, &priv->sname);
	if (ret)
	    goto out;
	spn = priv->sname;

	goto server_lookup;
    } else if (ret) {
	const char *new_rlm, *msg;
	Realm req_rlm;
	krb5_realm *realms;

	if (!config->autodetect_referrals) {
		/* noop */
        } else if ((req_rlm = get_krbtgt_realm(&sp->name)) != NULL) {
            if (capath == NULL) {
                /* With referalls, hierarchical capaths are always enabled */
                ret2 = _krb5_find_capath(context, tgt->crealm, our_realm,
                                         req_rlm, TRUE, &capath, &num_capath);
                if (ret2) {
                    ret = ret2;
                    _kdc_audit_addreason((kdc_request_t)priv,
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

                krb5_free_principal(context, sp);
                sp = NULL;
                krb5_make_principal(context, &sp, r,
                                    KRB5_TGS_NAME, ref_realm, NULL);
                free(priv->sname);
                priv->sname = NULL;
                ret = krb5_unparse_name(context, sp, &priv->sname);
                if (ret)
                    goto out;
                spn = priv->sname;
                goto server_lookup;
            }
	} else if (need_referral(context, config, &b->kdc_options, sp, &realms)) {
	    if (strcmp(realms[0], sp->realm) != 0) {
		kdc_log(context, config, 4,
			"Returning a referral to realm %s for "
			"server %s that was not found",
			realms[0], spn);
		krb5_free_principal(context, sp);
                sp = NULL;
		krb5_make_principal(context, &sp, r, KRB5_TGS_NAME,
				    realms[0], NULL);
		free(priv->sname);
                priv->sname = NULL;
		ret = krb5_unparse_name(context, sp, &priv->sname);
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
        _kdc_audit_addreason((kdc_request_t)priv,
                             "Service principal unknown");
	goto out;
    }

    /*
     * RFC 6806 notes that names MUST NOT be changed in the response to
     * a TGS request. Hence we ignore the setting of the canonicalize
     * KDC option. However, for legacy interoperability we do allow the
     * backend to override this by setting the force-canonicalize HDB
     * flag in the server entry.
     */
    if (server->entry.flags.force_canonicalize)
	rsp = server->entry.principal;
    else
	rsp = sp;

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
			HDB_F_GET_KRBTGT, NULL, NULL, &krbtgt_out);
    if (ret) {
	char *ktpn = NULL;
	ret = krb5_unparse_name(context, krbtgt->entry.principal, &ktpn);
	kdc_log(context, config, 4,
		"No such principal %s (needed for authz-data signature keys) "
		"while processing TGS-REQ for service %s with krbtg %s",
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
	    hdb_entry_ex *user2user_client = NULL;
	    krb5_boolean user2user_kdc_issued = FALSE;

	    if(b->additional_tickets == NULL ||
	       b->additional_tickets->len == 0){
		ret = KRB5KDC_ERR_BADOPTION; /* ? */
		kdc_log(context, config, 4,
			"No second ticket present in user-to-user request");
		_kdc_audit_addreason((kdc_request_t)priv,
				     "No second ticket present in user-to-user request");
		goto out;
	    }
	    t = &b->additional_tickets->val[0];
	    if(!get_krbtgt_realm(&t->sname)){
		kdc_log(context, config, 4,
			"Additional ticket is not a ticket-granting ticket");
		_kdc_audit_addreason((kdc_request_t)priv,
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
				NULL, &user2user_krbtgt);
	    krb5_free_principal(context, p);
	    if(ret){
		if (ret == HDB_ERR_NOENTRY)
		    ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
		_kdc_audit_addreason((kdc_request_t)priv,
				     "User-to-user service principal (TGS) unknown");
		goto out;
	    }
	    ret = hdb_enctype2key(context, &user2user_krbtgt->entry, NULL,
				  t->enc_part.etype, &uukey);
	    if(ret){
		ret = KRB5KDC_ERR_ETYPE_NOSUPP; /* XXX */
		_kdc_audit_addreason((kdc_request_t)priv,
				     "User-to-user enctype not supported");
		goto out;
	    }
	    ret = krb5_decrypt_ticket(context, t, &uukey->key, &adtkt, 0);
	    if(ret) {
		_kdc_audit_addreason((kdc_request_t)priv,
				     "User-to-user TGT decrypt failure");
		goto out;
	    }

	    ret = _kdc_verify_flags(context, config, &adtkt, tpn);
	    if (ret) {
		_kdc_audit_addreason((kdc_request_t)priv,
				     "User-to-user TGT expired or invalid");
		goto out;
	    }

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
				HDB_F_GET_CLIENT | flags,
				NULL, NULL, &user2user_client);
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
		_kdc_free_ent(context, user2user_client);
		goto out;
	    }

	    /*
	     * Also check that the account is the same one specified in the
	     * request.
	     */
	    ret = check_client_matches_target_service(context,
						      config,
						      serverdb,
						      server,
						      user2user_client,
						      user2user_princ);
	    if (ret) {
		_kdc_free_ent(context, user2user_client);
		goto out;
	    }

	    /* Verify the PAC of the TGT. */
	    ret = _kdc_check_pac(context, config, user2user_princ, NULL,
				 user2user_client, user2user_krbtgt, user2user_krbtgt, user2user_krbtgt,
				 &uukey->key, &priv->ticket_key->key, &adtkt,
				 &user2user_kdc_issued, &user2user_pac, NULL, NULL);
	    _kdc_free_ent(context, user2user_client);
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
			"Addition ticket have not matching etypes");
		krb5_clear_error_message(context);
		ret = KRB5KDC_ERR_ETYPE_NOSUPP;
                _kdc_audit_addreason((kdc_request_t)priv,
                                     "No matching enctypes for 2nd ticket");
		goto out;
	    }
	    etype = b->etype.val[i];
	    kvno = 0;
	} else {
	    Key *skey;

	    ret = _kdc_find_etype(priv, krb5_principal_is_krbtgt(context, sp)
							     ? KFE_IS_TGS : 0,
				  b->etype.val, b->etype.len, &etype, NULL,
				  NULL);
	    if(ret) {
		kdc_log(context, config, 4,
			"Server (%s) has no support for etypes", spn);
                _kdc_audit_addreason((kdc_request_t)priv,
                                     "Enctype not supported");
		goto out;
	    }
	    ret = _kdc_get_preferred_key(context, config, server, spn,
					 NULL, &skey);
	    if(ret) {
		kdc_log(context, config, 4,
			"Server (%s) has no supported etypes", spn);
                _kdc_audit_addreason((kdc_request_t)priv,
                                     "Enctype not supported");
		goto out;
	    }
	    ekey = &skey->key;
	    kvno = server->entry.kvno;
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
    if (strcmp(krb5_principal_get_realm(context, server->entry.principal),
	       krb5_principal_get_realm(context, krbtgt_out->entry.principal)) != 0) {
	char *ktpn;
	ret = krb5_unparse_name(context, krbtgt_out->entry.principal, &ktpn);
	kdc_log(context, config, 4,
		"Request with wrong krbtgt: %s",
		(ret == 0) ? ktpn : "<unknown>");
	if(ret == 0)
	    free(ktpn);
	ret = KRB5KRB_AP_ERR_NOT_US;
        _kdc_audit_addreason((kdc_request_t)priv, "Request with wrong TGT");
	goto out;
    }

    ret = _kdc_get_preferred_key(context, config, krbtgt_out, krbtgt_out_n,
				 NULL, &tkey_sign);
    if (ret) {
	kdc_log(context, config, 4,
		    "Failed to find key for krbtgt PAC signature");
        _kdc_audit_addreason((kdc_request_t)priv,
                             "Failed to find key for krbtgt PAC signature");
	goto out;
    }
    ret = hdb_enctype2key(context, &krbtgt_out->entry, NULL,
			  tkey_sign->key.keytype, &tkey_sign);
    if(ret) {
	kdc_log(context, config, 4,
		    "Failed to find key for krbtgt PAC signature");
        _kdc_audit_addreason((kdc_request_t)priv,
                             "Failed to find key for krbtgt PAC signature");
	goto out;
    }

    if (_kdc_synthetic_princ_used_p(context, ticket))
	flags |= HDB_F_SYNTHETIC_OK;

    ret = _kdc_db_fetch_client(context, config, flags, cp, cpn, our_realm,
			       &clientdb, &client);
    if (ret)
	goto out;
    flags &= ~HDB_F_SYNTHETIC_OK;
    priv->client = client;

    heim_assert(priv->client_princ == NULL, "client_princ should be NULL for TGS");

    ret = _kdc_check_pac(context, config, cp, NULL, client, server, krbtgt, krbtgt,
			 &priv->ticket_key->key, &priv->ticket_key->key, tgt,
			 &kdc_issued, &priv->pac, &priv->client_princ, &priv->pac_attributes);
    if (ret) {
	const char *msg = krb5_get_error_message(context, ret);
        _kdc_audit_addreason((kdc_request_t)priv, "PAC check failed");
	kdc_log(context, config, 4,
		"Verify PAC failed for %s (%s) from %s with %s",
		spn, cpn, from, msg);
	krb5_free_error_message(context, msg);
	goto out;
    }

    /*
     * Process request
     */

    /* by default the tgt principal matches the client principal */
    tp = cp;
    tpn = cpn;

    if (client) {
	const PA_DATA *sdata;
	int i = 0;

	sdata = _kdc_find_padata(req, &i, KRB5_PADATA_FOR_USER);
	if (sdata) {
	    krb5_crypto crypto;
	    krb5_data datack;
	    PA_S4U2Self self;
	    const char *str;

	    ret = decode_PA_S4U2Self(sdata->padata_value.data,
				     sdata->padata_value.length,
				     &self, NULL);
	    if (ret) {
                _kdc_audit_addreason((kdc_request_t)priv,
                                     "Failed to decode PA-S4U2Self");
		kdc_log(context, config, 4, "Failed to decode PA-S4U2Self");
		goto out;
	    }

	    if (!krb5_checksum_is_keyed(context, self.cksum.cksumtype)) {
		free_PA_S4U2Self(&self);
                _kdc_audit_addreason((kdc_request_t)priv,
                                     "PA-S4U2Self with unkeyed checksum");
		kdc_log(context, config, 4, "Reject PA-S4U2Self with unkeyed checksum");
		ret = KRB5KRB_AP_ERR_INAPP_CKSUM;
		goto out;
	    }

	    ret = _krb5_s4u2self_to_checksumdata(context, &self, &datack);
	    if (ret)
		goto out;

	    ret = krb5_crypto_init(context, &tgt->key, 0, &crypto);
	    if (ret) {
		const char *msg = krb5_get_error_message(context, ret);
		free_PA_S4U2Self(&self);
		krb5_data_free(&datack);
		kdc_log(context, config, 4, "krb5_crypto_init failed: %s", msg);
		krb5_free_error_message(context, msg);
		goto out;
	    }

	    /* Allow HMAC_MD5 checksum with any key type */
	    if (self.cksum.cksumtype == CKSUMTYPE_HMAC_MD5) {
		struct krb5_crypto_iov iov;
		unsigned char csdata[16];
		Checksum cs;

		cs.checksum.length = sizeof(csdata);
		cs.checksum.data = &csdata;

		iov.data.data = datack.data;
		iov.data.length = datack.length;
		iov.flags = KRB5_CRYPTO_TYPE_DATA;

		ret = _krb5_HMAC_MD5_checksum(context, NULL, &crypto->key,
					      KRB5_KU_OTHER_CKSUM, &iov, 1,
					      &cs);
		if (ret == 0 &&
		    krb5_data_ct_cmp(&cs.checksum, &self.cksum.checksum) != 0)
		    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	    }
	    else {
		ret = _kdc_verify_checksum(context,
					   crypto,
					   KRB5_KU_OTHER_CKSUM,
					   &datack,
					   &self.cksum);
	    }
	    krb5_data_free(&datack);
	    krb5_crypto_destroy(context, crypto);
	    if (ret) {
		const char *msg = krb5_get_error_message(context, ret);
		free_PA_S4U2Self(&self);
                _kdc_audit_addreason((kdc_request_t)priv,
                                     "S4U2Self checksum failed");
		kdc_log(context, config, 4,
			"krb5_verify_checksum failed for S4U2Self: %s", msg);
		krb5_free_error_message(context, msg);
		goto out;
	    }

	    ret = _krb5_principalname2krb5_principal(context,
						     &tp,
						     self.name,
						     self.realm);
	    free_PA_S4U2Self(&self);
	    if (ret)
		goto out;

	    ret = krb5_unparse_name(context, tp, &tpn);
	    if (ret)
		goto out;

            /*
             * Note no HDB_F_SYNTHETIC_OK -- impersonating non-existent clients
             * is probably not desirable!
             */
	    ret = _kdc_db_fetch(context, config, tp, HDB_F_GET_CLIENT | flags,
				NULL, &s4u2self_impersonated_clientdb,
				&s4u2self_impersonated_client);
	    if (ret) {
		const char *msg;

		/*
		 * If the client belongs to the same realm as our krbtgt, it
		 * should exist in the local database.
		 *
		 */

		if (ret == HDB_ERR_NOENTRY)
		    ret = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
		msg = krb5_get_error_message(context, ret);
                _kdc_audit_addreason((kdc_request_t)priv,
                                     "S4U2Self principal to impersonate not found");
		kdc_log(context, config, 2,
			"S4U2Self principal to impersonate %s not found in database: %s",
			tpn, msg);
		krb5_free_error_message(context, msg);
		goto out;
	    }

	    /* Ignore require_pwchange and pw_end attributes (as Windows does),
	     * since S4U2Self is not password authentication. */
	    s4u2self_impersonated_client->entry.flags.require_pwchange = FALSE;
	    free(s4u2self_impersonated_client->entry.pw_end);
	    s4u2self_impersonated_client->entry.pw_end = NULL;

	    ret = kdc_check_flags(priv, FALSE, s4u2self_impersonated_client, priv->server);
	    if (ret)
		goto out; /* kdc_check_flags() calls _kdc_audit_addreason() */

	    /* If we were about to put a PAC into the ticket, we better fix it to be the right PAC */
	    krb5_pac_free(context, priv->pac);
	    priv->pac = NULL;

	    ret = _kdc_pac_generate(context,
				    s4u2self_impersonated_client,
				    server,
				    NULL,
				    KRB5_PAC_WAS_GIVEN_IMPLICITLY,
				    &priv->pac);
	    if (ret) {
		kdc_log(context, config, 4, "PAC generation failed for -- %s", tpn);
		goto out;
	    }

	    /*
	     * Check that service doing the impersonating is
	     * requesting a ticket to it-self.
	     */
	    ret = check_client_matches_target_service(context,
						      config,
						      clientdb,
						      client,
						      server,
						      sp);
	    if (ret) {
		kdc_log(context, config, 4, "S4U2Self: %s is not allowed "
			"to impersonate to service "
			"(tried for user %s to service %s)",
			cpn, tpn, spn);
		goto out;
	    }

	    /*
	     * If the service isn't trusted for authentication to
	     * delegation or if the impersonate client is disallowed
	     * forwardable, remove the forwardable flag.
	     */

	    if (client->entry.flags.trusted_for_delegation &&
		s4u2self_impersonated_client->entry.flags.forwardable) {
		str = "[forwardable]";
	    } else {
		b->kdc_options.forwardable = 0;
		str = "";
	    }
	    kdc_log(context, config, 4, "s4u2self %s impersonating %s to "
		    "service %s %s", cpn, tpn, spn, str);
	}
    }

    /*
     * Constrained delegation
     */

    if (client != NULL
	&& b->additional_tickets != NULL
	&& b->additional_tickets->len != 0
	&& b->kdc_options.cname_in_addl_tkt
	&& b->kdc_options.enc_tkt_in_skey == 0)
    {
	hdb_entry_ex *adclient = NULL;
	krb5_boolean ad_kdc_issued = FALSE;
	Key *clientkey;
	Ticket *t;

	/*
	 * We require that the service's krbtgt has a PAC.
	 */
	if (priv->pac == NULL) {
	    ret = KRB5KDC_ERR_BADOPTION;
	    _kdc_audit_addreason((kdc_request_t)priv, "Missing PAC");
	    kdc_log(context, config, 4,
		    "Constrained delegation without PAC, %s/%s",
		    cpn, spn);
	    goto out;
	}

	krb5_pac_free(context, priv->pac);
	priv->pac = NULL;

	krb5_free_principal(context, priv->client_princ);
	priv->client_princ = NULL;

	t = &b->additional_tickets->val[0];

	ret = hdb_enctype2key(context, &client->entry,
			      hdb_kvno2keys(context, &client->entry,
					    t->enc_part.kvno ? * t->enc_part.kvno : 0),
			      t->enc_part.etype, &clientkey);
	if(ret){
	    ret = KRB5KDC_ERR_ETYPE_NOSUPP; /* XXX */
	    goto out;
	}

	ret = krb5_decrypt_ticket(context, t, &clientkey->key, &adtkt, 0);
	if (ret) {
            _kdc_audit_addreason((kdc_request_t)priv,
                                 "Failed to decrypt constrained delegation ticket");
	    kdc_log(context, config, 4,
		    "failed to decrypt ticket for "
		    "constrained delegation from %s to %s ", cpn, spn);
	    goto out;
	}

	ret = _krb5_principalname2krb5_principal(context,
						 &tp,
						 adtkt.cname,
						 adtkt.crealm);
	if (ret)
	    goto out;

	ret = krb5_unparse_name(context, tp, &tpn);
	if (ret)
	    goto out;

        _kdc_audit_addkv((kdc_request_t)priv, 0, "impersonatee", "%s", tpn);

	ret = _krb5_principalname2krb5_principal(context,
						 &dp,
						 t->sname,
						 t->realm);
	if (ret)
	    goto out;

	ret = krb5_unparse_name(context, dp, &dpn);
	if (ret)
	    goto out;

	/* check that ticket is valid */
	if (adtkt.flags.forwardable == 0) {
            _kdc_audit_addreason((kdc_request_t)priv,
                                 "Missing forwardable flag on ticket for constrained delegation");
	    kdc_log(context, config, 4,
		    "Missing forwardable flag on ticket for "
		    "constrained delegation from %s (%s) as %s to %s ",
		    cpn, dpn, tpn, spn);
	    ret = KRB5KDC_ERR_BADOPTION;
	    goto out;
	}

	ret = check_constrained_delegation(context, config, clientdb,
					   client, server, sp);
	if (ret) {
            _kdc_audit_addreason((kdc_request_t)priv,
                                 "Constrained delegation not allowed");
	    kdc_log(context, config, 4,
		    "constrained delegation from %s (%s) as %s to %s not allowed",
		    cpn, dpn, tpn, spn);
	    goto out;
	}

	ret = _kdc_verify_flags(context, config, &adtkt, tpn);
	if (ret) {
            _kdc_audit_addreason((kdc_request_t)priv,
                                 "Constrained delegation ticket expired or invalid");
	    goto out;
	}

	/* Try lookup the delegated client in DB */
	ret = _kdc_db_fetch_client(context, config, flags, tp, tpn, our_realm,
				   NULL, &adclient);
	if (ret)
	    goto out;

	if (adclient != NULL) {
	    ret = kdc_check_flags(priv, FALSE, adclient, priv->server);
	    if (ret) {
		_kdc_free_ent(context, adclient);
		goto out;
	    }
	}

	/*
	 * TODO: pass in t->sname and t->realm and build
	 * a S4U_DELEGATION_INFO blob to the PAC.
	 */
	ret = _kdc_check_pac(context, config, tp, dp, adclient, server, krbtgt, client,
			     &clientkey->key, &priv->ticket_key->key, &adtkt,
			     &ad_kdc_issued, &priv->pac, &priv->client_princ, &priv->pac_attributes);
	if (adclient)
	    _kdc_free_ent(context, adclient);
	if (ret) {
	    const char *msg = krb5_get_error_message(context, ret);
            _kdc_audit_addreason((kdc_request_t)priv,
                                 "Constrained delegation ticket PAC check failed");
	    kdc_log(context, config, 4,
		    "Verify delegated PAC failed to %s for client"
		    "%s (%s) as %s from %s with %s",
		    spn, cpn, dpn, tpn, from, msg);
	    krb5_free_error_message(context, msg);
	    goto out;
	}

	if (priv->pac == NULL || !ad_kdc_issued) {
	    ret = KRB5KDC_ERR_BADOPTION;
	    kdc_log(context, config, 4,
		    "Ticket not signed with PAC; service %s failed for "
		    "for delegation to %s for client %s (%s) from %s; (%s).",
		    spn, tpn, dpn, cpn, from, priv->pac ? "Ticket unsigned" : "No PAC");
            _kdc_audit_addreason((kdc_request_t)priv,
                                 "Constrained delegation ticket not signed");
	    goto out;
	}

	kdc_log(context, config, 4, "constrained delegation for %s "
		"from %s (%s) to %s", tpn, cpn, dpn, spn);
    }

    /*
     * Check flags
     */

    ret = kdc_check_flags(priv, FALSE, priv->client, priv->server);
    if(ret)
	goto out;

    if((b->kdc_options.validate || b->kdc_options.renew) &&
       !krb5_principal_compare(context,
			       krbtgt->entry.principal,
			       server->entry.principal)){
        _kdc_audit_addreason((kdc_request_t)priv, "Inconsistent request");
	kdc_log(context, config, 4, "Inconsistent request.");
	ret = KRB5KDC_ERR_SERVER_NOMATCH;
	goto out;
    }

    /* check for valid set of addresses */
    if (!_kdc_check_addresses(priv, tgt->caddr, from_addr)) {
        if (config->check_ticket_addresses) {
            ret = KRB5KRB_AP_ERR_BADADDR;
            _kdc_audit_addkv((kdc_request_t)priv, 0, "wrongaddr", "yes");
            kdc_log(context, config, 4, "Request from wrong address");
            _kdc_audit_addreason((kdc_request_t)priv, "Request from wrong address");
            goto out;
        } else if (config->warn_ticket_addresses) {
            _kdc_audit_addkv((kdc_request_t)priv, 0, "wrongaddr", "yes");
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
            _kdc_audit_addreason((kdc_request_t)priv, "Referral build failed");
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
	!krb5_principal_is_krbtgt(context, server->entry.principal)) {

	/* Validate armor TGT before potentially including device claims */
	if (priv->armor_ticket) {
	    ret = _kdc_fast_check_armor_pac(priv);
	    if (ret)
		goto out;
	}

	add_ticket_sig = TRUE;
    }

    /*
     * Active-Directory implementations use the high part of the kvno as the
     * read-only-dc identifier, we need to embed it in the PAC KDC signatures.
     */

    rodc_id = krbtgt_out->entry.kvno >> 16;

    /*
     *
     */

    ret = tgs_make_reply(priv,
			 tp,
			 tgt,
			 ekey,
			 &tkey_sign->key,
			 &sessionkey,
			 kvno,
			 *auth_data,
			 server,
			 rsp,
			 client,
			 cp,
                         tgt_realm,
			 rodc_id,
			 add_ticket_sig);

out:
    free(user2user_name);
    if (tpn != cpn)
	    free(tpn);
    free(dpn);
    free(krbtgt_out_n);
    _krb5_free_capath(context, capath);

    krb5_free_keyblock_contents(context, &sessionkey);
    if(krbtgt_out)
	_kdc_free_ent(context, krbtgt_out);
    if(server)
	_kdc_free_ent(context, server);
    if(client)
	_kdc_free_ent(context, client);
    if(s4u2self_impersonated_client)
	_kdc_free_ent(context, s4u2self_impersonated_client);
    if(user2user_krbtgt)
	_kdc_free_ent(context, user2user_krbtgt);

    krb5_free_principal(context, user2user_princ);
    if (tp && tp != cp)
	krb5_free_principal(context, tp);
    krb5_free_principal(context, cp);
    krb5_free_principal(context, dp);
    krb5_free_principal(context, sp);
    krb5_free_principal(context, krbtgt_out_principal);
    free(ref_realm);

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
    AuthorizationData *auth_data = NULL;
    krb5_error_code ret;
    int i = 0;
    const PA_DATA *tgs_req, *pa;

    hdb_entry_ex *krbtgt = NULL;
    krb5_ticket *ticket = NULL;
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
			    &krbtgt,
			    &krbtgt_etype,
			    &ticket,
			    from, from_addr,
			    &csec, &cusec,
			    &auth_data);
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
			  krbtgt,
			  krbtgt_etype,
			  ticket,
			  &auth_data,
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
    if(ret && ret != HDB_ERR_NOT_FOUND_HERE && data->data == NULL){
	METHOD_DATA error_method = { 0, NULL };

	kdc_log(r->context, config, 5, "tgs-req: sending error: %d to client", ret);
	ret = _kdc_fast_mk_error(r,
				 &error_method,
				 r->armor_crypto,
				 &req->req_body,
				 r->ret = ret,
				 ticket != NULL ? ticket->client : NULL,
				 ticket != NULL ? ticket->server : NULL,
				 csec, cusec,
				 data);
	free_METHOD_DATA(&error_method);
    }
    free(csec);
    free(cusec);

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

    if (r->client_princ) {
	krb5_free_principal(r->context, r->client_princ);
	r->client_princ = NULL;
    }
    if (r->armor_crypto) {
	krb5_crypto_destroy(r->context, r->armor_crypto);
	r->armor_crypto = NULL;
    }
    if (r->armor_ticket)
	krb5_free_ticket(r->context, r->armor_ticket);
    if (r->armor_server)
	_kdc_free_ent(r->context, r->armor_server);
    krb5_free_keyblock_contents(r->context, &r->reply_key);
    krb5_free_keyblock_contents(r->context, &r->strengthen_key);

    if (ticket)
	krb5_free_ticket(r->context, ticket);
    if(krbtgt)
	_kdc_free_ent(r->context, krbtgt);

    _kdc_free_fast_state(&r->fast);
    krb5_pac_free(r->context, r->pac);

    if (auth_data) {
	free_AuthorizationData(auth_data);
	free(auth_data);
    }

    return ret;
}
