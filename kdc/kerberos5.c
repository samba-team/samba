/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
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
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
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

RCSID("$Id$");

#define MAX_TIME ((time_t)((1U << 31) - 1))

krb5_error_code
as_rep(KDC_REQ *req, 
       krb5_data *reply,
       const char *from)
{
    KDC_REQ_BODY *b = &req->req_body;
    AS_REP rep;
    KDCOptions f = b->kdc_options;
    hdb_entry *client = NULL, *server = NULL;
    int etype;
    EncTicketPart et;
    EncKDCRepPart ek;
    krb5_principal client_princ, server_princ;
    char *client_name, *server_name;
    krb5_error_code ret = 0;
    const char *e_text = NULL;
    int i;

    Key *ckey, *skey, *ekey;

    if(b->sname == NULL){
	server_name = "<unknown server>";
	ret = KRB5KRB_ERR_GENERIC;
	e_text = "No server in request";
    } else{
	principalname2krb5_principal (&server_princ, *(b->sname), b->realm);
	krb5_unparse_name(context, server_princ, &server_name);
    }
    
    if(b->cname == NULL){
	client_name = "<unknown client>";
	ret = KRB5KRB_ERR_GENERIC;
	e_text = "No client in request";
    } else {
	principalname2krb5_principal (&client_princ, *(b->cname), b->realm);
	krb5_unparse_name(context, client_princ, &client_name);
    }
    kdc_log(0, "AS-REQ %s from %s for %s", 
	    client_name, from, server_name);

    if(ret)
	goto out;

    client = db_fetch(client_princ);
    if(client == NULL){
	kdc_log(0, "UNKNOWN -- %s", client_name);
	ret = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	goto out;
    }

    if (client->valid_start && *client->valid_start > kdc_time) {
	kdc_log(0, "Client not yet valid -- %s", client_name);
	ret = KRB5KDC_ERR_CLIENT_NOTYET;
	goto out;
    }

    if (client->valid_end && *client->valid_end < kdc_time) {
	kdc_log(0, "Client expired -- %s", client_name);
	ret = KRB5KDC_ERR_NAME_EXP;
	goto out;
    }

    server = db_fetch(server_princ);

    if(server == NULL){
	kdc_log(0, "UNKNOWN -- %s", server_name);
	ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	goto out;
    }

    if (server->valid_start && *server->valid_start > kdc_time) {
	kdc_log(0, "Server not yet valid -- %s", server_name);
	ret = KRB5KDC_ERR_SERVICE_NOTYET;
	goto out;
    }

    if (server->valid_end && *server->valid_end < kdc_time) {
	kdc_log(0, "Server expired -- %s", server_name);
	ret = KRB5KDC_ERR_SERVICE_EXP;
	goto out;
    }

    if(!client->flags.client){
	ret = KRB5KDC_ERR_POLICY;
	kdc_log(0, "Principal may not act as client -- %s", 
		client_name);
	goto out;
    }
    if(!server->flags.server){
	ret = KRB5KDC_ERR_POLICY;
	kdc_log(0, "Principal (%s) may not act as server -- %s", 
		server_name, client_name);
	goto out;
    }

    if (client->pw_end && *client->pw_end < kdc_time
	&& !server->flags.change_pw) {
	ret = KRB5KDC_ERR_KEY_EXPIRED;
	kdc_log(0, "Client (%s)'s key has expired", client_name);
	goto out;
    }

    /* Find appropriate key */
    for(i = 0; i < b->etype.len; i++){
	ret = hdb_etype2key(context, client, b->etype.val[i], &ckey);
	if(ret)
	    continue;
	ret = hdb_etype2key(context, server, b->etype.val[i], &skey);
	if(ret)
	    continue;
	break;
    }

    if(ret){
	ret = KRB5KDC_ERR_ETYPE_NOSUPP;
	kdc_log(0, "No support for etypes -- %s", client_name);
	goto out;
    }
    
    etype = b->etype.val[i];

    memset(&et, 0, sizeof(et));
    memset(&ek, 0, sizeof(ek));

    if(req->padata){
	int i;
	PA_DATA *pa;
	int found_pa = 0;
	kdc_log(5, "Looking for pa-data -- %s", client_name);
	for(i = 0; i < req->padata->len; i++){
	    PA_DATA *pa = &req->padata->val[i];
	    if(pa->padata_type == pa_enc_timestamp){
		krb5_data ts_data;
		PA_ENC_TS_ENC p;
		time_t patime;
		size_t len;
		EncryptedData enc_data;
		
		kdc_log(5, "Found pa-enc-timestamp -- %s", 
			client_name);
		found_pa = 1;
		
		ret = decode_EncryptedData(pa->padata_value.data,
					   pa->padata_value.length,
					   &enc_data,
					   &len);
		if (ret) {
		    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
		    kdc_log(5, "Failed to decode PA-DATA -- %s", 
			    client_name);
		    goto out;
		}

		ekey = unseal_key(ckey);

		ret = krb5_decrypt (context,
				    enc_data.cipher.data,
				    enc_data.cipher.length,
				    enc_data.etype,
				    &ekey->key,
				    &ts_data);
		free_key(ekey);
		free_EncryptedData(&enc_data);
		if(ret){
		    e_text = "Failed to decrypt PA-DATA";
		    kdc_log (5, "Failed to decrypt PA-DATA -- %s",
			     client_name);
		    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
		    continue;
		}
		ret = decode_PA_ENC_TS_ENC(ts_data.data,
					   ts_data.length,
					   &p,
					   &len);
		krb5_data_free(&ts_data);
		if(ret){
		    e_text = "Failed to decode PA-ENC-TS-ENC";
		    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
		    kdc_log (5, "Failed to decode PA-ENC-TS_ENC -- %s",
			     client_name);
		    continue;
		}
		patime = p.patimestamp;
		free_PA_ENC_TS_ENC(&p);
		if (abs(kdc_time - p.patimestamp) > context->max_skew) {
		    ret = KRB5KDC_ERR_PREAUTH_FAILED;
		    krb5_mk_error (context,
				   ret,
				   "Too large time skew",
				   NULL,
				   client_princ,
				   server_princ,
				   0,
				   reply);
		    kdc_log(0, "Too large time skew -- %s", 
			    client_name);
		    goto out2;
		}
		et.flags.pre_authent = 1;
		kdc_log(2, "Pre-authentication succeded -- %s", 
			client_name);
		break;
	    } else {
		kdc_log(5, "Found pa-data of type %d -- %s", 
			pa->padata_type, client_name);
	    }
	}
	/* XXX */
	if(found_pa == 0 && require_preauth)
	    goto use_pa;
	/* We come here if we found a pa-enc-timestamp, but if there
           was some problem with it, other than too large skew */
	if(et.flags.pre_authent == 0){
	    kdc_log(0, "%s -- %s", e_text, client_name);
	    e_text = NULL;
	    goto out;
	}
    }else if (require_preauth
	      || client->flags.require_preauth) {
	METHOD_DATA method_data;
	PA_DATA pa_data;
	u_char buf[16];
	size_t len;
	krb5_data foo_data;
	
    use_pa:
	method_data.len = 1;
	method_data.val = &pa_data;

	pa_data.padata_type         = pa_enc_timestamp;
	pa_data.padata_value.length = 0;
	pa_data.padata_value.data   = NULL;
	
	encode_METHOD_DATA(buf + sizeof(buf) - 1,
			   sizeof(buf),
			   &method_data,
			   &len);
	foo_data.length = len;
	foo_data.data   = buf + sizeof(buf) - len;
	
	ret = KRB5KDC_ERR_PREAUTH_REQUIRED;
	krb5_mk_error(context,
		      ret,
		      "Need to use PA-ENC-TIMESTAMP",
		      &foo_data,
		      client_princ,
		      server_princ,
		      0,
		      reply);
	
	kdc_log(0, "No PA-ENC-TIMESTAMP -- %s", client_name);
	goto out2;
    }

    kdc_log(2, "Using etype %d -- %s", etype, client_name);
    
    memset(&rep, 0, sizeof(rep));
    rep.pvno = 5;
    rep.msg_type = krb_as_rep;
    copy_Realm(&b->realm, &rep.crealm);
    copy_PrincipalName(b->cname, &rep.cname);
    rep.ticket.tkt_vno = 5;
    copy_Realm(&b->realm, &rep.ticket.realm);
    copy_PrincipalName(b->sname, &rep.ticket.sname);

    if(f.renew || f.validate || f.proxy || f.forwarded || f.enc_tkt_in_skey){
	ret = KRB5KDC_ERR_BADOPTION;
	kdc_log(0, "Bad KDC options -- %s", client_name);
	goto out;
    }
    
    et.flags.initial = 1;
    if(client->flags.forwardable && server->flags.forwardable)
	et.flags.forwardable = f.forwardable;
    else{
	ret = KRB5KDC_ERR_POLICY;
	kdc_log(0, "Ticket may not be forwardable -- %s", client_name);
	goto out;
    }
    if(client->flags.proxiable && server->flags.proxiable)
	et.flags.proxiable = f.proxiable;
    else{
	ret = KRB5KDC_ERR_POLICY;
	kdc_log(0, "Ticket may not be proxiable -- %s", client_name);
	goto out;
    }
    if(client->flags.postdate && server->flags.postdate)
	et.flags.may_postdate = f.allow_postdate;
    else{
	ret = KRB5KDC_ERR_POLICY;
	kdc_log(0, "Ticket may not be postdatable -- %s", client_name);
	goto out;
    }

    krb5_generate_random_keyblock(context, ckey->key.keytype, &et.key);
    copy_PrincipalName(b->cname, &et.cname);
    copy_Realm(&b->realm, &et.crealm);
    
    {
	time_t start;
	time_t t;
	
	start = et.authtime = kdc_time;
    
	if(f.postdated && req->req_body.from){
	    ALLOC(et.starttime);
	    start = *et.starttime = *req->req_body.from;
	    et.flags.invalid = 1;
	    et.flags.postdated = 1; /* XXX ??? */
	    kdc_log(2, "Postdated ticket requested -- %s", 
		    client_name);
	}
	if(b->till == 0)
	    b->till = MAX_TIME;
	t = b->till;
	if(client->max_life)
	    t = min(t, start + *client->max_life);
	if(server->max_life)
	    t = min(t, start + *server->max_life);
#if 0
	t = min(t, start + realm->max_life);
#endif
	et.endtime = t;
	if(f.renewable_ok && et.endtime < b->till){
	    f.renewable = 1;
	    if(b->rtime == NULL){
		ALLOC(b->rtime);
		*b->rtime = 0;
	    }
	    if(*b->rtime < b->till)
		*b->rtime = b->till;
	}
	if(f.renewable && b->rtime){
	    t = *b->rtime;
	    if(t == 0)
		t = MAX_TIME;
	    if(client->max_renew)
		t = min(t, start + *client->max_renew);
	    if(server->max_renew)
		t = min(t, start + *server->max_renew);
#if 0
	    t = min(t, start + realm->max_renew);
#endif
	    ALLOC(et.renew_till);
	    *et.renew_till = t;
	    et.flags.renewable = 1;
	}
    }
    
    if(b->addresses){
	ALLOC(et.caddr);
	copy_HostAddresses(b->addresses, et.caddr);
    }

    copy_EncryptionKey(&et.key, &ek.key);

    /* The MIT ASN.1 library (obviously) doesn't tell lengths encoded
     * as 0 and as 0x80 (meaning indefinite length) apart, and is thus
     * incapable to correctly decode vectors of zero length.
     *
     * To fix this, always send at least one no-op last_req
     *
     * If there's a pw_end or valid_end we will use that,
     * otherwise just a dummy lr.
     */
    ek.last_req.val = malloc(2 * sizeof(*ek.last_req.val));
    ek.last_req.len = 0;
    if (client->pw_end
	&& (kdc_warn_pwexpire == 0
	    || kdc_time + kdc_warn_pwexpire <= *client->pw_end)) {
	ek.last_req.val[ek.last_req.len].lr_type  = 6;
	ek.last_req.val[ek.last_req.len].lr_value = *client->pw_end;
	++ek.last_req.len;
    }
    if (client->valid_end) {
	ek.last_req.val[ek.last_req.len].lr_type  = 7;
	ek.last_req.val[ek.last_req.len].lr_value = *client->valid_end;
	++ek.last_req.len;
    }
    if (ek.last_req.len == 0) {
	ek.last_req.val[ek.last_req.len].lr_type  = 0;
	ek.last_req.val[ek.last_req.len].lr_value = 0;
	++ek.last_req.len;
    }
    ek.nonce = b->nonce;
    if (client->valid_end || client->pw_end) {
	ALLOC(ek.key_expiration);
	if (client->valid_end)
	    if (client->pw_end)
		*ek.key_expiration = min(*client->valid_end, *client->pw_end);
	    else
		*ek.key_expiration = *client->valid_end;
	else
	    *ek.key_expiration = *client->pw_end;
    } else
	ek.key_expiration = NULL;
    ek.flags = et.flags;
    ek.authtime = et.authtime;
    if (et.starttime) {
	ALLOC(ek.starttime);
	*ek.starttime = *et.starttime;
    } else
	ek.starttime = et.starttime;
    ek.endtime = et.endtime;
    if (et.renew_till) {
	ALLOC(ek.renew_till);
	*ek.renew_till = *et.renew_till;
    } else
	ek.renew_till = et.renew_till;
    copy_Realm(&rep.ticket.realm, &ek.srealm);
    copy_PrincipalName(&rep.ticket.sname, &ek.sname);
    if(et.caddr){
	ALLOC(ek.caddr);
	copy_HostAddresses(et.caddr, ek.caddr);
    }

    {
	unsigned char buf[1024]; /* XXX The data could be indefinite */
	size_t len;

	ret = encode_EncTicketPart(buf + sizeof(buf) - 1, sizeof(buf), 
				   &et, &len);
	free_EncTicketPart(&et);
	if(ret) {
	    kdc_log(0, "Failed to encode ticket -- %s", client);
	    goto out;
	}
	
	ekey = unseal_key(skey);
	krb5_encrypt_EncryptedData(context, 
				   buf + sizeof(buf) - len,
				   len,
				   etype,
				   &ekey->key,
				   &rep.ticket.enc_part);
	free_key(ekey);
	
	ret = encode_EncASRepPart(buf + sizeof(buf) - 1, sizeof(buf), 
				  &ek, &len);
	free_EncKDCRepPart(&ek);
	if(ret) {
	    kdc_log(0, "Failed to encode KDC-REP -- %s", client_name);
	    goto out;
	}
	ekey = unseal_key(ckey);
	krb5_encrypt_EncryptedData(context,
				   buf + sizeof(buf) - len,
				   len,
				   etype,
				   &ekey->key,
				   &rep.enc_part);
	free_key(ekey);
	if(ckey->salt){
	    ALLOC(rep.padata);
	    rep.padata->len = 1;
	    rep.padata->val = calloc(1, sizeof(*rep.padata->val));
	    rep.padata->val->padata_type = pa_pw_salt;
	    copy_octet_string(ckey->salt, &rep.padata->val->padata_value);
	}
	
	ret = encode_AS_REP(buf + sizeof(buf) - 1, sizeof(buf), &rep, &len);
	free_AS_REP(&rep);
	if(ret) {
	    kdc_log(0, "Failed to encode AS-REP -- %s", client_name);
	    goto out;
	}
	
	krb5_data_copy(reply, buf + sizeof(buf) - len, len);
    }
out:
    if(ret){
	krb5_mk_error(context,
		      ret,
		      e_text,
		      NULL,
		      client_princ,
		      server_princ,
		      0,
		      reply);
    }
out2:
    krb5_free_principal(context, client_princ);
    free(client_name);
    krb5_free_principal(context, server_princ);
    free(server_name);
    if(client){
	hdb_free_entry(context, client);
	free(client);
    }
    if(server){
	hdb_free_entry(context, server);
	free(server);
    }
    
    return ret;
}


static krb5_error_code
check_tgs_flags(KDC_REQ_BODY *b, EncTicketPart *tgt, EncTicketPart *et)
{
    KDCOptions f = b->kdc_options;
	
    if(f.validate){
	if(!tgt->flags.invalid || tgt->starttime == NULL){
	    kdc_log(0, "Bad request to validate ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	if(*tgt->starttime < kdc_time){
	    kdc_log(0, "Early request to validate ticket");
	    return KRB5KRB_AP_ERR_TKT_NYV;
	}
	/* XXX  tkt = tgt */
	et->flags.invalid = 0;
    }else if(tgt->flags.invalid){
	kdc_log(0, "Ticket-granting ticket has INVALID flag set");
	return KRB5KRB_AP_ERR_TKT_INVALID;
    }

    if(f.forwardable){
	if(!tgt->flags.forwardable){
	    kdc_log(0, "Bad request for forwardable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.forwardable = 1;
    }
    if(f.forwarded){
	if(!tgt->flags.forwardable){
	    kdc_log(0, "Request to forward non-forwardable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.forwarded = 1;
	et->caddr = b->addresses;
    }
    if(tgt->flags.forwarded)
	et->flags.forwarded = 1;
	
    if(f.proxiable){
	if(!tgt->flags.proxiable){
	    kdc_log(0, "Bad request for proxiable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.proxiable = 1;
    }
    if(f.proxy){
	if(!tgt->flags.proxiable){
	    kdc_log(0, "Request to proxy non-proxiable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.proxy = 1;
	et->caddr = b->addresses;
    }
    if(tgt->flags.proxy)
	et->flags.proxy = 1;

    if(f.allow_postdate){
	if(!tgt->flags.may_postdate){
	    kdc_log(0, "Bad request for post-datable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.may_postdate = 1;
    }
    if(f.postdated){
	if(!tgt->flags.may_postdate){
	    kdc_log(0, "Bad request for postdated ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	if(b->from)
	    *et->starttime = *b->from;
	et->flags.postdated = 1;
	et->flags.invalid = 1;
    }else if(b->from && *b->from > kdc_time + context->max_skew){
	kdc_log(0, "Ticket cannot be postdated");
	return KRB5KDC_ERR_CANNOT_POSTDATE;
    }

    if(f.renewable){
	if(!tgt->flags.renewable){
	    kdc_log(0, "Bad request for renewable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	et->flags.renewable = 1;
	ALLOC(et->renew_till);
	*et->renew_till = *b->rtime;
    }
    if(f.renew){
	time_t old_life;
	if(!tgt->flags.renewable || tgt->renew_till == NULL){
	    kdc_log(0, "Request to renew non-renewable ticket");
	    return KRB5KDC_ERR_BADOPTION;
	}
	old_life = tgt->endtime;
	if(tgt->starttime)
	    old_life -= *tgt->starttime;
	else
	    old_life -= tgt->authtime;
	et->endtime = *et->starttime + old_life;
    }	    
    
    /* check for excess flags */
    return 0;
}

static krb5_error_code
tgs_make_reply(KDC_REQ_BODY *b, EncTicketPart *tgt, 
	       hdb_entry *server, hdb_entry *client, krb5_data *reply)
{
    KDC_REP rep;
    EncKDCRepPart ek;
    EncTicketPart et;
    KDCOptions f = b->kdc_options;
    krb5_error_code ret;
    int i;
    krb5_enctype etype;
    Key *skey, *ekey;
    
    /* Find appropriate key */
    for(i = 0; i < b->etype.len; i++){
	ret = hdb_etype2key(context, server, b->etype.val[i], &skey);
	if(ret == 0)
	    break;
    }
	
    if(ret){
	kdc_log(0, "Failed to find requested etype");
	return KRB5KDC_ERR_ETYPE_NOSUPP;
    }
	
    etype = b->etype.val[i];

    memset(&rep, 0, sizeof(rep));
    memset(&et, 0, sizeof(et));
    memset(&ek, 0, sizeof(ek));
    
    rep.pvno = 5;
    rep.msg_type = krb_tgs_rep;

    et.authtime = tgt->authtime;
    et.endtime = tgt->endtime;
    ALLOC(et.starttime);
    *et.starttime = kdc_time;
    
    ret = check_tgs_flags(b, tgt, &et);
    if(ret)
	return ret;

    copy_Realm(krb5_princ_realm(context, server->principal), 
	       &rep.ticket.realm);
    krb5_principal2principalname(&rep.ticket.sname, server->principal);
    copy_Realm(&tgt->crealm, &rep.crealm);
    copy_PrincipalName(&tgt->cname, &rep.cname);
    rep.ticket.tkt_vno = 5;

    ek.caddr = et.caddr;
    if(et.caddr == NULL)
	et.caddr = tgt->caddr;

    {
	time_t life;
	life = et.endtime - *et.starttime;
	if(client->max_life)
	    life = min(life, *client->max_life);
	if(server->max_life)
	    life = min(life, *server->max_life);
	et.endtime = *et.starttime + life;
    }
    if(f.renewable_ok && tgt->flags.renewable && 
       et.renew_till == NULL && et.endtime < b->till){
	et.flags.renewable = 1;
	ALLOC(et.renew_till);
	*et.renew_till = b->till;
    }
    if(et.renew_till){
	time_t renew;
	renew = *et.renew_till - et.authtime;
	if(client->max_renew)
	    renew = min(renew, *client->max_renew);
	if(server->max_renew)
	    renew = min(renew, *server->max_renew);
	*et.renew_till = et.authtime + renew;
    }
	    
    if(et.renew_till){
	*et.renew_till = min(*et.renew_till, *tgt->renew_till);
	*et.starttime = min(*et.starttime, *et.renew_till);
	et.endtime = min(et.endtime, *et.renew_till);
    }
    
    *et.starttime = min(*et.starttime, et.endtime);

    if(*et.starttime == et.endtime){
	ret = KRB5KDC_ERR_NEVER_VALID;
	goto out;
    }
    if(et.renew_till && et.endtime == *et.renew_till){
	free(et.renew_till);
	et.renew_till = NULL;
	et.flags.renewable = 0;
    }
    
    et.flags.pre_authent = tgt->flags.pre_authent;
    et.flags.hw_authent = tgt->flags.hw_authent;
	    
    /* XXX Check enc-authorization-data */

    krb5_generate_random_keyblock(context,
				  skey->key.keytype,
				  &et.key);
    et.crealm = tgt->crealm;
    et.cname = tgt->cname;
    /* do cross realm stuff */
    et.transited = tgt->transited;
	    
	    
    ek.key = et.key;
    /* MIT must have at least one last_req */
    ek.last_req.len = 1;
    ek.last_req.val = calloc(1, sizeof(*ek.last_req.val));
    ek.nonce = b->nonce;
    ek.flags = et.flags;
    ek.authtime = et.authtime;
    ek.starttime = et.starttime;
    ek.endtime = et.endtime;
    ek.renew_till = et.renew_till;
    ek.srealm = rep.ticket.realm;
    ek.sname = rep.ticket.sname;
	    
    {
	unsigned char buf[1024]; /* XXX The data could be indefinite */
	size_t len;
	ret = encode_EncTicketPart(buf + sizeof(buf) - 1, 
				   sizeof(buf), &et, &len);
	if(ret){
	    kdc_log(0, "Failed to encode EncTicketPart: %s", 
		    krb5_get_err_text(context, ret));
	    goto out;
	}
	ekey = unseal_key(skey);
	krb5_encrypt_EncryptedData(context, buf + sizeof(buf) - len, len,
				   etype,
				   &ekey->key,
				   &rep.ticket.enc_part);
	free_key(ekey);
		
	ret = encode_EncTGSRepPart(buf + sizeof(buf) - 1, 
				   sizeof(buf), &ek, &len);
	if(ret){
	    kdc_log(0, "Failed to encode EncTicketPart: %s", 
		    krb5_get_err_text(context, ret));
	    goto out;
	}
	
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
		
		
	krb5_encrypt_EncryptedData(context,
				   buf + sizeof(buf) - len, len,
				   etype, /* XXX */
				   &tgt->key,
				   &rep.enc_part);
	
	ret = encode_TGS_REP(buf + sizeof(buf) - 1, sizeof(buf), &rep, &len);
	if(ret){
	    kdc_log(0, "Failed to encode TGS-REP: %s", 
		    krb5_get_err_text(context, ret));
	    goto out;
	}
	krb5_data_copy(reply, buf + sizeof(buf) - len, len);
    out:
	free_TGS_REP(&rep);
	if(et.starttime)
	    free(et.starttime);
	if(et.renew_till)
	    free(et.renew_till);
	free_LastReq(&ek.last_req);
	memset(et.key.keyvalue.data, 0, et.key.keyvalue.length);
	free_EncryptionKey(&et.key);
    }
    return ret;
}

static krb5_error_code
tgs_check_authenticator(krb5_auth_context ac,
			KDC_REQ_BODY *b, krb5_keyblock *key)
{
    krb5_authenticator auth;
    size_t len;
    unsigned char buf[1024];
    krb5_error_code ret;
    
    krb5_auth_getauthenticator(context, ac, &auth);
    if(auth->cksum == NULL){
	kdc_log(0, "No authenticator in request");
	ret = KRB5KRB_AP_ERR_INAPP_CKSUM;
	goto out;
    }
    /* XXX */
    if (auth->cksum->cksumtype != CKSUMTYPE_RSA_MD4 &&
	auth->cksum->cksumtype != CKSUMTYPE_RSA_MD5 &&
	auth->cksum->cksumtype != CKSUMTYPE_RSA_MD5_DES){
	kdc_log(0, "Bad checksum type in authenticator: %d", 
		auth->cksum->cksumtype);
	ret =  KRB5KRB_AP_ERR_INAPP_CKSUM;
	goto out;
    }
		
    /* XXX */
    ret = encode_KDC_REQ_BODY(buf + sizeof(buf) - 1, sizeof(buf),
			      b, &len);
    if(ret){
	kdc_log(0, "Failed to encode KDC-REQ-BODY: %s", 
		krb5_get_err_text(context, ret));
	goto out;
    }
    ret = krb5_verify_checksum(context, buf + sizeof(buf) - len, len,
			       key,
			       auth->cksum);
    if(ret){
	kdc_log(0, "Failed to verify checksum: %s", 
		krb5_get_err_text(context, ret));
    }
out:
    free_Authenticator(auth);
    free(auth);
    return 0;
}
	    


static krb5_error_code
tgs_rep2(KDC_REQ_BODY *b,
	 krb5_principal sp,
	 PA_DATA *pa_data,
	 krb5_data *reply,
	 const char *from)
{
    krb5_ap_req ap_req;
    size_t len;
    krb5_error_code ret;
    krb5_principal princ;
    krb5_auth_context ac = NULL;
    krb5_ticket *ticket;
    krb5_flags ap_req_options;
    const char *e_text = NULL;

    hdb_entry *krbtgt;
    EncTicketPart *tgt;
    Key *ekey;
    krb5_principal cp = NULL;

    ret = krb5_decode_ap_req(context, &pa_data->padata_value, &ap_req);
    if(ret){
	kdc_log(0, "Failed to decode AP-REQ: %s", 
		krb5_get_err_text(context, ret));
	goto out;
    }
    
    if(ap_req.ticket.sname.name_string.len != 2 ||
       strcmp(ap_req.ticket.sname.name_string.val[0], "krbtgt")){
	kdc_log(0, "PA-DATA is not a ticket-granting ticket");
	ret = KRB5KDC_ERR_POLICY; /* ? */
	goto out;
    }
    
    principalname2krb5_principal(&princ,
				 ap_req.ticket.sname,
				 ap_req.ticket.realm);
    
    krbtgt = db_fetch(princ);

    if(krbtgt == NULL) {
	char *p;
	krb5_unparse_name(context, princ, &p);
	kdc_log(0, "Ticket-granting ticket not found in database: %s",
		p);
	free(p);
	ret = KRB5KRB_AP_ERR_NOT_US;
	goto out;
    }
    
    ekey = unseal_key(&krbtgt->keys.val[0]); /* XXX */
    ret = krb5_verify_ap_req(context,
			     &ac,
			     &ap_req,
			     princ,
			     &ekey->key,
			     &ap_req_options,
			     &ticket);
    free_key(ekey);
			     
    krb5_free_principal(context, princ);
    if(ret) {
	kdc_log(0, "Failed to verify AP-REQ: %s", 
		krb5_get_err_text(context, ret));
	goto out;
    }

    tgt = &ticket->ticket;

    ret = tgs_check_authenticator(ac, b, &tgt->key);

    krb5_auth_con_free(context, ac);

    if(ret){
	kdc_log(0, "Failed to verify authenticator: %s", 
		krb5_get_err_text(context, ret));
	goto out;
    }
    
    {
	PrincipalName *s;
	Realm r;
	char *spn, *cpn;
	hdb_entry *server, *client;

	s = b->sname;
	r = b->realm;
	if(s == NULL)
	    if(b->kdc_options.enc_tkt_in_skey &&
	       b->additional_tickets && 
	       b->additional_tickets->len >= 1){
		krb5_principal p;
		hdb_entry *uu;
		principalname2krb5_principal(&p,
					     b->additional_tickets->val[0].sname,
					     b->additional_tickets->val[0].realm);
		uu = db_fetch(p);
		krb5_free_principal(context, p);
		if(uu == NULL){
		    ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
		    goto out;
		}
		/* XXX */
	    }else{
		ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
		goto out;
	    }

#if 0
	principalname2krb5_principal(&sp, *s, r);
#endif
	krb5_unparse_name(context, sp, &spn);
	server = db_fetch(sp);
    
	principalname2krb5_principal(&cp, tgt->cname, tgt->crealm);
	krb5_unparse_name(context, cp, &cpn);
	client = db_fetch(cp);

	kdc_log(0, "TGS-REQ %s from %s for %s", cpn, from, spn);
	
	if(server == NULL){
	    kdc_log(0, "Server not found in database: %s", spn);
	    /* do foreign realm stuff */
	    ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	    goto out;
	}

	if(client == NULL){
	    kdc_log(0, "Client not found in database: %s", cpn);
	    ret = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	    goto out;
	}

	if((b->kdc_options.validate || b->kdc_options.renew) && 
	   !krb5_principal_compare(context, 
				   krbtgt->principal,
				   server->principal)){
	    kdc_log(0, "Inconsistent request.");
	    ret = KRB5KDC_ERR_SERVER_NOMATCH;
	    goto out;
	}
	
	ret = tgs_make_reply(b, tgt, server, client, reply);
	
    out:
	if(ret)
	    krb5_mk_error(context,
			  ret,
			  e_text,
			  NULL,
			  cp,
			  sp,
			  0,
			  reply);
		      
	krb5_free_ticket(context, ticket);
	free(ticket);
	
	free_AP_REQ(&ap_req);
	free(spn);
	krb5_free_principal(context, cp);
	free(cpn);
	    
	if(krbtgt){
	    hdb_free_entry(context, krbtgt);
	    free(krbtgt);
	}
	if(server){
	    hdb_free_entry(context, server);
	    free(server);
	}
	if(client){
	    hdb_free_entry(context, client);
	    free(client);
	}
	    
	return ret;
    }
}

static krb5_error_code
request_server(KDC_REQ *req, krb5_principal *server)
{
    PrincipalName *s = NULL;
    Realm r;
    s = req->req_body.sname;
    r = req->req_body.realm;
    if(s == NULL && 
       req->req_body.additional_tickets &&
       req->req_body.additional_tickets->len){
	s = &req->req_body.additional_tickets->val[0].sname;
	r = req->req_body.additional_tickets->val[0].realm;
    }
    if(s)
	principalname2krb5_principal(server, *s, r);
    else
	krb5_build_principal(context, server, strlen(r), r, "anonymous", NULL);
    return 0;
}


krb5_error_code
tgs_rep(KDC_REQ *req, 
	krb5_data *data,
	const char *from)
{
    krb5_error_code ret;
    int i;
    PA_DATA *pa_data = NULL;
    krb5_principal server;

    request_server(req, &server);

    if(req->padata == NULL){
	ret = KRB5KDC_ERR_PREAUTH_REQUIRED; /* XXX ??? */
	kdc_log(0, "TGS-REQ from %s without PA-DATA", from);
	goto out;
    }
    
    for(i = 0; i < req->padata->len; i++)
	if(req->padata->val[i].padata_type == pa_tgs_req){
	    pa_data = &req->padata->val[i];
	    break;
	}
    if(pa_data == NULL){
	ret = KRB5KDC_ERR_PADATA_TYPE_NOSUPP;
	
	kdc_log(0, "TGS-REQ from %s without PA-TGS-REQ", from);
	goto out;
    }
    ret = tgs_rep2(&req->req_body, server, pa_data, data, from);
out:
    if(ret && data->data == NULL)
	krb5_mk_error(context,
		      ret,
		      NULL,
		      NULL,
		      NULL,
		      server,
		      0,
		      data);
    krb5_free_principal(context, server);
    return ret;
}
