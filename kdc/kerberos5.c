#include "kdc_locl.h"

RCSID("$Id$");

#define MAX_TIME ((time_t)((1U << 31) - 1))

krb5_error_code
as_rep(krb5_context context, 
       KDC_REQ *req, 
       krb5_data *reply)
{
    KDC_REQ_BODY *b = &req->req_body;
    AS_REP rep;
    KDCOptions f = b->kdc_options;
    hdb_entry *client, *server;
    int etype;
    EncTicketPart *et = calloc(1, sizeof(*et));
    EncKDCRepPart *ek = calloc(1, sizeof(*ek));
    krb5_principal client_princ;
    krb5_error_code ret;
    int i;

    krb5_keyblock *ckey, *skey;

    client = db_fetch(context, b->cname, b->realm);
    if(client == NULL)
	return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;

    server = db_fetch(context, b->sname, b->realm);

    if(server == NULL){
	hdb_free_entry(context, client);
	free(client);
	return KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
    }

    principalname2krb5_principal (&client_princ, *(b->cname), b->realm);

    /* XXX Check for pa_enc_timestamp */
    
    if(req->padata == NULL || req->padata->len < 1 ||
       req->padata->val->padata_type != pa_enc_timestamp) {
	PA_DATA foo;
	u_char buf[16];
	size_t len;
	krb5_data foo_data;

	foo.padata_type = pa_enc_timestamp;
	foo.padata_value.length = 0;
	foo.padata_value.data   = NULL;

	encode_PA_DATA(buf + sizeof(buf) - 1,
		       sizeof(buf),
		       &foo,
		       &len);
	foo_data.length = len;
	foo_data.data   = buf + sizeof(buf) - len;

	krb5_mk_error (client_princ,
		       KRB5KDC_ERR_PREAUTH_REQUIRED,
		       "Need to use PA-ENC-TIMESTAMP",
		       &foo_data,
		       reply);
	
	ret = 0;
	goto out;
    } else {
	krb5_data ts_data;
	PA_ENC_TS_ENC p;
	time_t patime;
	size_t len;
	EncryptedData enc_data;

	ret = decode_EncryptedData(req->padata->val->padata_value.data,
				 req->padata->val->padata_value.length,
				 &enc_data,
				 &len);
	if (ret) {
	    krb5_mk_error (client_princ,
			   KRB5KRB_AP_ERR_BAD_INTEGRITY,
			   "Couldn't decode",
			   NULL,
			   reply);
	    goto out;
	}

	ret = krb5_decrypt (context,
			    enc_data.cipher.data,
			    enc_data.cipher.length,
			    enc_data.etype,
			    &client->keyblock,
			    &ts_data);
	free_EncryptedData(&enc_data);
	if (ret) {
	    krb5_mk_error (client_princ,
			   KRB5KRB_AP_ERR_BAD_INTEGRITY,
			   "Couldn't decode",
			   NULL,
			   reply);
	    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	    goto out;
	}
	ret = decode_PA_ENC_TS_ENC(ts_data.data,
				   ts_data.length,
				   &p,
				   &len);
	krb5_data_free(&ts_data);
	if (ret) {
	    krb5_mk_error (client_princ,
			   KRB5KRB_AP_ERR_BAD_INTEGRITY,
			   "Couldn't decode",
			   NULL,
			   reply);
	    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	    goto out;
	}
	patime = p.patimestamp;
	free_PA_ENC_TS_ENC(&p);
	if (abs(kdc_time - p.patimestamp) > 300) {
	    krb5_mk_error (client_princ,
			   KRB5KDC_ERR_PREAUTH_FAILED,
			   "Too large time skew",
			   NULL,
			   reply);
	    ret = KRB5KDC_ERR_PREAUTH_FAILED;
	    goto out;
	}
	et->flags.pre_authent = 1;
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
	goto out;
    }
    
    etype = b->etype.val[i];
    
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
	goto out;
    }
    
    et->flags.initial = 1;
    et->flags.forwardable = f.forwardable;
    et->flags.proxiable = f.proxiable;
    et->flags.may_postdate = f.allow_postdate;

    krb5_generate_random_keyblock(context, ckey->keytype, &et->key);
    copy_PrincipalName(b->cname, &et->cname);
    copy_Realm(&b->realm, &et->crealm);
    
    {
	time_t start;
	time_t t;
	
	start = et->authtime = kdc_time;
    
	if(f.postdated && req->req_body.from){
	    et->starttime = malloc(sizeof(*et->starttime));
	    start = *et->starttime = *req->req_body.from;
	    et->flags.invalid = 1;
	    et->flags.postdated = 1; /* XXX ??? */
	}
	if(b->till == 0)
	    b->till = MAX_TIME;
	t = b->till;
	if(client->max_life)
	    t = min(t, start + client->max_life);
	if(server->max_life)
	    t = min(t, start + server->max_life);
#if 0
	t = min(t, start + realm->max_life);
#endif
	et->endtime = t;
	if(f.renewable_ok && et->endtime < b->till){
	    f.renewable = 1;
	    if(b->rtime == NULL){
		b->rtime = malloc(sizeof(*b->rtime));
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
		t = min(t, start + client->max_renew);
	    if(server->max_renew)
		t = min(t, start + server->max_renew);
#if 0
	    t = min(t, start + realm->max_renew);
#endif
	    et->renew_till = malloc(sizeof(*et->renew_till));
	    *et->renew_till = t;
	}
    }
    if(b->addresses){
	et->caddr = malloc(sizeof(*et->caddr));
	copy_HostAddresses(b->addresses, et->caddr);
    }

    memset(ek, 0, sizeof(*ek));
    copy_EncryptionKey(&et->key, &ek->key);
    /* MIT must have at least one last_req */
    ek->last_req.len = 1;
    ek->last_req.val = malloc(sizeof(*ek->last_req.val));
    ek->last_req.val->lr_type = 0;
    ek->last_req.val->lr_value = 0;
    ek->nonce = b->nonce;
    ek->flags = et->flags;
    ek->authtime = et->authtime;
    ek->starttime = et->starttime;
    ek->endtime = et->endtime;
    ek->renew_till = et->renew_till;
    copy_Realm(&rep.ticket.realm, &ek->srealm);
    copy_PrincipalName(&rep.ticket.sname, &ek->sname);
    if(et->caddr){
	ek->caddr = malloc(sizeof(*ek->caddr));
	copy_HostAddresses(et->caddr, ek->caddr);
    }

    {
	unsigned char buf[1024]; /* XXX The data could be indefinite */
	size_t len;

	ret = encode_EncTicketPart(buf + sizeof(buf) - 1, sizeof(buf),et, &len);
	free_EncTicketPart(et);
	free(et);
	if(ret) 
	    goto out;
	
	krb5_encrypt_EncryptedData(context, 
				   buf + sizeof(buf) - len,
				   len,
				   etype,
				   skey,
				   &rep.ticket.enc_part);
#if 0
	rep.ticket.enc_part.kvno = malloc(sizeof(*rep.ticket.enc_part.kvno));
	*rep.ticket.enc_part.kvno = server.kvno;
#endif
	
	ret = encode_EncASRepPart(buf + sizeof(buf) - 1, sizeof(buf), ek, &len);
	free_EncKDCRepPart(ek);
	free(ek);
	if(ret)
	    goto out;
	krb5_encrypt_EncryptedData(context,
				   buf + sizeof(buf) - len,
				   len,
				   etype,
				   ckey,
				   &rep.enc_part);
#if 0
	rep.enc_part.kvno = malloc(sizeof(*rep.enc_part.kvno));
	*rep.enc_part.kvno = client.kvno;
#endif
	
	ret = encode_AS_REP(buf + sizeof(buf) - 1, sizeof(buf), &rep, &len);
	free_AS_REP(&rep);
	if(ret)
	    goto out;
	
	krb5_data_copy(reply, buf + sizeof(buf) - len, len);
    }
out:
    krb5_free_principal(context, client_princ);
    hdb_free_entry(context, client);
    free(client);
    hdb_free_entry(context, server);
    free(server);
    
    return ret;
}

krb5_error_code
tgs_rep(krb5_context context, 
	KDC_REQ *req, 
	krb5_data *data)
{
    KDC_REQ_BODY *b = &req->req_body;
    KDCOptions f = req->req_body.kdc_options;
    EncTicketPart *tgt;
    hdb_entry *server, *krbtgt, *client;
    TGS_REP rep;
    EncTicketPart *et = calloc(1, sizeof(*et));
    EncKDCRepPart *ek = calloc(1, sizeof(*ek));
    int i;
    krb5_keyblock *skey;
    krb5_enctype etype;
    
    if(req->padata == NULL || req->padata->len < 1)
	return KRB5KDC_ERR_PREAUTH_REQUIRED; /* XXX ??? */
    if(req->padata->val->padata_type != pa_tgs_req)
	return KRB5KDC_ERR_PADATA_TYPE_NOSUPP;

    {
	krb5_auth_context ac = NULL;
	krb5_principal princ;
	krb5_flags ap_req_options;
	krb5_ticket *ticket;
	krb5_error_code ret;
	hdb_entry *ent;

	ret = krb5_build_principal(context,
				   &princ,
				   strlen(req->req_body.realm),
				   req->req_body.realm,
				   "krbtgt",
				   req->req_body.realm,
				   NULL);
	if(ret) return ret;
	
	{
	    PrincipalName p;
	    p.name_type = 0;
	    p.name_string.val = calloc(2, sizeof(*p.name_string.val));
	    p.name_string.len = 2;
	    p.name_string.val[0] = "krbtgt";
	    p.name_string.val[1] = req->req_body.realm;
	    krbtgt = db_fetch(context, &p, req->req_body.realm);
	    free(p.name_string.val);
	}
	if(krbtgt == NULL) 
	    return KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
    
	ret = krb5_rd_req_with_keyblock(context, &ac,
					&req->padata->val->padata_value,
					princ,
					&krbtgt->keyblock,
					&ap_req_options,
					&ticket);

	krb5_free_principal(context, princ);
	if(ret) 
	    return ret;

	tgt = &ticket->ticket;

	{
	    krb5_authenticator auth;
	    size_t len;
	    unsigned char buf[1024];
	    krb5_auth_getauthenticator(context, ac, &auth);
	    if(auth->cksum == NULL)
		return KRB5KRB_AP_ERR_INAPP_CKSUM;
	    /* XXX */
	    if (auth->cksum->cksumtype != CKSUMTYPE_RSA_MD4 &&
		auth->cksum->cksumtype != CKSUMTYPE_RSA_MD5 &&
		auth->cksum->cksumtype != CKSUMTYPE_RSA_MD5_DES)
		return KRB5KRB_AP_ERR_INAPP_CKSUM;
		
	    /* XXX */
	    encode_KDC_REQ_BODY(buf + sizeof(buf) - 1, sizeof(buf),
				b, &len);
	    ret = krb5_verify_checksum(context, buf + sizeof(buf) - len, len,
				       &tgt->key,
				       auth->cksum);
	    if(ret)
		return ret;
	    krb5_auth_con_free(context, ac);
	    free_Authenticator(auth);
	    free(auth);
	}
	    
	server = db_fetch(context, b->sname, b->realm);
	
	if(server == NULL){
	    /* do foreign realm stuff */
	    return KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	}

	client = db_fetch(context, &tgt->cname, tgt->crealm);
	if(client == NULL)
	    return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;

	/* Find appropriate key */
	for(i = 0; i < b->etype.len; i++){
	    ret = hdb_etype2key(context, server, b->etype.val[i], &skey);
	    if(ret == 0)
		break;
	}
	
	if(ret)
	    return KRB5KDC_ERR_ETYPE_NOSUPP;
	
	etype = b->etype.val[i];
    
	memset(&rep, 0, sizeof(rep));
	rep.pvno = 5;
	rep.msg_type = krb_tgs_rep;
	copy_Realm(&tgt->crealm, &rep.crealm);
	copy_PrincipalName(&tgt->cname, &rep.cname);
	rep.ticket.tkt_vno = 5;
	copy_Realm(&b->realm, &rep.ticket.realm);
	copy_PrincipalName (b->sname, &rep.ticket.sname);

	et->caddr = tgt->caddr;
	
	if(f.forwardable){
	    if(!tgt->flags.forwardable)
		return KRB5KDC_ERR_BADOPTION;
	    et->flags.forwardable = 1;
	}
	if(f.forwarded){
	    if(!tgt->flags.forwardable)
		return KRB5KDC_ERR_BADOPTION;
	    et->flags.forwarded = 1;
	    et->caddr = req->req_body.addresses;
	    /* resp.caddr := req.addresses */
	}
	if(tgt->flags.forwarded)
	    et->flags.forwarded = 1;

	if(f.proxiable){
	    if(!tgt->flags.proxiable)
		return KRB5KDC_ERR_BADOPTION;
	    et->flags.proxiable = 1;
	}
	if(f.proxy){
	    if(!tgt->flags.proxiable)
		return KRB5KDC_ERR_BADOPTION;
	    et->flags.proxy = 1;
	    et->caddr = req->req_body.addresses;
	    /* resp.caddr := req.addresses */
	}
	if(f.allow_postdate){
	    if(!tgt->flags.may_postdate)
		return KRB5KDC_ERR_BADOPTION;
	    et->flags.may_postdate = 1;
	}
	if(f.postdated){
	    if(!tgt->flags.may_postdate)
		return KRB5KDC_ERR_BADOPTION;
	    et->flags.postdated = 1;
	    et->flags.invalid = 1;
	    et->starttime = malloc(sizeof(*et->starttime));
	    *et->starttime = *req->req_body.from;
	}
	if(f.validate){
	    if(!tgt->flags.invalid)
		return KRB5KDC_ERR_BADOPTION;
	    if(*tgt->starttime > kdc_time)
		return KRB5KRB_AP_ERR_TKT_NYV;
	    /* XXX  tkt = tgt */
	    et->flags.invalid = 0;
	}
	
	/* check for excess flags */
	
	et->authtime = tgt->authtime;
	
	if(f.renew){
	    time_t old_life;
	    if(!tgt->flags.renewable)
		return KRB5KDC_ERR_BADOPTION;
	    if(*tgt->renew_till >= kdc_time)
		return KRB5KRB_AP_ERR_TKT_EXPIRED;
	    /* XXX tkt = tgt */
	    et->starttime = malloc(sizeof(*et->starttime));
	    *et->starttime = kdc_time;
	    old_life = tgt->endtime - *tgt->starttime;
	    et->endtime = min(*tgt->renew_till,
			      *et->starttime + old_life);
	}else{
	    time_t till;
	    et->starttime = malloc(sizeof(*et->starttime));
	    *et->starttime = kdc_time;
	    till = b->till;
	    if(till == 0)
		till = MAX_TIME;
	    if(client->max_life)
		till = min(till, *et->starttime + client->max_life);
	    if(server->max_life)
		till = min(till, *et->starttime + server->max_life);
	    till = min(till, tgt->endtime);
#if 0
	    till = min(till, et->starttime + realm->max_life);
#endif
	    et->endtime = till;
	    if(f.renewable_ok && 
	       et->endtime < b->till && 
	       tgt->flags.renewable){
		f.renewable = 1;
		b->rtime = malloc(sizeof(*b->rtime));
		*b->rtime = min(b->till, *tgt->renew_till);
	    }
	}
	if(f.renewable && tgt->flags.renewable && b->rtime){
	    time_t rtime;
	    rtime = *b->rtime;
	    if(rtime == 0)
		rtime = MAX_TIME;
	    et->flags.renewable = 1;
	    if(client->max_renew)
		rtime = min(rtime, *et->starttime + client->max_renew);
	    if(server->max_renew)
		rtime = min(rtime, *et->starttime + server->max_renew);
	    rtime = min(rtime, *tgt->renew_till);
#if 0
	    rtime = min(rtime, *et->starttime + realm->max_renew);
#endif
	    et->renew_till = malloc(sizeof(*et->renew_till));
	    *et->renew_till = rtime;
	}

	/* XXX Check enc-authorization-data */

	
	krb5_generate_random_keyblock(context,
				      skey->keytype,
				      &et->key);
	et->crealm = tgt->crealm;
	et->cname = tgt->cname;
	/* do cross realm stuff */
	et->transited = tgt->transited;
	

	memset(ek, 0, sizeof(*ek));
	ek->key = et->key;
	/* MIT must have at least one last_req */
	ek->last_req.len = 1;
	ek->last_req.val = calloc(1, sizeof(*ek->last_req.val));
	ek->nonce = b->nonce;
	ek->flags = et->flags;
	ek->authtime = et->authtime;
	ek->starttime = et->starttime;
	ek->endtime = et->endtime;
	ek->renew_till = et->renew_till;
	ek->srealm = rep.ticket.realm;
	ek->sname = rep.ticket.sname;
	ek->caddr = et->caddr;
	
	{
	    unsigned char buf[1024]; /* XXX The data could be indefinite */
	    size_t len;
	    int e;
	    e = encode_EncTicketPart(buf + sizeof(buf) - 1, 
				     sizeof(buf), et, &len);
	    if(e)
		return e;
	    krb5_encrypt_EncryptedData(context, buf + sizeof(buf) - len, len,
				       etype,
				       skey,
				       &rep.ticket.enc_part);
	    
	    e = encode_EncTGSRepPart(buf + sizeof(buf) - 1, 
				     sizeof(buf), ek, &len);
	    if(e)
		return e;
	    
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

	    e = encode_TGS_REP(buf + sizeof(buf) - 1, sizeof(buf), &rep, &len);
	    if(e)
		return e;
	    free_TGS_REP(&rep);
	    krb5_data_copy(data, buf + sizeof(buf) - len, len);
	}
	free_EncTicketPart(tgt);
	krb5_free_principal(context, ticket->client);
	free(ticket);
	
	hdb_free_entry(context, krbtgt);
	free(krbtgt);
	hdb_free_entry(context, server);
	free(server);
	hdb_free_entry(context, client);
	free(client);
	free_EncryptionKey(&et->key);
	if(et->starttime)
	    free(et->starttime);
	free(et);
	free(ek->last_req.val);
	free(ek);
	return 0;
    }
	    
}
