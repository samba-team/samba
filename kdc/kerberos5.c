#include "kdc_locl.h"

RCSID("$Id$");

#ifndef MIN
#define MIN(A,B) ((A)<(B)?(A):(B))
#endif

#define MAX_TIME ((time_t)((1U << 31) - 1))

krb5_error_code
as_rep(krb5_context context, 
       KDC_REQ *req, 
       krb5_data *data)
{
    KDC_REQ_BODY *b = &req->req_body;
    AS_REP rep;
    KDCOptions f = b->kdc_options;
    hdb_entry *client, *server;
    int use_etype;
    EncTicketPart *et = calloc(1, sizeof(*et));
    EncKDCRepPart *ek = calloc(1, sizeof(*ek));
    krb5_principal client_princ;
    int e;

    client = db_fetch(context, b->cname, b->realm);
    server = db_fetch(context, b->sname, b->realm);

    if(client == NULL)
	return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
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
		       data);

	return 0;
    } else {
	krb5_data ts_data;
	PA_ENC_TS_ENC p;
	size_t len;
	EncryptedData enc_data;

	e = decode_EncryptedData(req->padata->val->padata_value.data,
				 req->padata->val->padata_value.length,
				 &enc_data,
				 &len);
	if (e) {
	    krb5_mk_error (client_princ,
			   KRB5KRB_AP_ERR_BAD_INTEGRITY,
			   "Couldn't decode",
			   NULL,
			   data);
	    return 0;
	}

	krb5_decrypt (context,
		      enc_data.cipher.data,
		      enc_data.cipher.length,
		      &client->keyblock,
		      &ts_data);
	e = decode_PA_ENC_TS_ENC(ts_data.data,
				 ts_data.length,
				 &p,
				 &len);
	if (e) {
	    krb5_mk_error (client_princ,
			   KRB5KRB_AP_ERR_BAD_INTEGRITY,
			   "Couldn't decode",
			   NULL,
			   data);
	    return 0;
	}
	if (kdc_time - p.patimestamp > 300) {
	    krb5_mk_error (client_princ,
			   KRB5KDC_ERR_PREAUTH_FAILED,
			   "Too large time skew",
			   NULL,
			   data);
	    return 0;
	}

    }

    if(b->etype.len == 0)
	return KRB5KDC_ERR_ETYPE_NOSUPP; /* XXX */
    use_etype = b->etype.val[0];

    memset(&rep, 0, sizeof(rep));
    rep.pvno = 5;
    rep.msg_type = krb_as_rep;
    copy_Realm(&b->realm, &rep.crealm);
    copy_PrincipalName(b->cname, &rep.cname);
    rep.ticket.tkt_vno = 5;
    copy_Realm(&b->realm, &rep.ticket.realm);
    copy_PrincipalName(b->sname, &rep.ticket.sname);

    if(f.renew || f.validate || f.proxy || f.forwarded || f.enc_tkt_in_skey)
	return KRB5KDC_ERR_BADOPTION;
    
    et->flags.initial = 1;
    et->flags.forwardable = f.forwardable;
    et->flags.proxiable = f.proxiable;
    et->flags.may_postdate = f.allow_postdate;

    mk_des_keyblock(&et->key);
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
	    t = MIN(t, start + client->max_life);
	if(server->max_life)
	    t = MIN(t, start + server->max_life);
#if 0
	t = MIN(t, start + realm->max_life);
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
		t = MIN(t, start + client->max_renew);
	    if(server->max_renew)
		t = MIN(t, start + server->max_renew);
#if 0
	    t = MIN(t, start + realm->max_renew);
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

	e = encode_EncTicketPart(buf + sizeof(buf) - 1, sizeof(buf), et, &len);
	free_EncTicketPart(et);
	free(et);
	if(e)
	    return e;

	rep.ticket.enc_part.etype = ETYPE_DES_CBC_CRC;
	rep.ticket.enc_part.kvno = NULL;
	krb5_encrypt(context, buf + sizeof(buf) - len, len, &server->keyblock, 
		     &rep.ticket.enc_part.cipher);
	
	e = encode_EncASRepPart(buf + sizeof(buf) - 1, sizeof(buf), ek, &len);
	free_EncKDCRepPart(ek);
	free(ek);
	if(e)
	    return e;
	rep.enc_part.etype = ETYPE_DES_CBC_CRC;
	rep.enc_part.kvno = NULL;

	krb5_encrypt(context, buf + sizeof(buf) - len, len, &client->keyblock, 
		     &rep.enc_part.cipher);
	
	e = encode_AS_REP(buf + sizeof(buf) - 1, sizeof(buf), &rep, &len);
	if(e)
	    return e;
	free_AS_REP(&rep);
	
	krb5_data_copy(data, buf + sizeof(buf) - len, len);
	
    }
    
    return 0;
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
    
    if(req->padata == NULL || req->padata->len < 1)
	return KRB5KDC_ERR_PREAUTH_REQUIRED; /* XXX ??? */
    if(req->padata->val->padata_type != pa_tgs_req)
	return KRB5KDC_ERR_PADATA_TYPE_NOSUPP;

    {
	krb5_auth_context ac = NULL;
	krb5_principal princ;
	krb5_flags ap_req_options;
	krb5_ticket *ticket;
	krb5_error_code err;
	hdb_entry *ent;

	err = krb5_build_principal(context,
				   &princ,
				   strlen(req->req_body.realm),
				   req->req_body.realm,
				   "krbtgt",
				   req->req_body.realm,
				   NULL);
	if(err) return err;
	
	{
	    PrincipalName p;
	    p.name_string.val = calloc(2, sizeof(*p.name_string.val));
	    p.name_string.len = 2;
	    p.name_string.val[0] = "krbtgt";
	    p.name_string.val[1] = req->req_body.realm;
	    krbtgt = db_fetch(context, &p, req->req_body.realm);
	    free(p.name_string.val);
	}
	if(ent == NULL) 
	    return KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
    
	err = krb5_rd_req_with_keyblock(context, &ac,
					&req->padata->val->padata_value,
					princ,
					&krbtgt->keyblock,
					&ap_req_options,
					&ticket);
	if(err) 
	    return err;

	/* XXX Check authenticator */

	server = db_fetch(context, b->sname, b->realm);
	
	if(server == NULL)
	    return KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;

	tgt = &ticket->tkt;

	client = db_fetch(context, &tgt->cname, tgt->crealm);
	if(client == NULL)
	    return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;

	memset(&rep, 0, sizeof(rep));
	rep.pvno = 5;
	rep.msg_type = krb_tgs_rep;
	rep.crealm = tgt->crealm;
	rep.cname = tgt->cname;
	rep.ticket.tkt_vno = 5;
	rep.ticket.sname = *b->sname;
	rep.ticket.realm = b->realm;

	et->caddr = ticket->tkt.caddr;
	
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
	et->flags.forwarded = tgt->flags.forwarded;

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
	    et->endtime = MIN(*tgt->renew_till,
			      *et->starttime + old_life);
	}else{
	    time_t till;
	    et->starttime = malloc(sizeof(*et->starttime));
	    *et->starttime = kdc_time;
	    till = b->till;
	    if(till == 0)
		till = MAX_TIME;
	    if(client->max_life)
		till = MIN(till, *et->starttime + client->max_life);
	    if(server->max_life)
		till = MIN(till, *et->starttime + server->max_life);
	    till = MIN(till, tgt->endtime);
#if 0
	    till = MIN(till, et->starttime + realm->max_life);
#endif
	    et->endtime = till;
	    if(f.renewable_ok && 
	       et->endtime < b->till && 
	       tgt->flags.renewable){
		f.renewable = 1;
		b->rtime = malloc(sizeof(*b->rtime));
		*b->rtime = MIN(b->till, *tgt->renew_till);
	    }
	}
	if(f.renewable && tgt->flags.renewable && b->rtime){
	    time_t rtime;
	    rtime = *b->rtime;
	    if(rtime == 0)
		rtime = MAX_TIME;
	    et->flags.renewable = 1;
	    if(client->max_renew)
		rtime = MIN(rtime, *et->starttime + client->max_renew);
	    if(server->max_renew)
		rtime = MIN(rtime, *et->starttime + server->max_renew);
	    rtime = MIN(rtime, *tgt->renew_till);
#if 0
	    rtime = MIN(rtime, *et->starttime + realm->max_renew);
#endif
	    et->renew_till = malloc(sizeof(*et->renew_till));
	    *et->renew_till = rtime;
	}

	/* XXX Check enc-authorization-data */

	
	mk_des_keyblock(&et->key);
	et->crealm = tgt->crealm;
	et->cname = tgt->cname;
	et->transited = tgt->transited;
	

	memset(ek, 0, sizeof(*ek));
	ek->key = et->key;
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
	    rep.ticket.enc_part.etype = ETYPE_DES_CBC_CRC;
	    rep.ticket.enc_part.kvno = NULL;
	    krb5_encrypt(context, buf + sizeof(buf) - len, len, &server->keyblock, 
			 &rep.ticket.enc_part.cipher);
	    
	    e = encode_EncTGSRepPart(buf + sizeof(buf) - 1, 
				     sizeof(buf), ek, &len);
	    if(e)
		return e;
	    rep.enc_part.etype = ETYPE_DES_CBC_CRC;
	    rep.enc_part.kvno = NULL;
	    {
		krb5_keyblock kb;
		kb.keytype = tgt->key.keytype;
		kb.keyvalue = tgt->key.keyvalue;
		krb5_encrypt(context, buf + sizeof(buf) - len, len, &kb, 
			     &rep.enc_part.cipher);
	    }
	    
	    e = encode_TGS_REP(buf + sizeof(buf) - 1, sizeof(buf), &rep, &len);
	    if(e)
		return e;
	    free_TGS_REP(&rep);
	    krb5_data_copy(data, buf + sizeof(buf) - len, len);
	}
	
	return 0;
    }
	    
}
