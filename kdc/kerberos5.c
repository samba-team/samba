#include "kdc_locl.h"

RCSID("$Id$");

struct timeval now;
#define kdc_time now.tv_sec

struct db_entry*
db_fetch(krb5_context context, krb5_principal princ)
{
    DB *db;
    DBT key, value;
    krb5_storage *sp;
    struct db_entry *ent;
    int i;
    int32_t tmp;
    key.size = princ->realm.length;
    for(i = 0; i < princ->ncomp; i++)
	key.size += princ->comp[i].length;
    key.size += (princ->ncomp + 3) * 4;
    key.data = malloc(key.size);
    sp = krb5_storage_from_mem(key.data, key.size);
    tmp = princ->type;
    princ->type = 0;
    krb5_store_principal(sp, princ);
    princ->type = tmp;
    krb5_storage_free(sp);
    
    db = dbopen("foo.db", O_RDONLY, 0, DB_BTREE, NULL);
    if(db->get(db, &key, &value, 0)){
	db->close(db);
	return NULL;
    }
    sp = krb5_storage_from_mem(value.data, value.size);
    ent = malloc(sizeof(struct db_entry));
    krb5_copy_principal(context, princ, &ent->principal);
    krb5_ret_keyblock(sp, &ent->keyblock);
    krb5_ret_int32(sp, &tmp);
    ent->kvno = tmp;
    krb5_ret_int32(sp, &tmp);
    ent->max_life = tmp;
    krb5_ret_int32(sp, &tmp);
    ent->max_renew = tmp;
    krb5_storage_free(sp);
    db->close(db);
    return ent;
}

krb5_error_code
krb5_encrypt (krb5_context context,
	      void *ptr,
	      size_t len,
	      krb5_keyblock *keyblock,
	      krb5_data *result);

krb5_mk_error(krb5_principal princ, 
	      krb5_error_code error_code,
	      krb5_data *err)
{
    KRB_ERROR msg;
    unsigned char buf[1024];
    
    memset(&msg, 0, sizeof(msg));
    msg.pvno = 5;
    msg.msg_type = krb_error;
    msg.stime = time(0);
    msg.error_code = error_code;
    msg.realm = princ->realm.data;
    krb5_principal2principalname(&msg.sname, princ);
    err->length = encode_KRB_ERROR(buf + sizeof(buf) - 1, sizeof(buf), &msg);
    err->data = malloc(err->length);
    memcpy(err->data, buf + sizeof(buf) - err->length, err->length);
    return 0;
}

krb5_error_code
mk_des_keyblock(EncryptionKey *kb)
{
    kb->keytype = KEYTYPE_DES;
    kb->keyvalue.data = malloc(sizeof(des_cblock));
    kb->keyvalue.length = sizeof(des_cblock);
    des_rand_data_key(kb->keyvalue.data);
    return 0;
}



krb5_error_code
as_rep(krb5_context context, KDC_REQ *req, EncTicketPart *et)
{
    KDCOptions f = req->req_body.kdc_options;

    if(f.renew || f.validate || f.proxy || f.forwarded || f.enc_tkt_in_skey)
	return KRB5KDC_ERR_BADOPTION;
    
    et->flags.initial = 1;
    et->flags.forwardable = f.forwardable;
    et->flags.proxiable = f.proxiable;
    et->flags.may_postdate = f.allow_postdate;

    if(f.postdated && req->req_body.from){
	et->starttime = malloc(sizeof(*et->starttime));
	*et->starttime = *req->req_body.from;
	et->flags.invalid = 1;
	et->flags.postdated = 1;
    }
    return 0;
}

krb5_error_code
tgs_rep(krb5_context context, KDC_REQ *req, EncTicketPart *et)
{
    KDCOptions f = req->req_body.kdc_options;


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
	struct db_entry *ent;

	err = krb5_build_principal(context,
				   &princ,
				   strlen(req->req_body.realm),
				   req->req_body.realm,
				   "krbtgt",
				   req->req_body.realm,
				   NULL);
	if(err) return err;
	
	ent = db_fetch(context, princ);
	if(ent == NULL) return 17;
    
	err = krb5_rd_req_with_keyblock(context, &ac,
					&req->padata->val->padata_value,
					princ,
					&ent->keyblock,
					&ap_req_options,
					&ticket);
	if(err) return err;

	if(f.forwardable){
	    if(!ticket->tkt.flags.forwardable)
		return KRB5KDC_ERR_BADOPTION;
	    et->flags.forwardable = 1;
	}
	if(f.forwarded){
	    if(!ticket->tkt.flags.forwardable)
		return KRB5KDC_ERR_BADOPTION;
	    et->flags.forwarded = 1;
	    et->caddr = req->req_body.addresses;
	}
	if(ticket->tkt.flags.forwarded)
	    et->flags.forwarded = 1;
	if(f.proxiable){
	    if(!ticket->tkt.flags.proxiable)
		return KRB5KDC_ERR_BADOPTION;
	    et->flags.proxiable = 1;
	}
	if(f.proxy){
	    if(!ticket->tkt.flags.proxiable)
		return KRB5KDC_ERR_BADOPTION;
	    et->flags.proxy = 1;
	    et->caddr = req->req_body.addresses;
	}
	if(f.allow_postdate){
	    if(!ticket->tkt.flags.may_postdate)
		return KRB5KDC_ERR_BADOPTION;
	    et->flags.may_postdate = 1;
	}
	if(f.postdated){
	    if(!ticket->tkt.flags.may_postdate)
		return KRB5KDC_ERR_BADOPTION;
	    et->flags.postdated = 1;
	    et->flags.invalid = 1;
	    et->starttime = malloc(sizeof(*et->starttime));
	    *et->starttime = *req->req_body.from;
	}
	if(f.validate){
	    if(!ticket->tkt.flags.invalid)
		return KRB5KDC_ERR_BADOPTION;
	    if(*ticket->tkt.starttime > kdc_time)
		return KRB5KRB_AP_ERR_TKT_NYV;
	    /* XXX  tkt = tgt */
	    et->flags.invalid = 0;
	}
	/* check for excess flags */
	
	if(f.renew){
	    time_t old_life;
	    if(!ticket->tkt.flags.renewable)
		return KRB5KDC_ERR_BADOPTION;
	    if(*ticket->tkt.renew_till >= kdc_time)
		return KRB5KRB_AP_ERR_TKT_EXPIRED;
	    /* XXX tkt = tgt */
	    et->starttime = malloc(sizeof(*et->starttime));
	    *et->starttime = kdc_time;
	    old_life = ticket->tkt.endtime - *ticket->tkt.starttime;
	    et->endtime = MIN(*ticket->tkt.renew_till,
			      *et->starttime + old_life);
	}else{
	    time_t till;
	    et->starttime = malloc(sizeof(*et->starttime));
	    *et->starttime = kdc_time;
	}
	req->req_body.cname = malloc(sizeof(*req->req_body.cname));
	krb5_principal2principalname(req->req_body.cname, 
				     ticket->enc_part2.client);
    }
	    
}


krb5_error_code
process_request(krb5_context context, 
    KDC_REQ *req, 
    krb5_data *reply)
{
    krb5_error_code err;
    krb5_principal princ;
    unsigned char key_buf[1024];
    unsigned char *q;
    DB *db;
    DBT key, value;

    
    KDC_REP rep;
    EncTicketPart et;
    EncKDCRepPart ek;


    struct db_entry *cname, *sname;
    
    gettimeofday(&now, NULL);

    memset(&rep, 0, sizeof(rep));
    rep.pvno = 5;
    if(req->msg_type == krb_as_req)
	rep.msg_type = krb_as_rep;
    else if(req->msg_type == krb_tgs_req){
	rep.msg_type = krb_tgs_rep;
	
    }else{
	/* XXX */
	return KRB5KRB_AP_ERR_MSG_TYPE;
    }
    err = principalname2krb5_principal (&princ,
					*req->req_body.sname,
					req->req_body.realm);
    if(err) return err;
    sname = db_fetch(context, princ);
    if(sname == NULL){
	krb5_mk_error(princ, 
		      KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN,
		      reply);
	return 0;
    }
	
    krb5_free_principal(princ);

    memset(&et, 0, sizeof(et));
    if(req->msg_type == krb_as_req)
	as_rep(context, req, &et);
    else
	tgs_rep(context, req, &et);

    err = principalname2krb5_principal (&princ,
					*req->req_body.cname,
					req->req_body.realm);
    if(err) return err;
    cname = db_fetch(context, princ);
    if(cname == NULL){
	krb5_mk_error(sname->principal, 
		      KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN,
		      reply);
	return 0;
	
    }
    krb5_free_principal(princ);
    

    rep.crealm = req->req_body.realm;
    krb5_principal2principalname(&rep.cname, cname->principal);

    memset(&rep.ticket, 0, sizeof(rep.ticket));
    rep.ticket.tkt_vno = 5;
    rep.ticket.realm = req->req_body.realm;
    krb5_principal2principalname(&rep.ticket.sname, sname->principal);

    mk_des_keyblock(&et.key);
    et.crealm = req->req_body.realm;
    et.cname = *req->req_body.cname;
    et.authtime = kdc_time;
    {
	time_t till;
	time_t start = et.authtime;
	if(et.starttime)
	    start = *et.starttime;
	till = req->req_body.till;
	if(till == 0)
	    till = start + cname->max_life;
	till = MIN(till, start + sname->max_life);
	till = MIN(till, start + cname->max_life);
	et.endtime = till;
    }
    if(req->req_body.kdc_options.renewable && req->req_body.rtime){
	time_t rtime;
	time_t start = et.authtime;
	if(et.starttime)
	    start = *et.starttime;
	rtime = *req->req_body.rtime;
	if(rtime == 0)
	    rtime = start + cname->max_renew;
	rtime = MIN(rtime, start + sname->max_renew);
	rtime = MIN(rtime, start + cname->max_renew);
	if(rtime > et.endtime){
	    et.renew_till = malloc(sizeof(*et.renew_till));
	    *et.renew_till = rtime;
	    et.flags.renewable = 1;
	}
    }

    
    memset(&ek, 0, sizeof(ek));
    ek.key = et.key;
    /* MIT must have at least one last_req */
    ek.last_req.len = 1;
    ek.last_req.val = malloc(sizeof(*ek.last_req.val));
    ek.last_req.val->lr_type = 0;
    ek.last_req.val->lr_value = 0;
    ek.nonce = req->req_body.nonce;
    ek.flags = et.flags;
    ek.authtime = et.authtime;
    ek.starttime = et.starttime;
    ek.endtime = et.endtime;
    ek.renew_till = et.renew_till;
    ek.srealm = req->req_body.realm;
    ek.sname = *req->req_body.sname;
    ek.caddr = req->req_body.addresses;

    {
	unsigned char buf[1024];
	err = encode_EncTicketPart(buf + sizeof(buf) - 1, sizeof(buf), &et);

	rep.ticket.enc_part.etype = ETYPE_DES_CBC_CRC;
	rep.ticket.enc_part.kvno = NULL;
	err = krb5_encrypt(context, buf + sizeof(buf) - err, err, 
			   &sname->keyblock, 
			   &rep.ticket.enc_part.cipher);
	
	switch(rep.msg_type){
	case krb_as_rep:
	    err = encode_EncASRepPart(buf + sizeof(buf) - 1, sizeof(buf), &ek);
	    break;
	case krb_tgs_rep:
	    err = encode_EncTGSRepPart(buf + sizeof(buf) - 1, sizeof(buf), 
				       &ek);
	    break;
	default:
	    abort();
	    break;
	}
	
	rep.enc_part.etype = ETYPE_DES_CBC_CRC;
	rep.enc_part.kvno = NULL;
	err = krb5_encrypt(context, buf + sizeof(buf) - err, err, 
			   &cname->keyblock, 
			   &rep.enc_part.cipher);
	
	switch(rep.msg_type){
	case krb_as_rep:
	    reply->length = encode_AS_REP(buf + sizeof(buf) - 1, 
					  sizeof(buf), &rep);
	    break;
	case krb_tgs_rep:
	    reply->length = encode_TGS_REP(buf + sizeof(buf) - 1, 
					   sizeof(buf), &rep);
	    break;
	}
	reply->data = malloc(reply->length);
	memcpy(reply->data, buf + sizeof(buf) - reply->length, reply->length);
    }
    return 0;
}

int
kerberos(krb5_context context, 
	 unsigned char *buf, 
	 size_t len, 
	 krb5_data *reply)
{
    KDC_REQ req;
    int i;
    i = decode_AS_REQ(buf, len, &req);
    if(i >= 0){
	return process_request(context, &req, reply);
    }
    i = decode_TGS_REQ(buf, len, &req);
    if(i >= 0){
	return process_request(context, &req, reply);
    }
    return -1;
}

main(int argc, char **argv)
{
    krb5_context context;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sin;
    int one = 1;
    if(s < 0){
	perror("socket");
	exit(1);
    }
    krb5_init_context(&context);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(88);
    if(bind(s, (struct sockaddr*)&sin, sizeof(sin)) < 0){
	perror("bind");
	exit(1);
    }
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    while(1){
	fd_set fds;
	unsigned char buf[1024];
	size_t len;
	FD_ZERO(&fds);
	FD_SET(s, &fds);
	if(select(s + 1, &fds, NULL, NULL, NULL) < 0){
	    perror("select");
	    exit(1);
	}
	if(FD_ISSET(s, &fds)){
	    struct sockaddr_in from;
	    int from_len = sizeof(from);
	    krb5_error_code err;
	    krb5_data reply;
	    len = recvfrom(s, buf, sizeof(buf), 0, 
			   (struct sockaddr*)&from, &from_len);
	    err = kerberos(context, buf, len, &reply);
	    if(err){
		fprintf(stderr, "%s\n", krb5_get_err_text(context, err));
	    }else{
		sendto(s, reply.data, reply.length, 0, 
		       (struct sockaddr*)&from, from_len);
		krb5_data_free(&reply);
	    }
	}
    }
}
