#include "kdc_locl.h"

#define MIN(x,y) (((x)<(y))?(x):(y))
RCSID("$Id$");

struct timeval now;
#define kdc_time now.tv_sec

#ifndef MIN
#define MIN(A,B) ((A)<(B)?(A):(B))
#endif

hdb_entry*
db_fetch(krb5_context context, PrincipalName *principal, char *realm)
{
    HDB *db;
    hdb_entry *ent;

    ent = malloc(sizeof(*ent));
    principalname2krb5_principal(&ent->principal, *principal, realm);
    hdb_open(context, &db, NULL, O_RDONLY, 0);
    db->fetch(context, db, ent);
    db->close(context, db);
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
as_rep(krb5_context context, 
       KDC_REQ *req, 
       KDC_REP *rep,
       krb5_data *data)
{
    KDCOptions f = req->req_body.kdc_options;
    KDC_REQ_BODY *b = &req->req_body;
    hdb_entry *client, *server;
    int use_etype;
    EncTicketPart *et = calloc(1, sizeof(*et));
    EncKDCRepPart *ek = calloc(1, sizeof(*ek));

    client = db_fetch(context, b->cname, b->realm);
    server = db_fetch(context, b->sname, b->realm);

    if(client == NULL)
	return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
    if(server == NULL)
	return KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;

    /* XXX Check for pa_enc_timestamp */
    
    if(b->etype.len == 0)
	return KRB5KDC_ERR_ETYPE_NOSUPP; /* XXX */
    use_etype = b->etype.val[0];

    memset(rep, 0, sizeof(*rep));
    rep->pvno = 5;
    rep->msg_type = krb_as_rep;
    rep->crealm = b->realm;
    rep->cname = *b->cname;
    rep->ticket.tkt_vno = 5;
    rep->ticket.sname = *b->sname;
    rep->ticket.realm = b->realm;

    if(f.renew || f.validate || f.proxy || f.forwarded || f.enc_tkt_in_skey)
	return KRB5KDC_ERR_BADOPTION;
    
    et->flags.initial = 1;
    et->flags.forwardable = f.forwardable;
    et->flags.proxiable = f.proxiable;
    et->flags.may_postdate = f.allow_postdate;

    mk_des_keyblock(&et->key);
    
    et->cname = *b->cname;
    et->crealm = b->realm;
    
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
	t = b->till;
	if(b->till == 0)
	    t = start + client->max_life;
	t = MIN(t, start + client->max_life);
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
		t = start + client->max_renew;
	    t = MIN(t, start + client->max_renew);
	    t = MIN(t, start + server->max_renew);
#if 0
	    t = MIN(t, start + realm->max_renew);
#endif
	    et->renew_till = malloc(sizeof(*et->renew_till));
	    *et->renew_till = t;
	}
    }
    et->caddr = b->addresses;

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
    ek->srealm = rep->ticket.realm;
    ek->sname = rep->ticket.sname;
    ek->caddr = et->caddr;

    {
	unsigned char buf[1024]; /* XXX The data could be indefinite */
	int len;
	len = encode_EncTicketPart(buf + sizeof(buf) - 1, sizeof(buf), et);
	if(len < 0)
	    return ASN1_OVERFLOW;
	rep->ticket.enc_part.etype = ETYPE_DES_CBC_CRC;
	rep->ticket.enc_part.kvno = NULL;
	krb5_encrypt(context, buf + sizeof(buf) - len, len, &server->keyblock, 
		     &rep->ticket.enc_part.cipher);
	
	len = encode_EncASRepPart(buf + sizeof(buf) - 1, sizeof(buf), ek);
	if(len < 0)
	    return ASN1_OVERFLOW;
	rep->enc_part.etype = ETYPE_DES_CBC_CRC;
	rep->enc_part.kvno = NULL;
	krb5_encrypt(context, buf + sizeof(buf) - len, len, &client->keyblock, 
		     &rep->enc_part.cipher);
	
	len = encode_AS_REP(buf + sizeof(buf) - 1, sizeof(buf), rep);
	if(len < 0)
	    return ASN1_OVERFLOW;
	
	krb5_data_copy(data, buf + sizeof(buf) - len, len);
	
    }
    
    return 0;
}

krb5_error_code
tgs_rep(krb5_context context, 
	KDC_REQ *req, 
	KDC_REP *rep,
	krb5_data *data)
{
    KDC_REQ_BODY *b = &req->req_body;
    KDCOptions f = req->req_body.kdc_options;
    EncTicketPart *tgt;
    hdb_entry *server, *krbtgt, *client;
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

	memset(rep, 0, sizeof(*rep));
	rep->pvno = 5;
	rep->msg_type = krb_tgs_rep;
	rep->crealm = tgt->crealm;
	rep->cname = tgt->cname;
	rep->ticket.tkt_vno = 5;
	rep->ticket.sname = *b->sname;
	rep->ticket.realm = b->realm;

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
		till = *et->starttime + client->max_life;
	    till = MIN(till, *et->starttime + client->max_life);
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
		rtime = *et->starttime + client->max_renew;
	    et->flags.renewable = 1;
	    rtime = MIN(rtime, *et->starttime + client->max_renew);
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
	ek->srealm = rep->ticket.realm;
	ek->sname = rep->ticket.sname;
	ek->caddr = et->caddr;
	
	{
	    unsigned char buf[1024]; /* XXX The data could be indefinite */
	    int len;
	    len = encode_EncTicketPart(buf + sizeof(buf) - 1, sizeof(buf), et);
	    if(len < 0)
		return ASN1_OVERFLOW;
	    rep->ticket.enc_part.etype = ETYPE_DES_CBC_CRC;
	    rep->ticket.enc_part.kvno = NULL;
	    krb5_encrypt(context, buf + sizeof(buf) - len, len, &server->keyblock, 
			 &rep->ticket.enc_part.cipher);
	    
	    len = encode_EncTGSRepPart(buf + sizeof(buf) - 1, sizeof(buf), ek);
	    if(len < 0)
		return ASN1_OVERFLOW;
	    rep->enc_part.etype = ETYPE_DES_CBC_CRC;
	    rep->enc_part.kvno = NULL;
	    {
		krb5_keyblock kb;
		kb.keytype = tgt->key.keytype;
		kb.contents = tgt->key.keyvalue;
		krb5_encrypt(context, buf + sizeof(buf) - len, len, &kb, 
			     &rep->enc_part.cipher);
	    }
	    
	    len = encode_TGS_REP(buf + sizeof(buf) - 1, sizeof(buf), rep);
	    if(len < 0)
		return ASN1_OVERFLOW;

	    krb5_data_copy(data, buf + sizeof(buf) - len, len);
	}
	
	return 0;
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

    
    KDC_REP rep;


    hdb_entry *cname, *sname;
    
    gettimeofday(&now, NULL);

    if(req->msg_type == krb_as_req)
	as_rep(context, req, &rep, reply);
    else if(req->msg_type == krb_tgs_req)
	tgs_rep(context, req, &rep, reply);
    else
	/* XXX */
	return KRB5KRB_AP_ERR_MSG_TYPE;
    
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
