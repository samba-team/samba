#include "kdc_locl.h"

RCSID("$Id$");

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


krb5_error_code
foo(krb5_context context, KDC_REQ *req, unsigned char *reply, size_t *len)
{
    krb5_error_code err;
    krb5_principal princ;
    unsigned char key_buf[1024];
    unsigned char *q;
    DB *db;
    DBT key, value;

    struct timeval now;
    
    KDC_REP rep;
    EncTicketPart et;
    EncKDCRepPart ek;


    struct db_entry *cname, *sname;

    err = principalname2krb5_principal (&princ,
					*req->req_body.cname,
					req->req_body.realm);
    if(err) return err;
    cname = db_fetch(context, princ);
    krb5_free_principal(princ);
    
    err = principalname2krb5_principal (&princ,
					*req->req_body.sname,
					req->req_body.realm);
    if(err) return err;
    sname = db_fetch(context, princ);
    krb5_free_principal(princ);

    memset(&rep, 0, sizeof(rep));
    rep.pvno = 5;
    rep.msg_type = krb_as_rep;
    rep.crealm = req->req_body.realm;
    krb5_principal2principalname(&rep.cname, cname->principal);

    
    memset(&rep.ticket, 0, sizeof(rep.ticket));
    rep.ticket.tkt_vno = 5;
    rep.ticket.realm = req->req_body.realm;
    krb5_principal2principalname(&rep.ticket.sname, sname->principal);
    

    memset(&et, 0, sizeof(et));
    et.flags.initial = 1;
    et.key.keytype = sname->keyblock.keytype;
    et.key.keyvalue.data = sname->keyblock.contents.data;
    et.key.keyvalue.length = sname->keyblock.contents.length;
    et.crealm = req->req_body.realm;
    krb5_principal2principalname(&et.cname, cname->principal);
    gettimeofday(&now, NULL);
    et.authtime = now.tv_sec;
    {
	time_t till;
	till = req->req_body.till;
	till = MIN(till, now.tv_sec + sname->max_life);
	till = MIN(till, now.tv_sec + cname->max_life);
	et.endtime = till;
    }

    
    memset(&ek, 0, sizeof(ek));
    ek.key = et.key;
    ek.last_req.len = 1;
    ek.last_req.val = malloc(sizeof(*ek.last_req.val));
    ek.last_req.val->lr_type = 1;
    ek.last_req.val->lr_value = 0;
    ek.nonce = req->req_body.nonce;
    ek.flags = et.flags;
    ek.authtime = et.authtime;
    ek.starttime = et.starttime;
    ek.endtime = et.endtime;
    ek.renew_till = et.renew_till;
    ek.srealm = et.crealm;
    krb5_principal2principalname(&ek.sname, sname->principal);

    {
	unsigned char buf[1024];
	err = encode_EncTicketPart(buf + sizeof(buf) - 1, sizeof(buf), &et);

	rep.ticket.enc_part.etype = ETYPE_DES_CBC_CRC;
	rep.ticket.enc_part.kvno = NULL;
	err = krb5_encrypt(context, buf + sizeof(buf) - err, err, 
			   &sname->keyblock, 
			   &rep.ticket.enc_part.cipher);
	
	err = encode_EncASRepPart(buf + sizeof(buf) - 1, sizeof(buf), &ek);
	
	rep.enc_part.etype = ETYPE_DES_CBC_CRC;
	rep.enc_part.kvno = NULL;
	err = krb5_encrypt(context, buf + sizeof(buf) - err, err, 
			   &cname->keyblock, 
			   &rep.enc_part.cipher);
	
	*len = encode_AS_REP(reply + 1023, 1024, &rep);
	memmove(reply, reply + 1024 - *len, *len);
    }
    return 0;
}

int
kerberos(krb5_context context, unsigned char *buf, size_t len)
{
    KDC_REQ req;
    int i;
    i = decode_AS_REQ(buf, len, &req);
    if(i >= 0){
	foo(context, &req, buf, &len);
	return len;
    }
    i = decode_TGS_REQ(buf, len, &req);
    if(i >= 0){
	foo(context, &req, buf, &len);
	return len;
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
	    len = recvfrom(s, buf, sizeof(buf), 0, 
			   (struct sockaddr*)&from, &from_len);
	    len = kerberos(context, buf, len);
	    sendto(s, buf, len, 0, 
		   (struct sockaddr*)&from, from_len);
	}
    }
}
