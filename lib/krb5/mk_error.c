#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_mk_error(krb5_context context,
	      krb5_error_code error_code,
	      const char *e_text,
	      const krb5_data *e_data,
	      const krb5_principal client,
	      const krb5_principal server,
	      time_t ctime,
	      krb5_data *reply)
{
    KRB_ERROR msg;
    unsigned char buf[1024];
    
    memset(&msg, 0, sizeof(msg));
    msg.pvno = 5;
    msg.msg_type = krb_error;
    msg.stime = time(0);
    if(ctime){
	msg.ctime = &ctime;
    }
    msg.error_code = error_code;
    if (e_text)
	msg.e_text = (general_string*)&e_text;
    if (e_data)
	msg.e_data = (octet_string*)e_data;
#ifdef USE_ASN1_PRINCIPAL
    msg.realm = server->realm;
#else
    msg.realm = server->realm.data;
#endif
    msg.sname = server->name;
    if(client){
	msg.crealm = &client->realm;
	msg.cname = &client->name;
    }
    encode_KRB_ERROR(buf + sizeof(buf) - 1, sizeof(buf), &msg, &reply->length);
    reply->data = malloc(reply->length);
    memcpy(reply->data, buf + sizeof(buf) - reply->length, reply->length);
    return 0;
}

