#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_mk_error(krb5_principal princ, 
	      krb5_error_code error_code,
	      char *e_text,
	      krb5_data *e_data,
	      krb5_data *err)
{
    KRB_ERROR msg;
    unsigned char buf[1024];
    
    memset(&msg, 0, sizeof(msg));
    msg.pvno = 5;
    msg.msg_type = krb_error;
    msg.stime = time(0);
    msg.error_code = error_code;
#ifdef USE_ASN1_PRINCIPAL
    msg.realm = princ->realm;
#else
    msg.realm = princ->realm.data;
#endif
    krb5_principal2principalname(&msg.sname, princ);
    if (e_text)
	msg.e_text = &e_text;
    if (e_data)
	msg.e_data = e_data;
    encode_KRB_ERROR(buf + sizeof(buf) - 1, sizeof(buf), &msg, &err->length);
    err->data = malloc(err->length);
    memcpy(err->data, buf + sizeof(buf) - err->length, err->length);
    return 0;
}

