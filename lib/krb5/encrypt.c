#include <krb5_locl.h>
#include "crc.h"

RCSID("$Id$");

krb5_error_code
krb5_des_cbc_encrypt (krb5_context context,
		      void *ptr,
		      size_t len,
		      int etype,
		      krb5_keyblock *keyblock,
		      krb5_data *result)
{
    u_char *p;
    size_t sz;
    des_cblock key;
    des_key_schedule schedule;

    switch(etype){
    case ETYPE_DES_CBC_MD5:
	sz = 16;
	break;
    case ETYPE_DES_CBC_CRC:
	sz = 4;
	break;
    default:
	return KRB5_PROG_ETYPE_NOSUPP;
    }
    
    sz += len + 8;
    sz = (sz + 7) & ~7; /* pad to 8 bytes */
    p = calloc (1, sz);
    if (p == NULL)
	return ENOMEM;
    des_new_random_key((des_cblock*)p);
#if 0
    des_rand_data ((des_cblock*)p, 8);
#endif
    memcpy (p + 12, ptr, len);
    switch(etype){
    case ETYPE_DES_CBC_MD5:
	{
	    struct md5 m;
	    md5init(&m);
	    md5_update(&m, p, sz);
	    md5_finito(&m, p + 8);
	    break;
	}
    case ETYPE_DES_CBC_CRC:
	{
	    u_int32_t crc;
	    crc_init_table ();
	    crc = crc_update (p, sz, 0);
	    p[8]  = crc & 0xff;
	    p[9]  = (crc >> 8)  & 0xff;
	    p[10] = (crc >> 16) & 0xff;
	    p[11] = (crc >> 24) & 0xff;
	    break;
	}
    }
  
    memcpy (&key, keyblock->keyvalue.data, sizeof(key));
    des_set_key (&key, schedule);
    des_cbc_encrypt ((des_cblock *)p, (des_cblock *)p, sz, 
		     schedule, &key, DES_ENCRYPT);

    result->data = p;
    result->length = sz;
    return 0;
    
}

krb5_error_code
krb5_encrypt (krb5_context context,
	      void *ptr,
	      size_t len,
	      int etype,
	      krb5_keyblock *keyblock,
	      krb5_data *result)
{
    switch(etype){
    case ETYPE_DES_CBC_MD5:
    case ETYPE_DES_CBC_CRC:
	return krb5_des_cbc_encrypt(context, ptr, len, etype, 
				    keyblock, result);
    }
    return KRB5_PROG_ETYPE_NOSUPP;
}
