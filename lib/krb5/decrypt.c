#include <krb5_locl.h>
#include "crc.h"

RCSID("$Id$");

krb5_error_code
krb5_des_cbc_decrypt(krb5_context context,
		     void *ptr,
		     size_t len,
		     int etype,
		     const krb5_keyblock *keyblock,
		     krb5_data *result)
{
    u_char *p = (u_char *)ptr;
    size_t offset;
    des_cblock key;
    des_key_schedule schedule;

    memcpy (&key, keyblock->keyvalue.data, sizeof(key));
    des_set_key (&key, schedule);
    des_cbc_encrypt ((des_cblock *)ptr, (des_cblock *)ptr, len, 
		     schedule, &key, DES_DECRYPT);
    switch(etype){
    case ETYPE_DES_CBC_MD5:
	{
	    struct md5 m;
	    u_int32_t his_checksum[4];
	    u_int32_t my_checksum[4];
	    memcpy(his_checksum, p + 8, 16);
	    memset(p + 8, 0, 16);
	    md5_init(&m);
	    md5_update (&m, ptr, len);
	    md5_finito(&m, my_checksum);
	    if(memcmp(his_checksum, my_checksum, 16))
		return KRB5KRB_AP_ERR_BAD_INTEGRITY;
	    offset = 24;
	}
    break;
	
    case ETYPE_DES_CBC_CRC:
	{
	    u_int32_t my_crc, her_crc;
	    her_crc = (p[11] << 24) | (p[10] << 16) | 
		      (p[9] << 8) | (p[8] << 0);
	    memset (p + 8, 0, sizeof(her_crc));
	    crc_init_table ();
	    my_crc = crc_update (ptr, len, 0);
	    if (my_crc != her_crc)
		return KRB5KRB_AP_ERR_BAD_INTEGRITY;
	    offset = 12;
	}
    break;
    default:
	return KRB5_PROG_ETYPE_NOSUPP;
    }
    result->length = len - offset;
    result->data = malloc(result->length);
    if (result->data == NULL)
	return ENOMEM;
    memcpy(result->data, p + 12, result->length);
    return 0;
}
		    

krb5_error_code
krb5_decrypt (krb5_context context,
	      void *ptr,
	      size_t len,
	      int etype,
	      const krb5_keyblock *keyblock,
	      krb5_data *result)
{
    switch(etype){
    case ETYPE_DES_CBC_CRC:
    case ETYPE_DES_CBC_MD5:
	return krb5_des_cbc_decrypt(context, ptr, len, etype, keyblock,
				    result);
    }
    return KRB5_PROG_ETYPE_NOSUPP;
}
