#include "krb5_locl.h"

static void reverse(unsigned char *p)
{
  unsigned char tmp[8];
  unsigned int a, b;
  int i;
  
  a = 0;
  b = *(unsigned int*)p;
  for(i = 0; i < 32; i++){
    a >>= 1;
    a |= b & 0x80000000;
    b <<= 1;
  }
  *(unsigned int*)(tmp + 4) = a;
    
  a = 0;
  b = *(unsigned int*)(p + 4);
  for(i = 0; i < 32; i++){
    a >>= 1;
    a |= b & 0x80000000;
    b <<= 1;
  }
  *(unsigned int*)tmp = a;
    
  a = 0;
  b = 0;
  memmove(p, tmp, 8);
  memset(tmp, 0, 8);
}


krb5_error_code
mit_des_string_to_key(const krb5_keytype keytype,
		      krb5_keyblock *keyblock,
		      krb5_data *data, 
		      krb5_data *salt)
{
  unsigned char *p;
  unsigned char *key;
  unsigned char tmp[8];

  int len;
  int i, j;
  int odd = 0;

  len = data->length;
  if(salt)
    len += salt->length;
  len = (len / 8 + 1) * 8;
  p = (unsigned char*)malloc(len);
  memset(p, 0, len);
  memmove(p, data->data, data->length);
  if(salt)
    memmove(p + data->length, salt->data, salt->length);

  memset(key, 0, 8);

  for(i = 0; i < len; i += 8){
    memmove(tmp, p + i, 8);
    if(odd)
      reverse(tmp);
#ifndef RFC1510
    else
      for(j = 0; j < 8; j++) tmp[j] <<= 1;
#endif
    for(j = 0; j < 8; j++)
      key[j] ^= tmp[j];
    odd = !odd;
  }

  des_set_odd_parity(key);
  des_key_schedule(key, &sched);
  des_cbc_cksum(key, key, 8, &sched, key);
  des_set_odd_parity(key);
  if(des_is_weak_key(key))
    key[8] ^= 0xf0;
  memset(p, 0, len);
  memset(tmp, 0, 8);
  free(p);
  keyblock->keytype = KEYTYPE_DES;
  keyblock->contents.data = key;
  keyblock->contents.length = 8;
  
  return 0;
}
