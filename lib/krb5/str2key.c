#include <krb5_locl.h>

RCSID("$Id$");

/*
 * Reverse 8 bytes
 */

static void
reverse (unsigned char *s)
{
     static unsigned char tbl[] = {
	  0x0,
	  0x8,
	  0x4,
	  0xC,
	  0x2,
	  0xA,
	  0x6,
	  0xE,
	  0x1,
	  0x9,
	  0x5,
	  0xD,
	  0x3,
	  0xB,
	  0x7,
	  0xF
     };

     char tmp;

#define REVONE(str, i, j) \
do { tmp = str[i]; str[i] = str[j]; str[j] = tmp;} while(0)

     REVONE(s,0,7);
     REVONE(s,1,6);
     REVONE(s,2,5);
     REVONE(s,3,4);
#undef REVONE

#define REVTWO(q) \
q = (tbl[q & 0x0F] << 4) | (tbl[q >> 4])

     REVTWO(s[0]);
     REVTWO(s[1]);
     REVTWO(s[2]);
     REVTWO(s[3]);
     REVTWO(s[4]);
     REVTWO(s[5]);
     REVTWO(s[6]);
     REVTWO(s[7]);

#undef REVTWO
}

/*
 * A = A xor B. A & B is 8 bytes.
 */

static void
xor (unsigned char *a, unsigned char *b)
{
     a[0] ^= b[0];
     a[1] ^= b[1];
     a[2] ^= b[2];
     a[3] ^= b[3];
     a[4] ^= b[4];
     a[5] ^= b[5];
     a[6] ^= b[6];
     a[7] ^= b[7];
}

/*
 * Init a from b
 */

static void
init (unsigned char *a, unsigned char *b)
{
     a[0] = b[0] << 1;
     a[1] = b[1] << 1;
     a[2] = b[2] << 1;
     a[3] = b[3] << 1;
     a[4] = b[4] << 1;
     a[5] = b[5] << 1;
     a[6] = b[6] << 1;
     a[7] = b[7] << 1;
}

krb5_error_code
krb5_string_to_key (char *str,
		    krb5_data *salt,
		    krb5_keyblock *key)
{
     int odd, i;
     size_t len;
     char *s, *p;
     des_cblock tempkey;
     des_key_schedule sched;
     krb5_error_code err;

     len = strlen(str) + salt->length;
#if 1
     len = (len + 7) / 8 * 8;
#endif
     p = s = malloc (len);
     if (p == NULL)
	  return ENOMEM;
     err = krb5_data_alloc (&key->keyvalue, sizeof(des_cblock));
     if (err) {
	  free (p);
	  return err;
     }
     memset (s, 0, len);
     strncpy (p, str, strlen(str));
     p += strlen(str);
     memcpy (p, salt->data, salt->length);
     odd = 1;
     memset (tempkey, 0, sizeof(tempkey));
     for (i = 0; i < len; i += 8) {
	  unsigned char tmp[8];

	  init (tmp, (unsigned char*)&s[i]);

	  if (odd == 0) {
	       odd = 1;
	       reverse (tmp);
	       init (tmp, tmp);
	  } else
	       odd = 0;
	  xor (tempkey, tmp);
     }
     des_set_odd_parity (&tempkey);
     des_set_key (&tempkey, sched);
     des_cbc_cksum ((des_cblock *)s, &tempkey, len, sched, &tempkey);
     free (s);
     des_set_odd_parity (&tempkey);
     if (des_is_weak_key (&tempkey))
	 xor ((unsigned char *)&tempkey, (unsigned char*)"0x000x000x000x000x000x000x000xF0");
     memcpy (key->keyvalue.data, &tempkey, sizeof(tempkey));
     key->keytype = KEYTYPE_DES;
     key->keyvalue.length = sizeof(tempkey);
     return 0;
}

krb5_error_code
krb5_get_salt (krb5_principal princ,
	       krb5_data *salt)
{
    size_t len;
    int i;
    krb5_error_code err;
    char *p;
     
#ifdef USE_ASN1_PRINCIPAL
    len = strlen(princ->realm);
    for (i = 0; i < princ->name.name_string.len; ++i)
	len += strlen(princ->name.name_string.val[i]);
#else
    len = princ->realm.length;
    for (i = 0; i < princ->ncomp; ++i)
	len += princ->comp[i].length;
#endif
    err = krb5_data_alloc (salt, len);
    if (err)
	return err;
    p = salt->data;
#ifdef USE_ASN1_PRINCIPAL
    strcpy (p, princ->realm);
    for (i = 0; i < princ->name.name_string.len; ++i) 
	strcat (p, princ->name.name_string.val[i]);
#else
    strncpy (p, princ->realm.data, princ->realm.length);
    p += princ->realm.length;
    for (i = 0; i < princ->ncomp; ++i) {
	strncpy (p, princ->comp[i].data, princ->comp[i].length);
	p += princ->comp[i].length;
    }
#endif
    return 0;
}

