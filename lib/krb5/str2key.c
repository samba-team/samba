/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

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
xor (des_cblock *key, unsigned char *b)
{
    unsigned char *a = (unsigned char*)key;
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

static void
DES_string_to_key(const unsigned char *str, size_t len, des_cblock *key)
{
    int odd, i;
    des_key_schedule sched;

    memset (key, 0, sizeof(des_cblock));

    odd = 1;
    for (i = 0; i < len; i += 8) {
	unsigned char tmp[8];

	init (tmp, (unsigned char*)&str[i]);

	if (odd == 0) {
	    odd = 1;
	    reverse (tmp);
	    init (tmp, tmp);
	} else
	    odd = 0;
	xor (key, tmp);
    }
    des_set_odd_parity (key);
    des_set_key (key, sched);
    des_cbc_cksum ((des_cblock *)str, key, len, sched, key);
    des_set_odd_parity (key);
    if (des_is_weak_key (key))
	xor (key, (unsigned char*)"\0\0\0\0\0\0\0\xf0");
}

static int
gcd(int a, int b)
{
    do{
	int r = a % b;
	a = b;
	b = r;
    }while(b);
    return a;
}


static void
rr13(unsigned char *buf, size_t len)
{
    unsigned char *tmp = malloc(len);
    int i;
    for(i = 0; i < len; i++){
	int x = (buf[i] << 8) | buf[(i + 1) % len];
	x >>= 5;
	tmp[(i + 2) % len] = x & 0xff;
    }
    memcpy(buf, tmp, len);
    free(tmp);
}

static void
add1(unsigned char *a, unsigned char *b, size_t len)
{
    int i;
    int carry = 0;
    for(i = len - 1; i >= 0; i--){
	int x = a[i] + b[i];
	carry = x > 0xff;
	a[i] = x & 0xff;
    }
    for(i = len - 1; carry && i >= 0; i--){
	int x = a[i] + carry;
	carry = x > 0xff;
	a[i] = carry & 0xff;
    }
}

static void
fold(const unsigned char *str, size_t len, unsigned char *out)
{
    const int size = 24;
    unsigned char key[24];
    int num = 0;
    int i;
    int lcm = size * len / gcd(size, len);
    unsigned char *tmp = malloc(lcm);
    unsigned char *buf = malloc(len);
    memcpy(buf, str, len);
    for(; num < lcm; num += len){
	memcpy(tmp + num, buf, len);
	rr13(buf, len);
    }
    free(buf);
    memset(key, 0, sizeof(key));
    for(i = 0; i < lcm; i += size)
	add1(key, tmp + i, size);

    memcpy(out, key, size);
}

static void
DES3_string_to_key(const unsigned char *str, size_t len, des_cblock *keys)
{
    unsigned char tmp[24];
    des_cblock ivec;
    des_key_schedule s[3];
    int i;

    fold(str, len, tmp);
    for(i = 0; i < 3; i++){
	memcpy(keys + i, tmp + 8 * i, 8);
	des_set_odd_parity(keys + i);
	if(des_is_weak_key(keys + i))
	    xor(keys + i, (unsigned char*)"\0\0\0\0\0\0\0\xf0");
	des_set_key(keys + i, s[i]);
    }
    memset(&ivec, 0, sizeof(ivec));
    des_ede3_cbc_encrypt((void*)tmp, (void*)tmp, sizeof(tmp), 
			 s[0], s[1], s[2], &ivec, 1);
    memset(s, 0, sizeof(s));
    for(i = 0; i < 3; i++){
	memcpy(keys + i, tmp + 8 * i, 8);
	des_set_odd_parity(keys + i);
	if(des_is_weak_key(keys + i))
	    xor(keys + i, (unsigned char*)"\0\0\0\0\0\0\0\xf0");
    }
    memset(tmp, 0, sizeof(tmp));
}


static krb5_error_code
string_to_key_internal (const unsigned char *str,
			size_t str_len,
			krb5_data *salt,
			krb5_keytype ktype,
			krb5_keyblock *key)
{
     size_t len;
     unsigned char *s, *p;
     krb5_error_code ret;

     len = str_len + salt->length;
#if 1
     len = (len + 7) / 8 * 8;
#endif
     p = s = malloc (len);
     if (p == NULL)
	  return ENOMEM;
     memset (s, 0, len);
     strncpy ((char *)p, (char *)str, str_len);
     p += str_len;
     memcpy (p, salt->data, salt->length);

     switch(ktype){
     case KEYTYPE_DES:{
	 des_cblock tmpkey;
	 DES_string_to_key(s, len, &tmpkey);
	 ret = krb5_data_copy(&key->keyvalue, tmpkey, sizeof(des_cblock));
	 memset(&tmpkey, 0, sizeof(tmpkey));
	 break;
     }
     case KEYTYPE_DES3:{
	 des_cblock keys[3];
	 DES3_string_to_key(s, len, keys);
	 ret = krb5_data_copy(&key->keyvalue, keys, sizeof(keys));
	 memset(keys, 0, sizeof(keys));
	 break;
     }
     default:
	 ret = KRB5_PROG_KEYTYPE_NOSUPP;
	 break;
     }
     memset(s, 0, len);
     free(s);
     if(ret)
	 return ret;
     key->keytype = ktype;
     return 0;
}

krb5_error_code
krb5_string_to_key (char *str,
		    krb5_data *salt,
		    krb5_keytype ktype,
		    krb5_keyblock *key)
{
    return string_to_key_internal ((const unsigned char *)str,
				   strlen(str), salt, ktype, key);
}

krb5_error_code
krb5_string_to_key_data (krb5_data *str,
			 krb5_data *salt,
			 krb5_keytype ktype,
			 krb5_keyblock *key)
{
    return string_to_key_internal (str->data, str->length, salt, ktype, key);
}

krb5_error_code
krb5_get_salt (krb5_principal princ,
	       krb5_data *salt)
{
    size_t len;
    int i;
    krb5_error_code err;
    char *p;
     
    len = strlen(princ->realm);
    for (i = 0; i < princ->name.name_string.len; ++i)
	len += strlen(princ->name.name_string.val[i]);
    err = krb5_data_alloc (salt, len);
    if (err)
	return err;
    p = salt->data;
    strncpy (p, princ->realm, strlen(princ->realm));
    p += strlen(princ->realm);
    for (i = 0; i < princ->name.name_string.len; ++i) {
	strncpy (p,
		 princ->name.name_string.val[i],
		 strlen(princ->name.name_string.val[i]));
	p += strlen(princ->name.name_string.val[i]);
    }
    return 0;
}

