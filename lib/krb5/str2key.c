/*
 * Copyright (c) 1997, 1998 Kungliga Tekniska Högskolan
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
     static const unsigned char tbl[] = {
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

/* XXX what's this function supposed to do anyway? */
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

/* This defines the Andrew string_to_key function.  It accepts a password
 * string as input and converts its via a one-way encryption algorithm to a DES
 * encryption key.  It is compatible with the original Andrew authentication
 * service password database.
 */

static void
mklower(char *s)
{
    for (; *s; s++)
        if ('A' <= *s && *s <= 'Z')
            *s = *s - 'A' + 'a';
}

/*
 * Short passwords, i.e 8 characters or less.
 */
static void
afs_cmu_StringToKey (const char *pw, size_t pw_len, 
		     const char *cell, size_t cell_len, 
		     des_cblock *key)
{
    char  password[8+1];	/* crypt is limited to 8 chars anyway */
    int   i;
    
    memset (password, 0, sizeof(password));

    if(cell_len > 8) cell_len = 8;
    strncpy (password, cell, cell_len);

    if(pw_len > 8) pw_len = 8;
    for (i=0; i < pw_len; i++)
        password[i] ^= pw[i];

    for (i=0; i<8; i++)
        if (password[i] == '\0') password[i] = 'X';

    /* crypt only considers the first 8 characters of password but for some
       reason returns eleven characters of result (plus the two salt chars). */
    strncpy((char *)key, (char *)crypt(password, "#~") + 2, sizeof(des_cblock));

    /* parity is inserted into the LSB so leftshift each byte up one bit.  This
       allows ascii characters with a zero MSB to retain as much significance
       as possible. */
    {   char *keybytes = (char *)key;
        unsigned int temp;

        for (i = 0; i < 8; i++) {
            temp = (unsigned int) keybytes[i];
            keybytes[i] = (unsigned char) (temp << 1);
        }
    }
    des_fixup_key_parity (key);
}

/*
 * Long passwords, i.e 9 characters or more.
 */
static void
afs_transarc_StringToKey (const char *pw, size_t pw_len,
			  const char *cell, size_t cell_len,
			  des_cblock *key)
{
    des_key_schedule schedule;
    des_cblock temp_key;
    des_cblock ivec;
    char password[512];
    size_t passlen;

    memcpy(password, pw, min(pw_len, sizeof(password)));
    if(pw_len < sizeof(password))
	memcpy(password + pw_len, cell, min(cell_len, 
					    sizeof(password) - pw_len));
    passlen = min(sizeof(password), pw_len + cell_len);
    memcpy(&ivec, "kerberos", 8);
    memcpy(&temp_key, "kerberos", 8);
    des_fixup_key_parity (&temp_key);
    des_key_sched (&temp_key, schedule);
    des_cbc_cksum ((des_cblock *)password, &ivec, passlen, schedule, &ivec);

    memcpy(&temp_key, &ivec, 8);
    des_fixup_key_parity (&temp_key);
    des_key_sched (&temp_key, schedule);
    des_cbc_cksum ((des_cblock *)password, key, passlen, schedule, &ivec);
    memset(&schedule, 0, sizeof(schedule));
    memset(&temp_key, 0, sizeof(temp_key));
    memset(&ivec, 0, sizeof(ivec));
    memset(password, 0, sizeof(password));

    des_fixup_key_parity (key);
}

static void
AFS3_string_to_key(const char *pw, size_t pw_len,
		   const char *cell, size_t cell_len,
		   des_cblock *key)
{
    if(pw_len > 8)
	afs_transarc_StringToKey (pw, pw_len, cell, cell_len, key);
    else
	afs_cmu_StringToKey (pw, pw_len, cell, cell_len, key);
}

static void *
get_str(const void *pw, size_t pw_len, const void *salt, size_t salt_len, 
	size_t *ret_len)
{
    char *p;
    size_t len = pw_len + salt_len;
    len = (len + 7) & ~7;
    p = malloc(len);
    if(p == NULL)
	return NULL;
    memcpy(p, pw, pw_len);
    memcpy(p + pw_len, salt, salt_len);
    *ret_len = len;
    return p;
}

static krb5_error_code
string_to_key_internal (const unsigned char *str,
			size_t str_len,
			krb5_data *salt,
			krb5_keytype ktype,
			krb5_keyblock *key)
{
    size_t len;
    unsigned char *s = NULL;
    krb5_error_code ret;

    switch(ktype){
    case KEYTYPE_DES:{
	des_cblock tmpkey;
	s = get_str(str, str_len, salt->data, salt->length, &len);
	if(s == NULL)
	    return ENOMEM;
	DES_string_to_key(s, len, &tmpkey);
	ret = krb5_data_copy(&key->keyvalue, tmpkey, sizeof(des_cblock));
	memset(&tmpkey, 0, sizeof(tmpkey));
	break;
    }
    case KEYTYPE_DES_AFS3:{
	des_cblock tmpkey;
	AFS3_string_to_key(str, str_len, salt->data, salt->length, &tmpkey);
	ret = krb5_data_copy(&key->keyvalue, tmpkey, sizeof(des_cblock));
	key->keytype = KEYTYPE_DES;
	memset(&tmpkey, 0, sizeof(tmpkey));
	break;
    }
    case KEYTYPE_DES3:{
	des_cblock keys[3];
	s = get_str(str, str_len, salt->data, salt->length, &len);
	if(s == NULL)
	    return ENOMEM;
	DES3_string_to_key(s, len, keys);
	ret = krb5_data_copy(&key->keyvalue, keys, sizeof(keys));
	memset(keys, 0, sizeof(keys));
	break;
    }
    default:
	ret = KRB5_PROG_KEYTYPE_NOSUPP;
	break;
    }
    if(s){
	memset(s, 0, len);
	free(s);
    }
    if(ret)
	return ret;
    key->keytype = ktype;
    return 0;
}

krb5_error_code
krb5_string_to_key (const char *str,
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

