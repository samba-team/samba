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

#include "krb5_locl.h"

krb5_error_code
krb5_generate_random_des_key(krb5_context context,
			     krb5_keyblock *keyblock)
{
    des_new_random_key(keyblock->keyvalue.data);
    return 0;
}

static struct key_type {
    int keytype;
    int keysize;
    krb5_error_code (*func)(krb5_context, krb5_keyblock*);
} key_types[] = {
    { KEYTYPE_DES, 8, krb5_generate_random_des_key },
};

static const int num_key_types = sizeof(key_types) / sizeof(key_types[0]);

krb5_error_code
krb5_generate_random_keyblock(krb5_context context,
			      int keytype,
			      krb5_keyblock *keyblock)
{
    struct key_type *k;
    for(k = key_types; k < key_types + num_key_types; k++)
	if(keytype == k->keytype){
	    keyblock->keytype = keytype;
	    keyblock->keyvalue.length = k->keysize;
	    keyblock->keyvalue.data = malloc(keyblock->keyvalue.length);
	    return (*k->func)(context, keyblock);
	}
    return KRB5_PROG_KEYTYPE_NOSUPP;
}
