/*
 * Copyright (c) 2000 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of the Institute nor the names of its contributors 
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

#include "hdb_locl.h"
#ifndef O_BINARY
#define O_BINARY 0
#endif

RCSID("$Id$");

struct hdb_master_key_data {
    krb5_keytab_entry keytab;
    krb5_crypto crypto;
    struct hdb_master_key_data *next;
};

void
hdb_free_master_key(krb5_context context, hdb_master_key mkey)
{
    struct hdb_master_key_data *ptr;
    while(mkey) {
	krb5_kt_free_entry(context, &mkey->keytab);
	krb5_crypto_destroy(context, mkey->crypto);
	ptr = mkey;
	mkey = mkey->next;
	free(ptr);
    }
}

krb5_error_code
hdb_process_master_key(krb5_context context,
		       int kvno, krb5_keyblock *key, krb5_enctype etype,
		       hdb_master_key *mkey)
{
    krb5_error_code ret;
    *mkey = calloc(1, sizeof(**mkey));
    if(*mkey == NULL)
	return ENOMEM;
    (*mkey)->keytab.vno = kvno;
    ret = krb5_parse_name(context, "K/M", &(*mkey)->keytab.principal);
    ret = krb5_copy_keyblock_contents(context, key, &(*mkey)->keytab.keyblock);
    if(ret) {
	free(*mkey);
	*mkey = NULL;
	return ret;
    }
    if(etype != 0)
	(*mkey)->keytab.keyblock.keytype = etype;
    (*mkey)->keytab.timestamp = time(NULL);
    ret = krb5_crypto_init(context, key, etype, &(*mkey)->crypto);
    if(ret) {
	krb5_free_keyblock_contents(context, &(*mkey)->keytab.keyblock);
	free(*mkey);
	*mkey = NULL;
    }
    return ret;
}

krb5_error_code
hdb_add_master_key(krb5_context context, krb5_keyblock *key,
		   hdb_master_key *inout)
{
    int vno = 0;
    hdb_master_key p;
    krb5_error_code ret;

    for(p = *inout; p; p = p->next)
	vno = max(vno, p->keytab.vno);
    vno++;
    ret = hdb_process_master_key(context, vno, key, 0, &p);
    if(ret)
	return ret;
    p->next = *inout;
    *inout = p;
    return 0;
}

static krb5_error_code
read_master_keytab(krb5_context context, const char *filename, 
		   hdb_master_key *mkey)
{
    krb5_error_code ret;
    krb5_keytab id;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    hdb_master_key p;
    
    ret = krb5_kt_resolve(context, filename, &id);
    if(ret)
	return ret;

    ret = krb5_kt_start_seq_get(context, id, &cursor);
    if(ret)
	goto out;
    *mkey = NULL;
    while(krb5_kt_next_entry(context, id, &entry, &cursor) == 0) {
	p = calloc(1, sizeof(*p));
	p->keytab = entry;
	ret = krb5_crypto_init(context, &p->keytab.keyblock, 0, &p->crypto);
	p->next = *mkey;
	*mkey = p;
    }
    krb5_kt_end_seq_get(context, id, &cursor);
  out:
    krb5_kt_close(context, id);
    return ret;
}

/* read a MIT master keyfile */
static krb5_error_code
read_master_mit(krb5_context context, const char *filename, 
		hdb_master_key *mkey)
{
    int fd;
    krb5_error_code ret;
    krb5_storage *sp;
    u_int16_t enctype;
    krb5_keyblock key;
	       
    fd = open(filename, O_RDONLY | O_BINARY);
    if(fd < 0)
	return errno;
    sp = krb5_storage_from_fd(fd);
    if(sp == NULL) {
	close(fd);
	return errno;
    }
    krb5_storage_set_flags(sp, KRB5_STORAGE_HOST_BYTEORDER);
    ret = krb5_ret_int16(sp, &enctype);
    if((htons(enctype) & 0xff00) == 0x3000) {
	ret = HEIM_ERR_BAD_MKEY;
	goto out;
    }
    ret = krb5_ret_keyblock(sp, &key);
    if(enctype != 0x1ff /* ENCTYPE_UNKNOWN */ && enctype != key.keytype)
	ret = HEIM_ERR_BAD_MKEY;
    else
	ret = hdb_process_master_key(context, 0, &key, 0, mkey);
    krb5_free_keyblock_contents(context, &key);
  out:
    krb5_storage_free(sp);
    close(fd);
    return ret;
}

/* read an old master key file */
static krb5_error_code
read_master_encryptionkey(krb5_context context, const char *filename, 
			  hdb_master_key *mkey)
{
    int fd;
    krb5_keyblock key;
    krb5_error_code ret;
    unsigned char buf[256];
    ssize_t len;
	       
    fd = open(filename, O_RDONLY | O_BINARY);
    if(fd < 0)
	return errno;
    
    len = read(fd, buf, sizeof(buf));
    close(fd);
    if(len < 0)
	return errno;

    ret = decode_EncryptionKey(buf, len, &key, &len);
    memset(buf, 0, sizeof(buf));
    if(ret)
	return ret;
    
    ret = hdb_process_master_key(context, 0, &key, ETYPE_DES_CFB64_NONE, mkey);
    return ret;
}

krb5_error_code
hdb_read_master_key(krb5_context context, const char *filename, 
		    hdb_master_key *mkey)
{
    FILE *f;
    unsigned char buf[16];
    krb5_error_code ret;

    off_t len;

    if(filename == NULL)
	filename = HDB_DB_DIR "/m-key";

    f = fopen(filename, "r");
    if(f == NULL)
	return errno;
    
    if(fread(buf, 1, 2, f) != 2) {
	fclose(f);
	return HEIM_ERR_EOF;
    }
    
    fseek(f, 0, SEEK_END);
    len = ftell(f);

    if(fclose(f) != 0)
	return errno;
    
    if(len < 0)
	return errno;
    
    if(buf[0] == 0x30 && len <= 127 && buf[1] == len - 2) {
	ret = read_master_encryptionkey(context, filename, mkey);
    } else if(buf[0] == 5 && buf[1] >= 1 && buf[1] <= 2) {
	ret = read_master_keytab(context, filename, mkey);
    } else {
	ret = read_master_mit(context, filename, mkey);
    }
    return ret;
}

krb5_error_code
hdb_write_master_key(krb5_context context, const char *filename, 
		     hdb_master_key mkey)
{
    krb5_error_code ret;
    hdb_master_key p;
    krb5_keytab kt;

    if(filename == NULL)
	filename = HDB_DB_DIR "/m-key";

    ret = krb5_kt_resolve(context, filename, &kt);
    if(ret)
	return ret;

    for(p = mkey; p; p = p->next) {
	ret = krb5_kt_add_entry(context, kt, &p->keytab);
    }

    krb5_kt_close(context, kt);

    return ret;
}

static hdb_master_key
find_master_key(Key *key, hdb_master_key mkey)
{
    hdb_master_key ret = NULL;
    while(mkey) {
	if(ret == NULL && mkey->keytab.vno == 0)
	    ret = mkey;
	if(key->mkvno == NULL) {
	    if(ret == NULL || mkey->keytab.vno > ret->keytab.vno)
		ret = mkey;
	} else if(mkey->keytab.vno == *key->mkvno)
	    return mkey;
	mkey = mkey->next;
    }
    return ret;
}

void
_hdb_unseal_keys_int(krb5_context context, hdb_entry *ent, hdb_master_key mkey)
{
    int i;
    krb5_error_code ret;
    krb5_data res;
    Key *k;
    for(i = 0; i < ent->keys.len; i++){
	hdb_master_key key;

	k = &ent->keys.val[i];
	if(k->mkvno == NULL)
	    continue;

	key = find_master_key(&ent->keys.val[i], mkey);

	ret = krb5_decrypt(context, key->crypto, 0, 
			   k->key.keyvalue.data,
			   k->key.keyvalue.length,
			   &res);

	memset(k->key.keyvalue.data, 0, k->key.keyvalue.length);
	free(k->key.keyvalue.data);
	k->key.keyvalue = res;
	free(k->mkvno);
	k->mkvno = NULL;
    }
}

void
hdb_unseal_keys(krb5_context context, HDB *db, hdb_entry *ent)
{
    if (db->master_key_set == 0)
	return;
    _hdb_unseal_keys_int(context, ent, db->master_key);
}

void
_hdb_seal_keys_int(krb5_context context, hdb_entry *ent, hdb_master_key mkey)
{
    int i;
    krb5_error_code ret;
    krb5_data res;
    for(i = 0; i < ent->keys.len; i++){
	Key *k = &ent->keys.val[i];
	hdb_master_key key;

	if(k->mkvno != NULL)
	    continue;

	key = find_master_key(k, mkey);

	ret = krb5_encrypt(context, key->crypto, 0,
			   k->key.keyvalue.data,
			   k->key.keyvalue.length,
			   &res);

	memset(k->key.keyvalue.data, 0, k->key.keyvalue.length);
	free(k->key.keyvalue.data);
	k->key.keyvalue = res;

	k->mkvno = malloc(sizeof(*k->mkvno));
	*k->mkvno = key->keytab.vno;
    }
}

void
hdb_seal_keys(krb5_context context, HDB *db, hdb_entry *ent)
{
    if (db->master_key_set == 0)
	return;
    
    _hdb_seal_keys_int(context, ent, db->master_key);
}

krb5_error_code
hdb_set_master_key (krb5_context context,
		    HDB *db,
		    krb5_keyblock *key)
{
    krb5_error_code ret;
    hdb_master_key mkey;

    ret = hdb_process_master_key(context, 0, key, 0, &mkey);
    if (ret)
	return ret;
    db->master_key = mkey;
#if 0 /* XXX - why? */
    des_set_random_generator_seed(key.keyvalue.data);
#endif
    db->master_key_set = 1;
    return 0;
}

krb5_error_code
hdb_set_master_keyfile (krb5_context context,
			HDB *db,
			const char *keyfile)
{
    hdb_master_key key;
    krb5_error_code ret;

    ret = hdb_read_master_key(context, keyfile, &key);
    if (ret) {
	if (ret != ENOENT)
	    return ret;
	return 0;
    }
    db->master_key = key;
    db->master_key_set = 1;
    return ret;
}

krb5_error_code
hdb_clear_master_key (krb5_context context,
		      HDB *db)
{
    if (db->master_key_set) {
	hdb_free_master_key(context, db->master_key);
	db->master_key_set = 0;
    }
    return 0;
}
