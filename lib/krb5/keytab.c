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

RCSID("$Id$");

krb5_error_code
krb5_kt_resolve(krb5_context context,
		const char *name,
		krb5_keytab *id)
{
  krb5_keytab k;

  if (strncmp (name, "FILE:", 5) != 0)
    return KRB5_KT_UNKNOWN_TYPE;

  ALLOC(k, 1);
  if (k == NULL)
    return ENOMEM;
  k->filename = strdup(name + 5);
  if (k->filename == NULL) {
    free(k);
    return ENOMEM;
  }
  *id = k;
  return 0;
}

#define KEYTAB_DEFAULT "FILE:/etc/v5srvtab"

krb5_error_code
krb5_kt_default_name(krb5_context context,
		     char *name,
		     int namesize)
{
  strncpy (name, KEYTAB_DEFAULT, namesize);
  return 0;
}

krb5_error_code
krb5_kt_default(krb5_context context,
		krb5_keytab *id)
{
  return krb5_kt_resolve (context, KEYTAB_DEFAULT, id);
}

krb5_error_code
krb5_kt_read_service_key(krb5_context context,
			 krb5_pointer keyprocarg,
			 krb5_principal principal,
			 krb5_kvno vno,
			 krb5_keytype keytype,
			 krb5_keyblock **key)
{
  krb5_keytab keytab;
  krb5_keytab_entry entry;
  krb5_error_code r;

  if (keyprocarg)
    r = krb5_kt_resolve (context, keyprocarg, &keytab);
  else
    r = krb5_kt_default (context, &keytab);

  if (r)
    return r;

  r = krb5_kt_get_entry (context, keytab, principal, vno, keytype, &entry);
  if (r)
    return r;
  *key = malloc(sizeof(**key));
  (*key)->keytype = entry.keyblock.keytype;
  (*key)->keyvalue.length = 0;
  (*key)->keyvalue.data = NULL;
  krb5_data_copy(&(*key)->keyvalue, entry.keyblock.keyvalue.data,
		 entry.keyblock.keyvalue.length);

  krb5_kt_close (context, keytab);
  return r;
}

#if 0 /* not implemented */
krb5_error_code
krb5_kt_remove_entry(krb5_context context,
		     krb5_keytab id,
		     krb5_keytab_entry *entry)
{
    abort();
}
#endif

krb5_error_code
krb5_kt_get_name(krb5_context context,
		 krb5_keytab keytab,
		 char *name,
		 int namesize)
{
  strncpy (name, keytab->filename, namesize);
  return 0;
}

krb5_error_code
krb5_kt_close(krb5_context context,
	      krb5_keytab id)
{
  free (id->filename);
  free (id);
  return 0;
}

krb5_error_code
krb5_kt_get_entry(krb5_context context,
		  krb5_keytab id,
		  krb5_const_principal principal,
		  krb5_kvno kvno,
		  krb5_keytype keytype,
		  krb5_keytab_entry *entry)
{
    krb5_keytab_entry tmp;
    krb5_error_code r;
    krb5_kt_cursor cursor;

    r = krb5_kt_start_seq_get (context, id, &cursor);
    if (r)
	return KRB5_KT_NOTFOUND; /* XXX i.e. file not found */

    entry->vno = 0;
    while (krb5_kt_next_entry(context, id, &tmp, &cursor) == 0) {
	if ((principal == NULL
	     || krb5_principal_compare(context,
				       principal,
				       tmp.principal))
	    && (keytype == 0 || keytype == tmp.keyblock.keytype)) {
	    if (kvno == tmp.vno) {
		krb5_kt_copy_entry_contents (context, &tmp, entry);
		krb5_kt_free_entry (context, &tmp);
		krb5_kt_end_seq_get(context, id, &cursor);
		return 0;
	    } else if (kvno == 0 && tmp.vno > entry->vno) {
		if (entry->vno)
		    krb5_kt_free_entry (context, entry);
		krb5_kt_copy_entry_contents (context, &tmp, entry);
	    }
	}
	krb5_kt_free_entry(context, &tmp);
    }
    krb5_kt_end_seq_get (context, id, &cursor);
    if (entry->vno)
	return 0;
    else
	return KRB5_KT_NOTFOUND;
}

krb5_error_code
krb5_kt_copy_entry_contents(krb5_context context,
			    const krb5_keytab_entry *in,
			    krb5_keytab_entry *out)
{
    krb5_error_code ret;

    memset(out, 0, sizeof(*out));
    out->vno = in->vno;

    ret = krb5_copy_principal (context, in->principal, &out->principal);
    if (ret)
	goto fail;
    ret = krb5_copy_keyblock_contents (context,
				       &in->keyblock,
				       &out->keyblock);
    if (ret)
	goto fail;
    return 0;
fail:
    krb5_kt_free_entry (context, out);
    return ret;
}

krb5_error_code
krb5_kt_free_entry(krb5_context context,
		   krb5_keytab_entry *entry)
{
  krb5_free_principal (context, entry->principal);
  krb5_free_keyblock_contents (context, &entry->keyblock);
  return 0;
}

krb5_error_code
krb5_kt_start_seq_get(krb5_context context,
		      krb5_keytab id,
		      krb5_kt_cursor *cursor)
{
  int16_t tag;
  int ret;

  cursor->fd = open (id->filename, O_RDONLY);
  if (cursor->fd < 0)
    return errno;
  cursor->sp = krb5_storage_from_fd(cursor->fd);
  ret = krb5_ret_int16(cursor->sp, &tag);
  if (ret)
    return ret;
  if (tag != 0x0502)
    return KRB5_KT_UNKNOWN_TYPE;
  return 0;
}

static krb5_error_code
krb5_kt_ret_data(krb5_storage *sp,
		 krb5_data *data)
{
    int ret;
    int16_t size;
    ret = krb5_ret_int16(sp, &size);
    if(ret)
	return ret;
    data->length = size;
    data->data = malloc(size);
    if (data->data == NULL)
	return ENOMEM;
    ret = sp->fetch(sp, data->data, size);
    if(ret != size)
	return (ret < 0)? errno : KRB5_KT_END;
    return 0;
}

static krb5_error_code
krb5_kt_ret_string(krb5_storage *sp,
		   general_string *data)
{
    int ret;
    int16_t size;
    ret = krb5_ret_int16(sp, &size);
    if(ret)
	return ret;
    *data = malloc(size + 1);
    if (*data == NULL)
	return ENOMEM;
    ret = sp->fetch(sp, *data, size);
    (*data)[size] = '\0';
    if(ret != size)
	return (ret < 0)? errno : KRB5_KT_END;
    return 0;
}

static krb5_error_code
krb5_kt_ret_principal(krb5_storage *sp,
		      krb5_principal *princ)
{
    int i;
    int ret;
    krb5_principal p;
    int16_t tmp;
    
    ALLOC(p, 1);
    if(p == NULL)
	return ENOMEM;

    ret = krb5_ret_int16(sp, &tmp);
    if(ret)
	return ret;
    p->name.name_type = KRB5_NT_SRV_HST;
    p->name.name_string.len = tmp;
    ret = krb5_kt_ret_string(sp, &p->realm);
    if(ret) return ret;
    p->name.name_string.val = calloc(p->name.name_string.len, 
				     sizeof(*p->name.name_string.val));
    if(p->name.name_string.val == NULL)
	return ENOMEM;
    for(i = 0; i < p->name.name_string.len; i++){
	ret = krb5_kt_ret_string(sp, p->name.name_string.val + i);
	if(ret) return ret;
    }
    *princ = p;
    return 0;
}

static krb5_error_code
krb5_kt_ret_keyblock(krb5_storage *sp, krb5_keyblock *p)
{
    int ret;
    int16_t tmp;

    ret = krb5_ret_int16(sp, &tmp); /* keytype + etype */
    if(ret) return ret;
    p->keytype = tmp;
    ret = krb5_kt_ret_data(sp, &p->keyvalue);
    return ret;
}

static krb5_error_code
krb5_kt_store_data(krb5_storage *sp,
		   krb5_data data)
{
    int ret;
    ret = krb5_store_int16(sp, data.length);
    if(ret < 0)
	return ret;
    ret = sp->store(sp, data.data, data.length);
    if(ret != data.length){
	if(ret < 0)
	    return errno;
	return KRB5_KT_END;
    }
    return 0;
}

static krb5_error_code
krb5_kt_store_string(krb5_storage *sp,
		     general_string data)
{
    int ret;
    size_t len = strlen(data);
    ret = krb5_store_int16(sp, len);
    if(ret < 0)
	return ret;
    ret = sp->store(sp, data, len);
    if(ret != len){
	if(ret < 0)
	    return errno;
	return KRB5_KT_END;
    }
    return 0;
}

static krb5_error_code
krb5_kt_store_keyblock(krb5_storage *sp, 
		       krb5_keyblock *p)
{
    int ret;

    ret = krb5_store_int16(sp, p->keytype); /* keytype + etype */
    if(ret) return ret;
    ret = krb5_kt_store_data(sp, p->keyvalue);
    return ret;
}


static krb5_error_code
krb5_kt_store_principal(krb5_storage *sp,
			krb5_principal p)
{
    int i;
    int ret;
    
    ret = krb5_store_int16(sp, p->name.name_string.len);
    if(ret) return ret;
    ret = krb5_kt_store_string(sp, p->realm);
    if(ret) return ret;
    for(i = 0; i < p->name.name_string.len; i++){
	ret = krb5_kt_store_string(sp, p->name.name_string.val[i]);
	if(ret) return ret;
    }
    return 0;
}


krb5_error_code
krb5_kt_add_entry(krb5_context context,
		  krb5_keytab id,
		  krb5_keytab_entry *entry)
{
    int ret;
    int fd;
    krb5_storage *sp;

    fd = open (id->filename, O_WRONLY | O_APPEND);
    if (fd < 0) {
	fd = open (id->filename, O_WRONLY | O_CREAT, 0600);
	if (fd < 0)
	    return errno;
	sp = krb5_storage_from_fd(fd);
	ret = krb5_store_int16 (sp, 0x0502);
	if (ret) return ret;
    } else {
	sp = krb5_storage_from_fd(fd);
    }

    ret = krb5_store_int32 (sp, 4711); /* XXX */
    if (ret) return ret;
    ret = krb5_kt_store_principal (sp, entry->principal);
    if (ret) return ret;
    ret = krb5_store_int32 (sp, entry->principal->name.name_type);
    if (ret) return ret;
    ret = krb5_store_int32 (sp, time(NULL));
    if (ret) return ret;
    ret = krb5_store_int8 (sp, entry->vno);
    if (ret) return ret;
    ret = krb5_kt_store_keyblock (sp, &entry->keyblock);
    if (ret) return ret;
    krb5_storage_free (sp);
    close (fd);
    return 0;
}

krb5_error_code
krb5_kt_next_entry(krb5_context context,
		   krb5_keytab id,
		   krb5_keytab_entry *entry,
		   krb5_kt_cursor *cursor)
{
  u_int32_t len;
  u_int32_t timestamp;
  int ret;
  int8_t tmp8;
  int32_t tmp32;

  ret = krb5_ret_int32(cursor->sp, &tmp32);
  if (ret)
    return ret;
  len = tmp32;
  ret = krb5_kt_ret_principal (cursor->sp, &entry->principal);
  if (ret)
    return ret;
  ret = krb5_ret_int32(cursor->sp, &tmp32);
  entry->principal->name.name_type = tmp32;
  if (ret)
    return ret;
  ret = krb5_ret_int32(cursor->sp, &tmp32);
  timestamp = tmp32;
  if (ret)
    return ret;
  ret = krb5_ret_int8(cursor->sp, &tmp8);
  if (ret)
    return ret;
  entry->vno = tmp8;
  ret = krb5_kt_ret_keyblock (cursor->sp, &entry->keyblock);
  if (ret)
    return ret;
  return 0;
}

krb5_error_code
krb5_kt_end_seq_get(krb5_context context,
		    krb5_keytab id,
		    krb5_kt_cursor *cursor)
{
    krb5_storage_free(cursor->sp);
    close (cursor->fd);
    return 0;
}
