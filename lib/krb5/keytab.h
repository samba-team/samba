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

/* $Id$ */

#ifndef __KEYTAB_H__
#define __KEYTAB_H__

#if 0
krb5_error_code
krb5_kt_register(krb5_context, krb5_kt_ops *);
#endif

krb5_error_code
krb5_kt_resolve(krb5_context, const char *, krb5_keytab *id);

krb5_error_code
krb5_kt_default_name(krb5_context, char *name, int namesize);

krb5_error_code
krb5_kt_default(krb5_context, krb5_keytab *id);

krb5_error_code
krb5_kt_read_service_key(krb5_context,
			 krb5_pointer keyprocarg,
			 krb5_principal principal,
			 krb5_kvno vno,
			 krb5_keytype keytype,
			 krb5_keyblock **key);

krb5_error_code
krb5_kt_add_entry(krb5_context,
		  krb5_keytab id,
		  krb5_keytab_entry *entry);

krb5_error_code
krb5_kt_remove_entry(krb5_context,
		     krb5_keytab id,
		     krb5_keytab_entry *entry);

krb5_error_code
krb5_kt_get_name(krb5_context,
		 krb5_keytab,
		 char *name,
		 int namesize);

krb5_error_code
krb5_kt_close(krb5_context,
	      krb5_keytab id);

krb5_error_code
krb5_kt_get_entry(krb5_context context,
		  krb5_keytab id,
		  krb5_principal principal,
		  krb5_kvno kvno,
		  krb5_keytype keytype,
		  krb5_keytab_entry *entry);

krb5_error_code
krb5_kt_free_entry(krb5_context,
		   krb5_keytab_entry *);

krb5_error_code
krb5_kt_start_seq_get(krb5_context,
		      krb5_keytab id,
		      krb5_kt_cursor *);

krb5_error_code
krb5_kt_next_entry(krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry *,
		   krb5_kt_cursor *);

krb5_error_code
krb5_kt_end_seq_get(krb5_context,
		    krb5_keytab,
		    krb5_kt_cursor *);

#endif /* __KEYTAB_H__ */
