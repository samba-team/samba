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

#ifndef __CACHE_H__
#define __CACHE_H__

krb5_error_code
krb5_cc_register(krb5_context context, krb5_cc_ops *ops, int override);

krb5_error_code
krb5_cc_resolve(krb5_context context,
		const char *residual,
		krb5_ccache *id);

krb5_error_code
krb5_cc_gen_new(krb5_context context,
		krb5_cc_ops *ops,
		krb5_ccache *id);

char *
krb5_cc_get_name (krb5_context context,
		  krb5_ccache id);

char *
krb5_cc_default_name (krb5_context context);

krb5_error_code
krb5_cc_default (krb5_context context,
		 krb5_ccache *id);

krb5_error_code
krb5_cc_initialize (krb5_context context,
		    krb5_ccache id,
		    krb5_principal primary_principal);

krb5_error_code
krb5_cc_destroy (krb5_context context,
		 krb5_ccache id);

krb5_error_code
krb5_cc_close (krb5_context context,
	       krb5_ccache id);

krb5_error_code
krb5_cc_store_cred (krb5_context context,
		    krb5_ccache id,
		    krb5_creds *creds);

krb5_error_code
krb5_cc_retrieve_cred (krb5_context context,
		       krb5_ccache id,
		       krb5_flags whichfields,
		       krb5_creds *mcreds,
		       krb5_creds *creds);

krb5_error_code
krb5_cc_get_principal (krb5_context context,
		       krb5_ccache id,
		       krb5_principal *principal);

krb5_error_code
krb5_cc_get_first (krb5_context context,
		   krb5_ccache id,
		   krb5_cc_cursor *cursor);

krb5_error_code
krb5_cc_get_next (krb5_context context,
		  krb5_ccache id,
		  krb5_creds *creds,
		  krb5_cc_cursor *cursor);

krb5_error_code
krb5_cc_end_get (krb5_context context,
		 krb5_ccache id,
		 krb5_cc_cursor *cursor);

krb5_error_code
krb5_cc_remove_cred (krb5_context context,
		     krb5_ccache id,
		     krb5_flags which,
		     krb5_creds *cred);

krb5_error_code
krb5_cc_set_flags (krb5_context context,
		   krb5_ccache id,
		   krb5_flags flags);

krb5_error_code
krb5_cc_start_seq_get (krb5_context context,
		       krb5_ccache id,
		       krb5_cc_cursor *cursor);

krb5_error_code
krb5_cc_next_cred (krb5_context context,
		   krb5_ccache id,
		   krb5_creds *creds,
		   krb5_cc_cursor *cursor);

krb5_error_code
krb5_cc_end_seq_get (krb5_context context,
		     krb5_ccache id,
		     krb5_cc_cursor *cursor);

extern krb5_cc_ops fcc_ops;

extern krb5_cc_ops mcc_ops;

#endif /* __CACHE_H__ */
