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

krb5_error_code
krb5_mk_req_extended(krb5_context context,
		     krb5_auth_context *auth_context,
		     const krb5_flags ap_req_options,
		     krb5_data *in_data,
		     krb5_creds *in_creds,
		     krb5_data *outbuf)
{
  krb5_error_code r;
  krb5_data authenticator;
  Checksum c;
  Checksum *c_opt;
  krb5_cksumtype cksumtype;
  krb5_auth_context ac;

  if(auth_context) {
      if(*auth_context == NULL)
	  r = krb5_auth_con_init(context, auth_context);
      else
	  r = 0;
      ac = *auth_context;
  } else
      r = krb5_auth_con_init(context, &ac);
  if(r)
      return r;
      
  krb5_free_keyblock(context, ac->keyblock);
  krb5_copy_keyblock(context, &in_creds->session, &ac->keyblock);
  
  if (ac->cksumtype)
      cksumtype = ac->cksumtype;
  else
      krb5_keytype_to_cksumtype (context, ac->keyblock->keytype, &cksumtype);

  if (in_data) {
      r = krb5_create_checksum (context,
				cksumtype,
				in_data->data,
				in_data->length,
				ac->keyblock,
				&c);
      c_opt = &c;
  } else {
      c_opt = NULL;
  }
  
  r = krb5_build_authenticator (context,
				ac,
				in_creds,
				c_opt,
				NULL,
				&authenticator);
  if (c_opt)
      free_Checksum (c_opt);
  if (r)
    return r;

  r = krb5_build_ap_req (context, in_creds, ap_req_options,
			 authenticator, outbuf);
  if(auth_context == NULL)
      krb5_auth_con_free(context, ac);
  return r;
}
