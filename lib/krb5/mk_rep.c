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

krb5_error_code
krb5_mk_rep(krb5_context context,
	    krb5_auth_context *auth_context,
	    krb5_data *outbuf)
{
  krb5_error_code ret;
  AP_REP ap;
  EncAPRepPart body;
  krb5_enctype etype;
  u_char *buf = NULL;
  size_t buf_size;
  size_t len;

  ap.pvno = 5;
  ap.msg_type = krb_ap_rep;

  memset (&body, 0, sizeof(body));

  body.ctime = (*auth_context)->authenticator->ctime;
  body.cusec = (*auth_context)->authenticator->cusec;
  body.subkey = NULL;
  if ((*auth_context)->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) {
    krb5_generate_seq_number (context,
			      (*auth_context)->keyblock,
			      &(*auth_context)->local_seqnumber);
    body.seq_number = malloc (sizeof(*body.seq_number));
    if (body.seq_number == NULL)
	return ENOMEM;
    *(body.seq_number) = (*auth_context)->local_seqnumber;
  } else
    body.seq_number = NULL;

  krb5_keytype_to_etype(context, (*auth_context)->keyblock->keytype, &etype);
  ap.enc_part.etype = etype;
  ap.enc_part.kvno  = NULL;

  buf_size = 1024;
  buf = malloc (buf_size);
  if (buf == NULL) {
      free_EncAPRepPart (&body);
      return ENOMEM;
  }

  do {
      ret = krb5_encode_EncAPRepPart (context, buf + buf_size - 1,
				      buf_size,
				      &body, &len);
      if (ret) {
	  if (ret == ASN1_OVERFLOW) {
	      u_char *tmp;

	      buf_size *= 2;
	      tmp = realloc (buf, buf_size);
	      if (tmp == NULL) {
		  free(buf);
		  free_EncAPRepPart (&body);
		  return ENOMEM;
	      }
	      buf = tmp;
	  } else {
	      free_EncAPRepPart (&body);
	      free(buf);
	      return ret;
	  }
      }
  } while(ret == ASN1_OVERFLOW);

  ret = krb5_encrypt (context,
		      buf + buf_size - len, len,
		      ap.enc_part.etype,
		      (*auth_context)->keyblock,
		      &ap.enc_part.cipher);
  if (ret) {
      free(buf);
      free_EncAPRepPart (&body);
      return ret;
  }

  do {
      ret = encode_AP_REP (buf + buf_size - 1, buf_size, &ap, &len);
      if (ret) {
	  if (ret == ASN1_OVERFLOW) {
	      u_char *tmp;

	      buf_size *= 2;
	      tmp = realloc (buf, buf_size);
	      if (tmp == NULL) {
		  free_AP_REP (&ap);
		  free_EncAPRepPart (&body);
		  free (buf);
		  return ENOMEM;
	      }
	      buf = tmp;
	  } else {
	      free_AP_REP (&ap);
	      free_EncAPRepPart (&body);
	      free(buf);
	      return ret;
	  }
      }
  } while (ret == ASN1_OVERFLOW);

  free_AP_REP (&ap);
  free_EncAPRepPart (&body);

  outbuf->length = len;
  outbuf->data = malloc(len);
  if (outbuf->data == NULL) {
      free (buf);
      return ENOMEM;
  }
  memcpy(outbuf->data, buf + buf_size - len, len);
  free (buf);
  return 0;
}
