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

#ifndef __KRB5_LOCL_H__
#define __KRB5_LOCL_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#if defined(HAVE_SYS_IOCTL_H) && SunOS != 4
#include <sys/ioctl.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif
#include <roken.h>

#include <des.h>
#include <md4.h>
#include <md5.h>
#include <sha.h>

#include <krb5.h>
#include <krb5_err.h>
#include <asn1_err.h>
#include <error.h>

/* data.c */

/* set_default_realm.c */

krb5_error_code
krb5_set_default_realm(krb5_context context,
		       char *realm);

/* get_default_realm.c */

krb5_error_code
krb5_get_default_realm(krb5_context context,
		       char **realm);

/* config_file.c */

krb5_error_code krb5_config_parse_file (const char *fname,
					krb5_config_section **res);
const void *krb5_config_get_next (krb5_config_section *c,
				  krb5_config_binding **pointer,
				  int type,
				  ...);
const void *krb5_config_vget_next (krb5_config_section *c,
				   krb5_config_binding **pointer,
				   int type,
				   va_list args);

const void *krb5_config_get (krb5_config_section *c,
			     int type,
			     ...);

const void *krb5_config_vget (krb5_config_section *c,
			      int type,
			      va_list args);

const char *krb5_config_get_string (krb5_config_section *c,
				    ...);
const char *krb5_config_vget_string (krb5_config_section *c,
				     va_list args);

char **krb5_config_vget_strings(krb5_config_section *c, va_list args);
char **krb5_config_get_strings(krb5_config_section *c, ...);
void krb5_config_free_strings(char **strings);

krb5_boolean krb5_config_vget_bool (krb5_config_section *c, va_list args);

krb5_boolean krb5_config_get_bool (krb5_config_section *c, ...);

int krb5_config_vget_time (krb5_config_section *c, va_list args);

int krb5_config_get_time (krb5_config_section *c, ...);

const krb5_config_binding *krb5_config_get_list (krb5_config_section *c,
						 ...);
const krb5_config_binding *krb5_config_vget_list (krb5_config_section *c,
						  va_list args);

krb5_error_code
krb5_config_file_free (krb5_config_section *s);

int
krb5_getportbyname (const char *service,
		    const char *proto,
		    int default_port);

krb5_error_code
krb5_sendto_kdc (krb5_context context,
		 const krb5_data *send,
		 const krb5_realm *realm,
		 krb5_data *receive);

krb5_error_code
krb5_build_ap_req (krb5_context context,
		   krb5_creds *cred,
		   krb5_flags ap_options,
		   krb5_data authenticator,
		   krb5_data *ret);

krb5_error_code
krb5_build_authenticator (krb5_context context,
			  krb5_auth_context auth_context,
			  krb5_creds *cred,
			  Checksum *cksum,
			  Authenticator **auth,
			  krb5_data *result);

void
krb5_generate_random_block(void *buf, size_t len);

#define ALLOC(X, N) (X) = calloc((N), sizeof(*(X)))

int
extract_ticket(krb5_context context, 
	       krb5_kdc_rep *rep, 
	       krb5_creds *creds,		
	       krb5_keyblock *key,
	       krb5_const_pointer keyseed,
	       krb5_addresses *addr,
	       unsigned nonce,
	       krb5_decrypt_proc decrypt_proc,
	       krb5_const_pointer decryptarg);

krb5_error_code
krb5_init_etype (krb5_context context,
		 unsigned *len,
		 unsigned **val,
		 const krb5_enctype *etypes);

PA_DATA *krb5_find_padata(PA_DATA*, unsigned, int, int*);

#endif /* __KRB5_LOCL_H__ */
