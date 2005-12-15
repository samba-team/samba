/*
 * Copyright (c) 1997-2005 Kungliga Tekniska Högskolan
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

/* 
 * $Id: kdc_locl.h,v 1.74 2005/12/12 12:23:33 lha Exp $ 
 */

#ifndef __KDC_LOCL_H__
#define __KDC_LOCL_H__

#include "headers.h"
#include "kdc.h"

typedef struct pk_client_params pk_client_params;
#include <kdc-private.h>

extern sig_atomic_t exit_flag;
extern size_t max_request;
extern const char *port_str;
extern krb5_addresses explicit_addresses;

extern int enable_http;

#define DETACH_IS_DEFAULT FALSE

extern int detach_from_console;

#define _PATH_KDC_CONF		HDB_DB_DIR "/kdc.conf"
#define DEFAULT_LOG_DEST	"0-1/FILE:" HDB_DB_DIR "/kdc.log"

extern struct timeval _kdc_now;
#define kdc_time (_kdc_now.tv_sec)

krb5_error_code
_kdc_as_rep(krb5_context context, 
	    krb5_kdc_configuration *config,
	    KDC_REQ*, const krb5_data*, krb5_data*, 
	    const char*, struct sockaddr*);

krb5_kdc_configuration *
configure(krb5_context context, int argc, char **argv);

krb5_error_code
_kdc_db_fetch(krb5_context context,
	      krb5_kdc_configuration *config,
	      krb5_principal principal, enum hdb_ent_type ent_type, 
	      hdb_entry_ex **h);

void
_kdc_free_ent(krb5_context context, hdb_entry_ex *ent);

void
loop(krb5_context context, krb5_kdc_configuration *config);

krb5_error_code
_kdc_tgs_rep (krb5_context context, 
	      krb5_kdc_configuration *config,
	      KDC_REQ*, krb5_data*, const char*, struct sockaddr *);

krb5_error_code
_kdc_check_flags(krb5_context context, 
		 krb5_kdc_configuration *config,
		 hdb_entry *client, const char *client_name,
		 hdb_entry *server, const char *server_name,
		 krb5_boolean is_as_req);

krb5_error_code
_kdc_get_des_key(krb5_context context, hdb_entry_ex*, 
		 krb5_boolean, krb5_boolean, Key**);

krb5_error_code
_kdc_encode_v4_ticket(krb5_context context, 
		      krb5_kdc_configuration *config,
		      void *buf, size_t len, const EncTicketPart *et,
		      const PrincipalName *service, size_t *size);
krb5_error_code
_kdc_do_524(krb5_context context, 
	    krb5_kdc_configuration *config,
	    const Ticket *t, krb5_data *reply,
	    const char *from, struct sockaddr *addr);


#ifdef PKINIT
typedef struct pk_client_params pk_client_params;
krb5_error_code _kdc_pk_initialize(krb5_context,
				   krb5_kdc_configuration *, 
				   const char *,
				   const char *);
krb5_error_code _kdc_pk_rd_padata(krb5_context, krb5_kdc_configuration *, 
			      KDC_REQ *, PA_DATA *, pk_client_params **);
krb5_error_code	_kdc_pk_mk_pa_reply(krb5_context,
				    krb5_kdc_configuration *, 
				    pk_client_params *,
				    const hdb_entry *,
				    const KDC_REQ *,
				    const krb5_data *,
				    krb5_keyblock **,
				    METHOD_DATA *);
krb5_error_code _kdc_pk_check_client(krb5_context, 
				     krb5_kdc_configuration *,
				     krb5_principal,
				     const hdb_entry *, 
				     pk_client_params *, char **);
void _kdc_pk_free_client_param(krb5_context, pk_client_params *);
#endif

/*
 * Kerberos 4
 */

krb5_error_code
_kdc_db_fetch4 (krb5_context context, 
		krb5_kdc_configuration *config,
		const char*, const char*, const char*, enum hdb_ent_type, hdb_entry_ex**);

krb5_error_code
_kdc_do_version4 (krb5_context context, 
		  krb5_kdc_configuration *config,
		  unsigned char*, size_t, krb5_data*, const char*, 
		  struct sockaddr_in*);
int
_kdc_maybe_version4(unsigned char*, int);

krb5_error_code
_kdc_do_kaserver (krb5_context context, 
		  krb5_kdc_configuration *config,
		  unsigned char*, size_t, krb5_data*,
		  const char*, struct sockaddr_in*);


#endif /* __KDC_LOCL_H__ */
