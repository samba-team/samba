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

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <pwd.h>

#include <sys/param.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#include <netdb.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif
#include <des.h>
#include <md4.h>
#include <md5.h>
#include <sha.h>

#include <krb5.h>
#include <krb5_err.h>
#include <asn1_err.h>

void 		krb5_data_free(krb5_data *);
krb5_error_code krb5_data_alloc(krb5_data *, int);
krb5_error_code krb5_data_realloc(krb5_data *, int);
krb5_error_code krb5_data_copy(krb5_data *, void *, size_t);

krb5_error_code
krb5_set_default_realm(krb5_context context,
		       char *realm);

krb5_error_code
krb5_get_default_realm(krb5_context context,
		       char **realm);

krb5_error_code krb5_config_parse_file (const char *fname,
					krb5_config_section **res);
const char *krb5_config_get_next (krb5_config_section *c,
				  krb5_config_binding **pointer,
				  int type,
				  ...);
const char *krb5_config_vget_next (krb5_config_section *c,
				   krb5_config_binding **pointer,
				   int type,
				   va_list args);
const char *krb5_config_get_string (krb5_config_section *c,
				    ...);
const char *krb5_config_vget_string (krb5_config_section *c,
				     va_list args);

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

#define ALLOC(N, X) ((X*)malloc((N) * sizeof(X)))
#define FREE(X) do{if(X)free(X);}while(0)

int
extract_ticket(krb5_context context, 
	       krb5_kdc_rep *rep, 
	       krb5_creds *creds,		
	       krb5_keyblock *key,
	       krb5_const_pointer keyseed,
	       krb5_decrypt_proc decrypt_proc,
	       krb5_const_pointer decryptarg);

void krb5_NULL_checksum(void *p, size_t len, void *result);

void krb5_MD4_checksum(void *p, size_t len, void *result);

void krb5_MD5_checksum(void *p, size_t len, void *result);

void krb5_SHA1_checksum(void *p, size_t len, void *result);

void krb5_CRC_checksum(void *p, size_t len, void *result);

#endif /* __KRB5_LOCL_H__ */
