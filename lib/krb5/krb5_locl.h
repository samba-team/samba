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

#include <sys/param.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif
#include <des.h>

#include <krb5.h>
#include <krb5_err.h>
#include <asn1_err.h>

void 		krb5_data_free(krb5_data *);
krb5_error_code krb5_data_alloc(krb5_data *, int);
krb5_error_code krb5_data_realloc(krb5_data *, int);
krb5_error_code krb5_data_copy(krb5_data *, void *, size_t);


krb5_error_code krb5_get_lrealm(char ** realm);

krb5_error_code
krb5_parse_config_file(k5_cfile **cfile, const char *filename);

krb5_error_code
krb5_get_config_tag(k5_cfile *cf, const char *tag, char **value);

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

krb5_error_code
krb5_encrypt (krb5_context context,
	      void *ptr,
	      size_t len,
	      krb5_keyblock *keyblock,
	      krb5_data *result);

krb5_error_code
krb5_decrypt (krb5_context context,
	      void *ptr,
	      size_t len,
	      const krb5_keyblock *keyblock,
	      krb5_data *result);

krb5_error_code
krb5_create_checksum (krb5_context context,
		      krb5_cksumtype type,
		      void *ptr,
		      size_t len,
		      Checksum *result);

krb5_error_code
krb5_verify_checksum (krb5_context context,
		      void *ptr,
		      size_t len,
		      Checksum *sum);

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

#endif /* __KRB5_LOCL_H__ */
