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

#include "krb5.h"

void 		krb5_data_free(krb5_data *);
krb5_error_code krb5_data_alloc(krb5_data *, int);
krb5_error_code krb5_data_realloc(krb5_data *, int);
krb5_error_code krb5_data_copy(krb5_data *, void *, size_t);


krb5_error_code krb5_principal_alloc(krb5_principal*);
void 		krb5_principal_free(krb5_principal);

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
		 const krb5_data *realm,
		 krb5_data *receive);

krb5_error_code
krb5_build_ap_req (krb5_context context,
		   krb5_creds *cred,
		   krb5_flags ap_options,
		   krb5_data authenticator,
		   krb5_data *ret);

krb5_error_code
krb5_build_authenticator (krb5_context context,
			  krb5_principal client,
			  Checksum *cksum,
			  Authenticator **auth,
			  krb5_data *result);

#define ALLOC(N, X) ((X*)malloc((N) * sizeof(X)))
#define FREE(X) do{if(X)free(X);}while(0)

#endif /* __KRB5_LOCL_H__ */
