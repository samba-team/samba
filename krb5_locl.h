#ifndef __KRB5_LOCL_H__
#define __KRB5_LOCL_H__

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

#include <des.h>

#include "krb5.h"

void 		krb5_data_free(krb5_data *);
krb5_error_code krb5_data_alloc(krb5_data *, int);
krb5_error_code krb5_data_realloc(krb5_data *, int);
krb5_error_code krb5_data_copy(krb5_data *, void *, size_t);


krb5_error_code krb5_principal_alloc(krb5_principal*);
void 		krb5_principal_free(krb5_principal);

krb5_error_code krb5_get_lrealm(char ** realm);



#define ALLOC(N, X) ((X*)malloc((N) * sizeof(X)))
#define FREE(X) do{if(X)free(X);}while(0)

#define RCSID(X) static char *rcsid[] = { (char*)rcsid, X }

#endif /* __KRB5_LOCL_H__ */
