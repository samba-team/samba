/* $Id$ */

#ifndef GSSAPI_LOCL_H
#define GSSAPI_LOCL_H

#include <stdlib.h>
#include <string.h>

#include <gssapi.h>

#include <krb5.h>
#include <krb5_locl.h>

extern krb5_context gssapi_krb5_context;

void gssapi_krb5_init (void);

OM_uint32
gssapi_krb5_encapsulate(
			krb5_data *in_data,
			gss_buffer_t output_token,
			u_char *type);

OM_uint32
gssapi_krb5_decapsulate(
			gss_buffer_t input_token_buffer,
			krb5_data *out_data,
			u_char *type);

#endif
