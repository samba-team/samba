#include "gssapi_locl.h"

RCSID("$Id$");

void
gssapi_krb5_encap_length (size_t data_len,
			  size_t *len,
			  size_t *total_len)
{
    size_t len_len;

    *len = 1 + 1 + GSS_KRB5_MECHANISM->length + 2 + data_len;

    len_len = length_len(*len);

    *total_len = 1 + len_len + *len;
}

u_char *
gssapi_krb5_make_header (u_char *p,
			 size_t len,
			 u_char *type)
{
    int e;
    size_t len_len, foo;

    *p++ = 0x60;
    len_len = length_len(len);
    e = der_put_length (p + len_len - 1, len_len, len, &foo);
    if(e || foo != len_len)
	abort ();
    p += len_len;
    *p++ = 0x06;
    *p++ = GSS_KRB5_MECHANISM->length;
    memcpy (p, GSS_KRB5_MECHANISM->elements, GSS_KRB5_MECHANISM->length);
    p += GSS_KRB5_MECHANISM->length;
    memcpy (p, type, 2);
    p += 2;
    return p;
}

/*
 * Give it a krb5_data and it will encapsulate with extra GSS-API wrappings.
 */

OM_uint32
gssapi_krb5_encapsulate(
			krb5_data *in_data,
			gss_buffer_t output_token,
			u_char *type
)
{
    size_t len, outer_len;
    u_char *p;

    gssapi_krb5_encap_length (in_data->length, &len, &outer_len);
    
    output_token->length = outer_len;
    output_token->value  = malloc (outer_len);
    if (output_token->value == NULL)
	return GSS_S_FAILURE;

    p = gssapi_krb5_make_header (output_token->value, len, type);
    memcpy (p, in_data->data, in_data->length);
    krb5_data_free (in_data);
    return GSS_S_COMPLETE;
}
