#include "gssapi_locl.h"

RCSID("$Id$");

static OM_uint32
import_krb5_name (OM_uint32 *minor_status,
		  const gss_buffer_t input_name_buffer,
		  gss_name_t *output_name)
{
    krb5_error_code kerr;
    char *tmp;

    tmp = malloc (input_name_buffer->length + 1);
    if (tmp == NULL)
	return GSS_S_FAILURE;
    memcpy (tmp,
	    input_name_buffer->value,
	    input_name_buffer->length);
    tmp[input_name_buffer->length] = '\0';

    kerr = krb5_parse_name (gssapi_krb5_context,
			    tmp,
			    output_name);
    free (tmp);
    if (kerr == 0)
	return GSS_S_COMPLETE;
    else if (kerr == KRB5_PARSE_ILLCHAR || kerr == KRB5_PARSE_MALFORMED)
	return GSS_S_BAD_NAME;
    else
	return GSS_S_FAILURE;
}

static OM_uint32
import_hostbased_name (OM_uint32 *minor_status,
		       const gss_buffer_t input_name_buffer,
		       gss_name_t *output_name)
{
    krb5_error_code kerr;
    char *tmp;
    char *p;
    char *host;
    char local_hostname[MAXHOSTNAMELEN];
    struct hostent *hostent;

    tmp = malloc (input_name_buffer->length + 1);
    if (tmp == NULL)
	return GSS_S_FAILURE;
    memcpy (tmp,
	    input_name_buffer->value,
	    input_name_buffer->length);
    tmp[input_name_buffer->length] = '\0';

    p = strchr (tmp, '@');
    if (p != NULL) {
	*p = '\0';
	host = p + 1;
    } else {
	if (gethostname(local_hostname, sizeof(local_hostname)) < 0) {
	    free (tmp);
	    return GSS_S_FAILURE;
	}
	host = local_hostname;
    }
    hostent = gethostbyname (host);
    if (hostent != NULL)
	host = hostent->h_name;
    strlwr (host);

    kerr = krb5_sname_to_principal (gssapi_krb5_context,
				    host,
				    tmp,
				    KRB5_NT_SRV_HST,
				    output_name);
    free (tmp);
    if (kerr == 0)
	return GSS_S_COMPLETE;
    else if (kerr == KRB5_PARSE_ILLCHAR || kerr == KRB5_PARSE_MALFORMED)
	return GSS_S_BAD_NAME;
    else
	return GSS_S_FAILURE;
}

OM_uint32 gss_import_name
           (OM_uint32 * minor_status,
            const gss_buffer_t input_name_buffer,
            const gss_OID input_name_type,
            gss_name_t * output_name
           )
{
    gssapi_krb5_init ();

    if (input_name_type == GSS_C_NT_HOSTBASED_SERVICE)
	return import_hostbased_name (minor_status,
				      input_name_buffer,
				      output_name);
    else if (input_name_type == GSS_C_NO_OID) 	/* default printable syntax */
	return import_krb5_name (minor_status,
				 input_name_buffer,
				 output_name);
    else
	return GSS_S_BAD_NAMETYPE;
}
