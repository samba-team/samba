#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_init_context(krb5_context *context)
{
    krb5_context p;
    const char *skew;
    p = ALLOC(1, krb5_context_data);
    if(!p)
	return ENOMEM;
    memset(p, 0, sizeof(krb5_context_data));
    krb5_init_ets(p);
    p->cc_ops = NULL;
    krb5_config_parse_file (krb5_config_file, &p->cf);
    p->max_skew = 5 * 60;
    skew = krb5_config_get_string (p->cf, "libdefaults", "clockskew", NULL);
    if(skew){
	int tmp;
	if(sscanf(skew, "%d", &tmp) == 1)
	    p->max_skew = tmp;
    }
    krb5_set_default_realm(p, NULL);
    *context = p;
    return 0;
}

void krb5_os_free_context(krb5_context context)
{
  
}

void krb5_free_context(krb5_context context)
{
  int i;

  free(context->etypes);
  free(context->default_realm);
  krb5_config_file_free (context->cf);
  destroy_hdb_error_table (context->et_list);
  for(i = 0; i < context->num_ops; ++i)
    free(context->cc_ops[i].prefix);
  free(context->cc_ops);
  free(context);
}


static krb5_boolean
valid_etype(krb5_enctype e)
{
  return e == ETYPE_DES_CBC_CRC;
}

static krb5_error_code
default_etypes(krb5_enctype **etype)
{
  krb5_enctype *p;
  p = ALLOC(1, krb5_enctype);
  if(!p)
    return ENOMEM;
  p[0] = ETYPE_DES_CBC_CRC;
  *etype = p;
  return 0;
}

krb5_error_code
krb5_set_default_in_tkt_etypes(krb5_context context, 
			       const krb5_enctype *etypes)
{
  int i;
  krb5_enctype *p = NULL;
  if(etypes){
    i = 0;
    while(etypes[i])
      if(!valid_etype(etypes[i++]))
	return KRB5_PROG_ETYPE_NOSUPP;
    p = ALLOC(i, krb5_enctype);
    if(!p)
      return ENOMEM;
    memmove(p, etypes, i * sizeof(krb5_enctype));
  }
  if(context->etypes) free(context->etypes);
  context->etypes = p;
  return 0;
}



krb5_error_code
krb5_get_default_in_tkt_etypes(krb5_context context,
			       krb5_enctype **etypes)
{
  krb5_enctype *p;
  int i;
  if(context->etypes){
    for(i = 0; context->etypes[i]; i++);
    p = ALLOC(i, krb5_enctype);
    if(!p)
      return ENOMEM;
    memmove(p, context->etypes, i * sizeof(krb5_enctype));
  }else
    if(default_etypes(&p))
      return ENOMEM;
  *etypes = p;
  return 0;
}

const char *
krb5_get_err_text(krb5_context context, long code)
{
    const char *p = com_right(context->et_list, code);
    if(p == NULL)
	p = strerror(code);
    return p;
}

void
krb5_init_ets(krb5_context context)
{
    if(context->et_list == NULL){
	initialize_krb5_error_table(&context->et_list);
#if 0
	initialize_kv5m_error_table(&context->et_list);
	initialize_kdb5_error_table(&context->et_list);
#endif
	initialize_asn1_error_table(&context->et_list);
	initialize_hdb_error_table(&context->et_list);
    }
}
