#include "krb5_locl.h"

krb5_error_code
krb5_init_context(krb5_context *context)
{
  krb5_context p;
  p = ALLOC(1, krb5_context_data);
  if(!p)
    return ENOMEM;
  memset(p, 0, sizeof(krb5_context_data));
  krb5_parse_config_file(&p->cf, NULL);
  krb5_get_lrealm(&p->default_realm);
  *context = p;
  return 0;
}

void krb5_os_free_context(krb5_context context)
{
  
}

void krb5_free_context(krb5_context context)
{
  free(context->default_realm);
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

